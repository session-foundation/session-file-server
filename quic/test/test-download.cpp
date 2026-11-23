#include <fmt/chrono.h>
#include <fmt/format.h>
#include <fmt/std.h>
#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>

#include <exception>
#include <filesystem>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/quic/btstream.hpp>
#include <oxen/quic/endpoint.hpp>

using namespace std::literals;
using namespace oxen;
using namespace log::literals;

static auto cat = log::Cat("upload");

int main(int argc, char* argv[]) {

    log::add_sink(log::Type::Print, "-");
    log::reset_level(log::Level::warn);
    log::set_level(cat, log::Level::info);

    auto usage = [&argv](std::string_view msg) {
        if (!msg.empty())
            log::error(cat, "{}", msg);
        log::info(
                cat,
                "\n\nUsage: {} IP:PORT PUBKEY FILEID [FILEID2 ...]\n\nDownloads files from a "
                "fileserver to ./FILEID ./FILEID2 etc.\n\n",
                argv[0]);
        return 1;
    };

    if (argc < 4)
        return usage("Insufficient arguments");

    quic::Address addr;
    try {
        addr = quic::Address::parse(argv[1]);
    } catch (const std::exception& e) {
        return usage("{} doesn't look like an IP:PORT address ({})"_format(argv[2], e.what()));
    }

    std::string_view pubkey{argv[2]};
    if (pubkey.size() != 64 || !oxenc::is_hex(pubkey))
        return usage("{} is not a valid pubkey"_format(pubkey));

    int ttl = 0;
    int id_i = 3;

    if (id_i >= argc)
        return usage("No upload files given!");

    constexpr auto b64_url_chars =
            "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"sv;
    struct state {
        std::string id;
        std::filesystem::path f;
        std::string partial;
        std::vector<std::byte> meta;
        int meta_size = -1;
        int size = -1;
        std::chrono::sys_seconds uploaded;
        std::chrono::sys_seconds expiry;
        int received = 0;
        std::ofstream out;
    };

    std::vector<state> downloads;
    std::unordered_set<std::filesystem::path> dupes;
    for (; id_i < argc; id_i++) {
        auto& st = downloads.emplace_back();
        st.id = argv[id_i];
        if (!((st.id.size() == 44 && st.id.find_first_not_of(b64_url_chars) == std::string::npos) ||
              (st.id.size() >= 1 && st.id.size() <= 16 &&
               st.id.find_first_not_of("0123456789") == std::string::npos)))
            throw std::runtime_error{
                    "invalid id '{}': expected 44 b64url or 1-16 decimal digits"_format(st.id)};

        st.f = st.id;
        for (int i = 1; std::filesystem::exists(st.f) || !dupes.insert(st.f).second; i++)
            st.f.replace_extension(".{}"_format(i));
    }

    quic::Loop loop;
    auto ep = quic::Endpoint::endpoint(loop, quic::Address{});

    auto conn = ep->connect(
            quic::RemoteAddress{oxenc::from_hex(pubkey), addr},
            quic::opt::outbound_alpn("quic-files"));

    // We must always open this stream first (even if we aren't going to use it); this is the stream
    // on which we can make simple requests; all later streams are for file transfers.
    auto bt_str = conn->open_stream<quic::BTRequestStream>();

    // stream -> downloads_index
    std::unordered_map<std::shared_ptr<quic::Stream>, size_t> dl_idx;

    std::atomic<size_t> remaining{downloads.size()};
    auto on_stream_close = [&](quic::Stream& s, uint64_t err) {
        --remaining;
        remaining.notify_one();
        auto& st = downloads[dl_idx.at(s.shared_from_this())];
        auto sid = s.stream_id();
        if (err != 0) {
            log::error(cat, "Download {} stream (id={}) closed with error {}", st.id, sid, err);
            return;
        }

        if (st.size < 0) {
            log::error(
                    cat, "Download {} stream (id={}) closed before metadata received!", st.id, sid);
            return;
        }
        if (st.received < st.size) {
            log::error(
                    cat,
                    "Download {} stream (id={}) closed before file content received (received {} "
                    "of {}B)",
                    st.id,
                    sid,
                    st.received,
                    st.size);
            return;
        } else {
            st.out.close();
            log::info(
                    cat,
                    "Successfully downloaded {} (on stream {}):\nsaved to: {}\nuploaded: {}\n  "
                    "expiry: {}",
                    st.id,
                    sid,
                    st.f,
                    st.uploaded,
                    st.expiry);
        }
    };

    auto on_stream_data = [&](quic::Stream& s, std::span<const std::byte> data) {
        auto sid = s.stream_id();
        auto& st = downloads[dl_idx.at(s.shared_from_this())];

        if (st.meta_size < 0) {
            try {
                if (auto size = quic::prefix_accumulator(st.partial, data)) {
                    if (*size == 0)
                        throw std::runtime_error{"Invalid 0-byte metadata block"};
                    st.meta_size = *size;
                } else
                    return;
            } catch (const std::exception& e) {
                log::error(cat, "Invalid file stream metadata on stream {}: {}", sid, e.what());
                s.close(1234);
                return;
            }

            st.meta.reserve(st.meta_size);
        }

        if (st.size < 0) {
            try {
                if (!quic::data_accumulator(st.meta, data, st.meta_size))
                    return;
            } catch (const std::exception& e) {
                log::error(cat, "Invalid file metadata received from server: {}", e.what());
                s.close(1234);
                return;
            }

            try {
                oxenc::bt_dict_consumer d{st.meta};
                auto size = d.require<int>("s");
                if (size <= 0)
                    throw std::runtime_error{"Invalid non-positive file size {}"_format(size)};
                auto upl = d.require<int64_t>("u");
                auto exp = d.require<int64_t>("x");
                d.finish();

                st.size = size;
                st.uploaded = std::chrono::sys_seconds{std::chrono::seconds{upl}};
                st.expiry = std::chrono::sys_seconds{std::chrono::seconds{exp}};
            } catch (const std::exception& e) {
                log::error(cat, "Failed to parse file metadata for {} on stream {}", st.id, sid);
                s.close(444);
                return;
            }

            try {
                st.out.exceptions(std::ios::failbit | std::ios::badbit);
                st.out.open(st.f, std::ios::binary | std::ios::out);
            } catch (const std::exception& e) {
                log::error(cat, "Failed to open {} for download: {}", st.f, e.what());
                s.close(400);
            }
        }

        try {
            if (st.received + data.size() > st.size)
                throw std::runtime_error{"Invalid file data received from server: received {}, expected {}"_format(st.received + data.size(), st.size)};
            st.out.write(reinterpret_cast<const char*>(data.data()), data.size());
            st.received += data.size();
        }
            catch (const std::exception& e) {
                log::error(cat, "Failed writing to {}: {}", st.f, e.what());
                s.close(400);
            }
    };

    loop.call([&] {
        for (size_t i = 0; i < downloads.size(); i++) {
            auto& st = downloads[i];
            auto str = conn->open_stream(on_stream_data, on_stream_close);
            dl_idx[str] = i;

            oxenc::bt_dict_producer info;
            info.append("!", "GET");
            info.append("#", st.id);
            str->send("{}:{}"_format(info.view().size(), info.view()));
            str->send_fin();
        }
    });

    size_t r = remaining.load();
    while (r > 0) {
        remaining.wait(r);
        r = loop.call_get([&] { return remaining.load(); });
    }
}
