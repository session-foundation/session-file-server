#include <fmt/chrono.h>
#include <fmt/format.h>
#include <fmt/std.h>
#include <oxenc/bt_producer.h>
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
                "\n\nUsage: {} IP:PORT PUBKEY [TTL=SECONDS] FILENAME [FILENAME ...]\n\n",
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
    int file_i = 3;
    if (std::string_view ttl_opt{argv[3]}; ttl_opt.starts_with("TTL=")) {
        file_i++;
        auto [ptr, ec] = std::from_chars(ttl_opt.data() + 4, ttl_opt.data() + ttl_opt.size(), ttl);
        if (ptr != ttl_opt.data() + ttl_opt.size() || ec != std::errc{})
            return usage("Invalid time-to-live option: {}"_format(ttl_opt));
    }

    if (file_i >= argc)
        return usage("No upload files given!");

    std::vector<std::tuple<std::filesystem::path, uintmax_t, int>> uploads;
    for (; file_i < argc; file_i++) {
        std::filesystem::path f{argv[file_i]};
        if (!std::filesystem::exists(f) || !std::filesystem::is_regular_file(f))
            return usage("{} does not exist or is not a file"_format(f));
        auto s = std::filesystem::file_size(f);
        if (s == 0)
            return usage("Cannot upload empty file {}"_format(f));
        uploads.emplace_back(std::move(f), s, -1);
    }

    quic::Loop loop;
    auto ep = quic::Endpoint::endpoint(loop, quic::Address{});

    auto conn = ep->connect(
            quic::RemoteAddress{oxenc::from_hex(pubkey), addr},
            quic::opt::outbound_alpn("quic-files"));

    // We must always open this stream first (even if we aren't going to use it); this is the stream
    // on which we can make simple requests; all later streams are for file transfers.
    auto bt_str = conn->open_stream<quic::BTRequestStream>();

    // stream -> [data, uploads_index]
    std::unordered_map<std::shared_ptr<quic::Stream>, std::pair<std::string, size_t>> streams;

    std::atomic<size_t> remaining{uploads.size()};
    auto on_stream_close = [&](quic::Stream& s, uint64_t err) {
        --remaining;
        remaining.notify_one();
        auto str = s.shared_from_this();
        auto sid = str->stream_id();
        auto it = streams.find(str);
        if (it == streams.end()) {
            log::error(cat, "Unknown stream {} closed with error {}!", sid, err);
            return;
        }
        const auto& [data, upload_id] = it->second;
        auto& [f, size, fd] = uploads[upload_id];
        if (err != 0) {
            log::error(cat, "Upload {} stream (id={}) closed with error {}", f, sid, err);
            return;
        }

        if (data.empty()) {
            log::error(
                    cat,
                    "Upload {} stream (id={}) closed without error, but with no response data!",
                    f,
                    sid);
            return;
        }

        try {
            oxenc::bt_dict_consumer resp{data};
            std::string id = resp.require<std::string>("#");
            std::chrono::sys_seconds uploaded{std::chrono::seconds{resp.require<int64_t>("u")}};
            std::chrono::sys_seconds expiry{std::chrono::seconds{resp.require<int64_t>("x")}};

            log::info(
                    cat,
                    "Uploaded {} successfully (on stream {}):\n      id: {}\nuploaded: {}\n  "
                    "expiry: {}",
                    f,
                    sid,
                    id,
                    uploaded,
                    expiry);
        } catch (const std::exception& e) {
            log::warning(
                    cat, "Failed to parse stream {} ({}) upload response: {}", sid, f, e.what());
        }
    };
    auto on_stream_data = [&](quic::Stream& s, std::span<const std::byte> data) {
        auto sid = s.stream_id();
        auto str = s.shared_from_this();
        auto it = streams.find(str);
        if (it == streams.end()) {
            log::error(cat, "Received data on unknown stream {}!", sid);
            return;
        }
        auto& [d, upload_id] = it->second;
        d += std::string_view{reinterpret_cast<const char*>(data.data()), data.size()};
    };

    loop.call([&] {
        for (size_t i = 0; i < uploads.size(); i++) {
            auto& [f, size, fd] = uploads[i];
            fd = open(f.c_str(), O_RDONLY);
            if (fd < 0) {
                log::error(cat, "Failed to open {}: {}", f, strerror(errno));
                --remaining;
                continue;
            }
            auto str = conn->open_stream(on_stream_data, on_stream_close);
            auto next_chunk = [f, fd, str, f_remaining = size](const quic::Stream&) mutable {
                std::vector<std::byte> chunk;
                if (f_remaining == 0)
                    return chunk;
                chunk.resize(std::min<size_t>(f_remaining, 65'536));
                int offset = 0;
                while (true) {
                    auto r = read(fd, chunk.data() + offset, chunk.size() - offset);
                    if (r == -1) {
                        log::error(cat, "Error while reading from {}: {}", f, strerror(errno));
                        str->close(1480);
                        chunk.clear();
                        return chunk;
                    }
                    assert(offset + r <= chunk.size());
                    if (offset + r >= chunk.size())
                        break;
                    if (r == 0) {
                        log::error(
                                cat,
                                "Error reading from {}: hit EOF too soon (file truncated while "
                                "reading?)",
                                f);
                        str->close(1480);
                        chunk.clear();
                        return chunk;
                    }

                    offset += r;
                }
                f_remaining -= chunk.size();
                return chunk;
            };

            auto& [s, upload_i] = streams[str];
            upload_i = i;

            oxenc::bt_dict_producer info;
            info.append("!", "PUT");
            info.append("s", size);
            if (ttl > 0)
                info.append("t", ttl);
            str->send("{}:{}"_format(info.view().size(), info.view()));
            str->send_chunks(
                    next_chunk, [](quic::Stream& s) { s.send_fin(); }, 100);
        }
    });

    size_t r = remaining.load();
    while (r > 0) {
        remaining.wait(r);
        r = loop.call_get([&] { return remaining.load(); });
    }
}
