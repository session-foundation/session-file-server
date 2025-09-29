#include "requests.hpp"

#include <event2/event.h>
#include <sys/eventfd.h>

#include <chrono>
#include <concepts>
#include <filesystem>
#include <memory>
#include <oxen/quic/btstream.hpp>
#include <oxen/quic/connection.hpp>
#include <oxen/quic/endpoint.hpp>
#include <oxen/quic/format.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <oxen/quic/opt.hpp>
#include <type_traits>
#include <variant>

#include "common.hpp"  // IWYU pragma: keep

namespace sfs {

bool back_compat_ids = false;
int max_ttl = 14 * 24 * 60 * 60;

using namespace oxen;
using namespace log::literals;
using namespace std::literals;

void handle_file_info(quic::message m) {}
void handle_file_extend(quic::message m) {}
void handle_session_version(quic::message m) {}
void handle_token_info(quic::message m) {}

static auto logcat = log::Cat("files");
static auto accesslog = log::Cat("access");

void FileStream::on_fin() {
    Stream::on_fin();
    std::visit(
            []<typename R>(R& req) {
                if constexpr (!std::same_as<R, std::monostate>)
                    req.finalize();
            },
            request);
}

void FileStream::receive(std::span<const std::byte> data) {
    if (is_closing())
        return;
    if (std::holds_alternative<std::monostate>(request)) {
        if (command_block_size < 0) {
            try {
                // The first thing we received on the stream is the size of the command block,
                // e.g. `123:`.  This call accumulates these digits until we hit a :, mutating data
                // to omit the prefix once found.
                if (auto size = quic::prefix_accumulator(partial_size, data)) {
                    if (*size == 0)
                        throw std::runtime_error{"Command block cannot be 0 bytes"};
                    command_block_size = *size;
                } else
                    return;  // Not enough data received yet
            } catch (const std::exception& e) {
                log::warning(
                        logcat,
                        "Invalid file stream command block on stream {}: {}; closing stream",
                        stream_id(),
                        e.what());
                close(STREAM_ERROR::bad_request);
                return;
            }
            command.reserve(command_block_size);
        }

        try {
            if (!quic::data_accumulator(command, data, command_block_size))
                return;
        } catch (const std::exception& e) {
            log::error(
                    logcat,
                    "Invalid file stream command block on stream {}: {}; closing stream",
                    stream_id(),
                    e.what());
            close(STREAM_ERROR::bad_request);
            return;
        }

        // We've completely read the request body, so now we can parse it:
        try {
            oxenc::bt_dict_consumer d{command};
            if (auto cmd = d.maybe<std::string_view>("!")) {
                if (*cmd == "GET")
                    parse_get(std::move(d));
                else if (*cmd == "PUT")
                    parse_put(std::move(d));
                else {
                    log::error(
                            logcat,
                            "Invalid file stream request '{}' on stream {}",
                            *cmd,
                            stream_id());
                    close(STREAM_ERROR::bad_endpoint);
                    return;
                }
            } else {
                log::error(
                        logcat,
                        "File stream request missing command field '!' on stream {}",
                        stream_id());
                close(STREAM_ERROR::bad_request);
                return;
            }
        } catch (const std::exception& e) {
            log::error(logcat, "Failure during command block parsing: {}", e.what());
            close(STREAM_ERROR::bad_request);
            return;
        }
    }

    if (is_closing())
        return;

    if (auto* put = std::get_if<put_req>(&request)) {
        // If this is a PUT request then everything after the command block is file data:
        put->append(data);
    } else {
        auto* get = std::get_if<get_req>(&request);
        assert(get);
        if (!data.empty()) {
            log::warning(logcat, "Error: {}B after GET command block", data.size());
            close(STREAM_ERROR::bad_request);
        }
    }
}

void FileStream::wrote(size_t size) {
    Stream::wrote(size);

    if (auto* get = std::get_if<get_req>(&request))
        get->queue_reads();
}

void FileStream::close(STREAM_ERROR e) {
    Stream::close(static_cast<uint64_t>(e));

    // If there is a request in progress, destroying whatever is in `request` will cancel any
    // ongoing I/O.  (This has to be deferred via call_soon because this can be called from *inside*
    // a live instance of `request`).
    loop.call_soon(
            [this,
             wself = std::weak_ptr{std::static_pointer_cast<FileStream>(shared_from_this())}] {
                if (auto self = wself.lock())
                    self->request.emplace<std::monostate>();
            });
}

FileStream::FileStream(quic::Connection& c, quic::Endpoint& e, ReqHandler& h) :
        quic::Stream{c, e}, handler{h}, fsid{handler._next_fsid++} {
    handler.streams[fsid] = this;
}

FileStream::~FileStream() {
    handler.streams.erase(fsid);
}

quic::opt::static_secret make_static_secret(std::string_view ed_keys) {
    constexpr auto STATIC_SEC_DOMAIN = "session-file-server-quic-files"sv;
    crypto_generichash_blake2b_state st;
    crypto_generichash_blake2b_init(
            &st,
            reinterpret_cast<const unsigned char*>(STATIC_SEC_DOMAIN.data()),
            STATIC_SEC_DOMAIN.size(),
            32);
    crypto_generichash_blake2b_update(
            &st, reinterpret_cast<const unsigned char*>(ed_keys.data()), ed_keys.size());
    std::vector<unsigned char> out;
    out.resize(32);
    crypto_generichash_blake2b_final(&st, out.data(), out.size());
    return quic::opt::static_secret{std::move(out)};
}

ReqHandler::ReqHandler(
        quic::Address listen,
        std::string ed_keys,
        bool enable_0rtt,
        std::string pgsql_uri,
        bool back_compat_ids,
        std::chrono::seconds max_ttl,
        std::filesystem::path files_path_,
        int64_t max_size) :
        back_compat_ids{back_compat_ids},
        max_ttl{max_ttl},
        max_size{max_size},
        files_path{std::move(files_path_)} {

    if (sodium_init() == -1)
        throw std::runtime_error{"Failed to initialize libsodium!"};

    loop.call_get([&] {
        pg_conn = pqxx::connection{pgsql_uri};

        std::list<bomb> cleanup;

        std::filesystem::create_directories(files_path);

        if (back_compat_ids)
            for (int i = 0; i < 1000; i++)
                std::filesystem::create_directories(files_path / "{:03d}"_format(i));
        else {
            for (auto a : b64_url_chars)
                for (auto b : b64_url_chars)
                    std::filesystem::create_directories(files_path / "{}{}"_format(a, b));
        }
        upload_path = files_path / "uploads";
        std::filesystem::create_directories(upload_path);

        upload_dir_fd = open(upload_path.c_str(), O_PATH | O_DIRECTORY);
        if (upload_dir_fd < 0)
            throw std::runtime_error{
                    "Unable to open upload path {}: {}"_format(upload_path, strerror(errno))};
        cleanup.emplace_back([this] { close(upload_dir_fd); });

        if (int err = io_uring_queue_init(128, &iou, IORING_SETUP_SINGLE_ISSUER); err != 0)
            throw std::runtime_error{
                    "Failed to initialize io_uring queue: {}"_format(strerror(-err))};
        cleanup.emplace_front([this] { io_uring_queue_exit(&iou); });

        if (int err = io_uring_register_files_sparse(&iou, MAX_OPEN_FILES); err != 0)
            throw std::runtime_error{
                    "Failed to initialize io_uring file descriptors: {}"_format(strerror(-err))};
        cleanup.emplace_front([this] { io_uring_unregister_files(&iou); });

        files_dir_fd = open(files_path.c_str(), O_PATH | O_DIRECTORY);
        if (files_dir_fd < 0)
            throw std::runtime_error{
                    "Unable to open files path {}: {}"_format(files_path, strerror(errno))};
        cleanup.emplace_back([this] { close(files_dir_fd); });

        iou_evfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (iou_evfd < 0)
            throw std::runtime_error{"Failed to set up eventfd: {}"_format(strerror(errno))};
        cleanup.emplace_front([this] { close(iou_evfd); });

        if (int err = io_uring_register_eventfd(&iou, iou_evfd); err != 0)
            throw std::runtime_error{"Failed to register eventfd: {}"_format(strerror(-err))};
        cleanup.emplace_front([this] { io_uring_unregister_eventfd(&iou); });

        ep = quic::Endpoint::endpoint(
                loop, listen, make_static_secret(ed_keys), quic::opt::inbound_alpn(sfs::ALPN));

        auto creds = quic::GNUTLSCreds::make_from_ed_seckey(ed_keys);
        if (enable_0rtt)
            creds->enable_inbound_0rtt(0s, 48h);

        ep->listen(
                std::move(creds),
                [this](quic::Connection& conn,
                       quic::Endpoint& e,
                       std::optional<int64_t> stream_id) {
                    assert(stream_id);  // Should always be set for incoming streams
                    return make_stream(conn, e, *stream_id);
                });

        iou_ev = event_new(
                loop.get_event_base(),
                iou_evfd,
                EV_READ | EV_PERSIST,
                [](evutil_socket_t fd, short, void* me) {
                    uint64_t dummy;
                    read(fd, &dummy, 8);
                    static_cast<ReqHandler*>(me)->process_cqes();
                },
                this);
        if (!iou_ev)
            throw std::runtime_error{"Failed to initialize io_uring fd event via libevent"};
        cleanup.emplace_front([this] { event_free(iou_ev); });
        if (0 != event_add(iou_ev, nullptr))
            throw std::runtime_error{"Failed to initialize io_uring event monitoring via libevent"};

        for (auto& x : cleanup)
            x.disarm();

        stats_timer = loop.call_every(30s, [this] {
            auto now = std::chrono::steady_clock::now();
            log::info(
                    logcat,
                    "{} uploads ({:.1f}GB), {} downloads ({:.1f}GB), {} other requests in {} since "
                    "startup.",
                    overall.puts,
                    overall.put_data / 1e9,
                    overall.gets,
                    overall.get_data / 1e9,
                    overall.others,
                    friendly_duration(now - overall.since));
            if (now - recent.since >= 10min) {
                recent_old = recent;
                recent = {};
            }
            if (recent_old.since > overall.since + 1s) {
                log::info(
                        logcat,
                        "{} uploads ({:.1f}GB), {} downloads ({:.1f}GB), {} other requests in last "
                        "{}",
                        recent.puts + recent_old.puts,
                        (recent.put_data + recent_old.put_data) / 1e9,
                        recent.gets + recent_old.gets,
                        (recent.get_data + recent_old.get_data) / 1e9,
                        recent.others + recent_old.others,
                        friendly_duration(now - recent_old.since));
            }
        });
    });
}

ReqHandler::~ReqHandler() {
    assert(ep.use_count() == 1);
    ep.reset();
    event_free(iou_ev);
    loop.call_get([this] {
        io_uring_unregister_files(&iou);
        io_uring_unregister_eventfd(&iou);
        close(iou_evfd);
        io_uring_queue_exit(&iou);
    });
}

void ReqHandler::process_cqes() {
    unsigned head;
    unsigned count = 0;
    io_uring_cqe* cqe;
    io_uring_for_each_cqe(&iou, head, cqe) {
        ++count;
        auto fsid = io_uring_cqe_get_data64(cqe);
        FileStream* sptr = nullptr;
        if (auto it = streams.find(fsid); it != streams.end())
            sptr = it->second;
        if (!sptr) {
            log::debug(logcat, "Ignoring CQE on dead stream (fsid={})", fsid);
            continue;
        }
        auto& str = *sptr;
        try {
            std::visit(
                    [cqe]<typename R>(R& req) {
                        if constexpr (!std::same_as<std::monostate, R>)
                            req.handle_cqe(cqe);
                    },
                    str.request);
        } catch (const std::exception& e) {
            log::warning(
                    logcat,
                    "Exception during I/O response processing ({}); closing stream",
                    e.what());
            str.close(STREAM_ERROR::io_error);
        }
    }
    io_uring_cq_advance(&iou, count);
}

std::shared_ptr<quic::Stream> ReqHandler::make_stream(
        quic::Connection& conn, quic::Endpoint& e, int64_t stream_id) {

    // Stream 0 is the bt request stream on which you can make simple requests such as getting
    // current versions, querying file metadata, or touching an uploaded file to renew its
    // expiry.
    //
    // It does *not*, however, handle uploads and downlods: each upload/download happens on a
    // new stream.
    if (stream_id == 0) {
        auto s = e.loop.make_shared<quic::BTRequestStream>(conn, e);
        s->register_handler(
                "file_info", [this](quic::message m) { handle_file_info(std::move(m)); });
        s->register_handler(
                "file_extend", [this](quic::message m) { handle_file_extend(std::move(m)); });
        s->register_handler("session_version", [this](quic::message m) {
            handle_session_version(std::move(m));
        });
        s->register_handler(
                "token_info", [this](quic::message m) { handle_token_info(std::move(m)); });
        return std::move(s);
    }

    return e.loop.make_shared<FileStream>(conn, e, *this);
}

}  // namespace sfs
