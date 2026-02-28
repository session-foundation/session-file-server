#pragma once

#include <event2/event.h>
#include <liburing.h>
#include <oxenc/bt_serialize.h>
#include <sodium/crypto_generichash_blake2b.h>

#include <chrono>
#include <filesystem>
#include <memory>
#include <oxen/quic/endpoint.hpp>
#include <oxen/quic/stream.hpp>
#include <pqxx/pqxx>
#include <string_view>
#include <variant>

namespace oxen::quic {
struct message;
}

namespace sfs {

namespace quic = oxen::quic;
using namespace std::literals;

inline constexpr auto ALPN = "quic-files"sv;

enum class STREAM_ERROR : uint64_t {
    bad_request = 400,

    not_found = 404,

    bad_endpoint = 405,

    size_missing = 450,
    invalid_size = 451,
    not_enough_data = 452,
    too_much_data = 453,
    io_error = 480,
};

// BTRequestStream request error strings:
namespace req_error {
    // BAD_REQUEST means you sent something the server didn't understand:
    static constexpr auto BAD_REQUEST = "BAD_REQUEST"sv;
    // The server encountered some sort of internal error and cannot complete the request:
    static constexpr auto INTERNAL_ERROR = "INTERNAL_ERROR"sv;
    // The file to modify or query does not exist:
    static constexpr auto NOT_FOUND = "NOT_FOUND"sv;
}  // namespace req_error

class FileStream;

struct req_stats {
    int64_t puts = 0, gets = 0, others = 0;
    int64_t put_data = 0, get_data = 0;
    std::chrono::steady_clock::time_point since = std::chrono::steady_clock::now();

    void put(int64_t size) {
        puts++;
        put_data += size;
    }
    void get(int64_t size) {
        gets++;
        get_data += size;
    }
    void other() { others++; }
};

class ReqHandler {

    quic::Loop loop;
    std::shared_ptr<quic::Endpoint> ep;
    bool back_compat_ids;
    std::chrono::seconds max_ttl;
    int64_t max_size{max_size};

    req_stats overall{};
    req_stats recent{}, recent_old{};
    std::shared_ptr<quic::Ticker> stats_timer;

    std::filesystem::path base_path;
    io_uring iou;
    int iou_evfd;
    event* iou_ev;

    pqxx::connection pg_conn;

    static constexpr int MAX_OPEN_FILES = 200000;

    // The u64 that we use to associated io_uring responses with the streams that made the request.
    // 0 is a special value (e.g. used for cancellation on destruction) that never maps to an actual
    // stream.
    uint64_t _next_fsid = 1;
    std::unordered_map<uint64_t, FileStream*> streams;

    uint64_t REQ_CQE_BASE_ID = 1ULL << 63;

    uint64_t _next_req_cqeid = REQ_CQE_BASE_ID;
    std::unordered_map<uint64_t, std::function<void(io_uring_cqe* cqe)>> _req_cqe_handlers;

    void process_cqes();

    struct file_pool {
        int id;
        bool active;
        std::filesystem::path files_path;
        int files_dir_fd;
        int upload_dir_fd;
    };
    std::vector<file_pool> _pools;
    std::vector<int> _active_pools_index;

    std::chrono::steady_clock::time_point _pools_refresh_at =
            std::chrono::steady_clock::now() - 24h;
    int _last_pool_index = -1;
    void refresh_pools();
    const file_pool& choose_pool();

    friend class FileStream;

    void handle_file_info(quic::message m);
    void handle_file_extend(quic::message m);
    void handle_session_version(quic::message m);
    void handle_token_info(quic::message m);

  public:
    ReqHandler(
            quic::Address listen,
            std::string ed_keys,
            bool enable_0rtt,
            const std::string& pgsql_uri,
            bool back_compat_ids,
            std::chrono::seconds max_ttl,
            std::filesystem::path base_path,
            int64_t max_size);

    ~ReqHandler();

    std::shared_ptr<quic::Stream> make_stream(
            quic::Connection& conn, quic::Endpoint& e, int64_t stream_id);
};

/// Stream subclass used for handling all incoming streams beyond the first (i.e. ids > 0; the first
/// stream, with id 0, is always a standard quic bt request stream for non-transfer responses).
///
/// Each of these streams is issued with an initial command block, optionally followed by stream
/// data.  The response is an initial response block, optionally followed by stream data.
///
/// Each command or response block is a bt-encoded string containing a bt-encoded dict of request
/// data.  The inner encoded dict may be no larger than 9999 bytes.  E.g.
///
///     19:d1:!3:PUT1:si8192ee..................
///
/// is a single upload command.  The reply (after successfully accepting the upload) could be:
///
///     67:d1:#44:abc…xyz1:xi1760388294ee
///
/// indicating the status of a successful upload.
///
/// Currently supported commands (which are in the "!" key):
///
/// PUT
/// ---
/// Command block is a dict containing:
/// - ! = PUT
/// - s = upload size, in bytes.  The upload will fail immediately if the size is not acceptable.
///   If the stream is closed (or FIN sent) before this size has been received, or if more than this
///   size is sent, then the stream is closed with an error (the file is not stored).
/// - t = file ttl, in seconds.  Optional; if omitted defaults to max ttl.
///
/// All data following the command block are the file contents being uploaded.
///
/// The successful response is a dict block (i.e. bt-encoded string encoding of a bt-dict)
/// containing keys:
/// - # = the accepted file id as a string.  This is a base64 (url variation) encoded value, unless
///   backwards compatible ids are enabled in which case it will be a stringified integer value.
/// - u = the file upload timestamp; typically now, but earlier if the upload was deduplicated.
/// - x = the file expiry, in unix epoch seconds, after the insert or update caused by this upload.
///
/// On error, the stream is closed (without sending a response) with one of the following error
/// codes:
/// - 450 -- no upload size given
/// - 451 -- invalid upload size (i.e. size is too large).  This will be triggered immediately if
/// the
///          size given in the initial command is not allowed, or if too little or too much data is
///          sent.
/// - 452 -- stream FIN received before all data received
/// - 453 -- too much file data received (i.e. more than "s" bytes)
/// - 480 -- the file could not be stored because of a server-side I/O error.
/// - other non-0 codes indicate some other internal server side error (e.g. server restarting).
///
///
/// GET
/// ---
/// Command block is a dict containing:
/// - ! = GET
/// - # = file ID to retrieve, as a string value.  Should be either a 44-character ID, or a shorter
///   numeric ID (but still passed as a string).
///
/// The successful response is a dict block followed by the file bytes.  The dict contains keys:
/// - s = the size of the file being sent, in bytes.  (Note that this is the file size, not the
///   stream size, i.e. it does not include the size of the response block).
/// - u = the original file creation data, in unix epoch seconds.  If the file was renewed (or
///   re-uploaded and de-duplicate), this is the original upload date, not the renewal date.
/// - x = the file expiry, in unix epoch seconds
///
/// The file immediately follows this double-encoded block (e.g. `123:d.....e`), in its entirety.
///
/// If the file is not found then the stream is closed, with no response sent, with a stream error
/// code of 404.  Error 480 can be issued for some sort of I/O error; other errors are possible,
/// e.g. if the server is restarted before handling the request, or if a server-side I/O error
/// occurs.
///
///
/// If some other command is sent on an auxiliary stream then the stream is closed with error 405.
/// If the command block is not parseable then it is closed with code 400.
///
class FileStream : public quic::Stream {

    class file_req {
      protected:
        // We queue reads and writes in blocks of this size
        static constexpr int64_t CHUNK_SIZE = 64 * 1024;

        file_req(FileStream& str, int pool_dir_fd) : str{str}, files_dir_fd{pool_dir_fd} {}

        FileStream& str;

        // The open storage pool base directory fd relative to which the file is read or written
        int fd = -1;

        int files_dir_fd;
        std::filesystem::path filepath;
        std::chrono::sys_seconds uploaded;
        std::chrono::sys_seconds expiry;

        virtual ~file_req() = default;

      public:
        std::string fileid;
        int64_t size = -1;

        // Called to process a CQE response to a queued event that this object submitted.
        virtual void handle_cqe(io_uring_cqe* cqe) = 0;
    };

    class get_req : public file_req {
        // Per-stream readahead; if we drop below this of unsent data then we queue additional reads
        // until we have unsent data on the stream >= this value (or hit EOF).
        static constexpr int64_t READAHEAD = 512 * 1024;

        // current io_uring state:
        // - IO_STATE::none means there is no pending io_uring request
        // - IO_STATE::reading means we have a chain of `chunk.size()` reads queued
        // - IO_STATE::statx means we are waiting on the statx that happens first
        // - IO_STATE::opening means we are waiting on the open (which happens chained with the
        //   statx).
        // - IO_STATE::closing means we are closing the file handle.
        enum class IO_STATE : int {
            none = -100,
            statx = -1,
            opening = 0,
            closing_done = -2,
            reading = 1,  // including all higher underlying values
        };

        struct statx statxbuf{};

        IO_STATE io_state = IO_STATE::none;

        bool eof = false;
        int64_t bytes_read = 0;

        std::deque<std::vector<std::byte>> chunks;

      public:
        get_req(FileStream& str, std::string id);

        void finalize();

        void handle_cqe(io_uring_cqe* cqe) override;

        void queue_reads();

        // Cancels operations (if something is queued) and closes the fd
        void close();
    };
    class put_req : public file_req {

        crypto_generichash_blake2b_state b2b;

        // current io_uring state:
        // - IO_STATE::none means there is no pending io_uring request
        // - >= IO_STATE::writing means we are writing the first N buffers of `chunks`, where N
        //   is the underlying value.
        // - IO_STATE::opening means we are creating the tempfile
        // - IO_STATE::rename_* means we are doing the fsync/close/renameat sequence to move the
        //   tempfile into its final location
        // - IO_STATE::cleanup_sleep is used when we failed the insert because of (rare) collision
        //   with the same file with the cleanup thread.
        // Tracking the currently scheduled I/O task:
        enum class IO_STATE : int {
            none = -100,
            // Rename consists of fsync, close, renameat, and these three states track our progress
            // through that chain:
            rename_fsync = -1,
            rename_close = -2,
            rename_at = -3,
            cleanup_sleep = -4,
            opening = 0,
            writing = 1,  // >= writing means a writev of the underlying number of chunks
        };

        IO_STATE io_state = IO_STATE::none;

        // The upload directory fd for the storage pool we are uploading into
        int upload_dir_fd;
        // The storage pool id, determined when the upload starts and inserted into the db when it
        // finishes.
        int pool_id;

        // When waiting on a write, this is how many bytes we tried writing
        int io_write_size;
        // In some cases (such as a partial write) we end up starting a write with an offset into
        // the first chunk; this is where we store it:
        size_t io_write_first_offset;

        std::deque<std::vector<std::byte>> chunks;

        int64_t received = 0;
        bool got_all = false;
        std::filesystem::path tmp_upload;
        __kernel_timespec cleanup_sleep;

        void initiate_rename();

        void insert_file();
        void respond();

        // Called upon error to close (if still open) the tempfile and then unlink it.  These are
        // submitted without a fsid, i.e. there is no event emitted when these complete.
        void abort_tempfile();

        friend class ReqHandler;

      public:
        std::optional<int> ttl;

        put_req(FileStream& s,
                size_t size,
                std::optional<int> ttl,
                const ReqHandler::file_pool& pool);

        // Appends data; the first time this is called a temporary file is opened into which the
        // data will be written.  Throws upon I/O error.
        void append(std::span<const std::byte> data);

        // If there is at least 1 full chunk accumulated (or the write is complete) then this
        // submits any full (or final) chunks to be written.  Does nothing if an I/O operation is
        // already submitted, or if there isn't a full chunk yet.
        //
        // retry_offset is used after a failed partial write to retry the first, beginning the first
        // chunk at the given offset.
        void send_chunks(std::optional<size_t> _retry_offset = std::nullopt);

        // Called when the sender sends FIN on the stream (to indicate it is done with the file
        // contents).  If not enough data has been sent, this closes the stream with an error code.
        // Otherwise this initiates linking the file to its final location on disk (based on the
        // hash), inserting the record into the database, and then replying on the stream with the
        // upload info.
        void finalize();

        // Called to process a CQE response to a queued event that this object submitted.
        void handle_cqe(io_uring_cqe* cqe) override;

        // Cancels any ongoing operations and closes the file descriptor.
        ~put_req();
    };

    ReqHandler& handler;

    // Unique identifier we use to reacquire the stream (if still alive) out of the ReqHandler when
    // a io_uring completion occurs.  (We store this id in the queue entry).
    // (NB: put_req destructor requires this, so this must be declared above `request`)
    const uint64_t fsid;

    std::variant<std::monostate, get_req, put_req> request;
    int command_block_size = -1;
    std::string partial_size;
    std::vector<std::byte> command;

    void parse_get(oxenc::bt_dict_consumer&& d);
    void parse_put(oxenc::bt_dict_consumer&& d);

    void on_fin() override;

    friend class ReqHandler;

  public:
    FileStream(quic::Connection& c, quic::Endpoint& e, ReqHandler& h);

    ~FileStream() override;

    void receive(std::span<const std::byte> data) override;

    void close(STREAM_ERROR e);

    void wrote(size_t size) override;
};

}  // namespace sfs
