#include <chrono>
#include <oxen/quic/format.hpp>

#include "common.hpp"  // IWYU pragma: keep
#include "requests.hpp"

namespace sfs {

static auto accesslog = log::Cat("access");

static auto logcat = log::Cat("files.get");

void FileStream::parse_get(oxenc::bt_dict_consumer&& d) {
    auto id = d.require<std::string>("#");
    if (!((id.size() == 44 && id.find_first_not_of(b64_url_chars) == std::string::npos) ||
          (id.size() >= 1 && id.size() <= 16 &&
           id.find_first_not_of("0123456789") == std::string::npos)))
        throw std::runtime_error{"invalid id: expected 44 b64url or 1-16 decimal digits"};
    d.finish();

    request.emplace<get_req>(*this, std::move(id));
}

FileStream::get_req::get_req(FileStream& str, std::string id) : file_req{str, -1} {
    fileid = std::move(id);

    auto info = db_lookup(str.handler.pg_conn, id);

    if (info) {
        expiry = info->expiry;
        uploaded = info->uploaded;
        filepath = info->path;

        auto& pools = str.handler._pools;
        if (auto it = std::ranges::find(pools, info->pool, &ReqHandler::file_pool::id);
            it != pools.end()) {
            files_dir_fd = it->files_dir_fd;
        } else {
            log::warning(
                    accesslog,
                    "GET {} returned pool {}, but that pool was not found!",
                    fileid,
                    info->pool);
            info.reset();
        }
    }

    if (!info) {
        if (log::get_level(accesslog) >= log::Level::info) {
            if (auto conn = str.get_conn())
                log::info(accesslog, "GET {} NOT FOUND ({})", fileid, conn->remote());
            else
                log::info(accesslog, "GET {} NOT FOUND (<connection-closed>)", fileid);
        }
        str.close(STREAM_ERROR::not_found);
        return;
    }
}

void FileStream::get_req::close() {
    if (io_state != IO_STATE::none) {
        auto* sqe = io_uring_get_sqe(&str.handler.iou);
        io_uring_sqe_set_data64(sqe, 0);
        io_uring_sqe_set_flags(sqe, IOSQE_CQE_SKIP_SUCCESS);
        io_uring_prep_cancel64(sqe, str.fsid, 0);
        io_uring_submit(&str.handler.iou);
    }

    if (fd >= 0) {
        auto* sqe = io_uring_get_sqe(&str.handler.iou);
        io_uring_sqe_set_data64(sqe, 0);
        io_uring_sqe_set_flags(sqe, IOSQE_CQE_SKIP_SUCCESS);
        io_uring_prep_close_direct(sqe, fd);
        io_uring_submit(&str.handler.iou);
    }

    chunks.clear();
    io_state = IO_STATE::none;
    fd = -1;
}

void FileStream::get_req::handle_cqe(io_uring_cqe* cqe) {
    assert(io_state != IO_STATE::none);

    if (str.is_closing()) {
        log::debug(logcat, "Ignoring CQE on closing stream");
        chunks.clear();
        return;
    }

    if (io_state == IO_STATE::statx) {
        if (cqe->res < 0) {
            log::error(
                    logcat,
                    "Failed to stat {}: {}; closing stream with I/O error code",
                    filepath,
                    strerror(-cqe->res));
            str.close(STREAM_ERROR::io_error);
            return;
        }
        size = statxbuf.stx_size;

        io_state = IO_STATE::opening;  // The open was chained immediately after the statx, so wait
                                       // for it next.

    } else if (io_state == IO_STATE::opening) {
        if (cqe->res < 0) {
            log::error(
                    logcat,
                    "Failed to open {}: {}; closing stream with I/O error code",
                    filepath,
                    strerror(-cqe->res));
            str.close(STREAM_ERROR::io_error);
            return;
        }
        fd = cqe->res;

        std::string buf{"XX:"};  // dummy value; we'll edit it to the correct size below
        buf.resize(63);

        oxenc::bt_dict_producer meta{buf.data() + 3, buf.data() + buf.size()};
        meta.append("s", size);
        meta.append("u", uploaded.time_since_epoch().count());
        meta.append("x", expiry.time_since_epoch().count());
        auto final_size = "{}:"_format(meta.view().size());
        assert(final_size.size() == 3);
        std::memcpy(buf.data(), final_size.data(), final_size.size());
        buf.resize(3 + meta.view().size());
        str.send(std::move(buf));

        io_state = IO_STATE::none;

    } else if (io_state == IO_STATE::reading) {  // A read has finished and delivered the data to us

        if (chunks.size() == 1)  // If 1 then this was the last outstanding read
            io_state = IO_STATE::none;
        // Otherwise there are more reads outstanding so leave the state as is
        auto buf = std::move(chunks.front());
        chunks.pop_front();

        if (cqe->res < 0) {
            log::error(
                    logcat,
                    "Failed to open {}: {}; closing stream with I/O error code",
                    filepath,
                    strerror(-cqe->res));
            str.close(STREAM_ERROR::io_error);
            close();
            return;
        }
        if (cqe->res > 0) {
            if (cqe->res < static_cast<int>(buf.size()))
                buf.resize(cqe->res);
            bytes_read += buf.size();
            str.send(std::move(buf));
            if (bytes_read >= size) {
                str.send_fin();
                close();
                str.handler.overall.get(size);
            }
        } else {
            eof = true;
            close();
            if (bytes_read < size) {
                log::error(
                        logcat,
                        "Hit EOF reading {} too early (read {}, expected {})",
                        filepath,
                        bytes_read,
                        size);
                str.close(STREAM_ERROR::io_error);
                return;
            }
            str.send_fin();
        }

    } else {
        assert(!"Unknown state!");
    }

    queue_reads();
}

void FileStream::get_req::finalize() {
    io_state = IO_STATE::statx;

    auto* sqe = io_uring_get_sqe(&str.handler.iou);
    io_uring_sqe_set_data64(sqe, str.fsid);
    io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);
    io_uring_prep_statx(sqe, files_dir_fd, filepath.c_str(), 0, STATX_SIZE, &statxbuf);

    sqe = io_uring_get_sqe(&str.handler.iou);
    io_uring_sqe_set_data64(sqe, str.fsid);
    io_uring_sqe_set_flags(sqe, 0);
    io_uring_prep_openat_direct(
            sqe, files_dir_fd, filepath.c_str(), O_RDONLY, 0644, IORING_FILE_INDEX_ALLOC);

    io_uring_submit(&str.handler.iou);
}

void FileStream::get_req::queue_reads() {
    if (io_state != IO_STATE::none || eof || bytes_read >= size)
        return;
    assert(chunks.empty());
    int64_t unsent = str.unsent();
    if (unsent >= READAHEAD)
        return;

    // Submit a chain of smaller sequential reads; we do this rather than one big read so that we
    // can hand earlier data off to our quic stream without having waiting for all data to be
    // available.
    int chunks_to_read =
            (std::min<int64_t>(READAHEAD - unsent, size - bytes_read) + CHUNK_SIZE - 1) /
            CHUNK_SIZE;
    chunks.resize(chunks_to_read);
    for (int i = 0; i < chunks_to_read; i++) {
        auto& c = chunks[i];
        c.resize(CHUNK_SIZE);
        auto* sqe = io_uring_get_sqe(&str.handler.iou);
        io_uring_sqe_set_data64(sqe, str.fsid);
        io_uring_sqe_set_flags(
                sqe, IOSQE_FIXED_FILE | (i == chunks_to_read - 1 ? 0 : IOSQE_IO_LINK));
        io_uring_prep_read(sqe, fd, c.data(), CHUNK_SIZE, -1);
    }
    io_uring_submit(&str.handler.iou);
    io_state = IO_STATE::reading;
}

}  // namespace sfs
