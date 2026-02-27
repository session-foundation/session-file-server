#include <oxen/quic/format.hpp>

#include "common.hpp"  // IWYU pragma: keep
#include "requests.hpp"

namespace sfs {

static auto logcat = log::Cat("files.put");
static auto accesslog = log::Cat("access");

constexpr auto FILE_ID_HASH_KEY = "SessionFileSvr\0\0"sv;

FileStream::put_req::put_req(
        FileStream& s, size_t size_, std::optional<int> ttl_, const ReqHandler::file_pool& pool) :
        file_req{s, pool.files_dir_fd},
        ttl{std::move(ttl_)},
        pool_id{pool.id},
        upload_dir_fd{pool.upload_dir_fd} {

    size = size_;

    crypto_generichash_blake2b_init(
            &b2b,
            reinterpret_cast<const unsigned char*>(FILE_ID_HASH_KEY.data()),
            FILE_ID_HASH_KEY.size(),
            33);
}

void FileStream::put_req::append(std::span<const std::byte> data) {

    if (got_all) {
        log::critical(logcat, "Internal error: append called *after* finalize()!");
        str.close(STREAM_ERROR::too_much_data);
    }

    if (received + static_cast<int64_t>(data.size()) > size) {
        auto conn = str.get_conn();
        log::warning(
                logcat,
                "PUT request from {} exceeded declared size (declared {}, received {}); closing "
                "stream with error",
                conn ? conn->remote().to_string() : "<unknown>",
                size,
                received + data.size());
        str.close(STREAM_ERROR::too_much_data);
        return;
    }

    if (fd == -1 && io_state == IO_STATE::none) {
        auto now = std::chrono::system_clock::now().time_since_epoch().count();
        uint64_t random;
        randombytes_buf(&random, sizeof(random));
        tmp_upload = std::filesystem::path{"upload-{}-{:016x}-{}B"_format(now, random, size)};

        auto* sqe = io_uring_get_sqe(&str.handler.iou);
        io_uring_sqe_set_data64(sqe, str.fsid);
        io_state = IO_STATE::opening;
        io_uring_prep_openat_direct(
                sqe,
                upload_dir_fd,
                tmp_upload.c_str(),
                O_CREAT | O_EXCL | O_WRONLY,
                0644,
                IORING_FILE_INDEX_ALLOC);
        io_uring_submit(&str.handler.iou);
    }

    if (!data.empty())
        crypto_generichash_blake2b_update(
                &b2b, reinterpret_cast<const unsigned char*>(data.data()), data.size());

    while (!data.empty()) {
        if (chunks.empty())
            chunks.emplace_back().reserve(CHUNK_SIZE);

        auto& c = chunks.back();
        auto s = c.size();
        if (s + data.size() <= CHUNK_SIZE) {
            c.resize(s + data.size());
            std::memcpy(c.data() + s, data.data(), data.size());
            received += data.size();
            data = {};
        } else if (s < CHUNK_SIZE) {
            c.resize(CHUNK_SIZE);
            std::memcpy(c.data() + s, data.data(), CHUNK_SIZE - s);
            received += CHUNK_SIZE - s;
            data = data.subspan(CHUNK_SIZE - s);
        } else {
            chunks.emplace_back();
        }
    }

    send_chunks();
}

void FileStream::put_req::send_chunks(std::optional<size_t> _retry_offset) {
    if (io_state != IO_STATE::none) {
        // We're already waiting on an open or write, so nothing else to do just yet; we'll queue
        // all the writes when it finishes.
        assert(!_retry_offset);  // An offset should only be given in response to a complete write
        return;
    }

    // If we get here then the file creation should have happened already:
    assert(fd >= 0);

    if (chunks.empty()) {
        if (got_all)
            // No more chunks and we received the FIN, so time to rename it into place
            initiate_rename();
        return;
    }

    bool send_last = chunks.back().size() >= CHUNK_SIZE || got_all;
    if (chunks.size() == 1 && !send_last && !_retry_offset)
        // Nothing to write right now
        return;

    int num_chunks = chunks.size() - !send_last;
    std::vector<iovec> iovecs;
    auto it = chunks.begin();
    iovecs.resize(num_chunks);
    io_write_size = 0;
    for (auto& v : iovecs) {
        v.iov_base = it->data();
        v.iov_len = it->size();
        io_write_size += v.iov_len;
        ++it;
    }
    if (_retry_offset) {
        assert(_retry_offset < chunks[0].size());
        iovecs[0].iov_base = chunks[0].data() + *_retry_offset;
        iovecs[0].iov_len -= *_retry_offset;
        io_write_size -= *_retry_offset;
        io_write_first_offset = *_retry_offset;
    } else {
        io_write_first_offset = 0;
    }

    auto* sqe = io_uring_get_sqe(&str.handler.iou);
    assert(sqe);
    io_uring_sqe_set_data64(sqe, str.fsid);
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    if (iovecs.size() == 1)
        io_uring_prep_write(sqe, fd, iovecs[0].iov_base, iovecs[0].iov_len, -1);
    else
        io_uring_prep_writev(sqe, fd, iovecs.data(), iovecs.size(), -1);
    io_uring_submit(&str.handler.iou);
    io_state = static_cast<IO_STATE>(num_chunks);
}

void FileStream::put_req::handle_cqe(io_uring_cqe* cqe) {
    assert(io_state != IO_STATE::none);

    auto state = io_state;
    if (state != IO_STATE::closing_done)  // closing_done is a "final" state we don't want to reset
        io_state = IO_STATE::none;

    if (str.is_closing()) {
        log::debug(logcat, "Ignoring CQE on closing stream");
        chunks.clear();
        return;
    }

    if (state == IO_STATE::opening) {
        if (cqe->res < 0) {
            log::error(
                    logcat,
                    "Failed to open temp file: {}; closing stream with I/O error code",
                    strerror(-cqe->res));
            str.close(STREAM_ERROR::io_error);
            chunks.clear();
            return;
        }
        fd = cqe->res;
        // Immediately queue any completed chunks we might have accumulated:
        send_chunks();
    } else if (state >= IO_STATE::writing) {  // writev response for N=`state` buffers
        auto n_bufs = static_cast<size_t>(state);
        assert(n_bufs <= chunks.size());

        auto written = cqe->res;
        if (written < 0) {
            log::error(
                    logcat,
                    "Failed to write upload data: {}; closing stream with I/O error code",
                    strerror(-written));
            str.close(STREAM_ERROR::io_error);
            chunks.clear();
            return;
        }

        // writev can return less than requested, in which case we need to retry from wherever the
        // write left off.  If it's something like being out of disk space, the subsequent write
        // will fail with an i/o error.
        if (written != io_write_size) {
            if (written > io_write_size)
                log::critical(
                        logcat,
                        "Internal error: write request returned *more* ({}) than we asked to write "
                        "({})",
                        written,
                        io_write_size);
            else
                log::debug(
                        logcat,
                        "Wrote less ({}) than expected ({}); requeuing write",
                        written,
                        io_write_size);

            written += io_write_first_offset;

            // For a partial write, head-drop any chunks that have been completely written:
            while (written >= static_cast<int>(chunks.front().size())) {
                written -= chunks.front().size();
                chunks.pop_front();
            }

            // written is now the offset into the first chunk where we want to retry; calling
            // send_chunks with a >= 0 offset will force it to always send at least the first chunk
            // (starting at the required offset), plus anything else that might have queued up in
            // the meantime.
            send_chunks(written);
            return;
        }

        log::debug(logcat, "Successfully wrote {}B to tempfile #{}", written, fd);
        chunks.erase(chunks.begin(), chunks.begin() + n_bufs);
        send_chunks();
    } else if (state == IO_STATE::renaming) {
        if (cqe->res == -EEXIST || cqe->res == 0) {
            if (cqe->res == -EEXIST)
                log::debug(logcat, "Rename failed: upload file already exists! Deleting tempfile");
            else
                log::debug(logcat, "Tempfile successfully renamed to final location {}", filepath);
        } else {
            log::warning(
                    logcat,
                    "Failed to rename tempfile {} to final location {}: {}",
                    tmp_upload,
                    filepath,
                    strerror(-cqe->res));
            str.close(STREAM_ERROR::io_error);
        }

        unlink_and_close(str.fsid, cqe->res != 0);
        io_state = IO_STATE::closing_done;
    } else if (state == IO_STATE::closing_done) {
        if (cqe->res < 0) {
            log::warning(logcat, "Failed to close tempfile: {}", strerror(-cqe->res));
            str.close(STREAM_ERROR::io_error);
        }
        // Respond anyway because the rename succeeded and such a close failure is probably
        // something weird or spurious?
        insert_and_respond();
    } else {
        assert(!"Unknown state!");
    }
}

void FileStream::put_req::finalize() {
    assert(!got_all);
    log::debug(logcat, "Stream FIN received");
    if (str.is_closing())
        return;

    assert(received <= size);  // other should already have failed in append()

    if (received < size) {
        log::warning(
                logcat,
                "Stream FIN received without receiving all data (received {} of {}); closing "
                "stream with error",
                received,
                size);
        str.close(STREAM_ERROR::not_enough_data);
    }
    log::debug(logcat, "Stream FIN received");
    got_all = true;

    std::array<unsigned char, 33> hash;
    crypto_generichash_blake2b_final(&b2b, hash.data(), hash.size());

    fileid = oxenc::to_base64(hash);
    // Convert to url-safe b64:
    for (auto& c : fileid) {
        if (c == '+')
            c = '-';
        else if (c == '/')
            c = '_';
    }

    if (!str.handler.back_compat_ids)
        filepath = std::filesystem::path{"{}/{}"_format(fileid.substr(0, 2), fileid)};
    else {
        std::string try_ttl = "{} seconds"_format(
                ttl && *ttl > 0 && *ttl <= str.handler.max_ttl.count()
                        ? *ttl
                        : str.handler.max_ttl.count());
        bool success = false;
        for (int i = 0; !success && i < 25; i++) {
            uint64_t bcid;
            randombytes_buf(&bcid, sizeof(bcid));
            // We can't go over 53 bits because nodejs doesn't have integers:
            bcid &= 0x1f'ffff'ffff'ffff;
            auto try_id = "{}"_format(bcid);
            double upl, exp;
            try {
                pg_retryable([&] {
                    pqxx::work tx{str.handler.pg_conn};
                    std::tie(upl, exp) = tx.exec(R"(
INSERT INTO files (id, expiry, pool) VALUES ($1, NOW() + $2, $3)
RETURNING EXTRACT(EPOCH FROM uploaded), EXTRACT(EPOCH FROM expiry))",
                                                 pqxx::params{try_id, try_ttl, pool_id})
                                                 .one_row()
                                                 .as<double, double>();
                    tx.commit();
                });
            } catch (const pqxx::unique_violation& e) {
                continue;
            }
            success = true;
            fileid = std::move(try_id);
            filepath = std::filesystem::path{"{:03d}/{}"_format(bcid % 1000, fileid)};
            expiry = std::chrono::sys_seconds{std::chrono::seconds{static_cast<int64_t>(exp)}};
            uploaded = std::chrono::sys_seconds{std::chrono::seconds{static_cast<int64_t>(upl)}};
        }

        if (!success) {
            log::error(
                    logcat,
                    "Tried 25 random backcompat IDs are got all constraint failures, something "
                    "getting wrong!");
            str.close(STREAM_ERROR::io_error);
            return;
        }
    }

    if (io_state == IO_STATE::none)
        send_chunks();
}

void FileStream::put_req::initiate_rename() {
    assert(!fileid.empty());
    assert(!filepath.empty());
    assert(chunks.empty());

    log::debug(
            logcat,
            "All data received; renaming pool {} tempfile #{} ({}) to final location {}",
            pool_id,
            fd,
            tmp_upload,
            filepath);

    auto* sqe = io_uring_get_sqe(&str.handler.iou);
    io_uring_sqe_set_data64(sqe, str.fsid);
    io_uring_prep_renameat(
            sqe,
            upload_dir_fd,
            tmp_upload.c_str(),
            files_dir_fd,
            filepath.c_str(),
            RENAME_NOREPLACE);
    io_uring_submit(&str.handler.iou);
    io_state = IO_STATE::renaming;
}

void FileStream::put_req::insert_and_respond() {
    if (str.handler.back_compat_ids) {
        // In back-compat mode, the insert already happened in finalize() because we had to do it to
        // get the location to link the file into.
    } else {
        int max_ttl = str.handler.max_ttl.count();
        std::string db_ttl = "{} seconds"_format(std::clamp(ttl.value_or(max_ttl), 1, max_ttl));
        try {
            pg_retryable([&] {
                pqxx::work tx{str.handler.pg_conn};

                auto [upl, exp, pool] = tx.exec(R"(
INSERT INTO files (id, expiry, pool) VALUES ($1, NOW() + $2, $3)
ON CONFLICT(id) DO UPDATE SET expiry = GREATEST(files.expiry, EXCLUDED.expiry)
RETURNING EXTRACT(EPOCH FROM uploaded), EXTRACT(EPOCH FROM expiry), pool)",
                                                pqxx::params{fileid, db_ttl, pool_id})
                                                .one_row()
                                                .as<double, double, int>();
                uploaded =
                        std::chrono::sys_seconds{std::chrono::seconds{static_cast<int64_t>(upl)}};
                expiry = std::chrono::sys_seconds{std::chrono::seconds{static_cast<int64_t>(exp)}};
                if (pool != pool_id) {
                    // The insert conflicts with a file in a different storage pool, and so we
                    // updated the expiry date of that other file, but still have the file that we
                    // moved into *our* pool, which is no longer referenced and so we need to delete
                    // it.
                    log::debug(
                            logcat,
                            "Deleting de-duplicated upload {} from pool {}"
                            " (file is already in pool {})",
                            filepath,
                            pool_id,
                            pool);
                    auto* sqe = io_uring_get_sqe(&str.handler.iou);
                    io_uring_sqe_set_flags(sqe, IOSQE_CQE_SKIP_SUCCESS);
                    io_uring_sqe_set_data64(sqe, 0);  // tell cqe handler to ignore the result
                    io_uring_prep_unlinkat(sqe, files_dir_fd, filepath.c_str(), 0);
                    io_uring_submit(&str.handler.iou);
                }

                tx.commit();
            });
        } catch (const pqxx::failure& e) {
            log::error(logcat, "Failed to insert DB record for file {}: {}", filepath, e.what());
            str.close(STREAM_ERROR::io_error);
            return;
        }
    }

    oxenc::bt_dict_producer resp;
    resp.append("#", fileid);
    resp.append("u", uploaded.time_since_epoch().count());
    resp.append("x", expiry.time_since_epoch().count());

    str.send(std::move(resp).str());
    str.send_fin();

    str.handler.overall.put(size);
}

void FileStream::put_req::unlink_and_close(uint64_t close_fsid, bool unlink) {
    auto* sqe = io_uring_get_sqe(&str.handler.iou);

    if (unlink) {
        io_uring_sqe_set_flags(sqe, IOSQE_CQE_SKIP_SUCCESS);
        io_uring_sqe_set_data64(sqe, 0);  // we can't do anything if this fails so 0 will just be
                                          // ignored by the cqe handling
        io_uring_prep_unlinkat(sqe, upload_dir_fd, tmp_upload.c_str(), 0);

        sqe = io_uring_get_sqe(&str.handler.iou);
    }
    io_uring_sqe_set_data64(sqe, close_fsid);
    if (close_fsid == 0)
        // Without an fsid we don't care about the outcome, so can skip handling entirely.  If we
        // *do* have an fsid then we want it so that it triggers whatever happens after closing.
        io_uring_sqe_set_flags(sqe, IOSQE_CQE_SKIP_SUCCESS);
    io_uring_prep_close_direct(sqe, fd);

    io_uring_submit(&str.handler.iou);

    fd = -1;
}

FileStream::put_req::~put_req() {
    if (io_state != IO_STATE::none) {
        // Some request is already in progress, so cancel it before we send the close.  This
        // particular io_uring submission is *synchronous* so that we aren't at risk of the close we
        // submit just after this actually getting queued before the cancellation (and thus itself
        // getting cancelled).
        auto* sqe = io_uring_get_sqe(&str.handler.iou);
        io_uring_sqe_set_data64(sqe, 0);
        io_uring_sqe_set_flags(sqe, IOSQE_CQE_SKIP_SUCCESS);
        io_uring_prep_cancel64(sqe, str.fsid, 0);
        io_uring_submit(&str.handler.iou);
    }

    if (fd >= 0)
        unlink_and_close(0 /* don't care about results, since we're destructing */);
}

void FileStream::parse_put(oxenc::bt_dict_consumer&& d) {
    auto size = d.require<int64_t>("s");
    auto ttl = d.maybe<int>("t");

    if (size <= 0 || size > handler.max_size) {
        log::error(logcat, "Invalid PUT size: {}, closing stream with error", size);
        close(STREAM_ERROR::invalid_size);
        return;
    }

    const auto& pool = handler.choose_pool();

    auto& put = request.emplace<put_req>(*this, std::move(size), std::move(ttl), pool);
    if (log::get_level(accesslog) >= log::Level::info) {
        auto ttl = put.ttl ? " (ttl={})"_format(*put.ttl) : "";
        if (auto conn = get_conn())
            log::info(accesslog, "PUT: {}B upload{} from {}", put.size, ttl, conn->remote());
        else
            log::info(accesslog, "PUT: {}B upload{} from <connection-closed>", put.size, ttl);
    }
}

}  // namespace sfs
