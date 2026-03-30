#include <oxen/quic/format.hpp>

#include "common.hpp"  // IWYU pragma: keep
#include "requests.hpp"

namespace sfs {

static auto logcat = log::Cat("files.put");
static auto accesslog = log::Cat("access");

constexpr auto FILE_ID_HASH_KEY = "SessionFileSvr\0\0"sv;
constexpr int MIN_TTL = 30;

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

    const auto state = io_state;
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
    } else if (state == IO_STATE::rename_fsync) {
        if (cqe->res != 0) {
            log::warning(
                    logcat, "Failed to fsync tempfile {}: {}", tmp_upload, strerror(-cqe->res));
            str.close(STREAM_ERROR::io_error);
            abort_tempfile();
            return;
        }
        log::debug(logcat, "tempfile {} fsync success; closing", tmp_upload);

        auto* sqe = io_uring_get_sqe(&str.handler.iou);
        io_uring_prep_close_direct(sqe, fd);
        io_uring_sqe_set_data64(sqe, str.fsid);
        io_uring_submit(&str.handler.iou);
        fd = -1;  // We've just sent the close, so we're done with this fd.
        io_state = IO_STATE::rename_close;
    } else if (state == IO_STATE::rename_close) {
        if (cqe->res != 0) {
            log::warning(
                    logcat, "Failed to close tempfile {}: {}", tmp_upload, strerror(-cqe->res));
            str.close(STREAM_ERROR::io_error);
            abort_tempfile();
            return;
        }
        log::debug(logcat, "tempfile {} closed; renaming", tmp_upload);

        auto* sqe = io_uring_get_sqe(&str.handler.iou);
        io_uring_prep_renameat(
                sqe, upload_dir_fd, tmp_upload.c_str(), files_dir_fd, filepath.c_str(), 0);
        io_uring_sqe_set_data64(sqe, str.fsid);
        io_uring_submit(&str.handler.iou);
        io_state = IO_STATE::rename_at;
    } else if (state == IO_STATE::rename_at) {
        if (cqe->res != 0) {
            log::warning(
                    logcat,
                    "Failed to rename tempfile {} to final location {}: {}",
                    tmp_upload,
                    filepath,
                    strerror(-cqe->res));
            str.close(STREAM_ERROR::io_error);
            abort_tempfile();
            return;
        }

        log::debug(
                logcat, "Tempfile successfully renamed to final location {}, responding", filepath);

        insert_file();
        respond();
    } else if (state == IO_STATE::cleanup_sleep) {
        initiate_rename();
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
        return;
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
        int max_ttl = str.handler.max_ttl.count();
        std::string db_ttl =
                "{} seconds"_format(std::clamp(ttl.value_or(max_ttl), MIN_TTL, max_ttl));
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
                                                 pqxx::params{try_id, db_ttl, pool_id})
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

static constexpr __kernel_timespec cleanup_collide_sleep{
        .tv_sec = 0, .tv_nsec = std::chrono::nanoseconds{20ms}.count()};

void FileStream::put_req::initiate_rename() {
    assert(!fileid.empty());
    assert(!filepath.empty());
    assert(chunks.empty());

    std::optional<bool> found_deleting;
    if (str.handler.back_compat_ids)
        // INSERT happened already and guaranteed unique; nothing else to do here.
        found_deleting = std::nullopt;
    else {
        int max_ttl = str.handler.max_ttl.count();
        std::string db_ttl =
                "{} seconds"_format(std::clamp(ttl.value_or(max_ttl), MIN_TTL, max_ttl));

        // We attempt to bump the expiry: if this matches (and doesn't give back a
        // delete-in-progress row) then we just detected a safe existing duplicate and can just
        // delete our tempfile because the existing file is good.
        pg_retryable([&] {
            pqxx::work tx{str.handler.pg_conn};

            auto maybe_row = tx.exec(R"(
UPDATE files SET expiry = GREATEST(expiry, NOW() + $2)
WHERE id = $1
RETURNING EXTRACT(EPOCH FROM uploaded), EXTRACT(EPOCH FROM expiry), deleting
)",
                                     pqxx::params{fileid, db_ttl})
                                     .opt_row();
            if (maybe_row) {
                auto [upl, exp, deleting] = maybe_row->as<double, double, bool>();
                uploaded =
                        std::chrono::sys_seconds{std::chrono::seconds{static_cast<int64_t>(upl)}};
                expiry = std::chrono::sys_seconds{std::chrono::seconds{static_cast<int64_t>(exp)}};
                found_deleting = deleting;
            }
            tx.commit();
        });
    }

    if (found_deleting && *found_deleting) {
        // We updated, but the row we updated collided with an in-progress file deletion, so we need
        // to go to sleep and retry in a few ms so that we don't get our file race-deleted with the
        // current deletion of that same file.  (We did update the expiry, but that is irrelevant
        // because once deleting is set there is no resurrecting it).
        log::debug(logcat, "Upload file {} collided with delete-in-progress; delaying", fileid);
        auto* sqe = io_uring_get_sqe(&str.handler.iou);
        io_uring_sqe_set_data64(sqe, str.fsid);
        cleanup_sleep = cleanup_collide_sleep;
        io_uring_prep_timeout(sqe, &cleanup_sleep, 0, 0);
        io_uring_submit(&str.handler.iou);
        io_state = IO_STATE::cleanup_sleep;
        return;
    }

    if (found_deleting /* implied: "and not *found_deleting" */) {
        // We updated and the row is *not* currently being deleted, which means we found a live
        // duplicate (and possibly updated its expiry) and so we can delete our tempfile (without
        // worrying about fsyncing it, thus possibly saving some I/O) and return early.
        log::debug(
                logcat, "Upload file {} already exists; expiry updated; deleting tempfile", fileid);
        abort_tempfile();
        respond();
        io_state = IO_STATE::none;
        return;
    }

    // Otherwise our UPDATE didn't find any rows, which means this is a new file, so start the
    // fsync+close+rename chain.  We will INSERT when we're done.  We *could* collide with another
    // insert, but we deal with that when we get to the actual INSERT.
    log::debug(
            logcat,
            "File not found in DB; initiating sync+close+rename in pool {} tempfile #{} ({})"
            " to final location {}",
            pool_id,
            fd,
            tmp_upload,
            filepath);

    auto* sqe = io_uring_get_sqe(&str.handler.iou);
    io_uring_sqe_set_data64(sqe, str.fsid);
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    io_uring_prep_fsync(sqe, fd, 0);
    io_uring_submit(&str.handler.iou);

    io_state = IO_STATE::rename_fsync;
}

void FileStream::put_req::insert_file() {
    if (str.handler.back_compat_ids) {
        // In back-compat mode, the insert already happened in finalize() because we had to do it to
        // get the location to link the file into.
    } else {
        int max_ttl = str.handler.max_ttl.count();
        std::string db_ttl =
                "{} seconds"_format(std::clamp(ttl.value_or(max_ttl), MIN_TTL, max_ttl));
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
                    // The insert conflicted with a file in a *different* storage pool, and so we
                    // just updated the expiry date of that other file, but still have the file that
                    // we uploaded into *this* pool, which is not referenced by the db (because of
                    // the above failure) and so we need to delete it.
                    log::debug(
                            logcat,
                            "Deleting duplicated upload {} from pool {}"
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
}

void FileStream::put_req::respond() {
    oxenc::bt_dict_producer resp;
    resp.append("#", fileid);
    resp.append("u", uploaded.time_since_epoch().count());
    resp.append("x", expiry.time_since_epoch().count());

    str.send(std::move(resp).str());
    str.send_fin();

    str.handler.overall.put(size);
}

void FileStream::put_req::abort_tempfile() {
    if (fd >= 0) {
        auto* sqe = io_uring_get_sqe(&str.handler.iou);
        io_uring_sqe_set_flags(sqe, IOSQE_CQE_SKIP_SUCCESS | IOSQE_IO_LINK);
        io_uring_sqe_set_data64(sqe, 0);
        io_uring_prep_close_direct(sqe, fd);
        fd = -1;
    }

    auto* sqe = io_uring_get_sqe(&str.handler.iou);
    io_uring_sqe_set_flags(sqe, IOSQE_CQE_SKIP_SUCCESS);
    io_uring_sqe_set_data64(sqe, 0);
    io_uring_prep_unlinkat(sqe, upload_dir_fd, tmp_upload.c_str(), 0);

    io_uring_submit(&str.handler.iou);
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
        abort_tempfile();
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
