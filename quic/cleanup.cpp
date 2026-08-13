#include "cleanup.hpp"

#include <liburing.h>

#include <chrono>
#include <exception>
#include <pqxx/pqxx>

#include "common.hpp"  // IWYU pragma: keep

namespace sfs {

auto logcat = log::Cat("files.cleanup");

namespace {
    class Cleaner {
        std::filesystem::path base_dir;
        io_uring iou;
        PGConn db;
        std::future<void> stop;

      public:
        Cleaner(std::filesystem::path base_dir, std::string pgsql_uri, std::future<void> stop) :
                base_dir{std::move(base_dir)}, db{std::move(pgsql_uri)}, stop{std::move(stop)} {

            if (int err = io_uring_queue_init(128, &iou, IORING_SETUP_SINGLE_ISSUER); err != 0)
                throw std::runtime_error{
                        "Failed to initialize io_uring queue: {}"_format(strerror(-err))};
        }

        void cleanup() {
            auto started = std::chrono::steady_clock::now();
            // Two-phase mark-and-sweep deletion: first we mark everything expiring as deleting,
            // which means they are gone but that the file might still exist.
            //
            // Then we get all files marked for deletion, and delete them from disk.
            //
            // Then we come back and actually delete the rows.
            //
            // This interacts with the PUT code which, if it sees a `deleting` row, goes to sleep
            // for a little bit to let the cleanup thread do its thing, so that the cleanup + PUT
            // can't race with how they write or delete duplicate files with the same id.

            db.retryable([](pqxx::connection& conn) {
                pqxx::work tx{conn};
                tx.exec("UPDATE files SET deleting = TRUE WHERE expiry <= NOW()").no_rows();
                tx.commit();
            });

            std::vector<std::pair<std::string, std::filesystem::path>> removed;
            unsigned submitted = 0;

            db.retryable([this, &removed](pqxx::connection& conn) {
                removed.clear();

                pqxx::work tx{conn};

                for (auto [fileid, pool_name] : tx.query<std::string, std::string>(
                             "SELECT id, pool_name FROM pool_files WHERE deleting")) {
                    std::filesystem::path p{
                            base_dir / std::filesystem::path{pool_name} / id_to_path(fileid)};
                    removed.emplace_back(std::move(fileid), std::move(p));
                }

                tx.commit();
            });

            if (removed.empty())
                return;

            for (size_t i = 0; i < removed.size(); i++) {
                const auto& [id, path] = removed[i];

                auto* sqe = io_uring_get_sqe(&iou);
                if (!sqe) {
                    io_uring_submit(&iou);
                    sqe = io_uring_get_sqe(&iou);
                }

                io_uring_sqe_set_flags(sqe, 0);
                io_uring_sqe_set_data64(sqe, i);
                io_uring_prep_unlink(sqe, path.c_str(), 0);
                submitted++;
            }

            io_uring_submit(&iou);

            while (submitted > 0) {
                unsigned nr = std::min<unsigned>(iou.cq.ring_entries, submitted);
                struct io_uring_cqe* cqe;
                io_uring_wait_cqe_nr(&iou, &cqe, nr);

                db.retryable([&](pqxx::connection& conn) {
                    pqxx::work tx{conn};
                    unsigned head;
                    io_uring_for_each_cqe(&iou, head, cqe) {
                        const auto& [fileid, path] = removed[io_uring_cqe_get_data64(cqe)];
                        if (cqe->res < 0) {
                            if (cqe->res == -ENOENT)
                                log::debug(logcat, "Failed to remove {}: file already gone", path);
                            else {
                                log::warning(
                                        logcat,
                                        "Failed to remove {}: {}",
                                        path,
                                        strerror(-cqe->res));
                            }
                        } else {
                            log::debug(logcat, "Removed expired file {}", path);
                        }
                        tx.exec("DELETE FROM files WHERE id = $1", pqxx::params{fileid});
                    }

                    tx.commit();

                    io_uring_cq_advance(&iou, nr);

                    submitted -= nr;
                });
            }

            log::info(
                    logcat,
                    "Deleted {} expired files in {}",
                    removed.size(),
                    std::chrono::steady_clock::now() - started);
        }

        bool wait() { return stop.wait_for(10s) == std::future_status::timeout; }
    };
}  // namespace

std::thread start_cleanup_thread(
        const std::filesystem::path& base_dir,
        const std::string& pgsql_uri,
        std::future<void> stop) {

    std::promise<void> started_prom;
    auto started = started_prom.get_future();
    std::thread th{[&started_prom, &base_dir, &pgsql_uri, &stop] {
        std::optional<Cleaner> cleaner;
        try {
            cleaner.emplace(base_dir, pgsql_uri, std::move(stop));
        } catch (...) {
            started_prom.set_exception(std::current_exception());
            return;
        }

        started_prom.set_value();

        do {
            try {
                cleaner->cleanup();
            } catch (const std::exception& e) {
                log::error(logcat, "Cleanup failed: {}", e.what());
            }
        } while (cleaner->wait());
    }};

    started.get();

    return th;
}

}  // namespace sfs
