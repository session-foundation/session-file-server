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
        pqxx::connection conn;
        std::future<void> stop;

      public:
        Cleaner(std::filesystem::path base_dir, std::string pgsql_uri, std::future<void> stop) :
                base_dir{std::move(base_dir)}, conn{pgsql_uri}, stop{std::move(stop)} {

            if (int err = io_uring_queue_init(128, &iou, IORING_SETUP_SINGLE_ISSUER); err != 0)
                throw std::runtime_error{
                        "Failed to initialize io_uring queue: {}"_format(strerror(-err))};
        }

        void cleanup() {
            pg_retryable([this] {
                pqxx::work tx{conn};

                auto started = std::chrono::steady_clock::now();
                std::vector<std::filesystem::path> removed;
                unsigned submitted = 0;
                for (auto [fileid, pool_name] :
                     tx.query<std::string, std::string>("DELETE FROM pool_files"
                                                        " WHERE expiry <= NOW()"
                                                        " RETURNING id, pool_name")) {
                    removed.push_back(
                            base_dir / std::filesystem::path{pool_name} / id_to_path(fileid));

                    auto* sqe = io_uring_get_sqe(&iou);
                    if (!sqe) {
                        io_uring_submit(&iou);
                        sqe = io_uring_get_sqe(&iou);
                    }

                    io_uring_sqe_set_flags(sqe, 0);
                    io_uring_sqe_set_data64(sqe, removed.size() - 1);
                    io_uring_prep_unlink(sqe, removed.back().c_str(), 0);
                    submitted++;
                }
                io_uring_submit(&iou);

                bool success = true;

                while (submitted > 0) {
                    unsigned nr = std::min<unsigned>(iou.cq.ring_entries, submitted);
                    struct io_uring_cqe* cqe;
                    io_uring_wait_cqe_nr(&iou, &cqe, nr);

                    unsigned head;
                    io_uring_for_each_cqe(&iou, head, cqe) {
                        const auto& id = removed[io_uring_cqe_get_data64(cqe)];
                        if (cqe->res < 0) {
                            if (cqe->res == -ENOENT)
                                log::debug(logcat, "Failed to remove {}: file already gone", id);
                            else {
                                log::warning(
                                        logcat, "Failed to remove {}: {}", id, strerror(-cqe->res));
                                success = false;
                            }
                        } else {
                            log::debug(logcat, "Removed expired file {}", id);
                        }
                    }

                    io_uring_cq_advance(&iou, nr);

                    submitted -= nr;
                }

                if (success) {
                    log::info(
                            logcat,
                            "Deleted {} expired files in {}",
                            removed.size(),
                            std::chrono::steady_clock::now() - started);
                    tx.commit();
                } else
                    tx.abort();
            });
        }

        bool wait() { return stop.wait_for(30s) == std::future_status::timeout; }
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
