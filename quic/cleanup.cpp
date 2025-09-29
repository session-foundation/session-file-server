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
        io_uring iou;
        int files_dir_fd;
        pqxx::connection conn;
        std::future<void> stop;

      public:
        Cleaner(const std::filesystem::path& files_dir,
                std::string pgsql_uri,
                std::future<void> stop) :
                conn{pgsql_uri}, stop{std::move(stop)} {
            std::filesystem::create_directories(files_dir);
            files_dir_fd = open(files_dir.c_str(), O_PATH | O_DIRECTORY);
            if (files_dir_fd < 0)
                throw std::runtime_error{
                        "Unable to open files path {}: {}"_format(files_dir, strerror(errno))};

            if (int err = io_uring_queue_init(128, &iou, IORING_SETUP_SINGLE_ISSUER); err != 0) {
                close(files_dir_fd);
                throw std::runtime_error{
                        "Failed to initialize io_uring queue: {}"_format(strerror(-err))};
            }
        }

        void cleanup() {
            pg_retryable([this] {
                pqxx::work tx{conn};

                auto started = std::chrono::steady_clock::now();
                std::vector<std::filesystem::path> removed;
                unsigned submitted = 0;
                for (auto r : tx.exec("DELETE FROM files WHERE expiry <= NOW() RETURNING id")) {
                    removed.push_back(id_to_path(r[0].as<std::string>()));
                    auto& filepath = removed.back();

                    auto* sqe = io_uring_get_sqe(&iou);
                    if (!sqe) {
                        io_uring_submit(&iou);
                        sqe = io_uring_get_sqe(&iou);
                    }

                    io_uring_sqe_set_flags(sqe, 0);
                    io_uring_sqe_set_data64(sqe, removed.size() - 1);
                    io_uring_prep_unlinkat(sqe, files_dir_fd, filepath.c_str(), 0);
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
        const std::string& pgsql_uri,
        const std::filesystem::path& files_dir,
        std::future<void> stop) {

    std::promise<void> started_prom;
    auto started = started_prom.get_future();
    std::thread th{[&started_prom, &files_dir, &pgsql_uri, &stop] {
        std::optional<Cleaner> cleaner;
        try {
            cleaner.emplace(files_dir, std::move(pgsql_uri), std::move(stop));
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
