#include "common.hpp"

namespace sfs {

pqxx::connection& PGConn::conn() {
    if (_conn && !_conn->is_open())
        _conn.reset();

    if (!_conn) {
        _conn.emplace(uri);
        log::info(db_logcat, "Connected to postgresql database");
    }

    return *_conn;
}

std::optional<file_db_info> db_lookup(PGConn& db, std::string_view fileid) {
    double upl, exp;
    int pool_id;
    bool found = false;
    try {
        db.retryable([&](pqxx::connection& conn) {
            found = false;
            pqxx::work tx{conn};
            auto row = tx.exec(R"(
SELECT EXTRACT(EPOCH FROM uploaded), EXTRACT(EPOCH FROM expiry), pool
FROM pool_files WHERE id = $1)",
                               pqxx::params{fileid})
                               .opt_row();

            if (row) {
                found = true;
                std::tie(upl, exp, pool_id) = row->as<double, double, int>();
            }

            tx.commit();
        });
    } catch (const pqxx::failure& e) {
        log::error(db_logcat, "Failed to query files table: {}", e.what());
    }

    std::optional<file_db_info> result;
    if (found) {
        std::chrono::sys_seconds expiry{std::chrono::seconds{static_cast<int64_t>(exp)}};
        if (expiry >= std::chrono::system_clock::now()) {
            auto& r = result.emplace();
            r.expiry = expiry;
            r.uploaded = std::chrono::sys_seconds{std::chrono::seconds{static_cast<int64_t>(upl)}};
            r.pool = pool_id;
            r.path = id_to_path(fileid);
        }
    }
    return result;
}

std::string friendly_duration(std::chrono::nanoseconds dur) {
    std::string friendly;
    auto append = std::back_inserter(friendly);
    bool some = false;
    if (dur >= 24h) {
        fmt::format_to(append, "{}d", dur / 24h);
        dur %= 24h;
        some = true;
    }
    if (dur >= 1h || some) {
        fmt::format_to(append, "{}h", dur / 1h);
        dur %= 1h;
        some = true;
    }
    if (dur >= 1min || some) {
        fmt::format_to(append, "{}m", dur / 1min);
        dur %= 1min;
        some = true;
    }
    if (some || dur % 1s == 0ns) {
        // If we have >= minutes or its an integer number of seconds then don't bother with
        // fractional seconds
        fmt::format_to(append, "{}s", dur / 1s);
    } else {
        double seconds = std::chrono::duration<double>(dur).count();
        if (dur >= 1s)
            fmt::format_to(append, "{:.3f}s", seconds);
        else if (dur >= 1ms)
            fmt::format_to(append, "{:.3f}ms", seconds * 1000);
        else if (dur >= 1us)
            fmt::format_to(append, "{:.3f}µs", seconds * 1'000'000);
        else
            fmt::format_to(append, "{:.0f}ns", seconds * 1'000'000'000);
    }
    return friendly;
}

}  // namespace sfs
