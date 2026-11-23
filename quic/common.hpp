#pragma once

#include <fmt/chrono.h>
#include <fmt/std.h>
#include <oxenc/base64.h>
#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>
#include <sodium.h>

#include <chrono>
#include <concepts>
#include <functional>
#include <optional>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <pqxx/pqxx>
#include <string>

namespace sfs {

// NOLINTBEGIN(misc-unused-alias-decls)

namespace log = oxen::log;

using namespace std::literals;
using namespace log::literals;

static constexpr auto b64_url_chars =
        "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"sv;

inline auto db_logcat = log::Cat("files.db");

/// Holds a postgresql connection, reconnecting as needed.  A pqxx::connection is dead for good once
/// its connection to the server breaks (e.g. because the database server restarted), so we keep the
/// connection parameters around to be able to establish a replacement connection.
///
/// This is not thread-safe: each thread that needs database access needs its own instance.
class PGConn {
    std::string uri;
    std::optional<pqxx::connection> _conn;

  public:
    explicit PGConn(std::string pgsql_uri) : uri{std::move(pgsql_uri)} {}

    /// Returns the current database connection, establishing a new one if we don't currently have a
    /// live connection.  Throws pqxx::broken_connection if not connected and the connection attempt
    /// fails.
    pqxx::connection& conn();

    /// True if we currently hold a connection that we believe to be alive.
    bool connected() const { return _conn && _conn->is_open(); }

    /// Drops the current connection, if any; the next `conn()` call will establish a new one.
    void disconnect() { _conn.reset(); }

    /// Invokes `c(conn)` with a live database connection; `c` is expected to construct a
    /// transaction on the given connection, do its work, and commit.
    ///
    /// If the call fails because the connection died then we drop the dead connection, reconnect,
    /// and invoke `c` again, up to `n_retries` times before giving up and rethrowing.  `c` must
    /// therefore be safe to invoke more than once: a broken connection aborts the transaction, and
    /// so a retried call starts from a clean slate -- except in the (rare) case of the connection
    /// breaking during the commit itself, where the transaction may or may not have been applied.
    ///
    /// Any exception other than a broken connection propagates immediately, as does a failure to
    /// establish a connection in the first place (i.e. we retry a *lost* connection, but do not sit
    /// here retrying a database server that is down).
    template <std::invocable<pqxx::connection&> Call>
    void retryable(Call c, const int n_retries = 3) {
        for (int attempt = 0;; attempt++) {
            // Connecting deliberately happens outside the try/catch: if the database server is
            // down then sitting here reconnecting in a tight loop won't help anyone, so we let
            // that failure go straight back to the caller.
            auto& db = conn();
            try {
                c(db);
                return;
            } catch (const pqxx::failure& e) {
                bool lost = dynamic_cast<const pqxx::broken_connection*>(&e) || !connected();
                if (!lost || attempt >= n_retries)
                    throw;
                log::warning(
                        db_logcat,
                        "Lost postgresql connection ({}); reconnecting and retrying query",
                        e.what());
                disconnect();
            }
        }
    }
};

// Returns the relative path within the storage pool directory to a file with the given id
inline std::filesystem::path id_to_path(std::string_view fileid) {
    std::filesystem::path p{
            fileid.size() == 44 ? fileid.substr(0, 2) :
                                // back compat numeric identifier, goes into 000, 001, ..., 999
                                // based on % 1000 id value:
                    "{:0>3s}"_format(fileid.substr(fileid.size() < 3 ? 0 : fileid.size() - 3))};

    p /= std::filesystem::path{fileid};
    return p;
}

struct file_db_info {
    std::chrono::sys_seconds uploaded;
    std::chrono::sys_seconds expiry;
    int pool;
    std::filesystem::path path;
};

std::optional<file_db_info> db_lookup(PGConn& db, std::string_view fileid);

// Simple class that "explodes" (by calling a callback) if not "disarmed" before being
// destructed.  Used to queue cleanup during partial construction.
class bomb {
  public:
    std::function<void()> explode;

    void disarm() { explode = nullptr; }

    ~bomb() {
        if (explode)
            explode();
    }
};

std::string friendly_duration(std::chrono::nanoseconds dur);

// NOLINTEND(misc-unused-alias-decls)

}  // namespace sfs
