#pragma once

#include <fmt/chrono.h>
#include <fmt/std.h>
#include <oxenc/base64.h>
#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>
#include <sodium.h>

#include <chrono>
#include <functional>
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

// Wraps a call `c()` in a transaction and executes it.  If we get a broken connection exception
// then the call is retried up to n_retries times before giving up and propagating the exception.
template <std::invocable Call>
static void pg_retryable(Call c, const int n_retries = 10) {
    int retries = n_retries;
    while (retries > 0) {
        try {
            c();
            break;
        } catch (const pqxx::broken_connection& e) {
            if (retries--)
                log::warning(log::Cat("files.db"), "Lost postgresql connection; retrying query...");
            else {
                log::error(
                        log::Cat("files.db"),
                        "Postgresql connection still failing after {} retries, giving up",
                        n_retries);
                throw;
            }
        }
    }
}

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

std::optional<file_db_info> db_lookup(pqxx::connection& conn, std::string_view fileid);

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
