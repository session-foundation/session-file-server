#pragma once

#include <fmt/chrono.h>
#include <fmt/std.h>
#include <oxenc/base64.h>
#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>
#include <sodium.h>

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

inline std::filesystem::path id_to_path(std::string_view fileid) {
    std::filesystem::path p;
    if (fileid.size() == 44)
        p = std::filesystem::path{fileid.substr(0, 2)};
    else
        // back compat numeric identifier, goes into 000, 001, ..., 999 based on % 1000 id value
        p = std::filesystem::path{
                "{:0>3s}"_format(fileid.substr(fileid.size() < 3 ? 0 : fileid.size() - 3))};

    p /= std::filesystem::path{fileid};
    return p;
}

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

inline std::string friendly_duration(std::chrono::nanoseconds dur) {
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

// NOLINTEND(misc-unused-alias-decls)

}  // namespace sfs
