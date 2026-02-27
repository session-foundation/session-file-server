#include <oxenc/hex.h>

#include <CLI/CLI.hpp>
#include <CLI/Error.hpp>
#include <CLI/Validators.hpp>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/log/level.hpp>
#include <oxen/quic/context.hpp>
#include <oxen/quic/endpoint.hpp>
#include <oxen/quic/format.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <oxen/quic/loop.hpp>
#include <oxen/quic/opt.hpp>
#include <string>

#include "cleanup.hpp"
#include "requests.hpp"

using namespace std::literals;
using namespace oxen::log::literals;

std::atomic<int> signalled = 0;
void handle_signal(int sig) {
    signalled = sig;
}

std::optional<std::string_view> get_env(std::string_view key) {
    if (const char* val = std::getenv(key.data()))
        return std::string_view{val};
    return std::nullopt;
}

std::string default_config_path() {
    if (auto xdg_home = get_env("XDG_CONFIG_HOME"))
        return "{}/quic-files/config"_format(*xdg_home);
    if (auto home = get_env("HOME"))
        return "{}/.config/quic-files/config"_format(*home);
    return ""s;
}

int main(int argc, char* argv[]) {

    using namespace oxen;

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    auto logcat = log::Cat("files");

    CLI::App cli{"Session QUIC file server"};

    cli.set_config("--config", default_config_path(), "Read config options from file", false);

    std::string pgsql_uri;
    cli.add_option(
               "--pgsql,-P",
               pgsql_uri,
               "Postgresql database or URI, e.g. 'mydb' or some more complicated "
               "'postgresql:///...'")
            ->type_name("URI")
            ->required();

    std::filesystem::path base_path;
    cli.add_option(
               "--base-dir,-d",
               base_path,
               "Base directory containing the storage pool subdirectories, within which files "
               "referenced in the database are stored on disk")
            ->type_name("DIRECTORY")
            ->required();

    bool back_compat_ids = false;
    cli.add_flag(
            "--compat-ids,-c",
            back_compat_ids,
            "Run in backwards-compatible, numeric ID mode.  New uploads will get random integer "
            "IDs instead of file hash IDs.");

    uint32_t max_ttl = 14 * 24 * 60 * 60;
    cli.add_option(
               "--ttl,-t",
               max_ttl,
               "Maximum TTL for uploads, in seconds.  This is the default lifetime for upload "
               "files (if not renewed).  Clients may request shorter TTLs during upload or renew "
               "requests, but requesting a longer TTL will be truncated to this value")
            ->capture_default_str()
            ->check(CLI::Range(60, 60 * 24 * 60 * 60));

    uint32_t max_size = 10'223'616;
    cli.add_option("--max-size,-S", max_size, "Maximum upload size, in bytes.")
            ->capture_default_str();

    bool no_delete_expired = false;
    cli.add_flag(
            "--no-delete-expired",
            no_delete_expired,
            "Disable expired file deletion.  Should only be used if something else is taking care "
            "of expired file deletions.");

    std::filesystem::path key_file;
    cli.add_option(
               "--key,-K",
               key_file,
               "Path to an Ed25519 secret key. Must be either 64 bytes (raw), or 128 hex "
               "characters")
            ->type_name("FILENAME")
            ->required();

    std::string addr{":11235"};
    cli.add_option("--bind,-b", addr, "Bind address for incoming quic connections")
            ->type_name("IP:PORT")
            ->capture_default_str()
            ->check([](const std::string& a) {
                try {
                    quic::Address::parse(a);
                } catch (const std::exception& e) {
                    return "Invalid bind address: {}"_format(e.what());
                }
                return ""s;
            });

    bool disable_0rtt = false;
    cli.add_flag("--disable-0rtt,-0", disable_0rtt, "Disables 0-RTT support");

    std::string log_level = "info,quic=warning";
    cli.add_option(
               "--log-level",
               log_level,
               "Log verbosity level, see Log Levels below for accepted values")
            ->type_name("LEVEL")
            ->capture_default_str();

    try {
        cli.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return cli.exit(e);
    }

    log::apply_categories(log_level);
    log::add_sink(log::Type::Print, "stdout");

    std::string ed_keys;
    try {
        std::ifstream in;
        in.exceptions(std::ios::badbit | std::ios::failbit);
        in.open(key_file, std::ios::binary | std::ios::in);
        in.seekg(0, in.end);
        auto size = in.tellg();
        in.seekg(0, in.beg);

        if (size == 64) {
            ed_keys.resize(64);
            in.read(reinterpret_cast<char*>(ed_keys.data()), 64);
        } else if (size >= 128 && size <= 130) {
            ed_keys.resize(size);
            in.read(ed_keys.data(), size);
            if ((size == 130 && ed_keys[128] == '\r' && ed_keys[129] == '\n') ||
                (size == 129 && ed_keys[128] == '\n'))
                ed_keys.resize(128);
            if (ed_keys.size() == 128 && oxenc::is_hex(ed_keys))
                ed_keys = oxenc::from_hex(ed_keys);
            else
                ed_keys.clear();
        }

        if (ed_keys.size() != 64)
            throw std::invalid_argument{
                    "Invalid --key file: expected 64 raw byte, or 128 hex character key file"};
    } catch (const std::exception& e) {
        fmt::print(stderr, "\n\n\x1b[31;1mInvalid --key file: {}\x1b[0m\n\n", e.what());
        return 1;
    }

    log::info(
            logcat,
            "Server Ed25519 pubkey: {}",
            oxenc::to_hex(ed_keys.begin() + 32, ed_keys.end()));
    auto address = quic::Address::parse(addr);
    log::info(
            logcat,
            "Starting quic listener @ {}{}",
            address,
            disable_0rtt ? " WITHOUT 0rtt support" : "");

    std::thread cleanup_thread;
    std::promise<void> stop_cleanup;
    if (!no_delete_expired)
        cleanup_thread = sfs::start_cleanup_thread(base_path, pgsql_uri, stop_cleanup.get_future());

    try {
        sfs::ReqHandler handler{
                address,
                std::move(ed_keys),
                !disable_0rtt,
                std::move(pgsql_uri),
                back_compat_ids,
                std::chrono::seconds{max_ttl},
                base_path,
                max_size};

        log::info(logcat, "Server started.");

        signalled.wait(0);
        log::warning(logcat, "Received signal {}, stopping server", signalled.load());
    } catch (const std::exception& e) {
        log::error(logcat, "An exception occured while running the server: {}", e.what());
    }

    if (cleanup_thread.joinable()) {
        log::info(logcat, "Stopping cleanup thread");
        stop_cleanup.set_value();
        cleanup_thread.join();
    }

    log::info(logcat, "Exiting");
}
