#pragma once

#include <filesystem>
#include <future>
#include <string>
#include <thread>

namespace sfs {

std::thread start_cleanup_thread(
        const std::filesystem::path& base_dir,
        const std::string& pgsql_uri,
        std::future<void> stop);

}
