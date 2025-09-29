#pragma once

#include <filesystem>
#include <future>
#include <string>
#include <thread>

namespace sfs {

std::thread start_cleanup_thread(
        const std::string& pgsql_uri,
        const std::filesystem::path& files_dir,
        std::future<void> stop);

}
