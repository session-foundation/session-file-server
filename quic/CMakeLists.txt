cmake_minimum_required(VERSION 3.20...3.31)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  foreach(lang C CXX)
    if(NOT DEFINED CMAKE_${lang}_COMPILER_LAUNCHER AND NOT CMAKE_${lang}_COMPILER MATCHES ".*/ccache")
      message(STATUS "Enabling ccache for ${lang}")
      set(CMAKE_${lang}_COMPILER_LAUNCHER ${CCACHE_PROGRAM} CACHE STRING "")
    endif()
  endforeach()
endif()

project(quic-files
    VERSION 0.0.1
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_CXX_EXTENSIONS FALSE)

include(cmake/submodule_check.cmake)
include(cmake/system_or_submodule.cmake)

find_package(PkgConfig REQUIRED)

system_or_submodule(OXENC oxenc oxenc::oxenc liboxenc>=1.4.0 oxen-libquic/external/oxen-encoding)
system_or_submodule(OXENLOGGING oxen-logging oxen::logging liboxen-logging>=1.2.0 oxen-libquic/external/oxen-logging)
system_or_submodule(FMT fmt fmt::fmt fmt>=9 oxen-libquic/external/oxen-logging/fmt)
system_or_submodule(LIBPQXX libpqxx libpqxx::pqxx libpqxx>=7.10.0 libpqxx)
system_or_submodule(CLI11 CLI11 CLI11::CLI11 CLI11>=2.3.0 CLI11)
system_or_submodule(OXENQUIC quic oxen::quic liboxenquic>=1.6 oxen-libquic)

pkg_check_modules(NLOHMANN_JSON IMPORTED_TARGET REQUIRED nlohmann_json>=3.7.0)
pkg_check_modules(SODIUM IMPORTED_TARGET REQUIRED libsodium>=1.0.17)
pkg_check_modules(LIBURING IMPORTED_TARGET REQUIRED liburing>=2.3)
pkg_check_modules(LIBEVENT_CORE IMPORTED_TARGET REQUIRED libevent_core>=2.1.12)

add_executable(quic-files
    quic-files.cpp
    requests.cpp
    put.cpp
    get.cpp
    cleanup.cpp
)

add_library(quic-files-common INTERFACE)
target_link_libraries(quic-files-common INTERFACE
    oxenc::oxenc
    oxen::logging
    oxen::quic
    fmt::fmt
)

target_link_libraries(quic-files
    PRIVATE
    quic-files-common
    PkgConfig::NLOHMANN_JSON
    PkgConfig::SODIUM
    libpqxx::pqxx
    CLI11::CLI11
    PkgConfig::LIBURING
    PkgConfig::LIBEVENT_CORE
)

option(BUILD_TESTS "Build upload/download test programs" ON)
if(BUILD_TESTS)
    foreach(x IN ITEMS upload download query)
        add_executable(quic-${x} test/test-${x}.cpp)
        target_link_libraries(quic-${x} PRIVATE quic-files-common)
    endforeach()
endif()
