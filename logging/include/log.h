#pragma once

#include <iostream> // IWYU pragma: keep

#ifdef DEBUG
#define LOG_INFO(msg)                                                          \
    std::cout << "\033[32mINFO:\033[0m " << __FILE__ << " | Line " << __LINE__ \
              << " :: " << msg << "\n";
#define LOG_WARN(msg)                                                          \
    std::cout << "\033[33mWARN:\033[0m " << __FILE__ << " | Line " << __LINE__ \
              << " :: " << msg << "\n";
#define LOG_ERROR(msg)                                                         \
    std::cerr << "\033[31mERROR:\033[0m " << __FILE__ << " | Line "            \
              << __LINE__ << " :: " << msg << "\n";
#else
#define LOG_INFO(msg) // No-op in release builds
#define LOG_WARN(msg) // No-op in release builds
#define LOG_ERROR(msg) std::cerr << "Error: " << msg << "\n";
#endif
