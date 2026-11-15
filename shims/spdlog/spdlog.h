#pragma once
#include <cstdio>
#include <format>
#include <mutex>
#include <string>
#include <string_view>

namespace spdlog
{
namespace detail
{
inline std::mutex& log_mutex()
{
    static std::mutex m;
    return m;
}
template <typename... Args>
inline void emit(const char* level, std::string_view fmt, Args&&... args)
{
    std::string msg = std::vformat(fmt, std::make_format_args(args...));
    std::lock_guard<std::mutex> lock(log_mutex());
    std::fprintf(stdout, "[%s] %s\n", level, msg.c_str());
    std::fflush(stdout);
}
} // namespace detail

template <typename... Args>
inline void info(std::string_view fmt, Args&&... args) { detail::emit("info", fmt, std::forward<Args>(args)...); }

template <typename... Args>
inline void warn(std::string_view fmt, Args&&... args) { detail::emit("warn", fmt, std::forward<Args>(args)...); }

template <typename... Args>
inline void error(std::string_view fmt, Args&&... args) { detail::emit("error", fmt, std::forward<Args>(args)...); }

template <typename... Args>
inline void debug(std::string_view fmt, Args&&... args) { detail::emit("debug", fmt, std::forward<Args>(args)...); }

template <typename... Args>
inline void trace(std::string_view fmt, Args&&... args) { detail::emit("trace", fmt, std::forward<Args>(args)...); }

template <typename... Args>
inline void critical(std::string_view fmt, Args&&... args) { detail::emit("critical", fmt, std::forward<Args>(args)...); }
} // namespace spdlog
