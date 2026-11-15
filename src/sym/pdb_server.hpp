#pragma once
#include "../util/log.hpp"
#include <pe.hpp>

#include <filesystem>
#include <format>
#include <string>
#include <string_view>

bool host_download_url_to_file(const char* url, const char* dest_path, unsigned int* out_hr);

namespace pdb_server
{

inline std::string format_guid(const pe::guid& g)
{
    return std::format("{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        g.data1, g.data2, g.data3,
        g.data4[0], g.data4[1], g.data4[2], g.data4[3],
        g.data4[4], g.data4[5], g.data4[6], g.data4[7]);
}

inline std::string build_key(const pe::codeview_rsds& cv)
{
    return std::format("{}{:X}", format_guid(cv.guid), cv.age);
}

inline std::string pdb_file_name(const pe::codeview_rsds& cv)
{
    const std::string_view path = cv.pdb_path();
    const auto slash = path.find_last_of("\\/");
    return std::string(slash == std::string_view::npos ? path : path.substr(slash + 1));
}

inline std::filesystem::path cached_path(const pe::codeview_rsds& cv)
{
    const auto name = pdb_file_name(cv);
    return std::filesystem::path("symbols") / name / build_key(cv) / name;
}

inline std::filesystem::path download(const pe::codeview_rsds& cv)
{
    auto dest = cached_path(cv);
    if (std::filesystem::exists(dest))
        return dest;

    auto name = pdb_file_name(cv);
    if (name == "Core.pdb") return {};
    auto key = build_key(cv);
    auto url = std::format("https://msdl.microsoft.com/download/symbols/{}/{}/{}", name, key, name);

    LOG_INFO("downloading {} from symbol server ({})...", name, url);
    std::filesystem::create_directories(dest.parent_path());

    unsigned int hr = 0;
    if (!host_download_url_to_file(url.c_str(), dest.string().c_str(), &hr) || !std::filesystem::exists(dest))
    {
        LOG_WARN("failed to download {} (hr=0x{:08X})", name, hr);
        std::filesystem::remove(dest);
        return {};
    }

    LOG_INFO("cached {} -> {}", name, dest.string());
    return dest;
}

} // namespace pdb_server
