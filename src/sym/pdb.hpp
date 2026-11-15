#pragma once
#include "symbol.hpp"
#include "pdb_server.hpp"
#include "../kernel/process.hpp"
#include "../util/file.hpp"
#include "../util/log.hpp"

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <string_view>
#include <vector>

struct pdb_symbols : symbols
{
    explicit pdb_symbols(std::vector<std::filesystem::path> search_paths = {})
        : search_paths_(std::move(search_paths)) { }

    void load(proc_module& mod) override
    {
        const auto* img = mod.pe();
        if (!img) return;
        const auto* cv = img->codeview();
        if (!cv) return;

        const auto pdb_path = find_pdb(*cv);
        if (pdb_path.empty()) return;

        auto data = util::read_file(pdb_path);
        if (data.size() < 64) return;

        // Parse MSF 7.0 ("Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0")
        static const char kMagic[32] = "Microsoft C/C++ MSF 7.00\r\n\x1a" "DS\0\0";
        if (std::memcmp(data.data(), kMagic, 29) != 0)
        {
            LOG_ERR("invalid MSF 7.0 header in {}", pdb_path.string());
            return;
        }

        const auto read_u32 = [](const std::uint8_t* p) -> std::uint32_t {
            std::uint32_t v; std::memcpy(&v, p, 4); return v;
        };
        const auto read_u16 = [](const std::uint8_t* p) -> std::uint16_t {
            std::uint16_t v; std::memcpy(&v, p, 2); return v;
        };

        const std::uint32_t block_size = read_u32(data.data() + 32);
        const std::uint32_t num_blocks = read_u32(data.data() + 40);
        const std::uint32_t dir_bytes  = read_u32(data.data() + 44);
        const std::uint32_t dir_map_blk = read_u32(data.data() + 52);
        if (block_size == 0 || static_cast<std::size_t>(dir_map_blk) * block_size >= data.size()) return;

        const std::uint32_t dir_blocks = (dir_bytes + block_size - 1) / block_size;
        const std::uint8_t* dir_map = data.data() + static_cast<std::size_t>(dir_map_blk) * block_size;
        std::vector<std::uint8_t> dir_stream(static_cast<std::size_t>(dir_blocks) * block_size);
        for (std::uint32_t i = 0; i < dir_blocks; i++)
        {
            std::uint32_t blk = read_u32(dir_map + i * 4);
            if (static_cast<std::size_t>(blk + 1) * block_size > data.size()) return;
            std::memcpy(dir_stream.data() + static_cast<std::size_t>(i) * block_size,
                        data.data() + static_cast<std::size_t>(blk) * block_size, block_size);
        }

        const std::uint32_t num_streams = read_u32(dir_stream.data());
        const std::uint8_t* sizes_ptr = dir_stream.data() + 4;
        const std::uint8_t* blks_ptr  = sizes_ptr + num_streams * 4;

        std::vector<std::uint32_t> stream_sizes(num_streams);
        std::vector<const std::uint8_t*> stream_blk_lists(num_streams);
        for (std::uint32_t s = 0; s < num_streams; s++)
        {
            std::uint32_t sz = read_u32(sizes_ptr + s * 4);
            if (sz == 0xFFFFFFFFu) sz = 0;
            stream_sizes[s] = sz;
            stream_blk_lists[s] = blks_ptr;
            std::uint32_t nblk = (sz + block_size - 1) / block_size;
            blks_ptr += nblk * 4;
        }

        auto read_stream = [&](std::uint32_t s) -> std::vector<std::uint8_t> {
            if (s >= num_streams || stream_sizes[s] == 0) return {};
            std::uint32_t sz = stream_sizes[s];
            std::uint32_t nblk = (sz + block_size - 1) / block_size;
            std::vector<std::uint8_t> out(static_cast<std::size_t>(nblk) * block_size);
            const std::uint8_t* blist = stream_blk_lists[s];
            for (std::uint32_t i = 0; i < nblk; i++)
            {
                std::uint32_t blk = read_u32(blist + i * 4);
                if (static_cast<std::size_t>(blk + 1) * block_size <= data.size())
                {
                    std::memcpy(out.data() + static_cast<std::size_t>(i) * block_size,
                                data.data() + static_cast<std::size_t>(blk) * block_size, block_size);
                }
            }
            out.resize(sz);
            return out;
        };

        // Stream 3 is DBI stream
        auto dbi = read_stream(3);
        if (dbi.size() < 64) return;
        const std::uint16_t sym_rec_stream_idx = read_u16(dbi.data() + 20);
        const std::int32_t gp_modi_size    = static_cast<std::int32_t>(read_u32(dbi.data() + 24));
        const std::int32_t sc_size         = static_cast<std::int32_t>(read_u32(dbi.data() + 28));
        const std::int32_t sec_map_size    = static_cast<std::int32_t>(read_u32(dbi.data() + 32));
        const std::int32_t file_info_size  = static_cast<std::int32_t>(read_u32(dbi.data() + 36));
        const std::int32_t ts_map_size     = static_cast<std::int32_t>(read_u32(dbi.data() + 40));
        const std::int32_t dbg_hdr_size    = static_cast<std::int32_t>(read_u32(dbi.data() + 48));
        const std::int32_t ec_info_size    = static_cast<std::int32_t>(read_u32(dbi.data() + 52));

        std::size_t dbg_hdr_off = 64ull + gp_modi_size + sc_size + sec_map_size + file_info_size + ts_map_size + ec_info_size;
        if (dbg_hdr_off + 22 > dbi.size() || dbg_hdr_size < 22) return;
        const std::uint16_t sec_hdr_stream_idx = read_u16(dbi.data() + dbg_hdr_off + 10);

        auto sec_hdrs = read_stream(sec_hdr_stream_idx);
        const std::size_t num_secs = sec_hdrs.size() / 40;
        if (num_secs == 0) return;

        auto sym_recs = read_stream(sym_rec_stream_idx);
        if (sym_recs.empty()) return;

        auto sec_to_rva = [&](std::uint16_t sec, std::uint32_t off) -> std::uint32_t {
            if (sec == 0 || sec > num_secs) return 0;
            std::uint32_t va = read_u32(sec_hdrs.data() + static_cast<std::size_t>(sec - 1) * 40 + 12);
            return va + off;
        };

        std::size_t pos = 0;
        while (pos + 4 <= sym_recs.size())
        {
            std::uint16_t rec_len = read_u16(sym_recs.data() + pos);
            if (rec_len < 2 || pos + 2 + rec_len > sym_recs.size()) break;
            std::uint16_t rec_kind = read_u16(sym_recs.data() + pos + 2);
            const std::uint8_t* payload = sym_recs.data() + pos + 4;
            std::size_t payload_len = rec_len - 2;

            if (rec_kind == 0x110E && payload_len >= 10) // S_PUB32
            {
                std::uint32_t off = read_u32(payload + 4);
                std::uint16_t sec = read_u16(payload + 8);
                const char* name = reinterpret_cast<const char*>(payload + 10);
                std::uint32_t rva = sec_to_rva(sec, off);
                if (rva != 0 && *name) mod.symbols.insert(name, mod.addr + rva);
            }
            else if ((rec_kind == 0x110F || rec_kind == 0x1110 || rec_kind == 0x1146 || rec_kind == 0x1147) && payload_len >= 35) // S_LPROC32 / S_GPROC32
            {
                std::uint32_t code_size = read_u32(payload + 12);
                std::uint32_t off = read_u32(payload + 28);
                std::uint16_t sec = read_u16(payload + 32);
                const char* name = reinterpret_cast<const char*>(payload + 35);
                std::uint32_t rva = sec_to_rva(sec, off);
                if (rva != 0 && *name) mod.symbols.insert(name, mod.addr + rva, code_size);
            }
            else if ((rec_kind == 0x110C || rec_kind == 0x110D) && payload_len >= 10) // S_LDATA32 / S_GDATA32
            {
                std::uint32_t off = read_u32(payload + 4);
                std::uint16_t sec = read_u16(payload + 8);
                const char* name = reinterpret_cast<const char*>(payload + 10);
                std::uint32_t rva = sec_to_rva(sec, off);
                if (rva != 0 && *name) mod.symbols.insert(name, mod.addr + rva);
            }

            pos += 2 + rec_len;
        }

        mod.symbols.sort();
        LOG_INFO("loaded {} symbols from {}", mod.symbols.size(), pdb_path.filename().string());
    }

private:
    std::vector<std::filesystem::path> search_paths_;

    [[nodiscard]] std::filesystem::path find_pdb(const pe::codeview_rsds& cv) const
    {
        auto name = std::filesystem::path(cv.pdb_path()).filename();
        for (const auto& dir : search_paths_)
        {
            auto candidate = dir / name;
            if (std::filesystem::exists(candidate)) return candidate;
        }
        if (std::filesystem::exists(name)) return name;
        auto cached = pdb_server::cached_path(cv);
        if (std::filesystem::exists(cached)) return cached;
        return pdb_server::download(cv);
    }
};
