#include "filesystem.hpp"
#include "process_params.hpp"
#include "../../util/file.hpp"
#include "../../util/log.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>

namespace
{
	// A guest that writes more than this into one file is copying, not reporting. The mirror
	// exists so a guest process can hand a result back, so the cap is there only to keep one
	// runaway run from filling the host disk.
	constexpr std::size_t mirror_size_limit = 64u * 1024 * 1024;
}

void win_file::write(const std::span<const std::uint8_t> buf)
{
	data_.assign(buf.begin(), buf.end());
	sync_mirror();
}

void win_file::write(const void* buf, const std::size_t size)
{
	data_.resize(size);
	if (buf && size > 0)
		std::memcpy(data_.data(), buf, size);
	sync_mirror();
}

void win_file::resize(const std::size_t size)
{
	data_.resize(size);
	sync_mirror();
}

// Synchronous on purpose: a guest run that faults halfway still leaves everything it wrote before
// the fault on the host, and that is often the only evidence of where it got to.
void win_file::sync_mirror()
{
	if (mirror_.empty())
		return;

	if (data_.size() > mirror_size_limit)
	{
		if (!mirror_announced_)
		{
			mirror_announced_ = true;
			LOG_WARN("filesystem: '{}' is {} bytes, past the {}-byte mirror limit; not written out",
				mirror_.string(), data_.size(), mirror_size_limit);
		}

		return;
	}

	std::error_code ec;
	std::filesystem::create_directories(mirror_.parent_path(), ec);

	std::ofstream out(mirror_, std::ios::binary | std::ios::trunc);

	if (!out.is_open())
	{
		LOG_WARN("filesystem: cannot write '{}': {}", mirror_.string(), ec.message());
		return;
	}

	out.write(reinterpret_cast<const char*>(data_.data()), static_cast<std::streamsize>(data_.size()));
	out.close();

	if (!mirror_announced_)
	{
		mirror_announced_ = true;
		LOG_INFO("filesystem: mirrored '{}' ({} bytes)", mirror_.string(), data_.size());
	}
}

namespace
{
	constexpr std::string_view systemroot_name = "/systemroot";

	// windows_dir_narrow in the spelling normalize() produces, derived rather than written out
	// so the two cannot drift apart.
	const std::string windows_dir_key = []
	{
		std::string s(windows_dir_narrow);

		for (auto& c : s)
		{
			if (c == '\\')
				c = '/';
			c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
		}

		return s;
	}();
}

std::string win_filesystem::normalize(const std::string_view path)
{
	std::string result(path);

	for (auto& c : result)
	{
		if (c == '\\')
			c = '/';
		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	}

	while (!result.empty() && result.back() == '/')
		result.pop_back();

	// Guest paths are object manager names; everything here is named from the drive letter down.
	for (const std::string_view prefix : { "/??/", "/dosdevices/" })
	{
		if (result.starts_with(prefix))
		{
			result.erase(0, prefix.size());
			break;
		}
	}

	// \SystemRoot is the one name for the windows directory that carries no drive letter, and
	// the kernel hands it out itself: a loaded module's path reads \SystemRoot\System32\... So
	// it has to come back to the same file the drive lettered spelling names, or a driver that
	// takes a module path and opens it finds nothing there.
	if (result.starts_with(systemroot_name)
		&& (result.size() == systemroot_name.size() || result[systemroot_name.size()] == '/'))
	{
		result.replace(0, systemroot_name.size(), windows_dir_key);
	}

	return result;
}

std::shared_ptr<win_file> win_filesystem::open(const std::string_view path) const
{
	const auto it = files_.find(normalize(path));
	return it != files_.end() ? it->second : nullptr;
}

std::shared_ptr<win_file> win_filesystem::create(const std::string_view path)
{
	const auto norm = normalize(path);
	auto file = std::make_shared<win_file>();

	// Every write the guest makes to a file it created itself is mirrored as it happens, so the
	// host can read what the guest produced even when the run ends in a fault.
	if (!mirror_root_.empty())
		file->mirror_to(mirror_path(norm));

	files_[norm] = file;
	return file;
}

// Guest paths are object manager names -- "c:/windows/system32/ntdll.dll" -- and a drive colon
// cannot appear in a host file name. Sanitising each component keeps the mirror tree shaped like
// the guest's own, so a path in a log line is findable in the mirror without a mapping table.
std::filesystem::path win_filesystem::mirror_path(const std::string_view virtual_path) const
{
	if (mirror_root_.empty())
		return {};

	constexpr std::string_view invalid_in_a_file_name = "<>:\"|?*";

	std::filesystem::path out = mirror_root_;
	std::size_t start = 0;

	while (start <= virtual_path.size())
	{
		const auto slash = virtual_path.find('/', start);
		const auto end = slash == std::string_view::npos ? virtual_path.size() : slash;

		std::string component(virtual_path.substr(start, end - start));

		for (auto& c : component)
		{
			if (invalid_in_a_file_name.find(c) != std::string_view::npos
				|| static_cast<unsigned char>(c) < 0x20)
			{
				c = '_';
			}
		}

		if (!component.empty() && component != "." && component != "..")
			out /= component;

		if (slash == std::string_view::npos)
			break;

		start = slash + 1;
	}

	return out;
}

std::size_t win_filesystem::flush_mirrors() const
{
	std::size_t count = 0;

	for (const auto& [_, file] : files_)
	{
		if (file && file->has_mirror())
		{
			file->sync_mirror();
			++count;
		}
	}

	return count;
}

bool win_filesystem::remove(const std::string_view path)
{
	const auto it = files_.find(normalize(path));
	if (it == files_.end())
		return false;

	if (it->second.use_count() > 1)
		return false;

	files_.erase(it);
	return true;
}

bool win_filesystem::unlink(const std::string_view path)
{
	return files_.erase(normalize(path)) != 0;
}

bool win_filesystem::directory_has_entries(const std::string_view path) const
{
	const auto prefix = normalize(path) + "/";

	for (const auto& [key, _] : files_)
	{
		if (key.starts_with(prefix))
			return true;
	}

	for (const auto& dir : dirs_)
	{
		if (dir.starts_with(prefix))
			return true;
	}

	return false;
}

bool win_filesystem::remove_directory(const std::string_view path)
{
	if (directory_has_entries(path))
		return false;

	return dirs_.erase(normalize(path)) != 0;
}

win_filesystem::rename_status win_filesystem::rename(const std::string_view from,
	const std::string_view to, const bool replace_existing)
{
	const auto source = normalize(from);
	const auto target = normalize(to);

	if (!files_.contains(source))
		return dir_exists(source) ? rename_status::unsupported : rename_status::not_found;

	if (source == target)
		return rename_status::renamed;

	const auto slash = target.find_last_of('/');

	if (slash != std::string::npos && target.find('/') != slash && !dir_exists(target.substr(0, slash)))
		return rename_status::path_not_found;

	if (files_.contains(target) || dir_exists(target))
	{
		if (!replace_existing || dir_exists(target))
			return rename_status::collision;

		files_.erase(target);
	}

	auto node = files_.extract(source);
	node.key() = target;
	files_.insert(std::move(node));

	return rename_status::renamed;
}

bool win_filesystem::exists(const std::string_view path) const
{
	return files_.contains(normalize(path));
}

// Every ancestor of a created directory counts as one too, so a single create_directory of a
// deep path makes the whole chain openable.
void win_filesystem::create_directory(const std::string_view path)
{
	auto norm = normalize(path);

	while (!norm.empty())
	{
		dirs_.insert(norm);

		const auto slash = norm.find_last_of('/');

		if (slash == std::string::npos)
			break;

		norm.resize(slash);
	}
}

bool win_filesystem::link(const std::string_view from, const std::string_view to)
{
	const auto it = files_.find(normalize(from));

	if (it == files_.end())
		return false;

	files_[normalize(to)] = it->second;
	return true;
}

bool win_filesystem::dir_exists(const std::string_view path) const
{
	const auto norm = normalize(path);

	if (norm.empty())
		return true;

	if (dirs_.contains(norm))
		return true;

	const auto prefix = norm + "/";

	for (const auto& [key, _] : files_)
	{
		if (key.starts_with(prefix))
			return true;
	}

	return false;
}

std::vector<win_filesystem::dir_entry> win_filesystem::list_dir(const std::string_view path) const
{
	auto prefix = normalize(path);
	if (!prefix.empty())
		prefix += '/';

	std::map<std::string, dir_entry> entries;

	for (const auto& [key, file] : files_)
	{
		if (!key.starts_with(prefix))
			continue;

		const auto rest = key.substr(prefix.size());
		if (rest.empty())
			continue;

		const auto slash = rest.find('/');

		if (slash == std::string::npos)
		{
			auto& e = entries[rest];
			e.name = rest;
			e.size = file ? file->size() : 0;
		}
		else
		{
			auto name = rest.substr(0, slash);
			auto& e = entries[name];
			e.name = std::move(name);
			e.is_directory = true;
		}
	}

	// A directory nothing has files under still has to show up in its parent's listing.
	for (const auto& dir : dirs_)
	{
		if (!dir.starts_with(prefix))
			continue;

		const auto rest = dir.substr(prefix.size());

		if (rest.empty())
			continue;

		const auto slash = rest.find('/');
		auto name = slash == std::string::npos ? rest : rest.substr(0, slash);

		auto& e = entries[name];
		e.name = std::move(name);
		e.is_directory = true;
	}

	std::vector<dir_entry> result;
	result.reserve(entries.size());

	for (auto& [_, e] : entries)
		result.push_back(std::move(e));

	return result;
}

bool win_filesystem::load_file(const std::filesystem::path& host_path, const std::string_view virtual_path)
{
	auto buffer = util::read_file(host_path);
	if (buffer.empty() && std::filesystem::file_size(host_path) != 0)
	{
		LOG_WARN("filesystem: failed to read '{}'", host_path.string());
		return false;
	}

	const auto size = buffer.size();
	const auto norm = normalize(virtual_path);
	files_[norm] = std::make_shared<win_file>(std::move(buffer));

	LOG_INFO("filesystem: loaded '{}' -> '{}' ({} bytes)", host_path.string(), norm, size);
	return true;
}

bool win_filesystem::load_dir(const std::filesystem::path& host_dir, const std::string_view virtual_path)
{
	std::error_code ec;

	if (!std::filesystem::is_directory(host_dir, ec))
	{
		LOG_WARN("filesystem: '{}' is not a directory", host_dir.string());
		return false;
	}

	const auto base = normalize(virtual_path);
	std::size_t file_count = 0;

	for (auto it = std::filesystem::recursive_directory_iterator(
			host_dir, std::filesystem::directory_options::skip_permission_denied, ec);
		it != std::filesystem::recursive_directory_iterator(); it.increment(ec))
	{
		if (ec)
		{
			ec.clear();
			continue;
		}

		if (!it->is_regular_file(ec))
			continue;

		const auto relative = std::filesystem::relative(it->path(), host_dir, ec);
		if (ec)
		{
			ec.clear();
			continue;
		}

		auto child = base.empty()
			? normalize(relative.string())
			: base + "/" + normalize(relative.string());

		if (load_file(it->path(), child))
			++file_count;
	}

	LOG_INFO("filesystem: loaded directory '{}' -> '{}' ({} files)", host_dir.string(), base, file_count);
	return true;
}
