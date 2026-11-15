#pragma once
#include <cstdint>
#include <filesystem>
#include <memory>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

class win_file
{
public:
	win_file() = default;
	explicit win_file(std::vector<std::uint8_t> data) : data_(std::move(data)) {}

	[[nodiscard]] std::span<const std::uint8_t> data() const { return data_; }
	[[nodiscard]] std::span<std::uint8_t> data() { return data_; }
	[[nodiscard]] std::size_t size() const noexcept { return data_.size(); }

	void write(std::span<const std::uint8_t> buf);
	void write(const void* buf, std::size_t size);

	void resize(std::size_t size);

	// Where these bytes also go on the host. A guest filesystem that lives only in memory is a
	// dead end for anything that has to report a result: the guest process can write its answer
	// and nothing outside the emulator can ever read it. Empty means guest only, which is every
	// file loaded from the host tree.
	void mirror_to(std::filesystem::path host_path) { mirror_ = std::move(host_path); }
	[[nodiscard]] bool has_mirror() const noexcept { return !mirror_.empty(); }
	void sync_mirror();

	struct byte_lock
	{
		std::uint64_t offset;
		std::uint64_t length;
		bool exclusive;
		const void* owner;
	};

	struct extended_attribute
	{
		std::string name;
		std::uint8_t flags = 0;
		std::vector<std::uint8_t> value;
	};

	std::vector<byte_lock> locks;
	std::vector<extended_attribute> eas;

private:
	std::vector<std::uint8_t> data_;
	std::filesystem::path mirror_;
	bool mirror_announced_ = false;
};

class win_filesystem
{
public:
	struct dir_entry
	{
		std::string name;
		bool is_directory = false;
		std::uint64_t size = 0;
	};

	[[nodiscard]] std::shared_ptr<win_file> open(std::string_view path) const;
	std::shared_ptr<win_file> create(std::string_view path);
	bool remove(std::string_view path);

	bool unlink(std::string_view path);

	[[nodiscard]] bool directory_has_entries(std::string_view path) const;

	bool remove_directory(std::string_view path);

	enum class rename_status { renamed, not_found, collision, path_not_found, unsupported };

	rename_status rename(std::string_view from, std::string_view to, bool replace_existing);

	[[nodiscard]] bool exists(std::string_view path) const;
	[[nodiscard]] bool dir_exists(std::string_view path) const;

	// A directory holding no files is otherwise unrepresentable: a directory is normally
	// inferred from the files under it, and an empty one has none to infer it from.
	void create_directory(std::string_view path);

	// The same file under a second name, sharing its bytes rather than copying them.
	bool link(std::string_view from, std::string_view to);

	[[nodiscard]] std::vector<dir_entry> list_dir(std::string_view path) const;

	bool load_file(const std::filesystem::path& host_path, std::string_view virtual_path);
	bool load_dir(const std::filesystem::path& host_dir, std::string_view virtual_path);

	// Every file the guest creates from here on also lands under this host directory, at its
	// guest path. Off unless a run asks for it, so an ordinary run still touches no host file.
	void set_mirror_root(std::filesystem::path host_dir) { mirror_root_ = std::move(host_dir); }
	[[nodiscard]] const std::filesystem::path& mirror_root() const noexcept { return mirror_root_; }

	// Re-syncs every mirrored file, which is what catches bytes a guest wrote through a mapped
	// section rather than through write(). Returns how many files it wrote.
	std::size_t flush_mirrors() const;

	[[nodiscard]] std::filesystem::path mirror_path(std::string_view virtual_path) const;

	[[nodiscard]] static std::string normalize(std::string_view path);

private:
	std::unordered_map<std::string, std::shared_ptr<win_file>> files_;

	// Only the ones nothing else implies. A directory with files under it is still inferred,
	// so this does not have to be kept in step with every create().
	std::set<std::string> dirs_;

	std::filesystem::path mirror_root_;
};
