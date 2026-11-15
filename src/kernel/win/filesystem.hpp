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

	void resize(std::size_t size) { data_.resize(size); dirty_ = true; }

	// Whether the guest put bytes into this file. A file the emulator loaded from the host is
	// clean until something writes to it, and a file the guest creates but never fills stays
	// clean too -- boot_seed creates physicaldriveN entries as placeholders, and dumping those
	// would be noise. So dirtiness, not creation, is what marks guest output.
	[[nodiscard]] bool dirty() const noexcept { return dirty_; }

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
	bool dirty_ = false;
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

	// Write every file the guest filled into host_disk_dir, mirroring the guest path so
	// c:/windows/foo lands as <dir>/c/windows/foo. Returns the number of files written.
	//
	// The guest filesystem is memory-only by design, which is fine while the guest is a driver
	// whose result is visible in its return status, and a hard blocker the moment the guest has
	// to report something it produced -- which is exactly what a user-mode experiment needs:
	// run b.dll inside the guest and get its crypto output back out to the host. Without this,
	// NtCreateFile/NtWriteFile succeed inside the emulator and the bytes go nowhere (0118).
	std::size_t dump_dirty_files(const std::filesystem::path& host_disk_dir) const;

	bool load_file(const std::filesystem::path& host_path, std::string_view virtual_path);
	bool load_dir(const std::filesystem::path& host_dir, std::string_view virtual_path);

	[[nodiscard]] static std::string normalize(std::string_view path);

private:
	std::unordered_map<std::string, std::shared_ptr<win_file>> files_;

	// Only the ones nothing else implies. A directory with files under it is still inferred,
	// so this does not have to be kept in step with every create().
	std::set<std::string> dirs_;
};
