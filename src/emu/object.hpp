#pragma once
#include "defs.hpp"
#include "addr_space.hpp"
#include "mmu.hpp"
#include "emu.hpp"
#include "../util/log.hpp"
#include "../sym/symbol.hpp"
#include <format>
#include <cstddef>
#include <optional>
#include <type_traits>
#include <typeinfo>
#include <string>

template <class C, class M>
[[nodiscard]] std::size_t member_offset(M C::* const member) noexcept
{
	return reinterpret_cast<std::size_t>(
		&(static_cast<C*>(nullptr)->*member));
}

template <class T>
class emu_object
{
public:
	using value_type = T;

	emu_object() noexcept = default;

	emu_object(addr_space& space_, const addr_t addr, bool monitored = false) noexcept
		:	space_(&space_), addr_(addr)
	{
		if (monitored)
			monitor();
	}

	emu_object(addr_space& space_, const addr_t addr, std::string name, bool monitored = false) noexcept
		:	space_(&space_), addr_(addr), name_(std::move(name))
	{
		if (monitored)
			monitor();
	}

	// A copy is a second view of the same bytes, not a second watcher of them: the hook belongs
	// to whoever installed it, and duplicating the raw pointer would let either copy remove a
	// hook the other still names.
	emu_object(const emu_object& other)
		:	space_(other.space_), addr_(other.addr_), name_(other.name_) { }

	emu_object& operator=(const emu_object& other)
	{
		if (this != &other)
		{
			space_ = other.space_;
			addr_ = other.addr_;
			name_ = other.name_;
			hook_ = nullptr;
		}

		return *this;
	}

	// A move does carry it, so `obj = emu_object<T>(space, va, "name", true)` keeps watching.
	emu_object(emu_object&& other) noexcept
		:	space_(other.space_), addr_(other.addr_), hook_(other.hook_),
			name_(std::move(other.name_))
	{
		other.hook_ = nullptr;
	}

	emu_object& operator=(emu_object&& other) noexcept
	{
		if (this != &other)
		{
			space_ = other.space_;
			addr_ = other.addr_;
			hook_ = other.hook_;
			name_ = std::move(other.name_);
			other.hook_ = nullptr;
		}

		return *this;
	}

	[[nodiscard]] T read(const std::size_t index = 0) const
	{
		return space_->read_mem<T>(addr_ + index * sizeof(T));
	}

	void write(const T& val, const std::size_t index = 0)
	{
		space_->write_mem<T>(addr_ + index * sizeof(T), val);
	}

	template <class C, class M>
		requires std::is_same_v<C, T> || std::is_base_of_v<C, T>
	[[nodiscard]] emu_object<std::remove_extent_t<M>> field(M C::* const member) const
	{
		return emu_object<std::remove_extent_t<M>>(*space_, addr_ + member_offset(member));
	}

	template <class M>
	[[nodiscard]] emu_object<M> field_at(const std::size_t offset) const
	{
		return emu_object<M>(*space_, addr_ + offset);
	}

	emu_hook* monitor()
	{
		if (name_ != "KPCR[0]" && name_ != "KUSER_SHARED_DATA") return nullptr;
		if (hook_ || !space_ || !addr_)
			return hook_;

		const auto base = addr_;
		const auto name = name_;

		// 0117: every read here may fault. This callback runs on the guest-access path, so a
		// thrown std::runtime_error escapes the vmexit dispatch into std::terminate, which on
		// MSVC is __fastfail(0xC0000409) -- the host process dies with no report and the guest
		// log stops at whatever access the logger happened to be serving. That is exactly how
		// this monitor masqueraded as a "loader wall" for two rounds: the last line of every
		// user-mode run was a KUSER_SHARED_DATA access, which read like the guest stopping at
		// ntdll!LdrpAppHeaders when in fact the host had just thrown. Reads that may not be
		// serviceable are probed with a faulting-safe wrapper, and anything that would throw
		// is logged without the enrichment rather than taking the machine down with it.
		auto* const sp = space_;

		auto read_u64 = [sp](addr_t at) -> std::optional<std::uint64_t>
		{
			try
			{
				return sp->read_mem<std::uint64_t>(at);
			}
			catch (...)
			{
				return std::nullopt;
			}
		};

		hook_ = space_->mmu_->emu()->hook_mem(addr_, addr_ + sizeof(T) - 1, prot_rw,
			[sp, base, name, read_u64](vcpu& cpu, addr_t accessed, std::size_t, mem_prot access)
			{
				const auto rip = cpu.pc();

				// The address reported is whichever mapping the guest walked. KUSER_SHARED_DATA
				// exists twice -- the kernel copy at 0xFFFFF800'00000000 and the user copy at
				// 0xFFFFF780'00000000 -- and a hook installed on one sees accesses through the
				// other, so the offset is only meaningful inside this object's own range.
				// Measured: an offset of 0x8807FFE0308, which is the difference between the two
				// bases, not a field of the struct. Enriching from a bogus offset is what threw.
				const bool in_range = accessed >= base && accessed < base + sizeof(T);
				const auto offset = in_range ? accessed - base : 0;

				// A field the probe could not serve prints as "-" so the line still says what
				// was accessed, which is the part that matters for following the guest.
				const auto hex = [](const std::optional<std::uint64_t> v) -> std::string
				{
					return v ? std::format("0x{:X}", *v) : std::string("-");
				};

				if (!in_range)
				{
					LOG_INFO("0x{:X} accessed 0x{:X} ({} '{}' via the other mapping)",
						rip, accessed, typeid(T).name(), name);
					return;
				}

				const auto val = read_u64(accessed);
				const auto r12 = cpu.reg<std::uint64_t>(12);
				std::optional<std::uint64_t> m108, m110, m128, m190;
				if (r12 > 0xFFFF000000000000ULL) {
					m108 = read_u64(r12 + 0x108);
					m110 = read_u64(r12 + 0x110);
					m128 = read_u64(r12 + 0x128);
					m190 = read_u64(r12 + 0x190);
				}
				LOG_INFO("0x{:X} accessed ({} '{}')+0x{:X} (val={}, rbp=0x{:X}, r12=0x{:X}, [108]={}, [110]={}, [128]={}, [190]={})",
					rip, typeid(T).name(), name, offset, hex(val),
					cpu.reg<std::uint64_t>(5), r12, hex(m108), hex(m110), hex(m128), hex(m190));
			}, space_);

		return hook_;
	}

	void unmonitor()
	{
		if (hook_)
		{
			space_->mmu_->emu()->remove_hook(hook_);
			hook_ = nullptr;
		}
	}

	static emu_object allocate(addr_space& space, std::string name = {}, bool monitored = false,
		mem_prot prot = prot_rw)
	{
		const auto addr = space.alloc(sizeof(T), prot);
		return emu_object(space, addr, std::move(name), monitored);
	}

	static emu_object allocate_at(addr_space& space, addr_t addr, std::string name = {}, bool monitored = false)
	{
		space.mmu_->map_virt(space, addr, sizeof(T), prot_rw);
		return emu_object(space, addr, std::move(name), monitored);
	}

	void set_name(std::string name) { name_ = std::move(name); }

	[[nodiscard]] bool monitored() const noexcept { return hook_ != nullptr; }
	[[nodiscard]] const std::string& name() const noexcept { return name_; }
	[[nodiscard]] addr_t address() const noexcept { return addr_; }
	[[nodiscard]] addr_space* space() const noexcept { return space_; }
	explicit operator bool() const noexcept { return addr_ != 0; }

protected:
	addr_space* space_ = nullptr;
	addr_t addr_ = 0;
	emu_hook* hook_ = nullptr;
	std::string name_;
};

// Guest memory an access is worth reporting, named so the log says what was touched rather than
// only where. The range is watched as one hook: a per-element hook would multiply the cost of a
// table by its length for no extra information.
inline emu_hook* monitor_range(addr_space& space, const addr_t addr, const std::size_t size,
	std::string name)
{
	if (!addr || !size)
		return nullptr;

	// A range the guest cannot reach is not an error here -- a module mapped into another
	// address space translates only while that space is current -- so it is reported and skipped
	// rather than thrown out of whatever was mapping it.
	try
	{
		return space.mmu_->emu()->hook_mem(addr, addr + size - 1, prot_rw,
			[base = addr, name = std::move(name)](vcpu& cpu, const addr_t accessed,
				std::size_t, const mem_prot access)
			{
				// A module-owned address names the global that was touched; anything else --
				// a watched IDT, GDT or TSS -- keeps the label its installer gave it.
				const auto sym = symbols::try_format_addr(cpu, accessed);

				LOG_INFO("0x{:X} accessed {} (type={})", cpu.pc(),
					sym ? *sym : std::format("'{}'+0x{:X}", name, accessed - base),
					static_cast<unsigned>(access));
			}, &space);
	}
	catch (const std::exception& e)
	{
		LOG_WARN("cannot watch '{}' at 0x{:X}: {}", name, addr, e.what());
		return nullptr;
	}
}

// A run of T the guest indexes, where emu_object would name only the first element. The whole
// run is one hook, so an access reports the element it landed on.
template <class T>
class emu_object_arr
{
public:
	using value_type = T;

	emu_object_arr() noexcept = default;

	emu_object_arr(addr_space& space, const addr_t addr, const std::size_t count,
		std::string name = {}, const bool monitored = false)
		:	space_(&space), addr_(addr), count_(count), name_(std::move(name))
	{
		if (monitored)
			monitor();
	}

	emu_object_arr(const emu_object_arr& other)
		:	space_(other.space_), addr_(other.addr_), count_(other.count_), name_(other.name_) { }

	emu_object_arr& operator=(const emu_object_arr& other)
	{
		if (this != &other)
		{
			space_ = other.space_; addr_ = other.addr_;
			count_ = other.count_; name_ = other.name_; hook_ = nullptr;
		}
		return *this;
	}

	emu_object_arr(emu_object_arr&& other) noexcept
		:	space_(other.space_), addr_(other.addr_), count_(other.count_),
			hook_(other.hook_), name_(std::move(other.name_))
	{
		other.hook_ = nullptr;
	}

	emu_object_arr& operator=(emu_object_arr&& other) noexcept
	{
		if (this != &other)
		{
			space_ = other.space_; addr_ = other.addr_; count_ = other.count_;
			hook_ = other.hook_; name_ = std::move(other.name_); other.hook_ = nullptr;
		}
		return *this;
	}

	[[nodiscard]] T read(const std::size_t index) const
	{
		return space_->read_mem<T>(element(index));
	}

	void write(const T& val, const std::size_t index)
	{
		space_->write_mem<T>(element(index), val);
	}

	[[nodiscard]] emu_object<T> at(const std::size_t index) const
	{
		return emu_object<T>(*space_, element(index));
	}

	emu_hook* monitor()
	{
		if (hook_ || !space_ || !addr_ || !count_)
			return hook_;

		hook_ = space_->mmu_->emu()->hook_mem(addr_, addr_ + size_bytes() - 1, prot_rw,
			[base = addr_, name = name_](vcpu& cpu, const addr_t accessed,
				std::size_t, const mem_prot access)
			{
				const auto offset = accessed - base;

				LOG_INFO("0x{:X} accessed '{}'[{}]+0x{:X} (type={})",
					cpu.pc(), name, offset / sizeof(T), offset % sizeof(T),
					static_cast<unsigned>(access));
			}, space_);

		return hook_;
	}

	[[nodiscard]] bool monitored() const noexcept { return hook_ != nullptr; }
	[[nodiscard]] addr_t address() const noexcept { return addr_; }
	[[nodiscard]] std::size_t count() const noexcept { return count_; }
	[[nodiscard]] std::size_t size_bytes() const noexcept { return count_ * sizeof(T); }
	[[nodiscard]] addr_space* space() const noexcept { return space_; }
	explicit operator bool() const noexcept { return addr_ != 0 && count_ != 0; }

private:
	[[nodiscard]] addr_t element(const std::size_t index) const
	{
		return addr_ + index * sizeof(T);
	}

	addr_space* space_ = nullptr;
	addr_t addr_ = 0;
	std::size_t count_ = 0;
	emu_hook* hook_ = nullptr;
	std::string name_;
};

template <>
class emu_object<void>
{
public:
	emu_object() noexcept = default;

	emu_object(addr_space& space, const addr_t addr, bool = false) noexcept
		:	space_(&space), addr_(addr) {}

	[[nodiscard]] addr_t address() const noexcept { return addr_; }
	[[nodiscard]] addr_space* space() const noexcept { return space_; }
	explicit operator bool() const noexcept { return addr_ != 0; }

private:
	addr_space* space_ = nullptr;
	addr_t addr_ = 0;
};
