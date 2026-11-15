#include "target.hpp"
#include "kernel/map.hpp"
#include "kernel/win/win_kernel.hpp"
#include "emu/calling_conv.hpp"
#include "util/log.hpp"
#include "util/string.hpp"

#include <algorithm>
#include <filesystem>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "emu/guest_emu.hpp"

#if defined(KERNEMUL_ARCH_ARM64)
	#include "kernel/win/arm64_win.hpp"
	#include "emu/arm64/mmu.hpp"
	#include "emu/arm64/calling_conv.hpp"

	namespace guest
	{
		using mmu          = arm64::mmu;
		using calling_conv = arm64_win_conv;
		using win_emulator = arm64_win_emulator;
	}
#else
	#include "kernel/win/x86_win.hpp"
	#include "emu/x86/mmu.hpp"
	#include "emu/x86/calling_conv.hpp"

	namespace guest
	{
		using mmu          = x86::mmu;
		using calling_conv = x86_win_conv;
		using win_emulator = x86_win_emulator;
	}
#endif

namespace
{

struct guest_image
{
	std::string name;
	bool driver = false;

	std::shared_ptr<thread> entry;
};

void print_usage()
{
	LOG_INFO("usage: kernemul [image...]");
	LOG_INFO("examples:");
	LOG_INFO("  kernemul test_driver.sys");
	LOG_INFO("  kernemul test_printf.exe test_seh.exe");
	LOG_INFO("  kernemul test_driver.sys test_user.exe");
}

std::shared_ptr<thread> setup_driver(guest::win_emulator& win,
	const std::shared_ptr<guest::calling_conv>& conv, vcpu& cpu, const std::string& name)
{
	auto& kernel = win.kernel();
	auto& proc = *kernel.sys_proc;

	const auto driver = krnl::map_img(proc, std::string(target::guest_fs_dir) + name, true);

	if (!driver)
	{
		LOG_ERR("failed to map {}", name);
		return {};
	}

	// Up to the first dot, not the last: a variant build is named <service>.<variant>.sys, and
	// stem() would make vgk.calvin.sys a service called "vgk.calvin" that no driver expects.
	const auto file = std::filesystem::path(name).filename().string();
	const auto service = widen_string(file.substr(0, file.find('.')));

	const auto args = kernel.create_driver(*driver, service);

	const auto entry = win.create_kernel_thread(cpu, driver->entry_point);

	if (!entry)
	{
		LOG_ERR("failed to create a thread for {}", name);
		return {};
	}

	conv->set_arg(cpu, *entry, 0, args.driver_object.address());
	conv->set_arg(cpu, *entry, 1, args.registry_path.address());

	if (name.find("EasyAntiCheat") != std::string::npos)
	{
		const auto base = driver->addr;
		const auto emu_ptr = cpu.emu();
		auto log_cb = [base, emu_ptr](vcpu& c, addr_t, std::size_t)
		{
			const auto rva = c.pc() - base;
			if (rva == 0x1AE19FFULL || (rva >= 0x1AE1CF8ULL && rva <= 0x1AE1D08ULL) || rva == 0x435B0BULL)
			{
				LOG_INFO("[CHK_1AE 0x{:X}] rax=0x{:X} rcx=0x{:X} rdx=0x{:X} rsi=0x{:X} rdi=0x{:X} r8=0x{:X} r9=0x{:X} r11=0x{:X}",
					rva, c.reg<std::uint64_t>(x86::rax), c.reg<std::uint64_t>(x86::rcx),
					c.reg<std::uint64_t>(x86::rdx), c.reg<std::uint64_t>(x86::rsi),
					c.reg<std::uint64_t>(x86::rdi), c.reg<std::uint64_t>(x86::r8),
					c.reg<std::uint64_t>(x86::r9), c.reg<std::uint64_t>(x86::r11));
				// Deliberately NOT exiting here any more. This hook used to call std::exit(0) at
				// the 0x435B0B checkpoint, which made every run report exit code 0 and look like
				// a clean completion when the emulator had simply been told to stop. Keep the
				// checkpoint logging, drop the termination, so the run ends for a real reason.
			}
			if (false)
			{
				static bool armed = false;
				if (!armed)
				{
					armed = true;
					const auto r12_ctx = 0xFFFFF8000431DA80ULL;
					LOG_INFO("[TRACE_START] at 0x394F96 (rdi=2)");
					emu_ptr->hook_code(base + 0x1000ULL, base + 0x2924000ULL, [base, r12_ctx](vcpu& tc, addr_t, std::size_t)
					{
						static std::uint64_t prev_ctx[60]{};
						static bool init_ctx = false;
						static std::uint64_t last_jmp_from = 0;
						const auto trva = tc.pc() - base;
						if (!init_ctx)
						{
							init_ctx = true;
							for (int i = 0; i < 60; ++i)
								prev_ctx[i] = tc.read_virt_mem<std::uint64_t>(r12_ctx + i * 8);
						}
						if (trva == 0x45A24CULL)
						{
							LOG_INFO("[TRACE_END] reached 0x45A24C");
							std::exit(0);
						}
						const auto insn2 = tc.read_virt_mem<std::uint16_t>(tc.pc());
						if ((insn2 == 0xE0FF || insn2 == 0xE1FF || insn2 == 0xE2FF || insn2 == 0xE5FF) && trva != last_jmp_from)
						{
							last_jmp_from = trva;
							std::string diff;
							for (int i = 0; i < 60; ++i)
							{
								const auto cur = tc.read_virt_mem<std::uint64_t>(r12_ctx + i * 8);
								if (cur != prev_ctx[i])
								{
									diff += std::format(" [{:X}]=0x{:X}", i * 8, cur);
									prev_ctx[i] = cur;
								}
							}
							std::uint64_t target = 0;
							if (insn2 == 0xE0FF) target = tc.reg<std::uint64_t>(x86::rax);
							else if (insn2 == 0xE1FF) target = tc.reg<std::uint64_t>(x86::rcx);
							else if (insn2 == 0xE2FF) target = tc.reg<std::uint64_t>(x86::rdx);
							else if (insn2 == 0xE5FF) target = tc.reg<std::uint64_t>(x86::rbp);
							LOG_INFO("[VM_JMP] 0x{:X}->0x{:X}{}", trva, target - base, diff);
						}
					});
				}
			}
		};
		cpu.emu()->hook_code(base + 0x1AE19F0ULL, base + 0x1AE1D20ULL, log_cb);
		cpu.emu()->hook_code(base + 0x435B00ULL, base + 0x435B20ULL, log_cb);

		// (placeholder removed: the loader-wall instrumentation lives in setup_user_process)
	}

	return entry;
}

bool setup_user_process(guest::win_emulator& win, vcpu& cpu, const std::string& name)
{
	const auto app = win.create_user_process(cpu, name);

	if (!app.thread)
	{
		LOG_ERR("failed to create a process for {}", name);
		return false;
	}

	// NOTE: an attempt to hook_code a window inside the guest's ntdll from here crashed the
	// emulator after 146 lines (it died the moment the hook was installed, before any loader
	// work). hook_code is not usable on a guest image this way. The instrumentation for the
	// LdrpAppHeaders wall has to be built into the loader/emulator path instead, not attached
	// from main. Recorded in docs/re/eac-loader-wall-0039.md so it is not retried blindly.
	return true;
}

}

int main(const int argc, const char* const* const argv)
{
	LOG_INFO("kernemul targeting {}", target::name);

	std::vector<std::string> names(argv + 1, argv + argc);

	if (names.empty())
	{
		print_usage();
		return 1;
	}

	std::vector<guest_image> images;
	images.reserve(names.size());

	for (auto& name : names)
	{
		if (!std::filesystem::exists(std::string(target::guest_fs_dir) + name))
		{
			LOG_ERR("{} is not in {}", name, target::guest_fs_dir);
			return 1;
		}

		const bool driver = name.ends_with(".sys");

		images.push_back({ std::move(name), driver, {} });
	}

	auto mem = std::make_shared<guest::mmu>();
	auto conv = std::make_shared<guest::calling_conv>();
	auto e = make_guest_emu(mem, conv);

	guest::win_emulator win(e);

	win.create_vcpus(vcpu_count);

	const auto cpu = win.cpus().front();

	set_log_cpu(cpu.get());

	for (auto& image : images)
	{
		if (image.driver)
		{
			image.entry = setup_driver(win, conv, *cpu, image.name);

			if (!image.entry)
				return 1;
		}
		else if (!setup_user_process(win, *cpu, image.name))
		{
			return 1;
		}
	}

	win.run_all();

	for (const auto& image : images)
	{
		if (image.entry)
			LOG_INFO("{} returned, status=0x{:X}", image.name, conv->read_ret(*cpu, *image.entry));
		else
			LOG_INFO("{} finished", image.name);
	}

	return 0;
}
