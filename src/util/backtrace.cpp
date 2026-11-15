#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>

#include "backtrace.hpp"

#include <cstring>
#include <format>
#include <mutex>

namespace util
{
	std::string host_backtrace(const unsigned skip, const unsigned max_frames)
	{
		// A host symbol engine of its own. The emulator already runs a PDB-backed one for
		// the guest, and sharing it would tie a diagnostic to the guest's state; the host
		// frames belong to this binary and its CRT, which the default search path finds.
		static std::once_flag once;
		static bool ready = false;

		std::call_once(once, []
		{
			SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_EXACT_SYMBOLS);
			ready = !!SymInitialize(GetCurrentProcess(), nullptr, TRUE);
		});

		// Frame 0 of the capture is this function, so it is always skipped.
		void* frames[64]{};
		const unsigned want = max_frames > 64 ? 64 : max_frames;
		const unsigned captured = CaptureStackBackTrace(1 + skip, want, frames, nullptr);

		std::string out;

		for (unsigned i = 0; i < captured; ++i)
		{
			const auto addr = reinterpret_cast<DWORD64>(frames[i]);

			HMODULE mod = nullptr;
			GetModuleHandleExW(
				GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				reinterpret_cast<LPCWSTR>(addr), &mod);

			char mod_name[MAX_PATH] = "?";
			DWORD64 mod_base = 0;

			if (mod)
			{
				mod_base = reinterpret_cast<DWORD64>(mod);

				// GetModuleFileNameW takes the handle alone, so this stays inside kernel32 and
				// does not pull psapi into a build that otherwise has no use for it.
				wchar_t wide[MAX_PATH]{};
				const DWORD n = GetModuleFileNameW(mod, wide, MAX_PATH);

				if (n > 0 && n < MAX_PATH)
				{
					int used = 0;
					for (DWORD i = 0; i < n && used < MAX_PATH - 1; ++i)
					{
						// Module paths here are ASCII; anything else becomes '?' rather than
						// needing a code-page conversion in a diagnostic.
						mod_name[used++] = wide[i] < 0x80
							? static_cast<char>(wide[i])
							: '?';
					}
					mod_name[used] = '\0';

					if (const auto* const slash = std::strrchr(mod_name, '\\'))
						std::memmove(mod_name, slash + 1, std::strlen(slash + 1) + 1);
				}
			}

			alignas(8) char sym_buf[sizeof(SYMBOL_INFO) + 256]{};
			auto* const sym = reinterpret_cast<SYMBOL_INFO*>(sym_buf);
			sym->SizeOfStruct = sizeof(SYMBOL_INFO);
			sym->MaxNameLen = 255;

			DWORD64 disp = 0;
			std::string fn;

			if (ready && SymFromAddr(GetCurrentProcess(), addr, &disp, sym))
				fn = sym->Name;

			out += fn.empty()
				? std::format("\n    #{:<2} {}+0x{:X}  [0x{:X}]", i, mod_name,
					mod_base ? addr - mod_base : addr, addr)
				: std::format("\n    #{:<2} {}!{}+0x{:X}  [0x{:X}]", i, mod_name, fn, disp, addr);
		}

		return out;
	}
}
