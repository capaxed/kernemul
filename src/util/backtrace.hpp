#pragma once
#include <string>

namespace util
{
	// The return addresses of the calling host thread, resolved to module!symbol+disp.
	//
	// Captured at a throw site on purpose. A host exception that escapes the scheduler
	// reaches std::terminate, and MSVC's terminate path is __fastfail with
	// FAST_FAIL_FATAL_APP_EXIT -- the process dies with 0xC0000409 and produces no WER
	// report, no Application log entry, and no message of any kind. The guest log just
	// stops, which reads for all the world like the guest refused to go on. See 0117.
	//
	// skip counts frames above this function's own, so 0 names the caller of the throw.
	std::string host_backtrace(unsigned skip = 0, unsigned max_frames = 24);
}
