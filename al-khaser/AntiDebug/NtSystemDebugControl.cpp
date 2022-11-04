#include "pch.h"

BOOL NtSystemDebugControl_Command() {
	auto NtSystemDebugControl_ = static_cast<pNtSystemDebugControl>(API::GetAPI(API_IDENTIFIER::API_NtSystemDebugControl));

	auto status = NtSystemDebugControl_(SYSDBG_COMMAND::SysDbgCheckLowMemory, 0, 0, 0, 0, 0);

	const auto STATUS_DEBUGGER_INACTIVE = 0xC0000354L;
	const auto STATUS_ACCESS_DENIED = 0xC0000022L;
	if (status == STATUS_DEBUGGER_INACTIVE) {
		return FALSE;
	} else {
		// kernel debugger found
		if (status != STATUS_ACCESS_DENIED) {
			// usermode debugger too
		}
		return TRUE;
	}
}