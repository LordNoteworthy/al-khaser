#include "Interrupt_0x2d.h"

/*
The Interrupt_0x2d function will check to see if a debugger is attached to the current process. It does this by setting up
SEH and using the Int 2D instruction which will only cause an exception if there is no debugger. Also when used in OllyDBG
it will skip a byte in the disassembly which could be used to detect the debugger.
Atm, only x86 version is available in VC++, in x64 I couln't find any __int2d in msdn
*/

extern "C" void __int2d();

BOOL Interrupt_0x2d()
{
	__try
	{
		__int2d();
		// The exception was swallowed so we are being debugged.
		return TRUE;
	}
	__except (GetExceptionCode() == EXCEPTION_BREAKPOINT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		// The exception was caught so there is nothing fiddly going on.
		return FALSE;
	}
}
