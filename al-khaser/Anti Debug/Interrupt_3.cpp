#include "Interrupt_3.h"

/*
INT 3 generates a call to trap in the debugger and is triggered by opcode 0xCC within the executing process.
When a debugger is attached, the 0xCC execution will cause the debugger to catch the breakpoint and handle
the resulting exception. If a debugger is not attached, the exception is passed through to a structured
exception handler thus informing the process that no debugger is present.
*/


BOOL Interrupt_3()
{
	__try
	{
		__debugbreak();
	}
	__except (GetExceptionCode() == EXCEPTION_BREAKPOINT ?
	EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		// No debugger is attached, so return FALSE 
		// and continue.
		return FALSE;
	}
	return TRUE;
}