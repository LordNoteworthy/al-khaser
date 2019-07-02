#include "pch.h"

#include "Interrupt_0x2d.h"

/*
The Interrupt_0x2d function will check to see if a debugger is attached to the current process. It does this by setting up
SEH and using the Int 2D instruction which will only cause an exception if there is no debugger. Also when used in OllyDBG
it will skip a byte in the disassembly which could be used to detect the debugger.

Vectored Exception Handling is used here because SEH is an anti-debug trick in itself.
*/

extern "C" void __int2d();

static BOOL SwallowedException = TRUE;

static LONG CALLBACK VectoredHandler(
	_In_ PEXCEPTION_POINTERS ExceptionInfo
)
{
	SwallowedException = FALSE;
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		//The Int 2D instruction already increased EIP/RIP so we don't do that (although it wouldnt hurt).
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

BOOL Interrupt_0x2d()
{
	PVOID Handle = AddVectoredExceptionHandler(1, VectoredHandler);
	SwallowedException = TRUE;
	__int2d();
	RemoveVectoredExceptionHandler(Handle);
	return SwallowedException;
}
