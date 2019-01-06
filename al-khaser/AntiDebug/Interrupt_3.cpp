#include "pch.h"

#include "Interrupt_3.h"

/*
INT 3 generates a call to trap in the debugger and is triggered by opcode 0xCC within the executing process.
When a debugger is attached, the 0xCC execution will cause the debugger to catch the breakpoint and handle
the resulting exception. If a debugger is not attached, the exception is passed through to a structured
exception handler thus informing the process that no debugger is present.

Vectored Exception Handling is used here because SEH is an anti-debug trick in itself.
*/

static BOOL SwallowedException = TRUE;

static LONG CALLBACK VectoredHandler(
	_In_ PEXCEPTION_POINTERS ExceptionInfo
)
{
	SwallowedException = FALSE;
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		//Increase EIP/RIP to continue execution.
#ifdef _WIN64
		ExceptionInfo->ContextRecord->Rip++;
#else
		ExceptionInfo->ContextRecord->Eip++;
#endif
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}



BOOL Interrupt_3()
{
	PVOID Handle = AddVectoredExceptionHandler(1, VectoredHandler);
	SwallowedException = TRUE;
	__debugbreak();
	RemoveVectoredExceptionHandler(Handle);
	return SwallowedException;
}
