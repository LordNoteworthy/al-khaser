#include "pch.h"

#include "TrapFlag.h"

/*
	This technique is similar to exceptions based debugger detections.
	You enable the trap flag in the current process and check whether
	an exception is raised or not. If an exception is not raised, you
	can assume that a debugger has “swallowed” the exception for us,
	and that the program is being traced. The beauty of this approach
	is that it detects every debugger, user mode or kernel mode,
	because they all use the trap flag for tracing a program.

	Vectored Exception Handling is used here because SEH is an
	anti-debug trick in itself.
*/

static BOOL SwallowedException = TRUE;

static LONG CALLBACK VectoredHandler(
	_In_ PEXCEPTION_POINTERS ExceptionInfo
)
{
	SwallowedException = FALSE;
	
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
		return EXCEPTION_CONTINUE_EXECUTION;
		
	return EXCEPTION_CONTINUE_SEARCH;
}



BOOL TrapFlag()
{
	PVOID Handle = AddVectoredExceptionHandler(1, VectoredHandler);
	SwallowedException = TRUE;

#ifdef _WIN64
	UINT64 eflags = __readeflags();
#else
	UINT eflags = __readeflags();
#endif

	//  Set the trap flag
	eflags |= 0x100;
	__writeeflags(eflags);

	RemoveVectoredExceptionHandler(Handle);
	return SwallowedException;
}
