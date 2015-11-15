#include <Windows.h>

/*
Hardware breakpoints are a technology implemented by Intel in their processor architecture,
and are controlled by the use of special registers known as Dr0-Dr7.
Dr0 through Dr3 are 32 bit registers that hold the address of the breakpoint .
*/

BOOL HardwareBreakpoints_SEH ()
{
	BOOL IsDbgPresent = TRUE;

	// Raises an exception in the calling thread
	LPEXCEPTION_POINTERS except_ptr; 
	__try   { 
		RaiseException(EXCEPTION_FLT_DIVIDE_BY_ZERO, 0, 0, NULL);
	} 

	// Handling the exception that have just been generated
	__except (except_ptr = GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER) 
		{ 
			//The thread context modified (it containsthe CPU registers at the time the exception was thrown)
			PCONTEXT ctx = except_ptr->ContextRecord; 

			if (ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0 )
				IsDbgPresent = TRUE;

			else
				IsDbgPresent = FALSE;
		}

	 /* If we reach this location, it means that the exception was handled by something else, maybe a debugger or another reversing or analysis
    tool, so we return true for security purposes, but not because a HW BP was detected.  */
	return IsDbgPresent;
}


BOOL HardwareBreakpoints_GetThreadContext ()
{

	// This structure is key to the function and is the 
	// medium for detection and removal
	PCONTEXT ctx;
	ctx = PCONTEXT(VirtualAlloc(NULL, sizeof(ctx), MEM_COMMIT, PAGE_READWRITE));
	SecureZeroMemory(ctx, sizeof(CONTEXT));

	// The CONTEXT structure is an in/out parameter therefore we have
	// to set the flags so Get/SetThreadContext knows what to set or get.
	ctx->ContextFlags = CONTEXT_DEBUG_REGISTERS;

	// Get the registers
	if (GetThreadContext(GetCurrentThread(), ctx) == 0)
		return -1;

	// Now we can check for hardware breakpoints, its not 
	// necessary to check Dr6 and Dr7, however feel free to
	if (ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0)
		return TRUE;
	else
		return FALSE;
}

BOOL HardwareBreakpoints()
{
	if (HardwareBreakpoints_GetThreadContext() || HardwareBreakpoints_SEH())
		return TRUE;
	else
		return FALSE;
}