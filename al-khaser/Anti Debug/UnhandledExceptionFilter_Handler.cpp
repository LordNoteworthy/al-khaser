#include "UnhandledExceptionFilter_Handler.h"


/*
When an exception occurs, and no registered Exception Handlers exist (neither Structured nor
Vectored), or if none of the registered handlers handles the exception, then the kernel32
UnhandledExceptionFilter() function will be called as a last resort. 
*/

BOOL bIsBeinDbg = TRUE;

LONG WINAPI UnhandledExcepFilter(PEXCEPTION_POINTERS pExcepPointers)
{
	// If a debugger is present, then this function will not be reached.
	bIsBeinDbg = FALSE;
    return EXCEPTION_CONTINUE_EXECUTION;
}


BOOL UnhandledExcepFilterTest ()
{
	SetUnhandledExceptionFilter(UnhandledExcepFilter);
	RaiseException(EXCEPTION_FLT_DIVIDE_BY_ZERO, 0, 0, NULL); 

    // Execution resumes here if there is no debugger
    // or if there is a debugger it will never
    // reach this point of execution
	return bIsBeinDbg;
}
