#include "IsDebuggerPresent.h"

BOOL IsDebuggerPresentAPI ()
{
	/* This function is part of the Win32 Debugging API 
	   It determines whether the calling process is being debugged by a user-mode debugger. 
	   If the current process is running in the context of a debugger, the return value is nonzero. */

	if(IsDebuggerPresent())
		return TRUE;
	else
		return FALSE;
}