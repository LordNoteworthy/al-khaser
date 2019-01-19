#include "pch.h"
#include "IsDebuggerPresent.h"

BOOL
IsDebuggerPresentAPI (
	VOID
	)
/*++

Routine Description:

	Calls the IsDebuggerPresent() API. This function is part of the
	Win32 Debugging API and it returns TRUE if a user mode debugger
	is present. Internally, it simply returns the value of the
	PEB->BeingDebugged flag.

Arguments:

	None

Return Value:

	TRUE - if debugger was detected
	FALSE - otherwise
--*/
{
	return IsDebuggerPresent();
}
