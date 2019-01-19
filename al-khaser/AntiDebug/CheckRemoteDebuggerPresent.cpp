#include "pch.h"
#include "CheckRemoteDebuggerPresent.h"

BOOL
CheckRemoteDebuggerPresentAPI (
	VOID
	)
/*++

Routine Description:

	CheckRemoteDebuggerPresent() is another Win32 Debugging API function;
	it can be used to check if a remote process is being debugged. However,
	we can also use this as another method for checking if our own process
	is being debugged. This API internally calls the NTDLL export
	NtQueryInformationProcess function with the SYSTEM_INFORMATION_CLASS
	set to 7 (ProcessDebugPort).

Arguments:

	None

Return Value:

	TRUE - if debugger was detected
	FALSE - otherwise
--*/
{
	BOOL bIsDbgPresent = FALSE;
	CheckRemoteDebuggerPresent(GetCurrentProcess(), &bIsDbgPresent);
	return bIsDbgPresent;
}
