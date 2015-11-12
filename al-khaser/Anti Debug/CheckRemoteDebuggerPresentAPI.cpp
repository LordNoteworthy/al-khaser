#include "CheckRemoteDebuggerPresentAPI.h"

/* 
This is another Win32 Debugging API function; it can be used to check if a remote process is being debugged,
However, we can also use this for checking if our own process is being debugged. it calls the NTDLL export
NtQueryInformationProcess with the SYSTEM_INFORMATION_CLASS set to 7 (ProcessDebugPort).
*/

BOOL CheckRemoteDebuggerPresentAPI ()
{
	BOOL bIsDbgPresent = FALSE;
	CheckRemoteDebuggerPresent(GetCurrentProcess(), &bIsDbgPresent);
	return bIsDbgPresent;
}
