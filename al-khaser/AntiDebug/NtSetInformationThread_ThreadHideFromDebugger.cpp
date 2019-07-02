#include "pch.h"

#include "NtSetInformationThread_ThreadHideFromDebugger.h"

/*
Calling NtSetInformationThread will attempt with ThreadInformationClass set to  x11 (ThreadHideFromDebugger)
to hide a thread from the debugger, Passing NULL for hThread will cause the function to hide the thread the
function is running in. Also, the function returns false on failure and true on success. When  the  function
is called, the thread will continue  to run but a debugger will no longer receive any events related to that thread.

These checks also look for hooks on the NtSetInformationThread API that try to block ThreadHideFromDebugger.
*/

BOOL NtSetInformationThread_ThreadHideFromDebugger()
{
	// ThreadHideFromDebugger
	const int ThreadHideFromDebugger =  0x11;

	auto NtSetInformationThread = static_cast<pNtSetInformationThread>(API::GetAPI(API_IDENTIFIER::API_NtSetInformationThread));
	auto NtQueryInformationThread = static_cast<pNtQueryInformationThread>(API::GetAPI(API_IDENTIFIER::API_NtQueryInformationThread));
	
	NTSTATUS Status;
	bool doQITcheck = false;

	// only do the QueryInformationThread check if we're on Vista and the API is available.
	// this is because the ThreadHideFromDebugger class can only be queried from Vista onwards.
	if (API::IsAvailable(API_IDENTIFIER::API_NtQueryInformationThread))
	{
		doQITcheck = IsWindowsVistaOrGreater();
	}

	BOOL isThreadHidden = FALSE;

	// First issue a bogus call with an incorrect length parameter. If it succeeds, we know NtSetInformationThread was hooked.
	Status = NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, &isThreadHidden, 12345);
	if (Status == 0)
		return TRUE;

	// Next try again but give it a bogus thread handle. If it succeeds, again we know NtSetInformationThread was hooked.
	Status = NtSetInformationThread((HANDLE)0xFFFF, ThreadHideFromDebugger, NULL, 0);
	if (Status == 0)
		return TRUE;
	
	// Now try a legitimate call.
	Status = NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0);

	if (Status == 0)
	{
		if (doQITcheck)
		{
			Status = NtQueryInformationThread(GetCurrentThread(), ThreadHideFromDebugger, &isThreadHidden, sizeof(BOOL), NULL);
			if (Status == 0)
			{
				// if the thread isn't hidden we know the ThreadHideFromDebugger call didn't do what it told us it did
				return isThreadHidden ? FALSE : TRUE;
			}
		}
	}
	else
	{
		// call failed, should've succeeded
		return TRUE;
	}

	// we didn't find any hooks.
	return FALSE;
}
