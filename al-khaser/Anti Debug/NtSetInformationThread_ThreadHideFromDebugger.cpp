#include "stdafx.h"

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

	// We have to import the function
	pNtSetInformationThread NtSetInformationThread = NULL;
	pNtQueryInformationThread NtQueryInformationThread = NULL;

	// Other Vars
	NTSTATUS Status;

	HMODULE hNtDll = LoadLibrary(_T("ntdll.dll"));
	if(hNtDll == NULL)
	{
		// Definitely something going wrong here!
		// TODO: warn instead of fail
		return TRUE;
	}
 
    NtSetInformationThread = (pNtSetInformationThread)GetProcAddress(hNtDll, "NtSetInformationThread");
	
	if(NtSetInformationThread == NULL)
	{
		// API should exist, this is VERY fishy.
		// TODO: warn instead of fail
		return TRUE;
	}

	bool doQITcheck = true;

	NtQueryInformationThread = (pNtQueryInformationThread)GetProcAddress(hNtDll, "NtQueryInformationThread");
	if (NtSetInformationThread == NULL)
	{
		if (IsWindowsVistaOrGreater())
		{
			// API should exist, this is kinda fishy.
			// TODO: warn instead of quit
			return TRUE;
		}
		doQITcheck = false;
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
