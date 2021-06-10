#include "pch.h"

#include "NtSetInformationThread_ThreadHideFromDebugger.h"

/*
Calling NtSetInformationThread will attempt with ThreadInformationClass set to  x11 (ThreadHideFromDebugger)
to hide a thread from the debugger, Passing NULL for hThread will cause the function to hide the thread the
function is running in. Also, the function returns false on failure and true on success. When  the  function
is called, the thread will continue  to run but a debugger will no longer receive any events related to that thread.

These checks also look for hooks on the NtSetInformationThread API that try to block ThreadHideFromDebugger.
*/

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((DWORD)0xC0000004L)
#endif
#ifndef STATUS_DATATYPE_MISALIGNMENT
#define STATUS_DATATYPE_MISALIGNMENT ((DWORD)0x80000002L)
#endif


BOOL NtSetInformationThread_ThreadHideFromDebugger()
{
	// this is needed because the bool data type can be at unaligned memory locations, whereas the NtQueryInformationThread API expects 32-bit aligned pointers.
	struct AlignedBool
	{
		alignas(4) bool Value;
	};

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

	AlignedBool isThreadHidden;
	isThreadHidden.Value = false;
	
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
			// note: the ThreadHideFromDebugger query expects a bool (1 byte), not a BOOL (4 bytes)
			// if a BOOL is used, the kernel returns 0xC0000004 (STATUS_INFO_LENGTH_MISMATCH) because BOOL is typedef int.

			// first do a legitimate call. this should succeed or return an error such as access denied.
			Status = NtQueryInformationThread(GetCurrentThread(), ThreadHideFromDebugger, &isThreadHidden.Value, sizeof(bool), NULL);

			// this shouldn't happen, because we used the correct length. this will only happen if a buggy hook mistakenly expects a BOOL rather than a bool.
			if (Status == STATUS_INFO_LENGTH_MISMATCH)
			{
				// we found a buggy hook that expects some size other than 1
				return TRUE;
			}

			// if the legitimate call succeeded, continue with additional bogus API call checks
			if (Status == 0)
			{
				AlignedBool bogusIsThreadHidden;
				bogusIsThreadHidden.Value = false;

				// now do a bogus call with the wrong size. this will catch buggy hooks that accept BOOL (4 bytes) or just don't have any size checks
				Status = NtQueryInformationThread(GetCurrentThread(), ThreadHideFromDebugger, &bogusIsThreadHidden.Value, sizeof(BOOL), NULL);
				if (Status != STATUS_INFO_LENGTH_MISMATCH)
				{
					// we found a buggy hook that allows for incorrect size values
					return TRUE;
				}

				// NtQueryInformationThread explicitly requires the ThreadInformation pointer to be aligned. as such, it should reject unaligned pointers.
				// hooks are almost certainly guaranteed to not retain this behaviour, so it's a very nice way to catch them out.
				const size_t UnalignedCheckCount = 8;
				bool bogusUnalignedValues[UnalignedCheckCount];
				int alignmentErrorCount = 0;
#if _WIN64
				// on 64-bit, up to two elements in the array should be aligned.
				const size_t MaxAlignmentCheckSuccessCount = 2;
#else
				// on 32-bit, there should be either two or four aligned elements (unsure how WoW64 affects this, so I'm just gonna assume 2 or 4 are ok)
				const size_t MaxAlignmentCheckSuccessCount = 4;
#endif
				for (size_t i = 0; i < UnalignedCheckCount; i++)
				{
					Status = NtQueryInformationThread(GetCurrentThread(), ThreadHideFromDebugger, &(bogusUnalignedValues[i]), sizeof(BOOL), NULL);
					if (Status == STATUS_DATATYPE_MISALIGNMENT)
					{
						alignmentErrorCount++;
					}
				}
				// if there weren't enough alignment errors, we know that the API must be hooked and not checking alignment properly!
				if (UnalignedCheckCount - MaxAlignmentCheckSuccessCount > alignmentErrorCount)
				{
					return TRUE;
				}

				// the legitimate call was successful, and the bogus call was unsuccessful, so return false (no detection) if the HideFromDebugger flag was properly set.
				// if the HideFromDebugger flag was not set, i.e. the NtSetInformationThread call lied to us about being successful, then return true (debugger/hook detected)
				return isThreadHidden.Value ? FALSE : TRUE;
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
