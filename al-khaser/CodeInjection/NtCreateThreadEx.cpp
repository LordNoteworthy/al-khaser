#include "pch.h"

#include "NtCreateThreadEx.h"

BOOL NtCreateThreadEx_Injection()
{
	// some vars
	HMODULE hNtdll;
	DWORD dwProcessId;
	HANDLE hProcess = NULL;
	TCHAR lpDllName[] = _T("InjectedDLL.dll");
	TCHAR lpDllPath[MAX_PATH];
	LPVOID lpBaseAddress = NULL;
	BOOL bStatus = FALSE;
	HMODULE hKernel32;
	FARPROC LoadLibraryAddress;
	HANDLE  hRemoteThread = NULL;
	NTSTATUS Status;
	SIZE_T dwSize;
	CLIENT_ID ClientId;
	PS_ATTRIBUTE_LIST PsAttrList;

	// we have to import our function
	pNtCreateThreadEx NtCreateThreadEx = NULL;

	/*
		GetLastError cannot be used with NtCreateThreadEx because this service does not set Win32 LastError value.
		Native status code must be translated to Win32 error code and set manually.
	*/
	pRtlNtStatusToDosError RtlNtStatusToDosErrorPtr = NULL;

	/* Get Process ID from Process name */
	dwProcessId = GetProcessIdFromName(_T("notepad.exe"));
	if (dwProcessId == 0)
		return FALSE;
	_tprintf(_T("\t[+] Getting proc id: %u\n"), dwProcessId);

	/* Obtain a handle the process */
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == NULL) {
		print_last_error(_T("OpenProcess"));
		goto Cleanup;
	}

	/* Get module handle of ntdll */
	hNtdll = GetModuleHandle(_T("ntdll.dll"));
	if (hNtdll == NULL) {
		print_last_error(_T("GetModuleHandle"));
		goto Cleanup;
	}

	/* Obtain a handle to kernel32 */
	hKernel32 = GetModuleHandle(_T("kernel32.dll"));
	if (hKernel32 == NULL) {
		print_last_error(_T("GetModuleHandle"));
		goto Cleanup;
	}

	/* Get routine pointer, failure is not critical */
	RtlNtStatusToDosErrorPtr = (pRtlNtStatusToDosError)GetProcAddress(hNtdll, "RtlNtStatusToDosError");

	// Get the address NtCreateThreadEx
	_tprintf(_T("\t[+] Looking for NtCreateThreadEx in ntdll\n"));
	NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
	if (NtCreateThreadEx == NULL) {
		print_last_error(_T("GetProcAddress"));
		goto Cleanup;
	}
	_tprintf(_T("\t[+] Found at 0x%p\n"), NtCreateThreadEx);

	/* Get LoadLibrary address */
	_tprintf(_T("\t[+] Looking for LoadLibrary in kernel32\n"));
	LoadLibraryAddress = GetProcAddress(hKernel32, "LoadLibraryW");
	if (LoadLibraryAddress == NULL) {
		print_last_error(_T("GetProcAddress"));
		goto Cleanup;
	}
	_tprintf(_T("\t[+] Found at 0x%p\n"), LoadLibraryAddress);

	/* Get the full path of the dll */
	GetFullPathName(lpDllName, MAX_PATH, lpDllPath, NULL);
	_tprintf(_T("\t[+] Full DLL Path: %s\n"), lpDllPath);

	/* Calculate the number of bytes needed for the DLL's pathname */
	dwSize = _tcslen(lpDllPath) * sizeof(TCHAR);

	/* Allocate memory into the remote process */
	_tprintf(_T("\t[+] Allocating space for the path of the DLL\n"));
	lpBaseAddress = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (lpBaseAddress == NULL) {
		print_last_error(_T("VirtualAllocEx"));
		goto Cleanup;
	}

	/* Write to the remote process */
	printf("\t[+] Writing into the current process space at 0x%p\n", lpBaseAddress);
	if (!WriteProcessMemory(hProcess, lpBaseAddress, lpDllPath, dwSize, NULL)) {
		print_last_error(_T("WriteProcessMemory"));
		goto Cleanup;
	}

	/* Create the more thread */
	SecureZeroMemory(&PsAttrList, sizeof(PsAttrList));

	/* Setup attributes entry */
	PsAttrList.TotalLength = sizeof(PS_ATTRIBUTE_LIST);
	PsAttrList.Attributes[0].Attribute = PS_ATTRIBUTE_CLIENT_ID;
	PsAttrList.Attributes[0].Size = sizeof(CLIENT_ID);
	PsAttrList.Attributes[0].u1.ValuePtr = &ClientId;

	Status = NtCreateThreadEx(&hRemoteThread, THREAD_ALL_ACCESS, NULL, hProcess,
		(LPTHREAD_START_ROUTINE)LoadLibraryAddress, lpBaseAddress, 0, 0, 0, 0, &PsAttrList);

	if (!NT_SUCCESS(Status)) {
		if (RtlNtStatusToDosErrorPtr) {
			SetLastError(RtlNtStatusToDosErrorPtr(Status));
		}
		else {
			SetLastError(ERROR_INTERNAL_ERROR);
		}
		print_last_error(_T("NtCreateThreadEx"));
	}

	else {
		_tprintf(_T("Remote thread has been created successfully ...\n"));
		WaitForSingleObject(hRemoteThread, INFINITE);
		CloseHandle(hRemoteThread);

		/* assign function success return result */
		bStatus = TRUE;
	}

Cleanup:
	/* If lpBaseAddress initialized then hProcess is initialized too because of upper check. */
	if (lpBaseAddress) {
		VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE);
	}
	if (hProcess) CloseHandle(hProcess);

	return bStatus;
}
