#include "pch.h"

#include "CreateRemoteThread.h"

BOOL CreateRemoteThread_Injection()
{
	/* Some vars */
	DWORD dwProcessId;
	HANDLE hProcess = NULL, hRemoteThread = NULL;
	HMODULE hKernel32;
	FARPROC LoadLibraryAddress;
	LPVOID lpBaseAddress = NULL;
	TCHAR lpDllName[] = _T("InjectedDLL.dll");
	TCHAR lpDllPath[MAX_PATH];
	SIZE_T dwSize;
	BOOL bStatus = FALSE, bDebugPrivilegeEnabled;
	
	/* Get Process ID from Process name */
	dwProcessId = GetProcessIdFromName(_T("notepad.exe"));
	if (dwProcessId == NULL)
		return FALSE;
	_tprintf(_T("\t[+] Getting proc id: %u\n"), dwProcessId);

	/* Set Debug privilege */
	bDebugPrivilegeEnabled = SetDebugPrivileges();
	_tprintf(_T("\t[+] Setting Debug Privileges [%d]\n"), bDebugPrivilegeEnabled);
	if (!bDebugPrivilegeEnabled)
		return FALSE;

	/* Obtain a handle the process */
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == NULL) {
		print_last_error(_T("OpenProcess"));
		goto Cleanup;
	}

	/* Obtain a handle to kernel32 */
	hKernel32 = GetModuleHandle(_T("kernel32.dll"));
	if (hKernel32 == NULL) {
		print_last_error(_T("GetModuleHandle"));
		goto Cleanup;
	}

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
	hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryAddress, lpBaseAddress, NULL, 0);
	if (hRemoteThread == NULL) {
		print_last_error(_T("CreateRemoteThread"));
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
