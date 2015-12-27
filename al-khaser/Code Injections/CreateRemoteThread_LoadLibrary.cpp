#include "CreateRemoteThread_LoadLibrary.h"


BOOL CreateRemoteThread_LoadLibrary()
{
	/* Some vars */
	DWORD dwProcessId;
	HANDLE hProcess, hThreadId;
	HMODULE hKernel32;
	FARPROC LoadLibraryAddress;
	LPVOID lpBaseAddress;
	TCHAR lpBuffer[] = _T("InjectedDLL.dll");
	BOOL bStatus;
	
	/* Get Process ID from Process name */
	dwProcessId = GetProcessIdFromName(_T("notepad.exe"));

	/* Obtain a handle the process */
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == NULL) {
		_tprintf(_T("Unable to open process. Error code: %d", GetLastError()));
		return FALSE;
	}

	/* Obtain a handle to kernel32 */
	hKernel32 = GetModuleHandle(_T("kernel32.dll"));
	if (hKernel32 == NULL) {
		_tprintf(_T("Unable to obtain a handle to kernel32.dll. Error code: %d", GetLastError()));
		return FALSE;
	}

	/* Get LoadLibrary address */
	LoadLibraryAddress = GetProcAddress(hKernel32, "LoadLibraryW");
	if (LoadLibraryAddress == NULL) {
		_tprintf(_T("Unable to obtain LoadLibrary address."));
		print_last_error(_T("GetProcAddress"));
		return FALSE;
	}

	/* Allocate memory into the remote process */
	lpBaseAddress = VirtualAllocEx(hProcess, NULL, 256, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (lpBaseAddress == NULL) {
		_tprintf(_T("Unable to allocate memory in remote process. Error code: %d", GetLastError()));
		return FALSE;
	}

	/* Write to the remote process */
	bStatus = WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, sizeof(lpBuffer), NULL);
	if (bStatus == NULL) {
		_tprintf(_T("Unable to write data to remote process. Error code: %d", GetLastError()));
		return FALSE;
	}

	/* Create the more thread */
	hThreadId = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryAddress, lpBaseAddress, NULL, 0);
	if (bStatus == NULL) {
		_tprintf(_T("CreateRemoteThread failed !. Error code: %d", GetLastError()));
		return FALSE;
	}

	else {
		_tprintf(_T("Remote thread has been created successfully ...\n"));
		return TRUE;
	}
}