#include "pch.h"

#include "CreateRemoteThread.h"

BOOL CreateRemoteThread_Injection()
{
	LPVOID lpBaseAddress = nullptr;
	TCHAR lpDllName[] = _T("InjectedDLL.dll");
	TCHAR lpDllPath[MAX_PATH];
	auto bStatus = FALSE;

	/* Get Process ID from Process name */
	const auto dwProcessId = GetProcessIdFromName(_T("notepad.exe"));
	if (dwProcessId == NULL)
		return FALSE;
	_tprintf(_T("\t[+] Getting proc id: %u\n"), dwProcessId);

	/* Set Debug privilege */
	const auto bDebugPrivilegeEnabled = SetDebugPrivileges();
	_tprintf(_T("\t[+] Setting Debug Privileges [%d]\n"), bDebugPrivilegeEnabled);
	if (!bDebugPrivilegeEnabled)
		return FALSE;

	/* Obtain a handle the process */
	const auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == nullptr)
	{
		print_last_error(_T("OpenProcess"));
		/* If lpBaseAddress initialized then hProcess is initialized too because of upper check. */
		if (lpBaseAddress)
		{
			VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE);
		}
		if (hProcess) CloseHandle(hProcess);
	}

	/* Obtain a handle to kernel32 */
	const auto hKernel32 = GetModuleHandle(_T("kernel32.dll"));
	if (hKernel32 == nullptr)
	{
		print_last_error(_T("GetModuleHandle"));
		/* If lpBaseAddress initialized then hProcess is initialized too because of upper check. */
		if (lpBaseAddress)
		{
			VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE);
		}
		if (hProcess) CloseHandle(hProcess);
	}

	/* Get LoadLibrary address */
	_tprintf(_T("\t[+] Looking for LoadLibrary in kernel32\n"));
	const FARPROC LoadLibraryAddress = GetProcAddress(hKernel32, "LoadLibraryW");
	if (LoadLibraryAddress == nullptr)
	{
		print_last_error(_T("GetProcAddress"));
		/* If lpBaseAddress initialized then hProcess is initialized too because of upper check. */
		if (lpBaseAddress)
		{
			VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE);
		}
		if (hProcess) CloseHandle(hProcess);
	}
	_tprintf(_T("\t[+] Found at 0x%p\n"), LoadLibraryAddress);

	/* Get the full path of the dll */
	GetFullPathName(lpDllName, MAX_PATH, lpDllPath, nullptr);
	_tprintf(_T("\t[+] Full DLL Path: %s\n"), lpDllPath);

	/* Calculate the number of bytes needed for the DLL's pathname */
	SIZE_T dwSize = _tcslen(lpDllPath) * sizeof(TCHAR);

	/* Allocate memory into the remote process */
	_tprintf(_T("\t[+] Allocating space for the path of the DLL\n"));
	lpBaseAddress = VirtualAllocEx(hProcess, nullptr, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (lpBaseAddress == nullptr)
	{
		print_last_error(_T("VirtualAllocEx"));
		/* If lpBaseAddress initialized then hProcess is initialized too because of upper check. */
		if (lpBaseAddress)
		{
			VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE);
		}
		if (hProcess) CloseHandle(hProcess);
	}

	/* Write to the remote process */
	printf("\t[+] Writing into the current process space at 0x%p\n", lpBaseAddress);
	if (!WriteProcessMemory(hProcess, lpBaseAddress, lpDllPath, dwSize, nullptr))
	{
		print_last_error(_T("WriteProcessMemory"));
		/* If lpBaseAddress initialized then hProcess is initialized too because of upper check. */
		if (lpBaseAddress)
		{
			VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE);
		}
		if (hProcess) CloseHandle(hProcess);
	}

	/* Create the more thread */
	const HANDLE hRemoteThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryAddress,
	                                                lpBaseAddress, NULL, nullptr);
	if (hRemoteThread == nullptr)
	{
		print_last_error(_T("CreateRemoteThread"));
	}
	else
	{
		_tprintf(_T("Remote thread has been created successfully ...\n"));
		WaitForSingleObject(hRemoteThread, INFINITE);
		CloseHandle(hRemoteThread);

		/* assign function success return result */
		bStatus = TRUE;
	}

	return bStatus;
}
