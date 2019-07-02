#include "pch.h"

#include "SetWindowsHooksEx.h"

BOOL SetWindowsHooksEx_Injection()
{
	TCHAR lpDllName[] = _T("InjectedDLL.dll");
	TCHAR lpDllPath[MAX_PATH];
	HOOKPROC myFunctionAddress;
	HMODULE hOurDll;
	DWORD dwProcessId, dwThreadId;
	HHOOK hHook;

	/* Get Process ID from Process name */
	dwProcessId = GetProcessIdFromName(_T("notepad.exe"));
	if (dwProcessId == NULL)
		return FALSE;
	_tprintf(_T("\t[+] Getting proc id: %u\n"), dwProcessId);

	/* Get thread id from process id */
	dwThreadId = GetMainThreadId(dwProcessId);
	if (dwThreadId == NULL)
		return FALSE;
	_tprintf(_T("\t[+] Getting main thread id of proc id: %u\n"), dwThreadId);

	/* Get the full path of the dll to be injected */
	GetFullPathName(lpDllName, MAX_PATH, lpDllPath, NULL);
	_tprintf(_T("\t[+] Full DLL Path: %s\n"), lpDllPath);

	/* Obtain a handle to our injected dll */
	hOurDll = LoadLibrary(lpDllPath);
	if (hOurDll == NULL) {
		print_last_error(_T("LoadLibrary"));
		return FALSE;
	}
	
	/* Get 'MyProc' address */
	_tprintf(_T("\t[+] Looking for 'MyProc' in our dll\n"));
	 myFunctionAddress = (HOOKPROC)GetProcAddress(hOurDll, "MyProc");
	if (myFunctionAddress == NULL) {
		print_last_error(_T("GetProcAddress"));
		return FALSE;
	}
	_tprintf(_T("\t[+] Found at 0x%p\n"), myFunctionAddress);

	/* Injection happens here */
	hHook = SetWindowsHookEx(WH_KEYBOARD, myFunctionAddress, hOurDll, dwThreadId);
	if (hHook == NULL) {
		print_last_error(_T("SetWindowsHookEx"));
		return FALSE;
	}

	/* Unhook */
	_tprintf(_T("SetWindowsHookEx created successfully ...\n"));

	/* When we want to remove the hook */
	// UnhookWindowsHookEx(hHook);

	return TRUE;

}
