#include "stdafx.h"
#include "InjectedDLL.h"

LRESULT CALLBACK MyProc(INT code, WPARAM wParam, LPARAM lParam);

LRESULT CALLBACK MyProc(INT code, WPARAM wParam, LPARAM lParam)
{
	//here goes our code
	TCHAR str[MAX_PATH] = _T("");
	_stprintf(str, _T("[Al-khaser] - Injected from process: %d"), GetCurrentProcessId());
	OutputDebugString(str);
	return CallNextHookEx(NULL, code, wParam, lParam);  //this is needed to let other applications set other hooks on this target
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
		case DLL_PROCESS_ATTACH:
			OutputDebugString(_T("[Al-khaser] - DLL is attached"));
			break;

		case DLL_PROCESS_DETACH:
			OutputDebugString(_T("[Al-khaser] - DLL is detached"));
			break;

		case DLL_THREAD_ATTACH:
			OutputDebugString(_T("[Al-khaser] - Thread is atached"));
			break;

		case DLL_THREAD_DETACH:
			OutputDebugString(_T("[Al-khaser] - Thread is detached"));
			break;
		}

	/* Returns TRUE on success, FALSE on failure */
	return TRUE;
}
