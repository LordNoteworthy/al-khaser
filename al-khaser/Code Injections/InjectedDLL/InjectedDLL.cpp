#include "InjectedDLL.h"

LRESULT CALLBACK myFunction(INT code, WPARAM wParam, LPARAM lParam);

LRESULT CALLBACK myFunction(INT code, WPARAM wParam, LPARAM lParam)
{
	//here goes our code
	TCHAR str[MAX_PATH] = _T("");
	_stprintf(str, _T("Injected from process: %d"), GetCurrentProcessId());
	MessageBox(NULL, str, _T("Al-Khaser"), MB_OK);
	return CallNextHookEx(NULL, code, wParam, lParam);  //this is needed to let other applications set other hooks on this target
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
		case DLL_PROCESS_ATTACH:
			break;

		case DLL_PROCESS_DETACH:
			break;

		case DLL_THREAD_ATTACH:
			break;

		case DLL_THREAD_DETACH:
			break;
		}

	/* Returns TRUE on success, FALSE on failure */
	return TRUE;
}
