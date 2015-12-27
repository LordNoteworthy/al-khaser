#include <Windows.h>
#include <tchar.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		MessageBox(NULL, _T("Injected DLL Attached !"), _T("Successfull!"), MB_OK);
    case DLL_PROCESS_DETACH:
		MessageBox(NULL, _T("Injected DLL Dettached !"), _T("Successfull!"), MB_OK);
	}
}