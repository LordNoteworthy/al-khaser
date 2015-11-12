#include <Windows.h>

BOOL IsWoW64();
BOOL Is_RegKeyValueExists(HKEY hKey, TCHAR* lpSubKey, TCHAR* lpValueName, TCHAR* search_str);
BOOL Is_RegKeyExists(HKEY hKey, TCHAR* lpSubKey);
BOOL is_FileExists(TCHAR* szPath);
BOOL is_DirectoryExists(TCHAR* szPath);
BOOL check_mac_addr(TCHAR* szMac);
BOOL GetOSDisplayString(LPTSTR pszOS);

#define	MALLOC(x)	HeapAlloc(GetProcessHeap(), 0, x)
#define FREE(x)		HeapFree(GetProcessHeap(), 0, x)

#if _WIN32 || _WIN64
#if _WIN64
#define ENV64BIT
#else
#define ENV32BIT
#endif
#endif