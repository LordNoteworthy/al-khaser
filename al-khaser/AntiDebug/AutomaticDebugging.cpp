#include "pch.h"
#include "AutomaticDebugging.h"

BOOL AutomaticDebugging()
{
	BOOL is_64;
	HKEY hkey = NULL;
	char key[] = "Debugger";
	IsWow64Process(GetCurrentProcess(), &is_64);
	char reg_dir_32bit[] = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug";
	char reg_dir_64bit[] = "SOFTWARE\\Wow6432Node\\Microsoft\\WindowsNT\\CurrentVersion\\AeDebug";
	DWORD ret = 0;
	if (is_64)
	{
		ret = RegCreateKeyA(HKEY_LOCAL_MACHINE, reg_dir_64bit, &hkey);
	}
	else
	{
		ret = RegCreateKeyA(HKEY_LOCAL_MACHINE, reg_dir_32bit, &hkey);
	}
	if (ret != ERROR_SUCCESS)
	{
		return FALSE;
	}
	DWORD type;
	char tmp[256];
	DWORD len = 256;
	ret = RegQueryValueExA(hkey, key, NULL, &type, (LPBYTE)tmp, &len);
	if (strstr(tmp, "OllyIce") != NULL || strstr(tmp, "OllyDBG") != NULL || strstr(tmp, "WinDbg") != NULL || strstr(tmp, "x64dbg") != NULL || strstr(tmp, "Immunity") != NULL)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}
