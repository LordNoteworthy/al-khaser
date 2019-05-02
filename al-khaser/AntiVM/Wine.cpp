#include "pch.h"

#include "Wine.h"

/*
Check against Wine export dlls
*/
BOOL wine_exports()
{
	/* Get kernel32 module handle */
	const auto hKernel32 = GetModuleHandle(_T("kernel32.dll"));
	if (hKernel32 == nullptr) {
		print_last_error(_T("GetModuleHandle"));
		return FALSE;
	}

	/* Check if wine_get_unix_file_name is exported by this dll */
	if (GetProcAddress(hKernel32, "wine_get_unix_file_name") == nullptr)
		return FALSE;
	return TRUE;
}

/*
Check against Wine registry keys
*/
VOID wine_reg_keys()
{
	/* Array of strings of blacklisted registry keys */
	const TCHAR* szKeys[] = {
		_T("SOFTWARE\\Wine")
	};

	const WORD dwlength = sizeof(szKeys) / sizeof(szKeys[0]);

	/* Check one by one */
	for (auto i = 0; i < dwlength; i++)
	{
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking reg key %s "), szKeys[i]);
		if (Is_RegKeyExists(HKEY_CURRENT_USER, szKeys[i]))
			print_results(TRUE, msg);
		else
			print_results(FALSE, msg);
	}
}
