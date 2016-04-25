#include "Wine.h"




BOOL wine_exports()
{
	/* Some vars */
	HMODULE hKernel32;

	/* Get kernel32 module handle */
	hKernel32 = GetModuleHandle(_T("kernel32.dll"));
	if (hKernel32 == NULL) {
		print_last_error(_T("GetModuleHandle"));
		return FALSE;
	}

	/* Check if wine_get_unix_file_name is exported by this dll */
	if (GetProcAddress(hKernel32, "wine_get_unix_file_name") == NULL)
		return FALSE;
	else
		return TRUE;

}