#include "ErasePEHeaderFromMemory.h"

/* This function will erase the current images PE header from memory preventing a successful image if dumped */


BOOL ErasePEHeaderFromMemory()
{
	DWORD OldProtect = 0;

	// Get base address of module
	char *pBaseAddr = (char*)GetModuleHandle(NULL);

	// Change memory protection
	VirtualProtect(pBaseAddr, 4096, // Assume x86 page size
		PAGE_READWRITE, &OldProtect);

	// Erase the header
	SecureZeroMemory(pBaseAddr, 4096);

	return TRUE;
}



