#include "pch.h"

#include "ErasePEHeaderFromMemory.h"

/* This function will erase the current images PE header from memory preventing a successful image if dumped */


VOID ErasePEHeaderFromMemory()
{
	_tprintf(_T("[*] Erasing PE header from memory\n"));
	DWORD OldProtect = 0;

	// Get base address of module
	char *pBaseAddr = (char*)GetModuleHandle(NULL);

	// Change memory protection
	VirtualProtect(pBaseAddr, 4096, // Assume x86 page size
		PAGE_READWRITE, &OldProtect);

	// Erase the header
	SecureZeroMemory(pBaseAddr, 4096);
}



