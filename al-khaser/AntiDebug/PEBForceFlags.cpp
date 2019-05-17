#include "pch.h"
#include "PEBForceFlags.h"

BOOL PEBForceFlags()
{
	DWORD dwRet = 0;

	__asm
	{
		// ForceFlags
		mov     eax, fs:[0x30]
		mov		eax, DWORD ptr[eax + 0x18] // PEB.ProcessHeap
		mov		eax, DWORD ptr[eax + 0x10] // ForceFlags
		mov		dwRet, eax
	}

	return dwRet != 0;
}
BOOL IsPEBForceFlags() {
	if (*(BYTE*)PEBForceFlags == 0xCC || *(BYTE*)PEBForceFlags == 0x64) {
		return FALSE;
	}
	else if (PEBForceFlags())
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}