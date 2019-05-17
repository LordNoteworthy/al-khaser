#include "pch.h"
#include "PEBForceFlags.h"

// TODO: PEBForceFlags need fix, does not work
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

BOOL IsPEBForceFlagsWithAsm() {
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

// TODO: PEBHeapFlags need fix, does not work
BOOL PEBHeapFlags()
{
	DWORD dwRet = 0;

	__asm
	{
		// heapflag
		mov     eax, fs:[0x30]
		mov		eax, DWORD ptr[eax + 0x18] // PEB.ProcessHeap
		mov		eax, DWORD ptr[eax + 0x0c] // heap flag
		mov		dwRet, eax
	}

	return dwRet != 2;
}

BOOL IsPEBHeapFlagsWithAsm() {
	if (*(BYTE*)PEBHeapFlags == 0xCC || *(BYTE*)PEBHeapFlags == 0x64){
		return FALSE;
	}
	else if (PEBHeapFlags())
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}