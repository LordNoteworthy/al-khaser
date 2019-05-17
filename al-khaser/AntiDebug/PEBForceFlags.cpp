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

// TODO: PEBNtGlobalFlags need fix, does not work
BOOL PEBNtGlobalFlags()
{
	BOOL bRet = FALSE;
	__asm
	{
		mov eax, fs:[30h]
		mov eax, [eax + 68h]
		and eax, 0x70
		mov bRet, eax
	}

	return bRet != 0;
}

// I think it works
BOOL PEBDebugFlagWithAsm()
{
	DWORD bRet = 0;

	__asm
	{
		// IsDebuggerPresent函数原型，获取PEB地址，PEB第三个字节存放的调试标志
		mov     eax, fs:[0x30]
		movzx   eax, byte ptr ds : [eax + 2]
		mov		bRet, eax
	}

	return bRet == TRUE;
}

