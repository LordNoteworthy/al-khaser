#include "pch.h"

#include "ProcessHeap_ForceFlags.h"

/* 
NtGlobalFlag is a DWORD value inside the process PEB. It contains many flags set by the OS
that affects the way the process runs When a process is being debugged, the flags
FLG_HEAP_ENABLE_TAIL_CHECK (0x10), FLG_HEAP_ENABLE_FREE_CHECK(0x20), and FLG_HEAP_VALIDATE_PARAMETERS(0x40)
are set for the process, and we can use this to our advantage to identify if our process is being debugged.
	0x70 =  FLG_HEAP_ENABLE_TAIL_CHECK |
			FLG_HEAP_ENABLE_FREE_CHECK |
			FLG_HEAP_VALIDATE_PARAMETERS
*/

BOOL NtGlobalFlag()
{
	PDWORD pNtGlobalFlag = NULL, pNtGlobalFlagWoW64 = NULL;

#if defined (ENV64BIT)
	pNtGlobalFlag = (PDWORD)(__readgsqword(0x60) + 0xBC);

#elif defined(ENV32BIT)
	/* NtGlobalFlags for real 32-bits OS */
	BYTE* _teb32 = (BYTE*)__readfsdword(0x18);
	DWORD _peb32 = *(DWORD*)(_teb32 + 0x30);
	pNtGlobalFlag = (PDWORD)(_peb32 + 0x68);

	if (IsWoW64())
	{
		/* In Wow64, there is a separate PEB for the 32-bit portion and the 64-bit portion
		which we can double-check */
		
		BYTE* _teb64 = (BYTE*)__readfsdword(0x18) - 0x2000;
		DWORD64 _peb64 = *(DWORD64*)(_teb64 + 0x60);
		pNtGlobalFlagWoW64 = (PDWORD)(_peb64 + 0xBC);
	}
#endif

	bool normalDetected = pNtGlobalFlag && *pNtGlobalFlag & 0x00000070;
	bool wow64Detected = pNtGlobalFlagWoW64 && *pNtGlobalFlagWoW64 & 0x00000070;
	
	if(normalDetected || wow64Detected)
		return TRUE;
	else
		return FALSE;
}
