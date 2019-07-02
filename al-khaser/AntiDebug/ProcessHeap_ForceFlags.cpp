#include "pch.h"

#include "ProcessHeap_ForceFlags.h"

/* 
When a program is run under a debugger, and is created using the debug process creation flags. The heap flags are changed.
These Flags exit at a different location depending upon the version of the operating system.
On Windows XP, these flags exist at 0x10 offset from heap base in 32bit system and offset 0x18 in bits.
On Windows 7, these flags exist at 0x44 offset from heap base in 32bit system and offset 0x74 in 64bits. 
*/


#if defined (ENV64BIT)
PUINT32 GetForceFlags_x64()
{
	PINT64 pProcessHeap = NULL;
	PUINT32 pHeapForceFlags = NULL;
	if (IsWindowsVistaOrGreater()){
		pProcessHeap = (PINT64)(__readgsqword(0x60) + 0x30);
		pHeapForceFlags = (PUINT32)(*pProcessHeap + 0x74);
	}

	else {
		pProcessHeap = (PINT64)(__readgsqword(0x60) + 0x30);
		pHeapForceFlags = (PUINT32)(*pProcessHeap + 0x18);
	}

	return pHeapForceFlags;
}

#elif defined(ENV32BIT)
PUINT32 GetForceFlags_x86()
{
	PUINT32 pProcessHeap, pHeapForceFlags = NULL;
	if (IsWindowsVistaOrGreater())
	{
		pProcessHeap = (PUINT32)(__readfsdword(0x30) + 0x18);
		pHeapForceFlags = (PUINT32)(*pProcessHeap + 0x44);

	}

	else {
		pProcessHeap = (PUINT32)(__readfsdword(0x30) + 0x18);
		pHeapForceFlags = (PUINT32)(*pProcessHeap + 0x10);
	}

	return pHeapForceFlags;
}
#endif

BOOL HeapForceFlags()
{
	PUINT32 pHeapForceFlags = NULL;

#if defined (ENV64BIT)
	pHeapForceFlags = GetForceFlags_x64();

#elif defined(ENV32BIT)
	pHeapForceFlags = GetForceFlags_x86();

#endif

	if (*pHeapForceFlags > 0)
		return TRUE;
	else
		return FALSE;

}
