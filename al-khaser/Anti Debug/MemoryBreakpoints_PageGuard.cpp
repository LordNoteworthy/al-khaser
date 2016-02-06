#include "MemoryBreakpoints_PageGuard.h"

/*
In essence, what occurs is that we allocate a dynamic buffer and write a RET to the buffer.
We then mark the page as a guard page and push a potential return address onto the stack. Next, we jump to our page,
and if we're under a debugger, specifically OllyDBG, then we will hit the RET instruction and return to the address we pushed onto
the stack before we jumped to our page. Otherwise, a STATUS_GUARD_PAGE_VIOLATION exception will occur, and we know we're not being
debugged by OllyDBG.
*/

BOOL MemoryBreakpoints_PageGuard()
{
	UCHAR *pMem = NULL;
	SYSTEM_INFO SystemInfo = { 0 };
	DWORD OldProtect = 0;
	PVOID pAllocation = NULL; // Get the page size for the system 

	// Retrieves information about the current system.
	GetSystemInfo(&SystemInfo);

	// Allocate memory 
	pAllocation = VirtualAlloc(NULL, SystemInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pAllocation == NULL)
		return FALSE;

	// Write a ret to the buffer (opcode 0xc3)
	RtlFillMemory(pAllocation, 1, 0xC3);

	// Make the page a guard page         
	if (VirtualProtect(pAllocation, SystemInfo.dwPageSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &OldProtect) == 0)
		return FALSE;

// I tested it only in the 32bits version of Olly since the 64bits is not their yet atm.
#if defined (ENV32BIT)
	__try
	{
		__asm mov eax, pAllocation
		// This is the address we'll return to if we're under a debugger
		__asm push MemBpBeingDebugged
		__asm jmp eax // Exception or execution, which shall it be :D?
	
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		// The exception occured and no debugger was detected
		VirtualFree(pAllocation, NULL, MEM_RELEASE);
		return FALSE;
	}

	__asm MemBpBeingDebugged:
#endif

	VirtualFree(pAllocation, NULL, MEM_RELEASE);
	return TRUE;
}