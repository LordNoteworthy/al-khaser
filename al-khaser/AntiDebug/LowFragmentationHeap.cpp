#include "pch.h"
#include "LowFragmentationHeap.h"


BOOL
LowFragmentationHeap(
	VOID
)
/*++

Routine Description:
	Originally found by Souhail Hammou:
	http://rce4fun.blogspot.com/2014/02/anti-debugging-trick-checking-for-low.html
	Under a debugger, the process does not have a Low Fragmentation Heap (LFH)
	The routine simply checks whether the nt!_HEAP.FrontEndHeap is NULL.

Arguments:

	None

Return Value:

	TRUE - if debugger was detected
	FALSE - otherwise
--*/
{

	PINT_PTR FrontEndHeap = NULL;

	// Get the default process heap.
	HANDLE hHeap = GetProcessHeap();

	// The FrontEndHeap offset of the _HEAP structure
	// is found on different locations depending of the OS.

	if (IsWindowsVista() || IsWindows7()) {
#if defined (ENV64BIT)
		FrontEndHeap = (PINT_PTR)((CHAR*)hHeap + 0x178);

#elif defined(ENV32BIT)
		FrontEndHeap = (PINT_PTR)((CHAR*)hHeap + 0xd4);
#endif
	}

	if (IsWindows8or8PointOne()) {
#if defined (ENV64BIT)
		FrontEndHeap = (PINT_PTR)((CHAR*)hHeap + 0x170);

#elif defined(ENV32BIT)
		FrontEndHeap = (PINT_PTR)((CHAR*)hHeap + 0xd0);
#endif
	}

	// In Windows 10. the offset changes very often.
	// Ignoring it from now.
	if (FrontEndHeap && *FrontEndHeap == NULL) {
		return TRUE;
	}

	return FALSE;
}
