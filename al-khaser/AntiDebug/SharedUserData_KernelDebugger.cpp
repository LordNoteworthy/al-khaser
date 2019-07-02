#include "pch.h"

#include "SharedUserData_KernelDebugger.h"

/*
NtQuerySystemInformation can be used to detect the presence of a kernel debugger. However, the
same information can be obtained from user mode with no system calls at all. This is done by
reading from the KUSER_SHARED_DATA struct, which is has a fixed user mode address of 0x7FFE0000 in all versions
of Windows in both 32 and 64 bit. In kernel mode it is located at 0xFFDF0000 (32 bit) or 0xFFFFF78000000000 (64 bit).
Detailed information about KUSER_SHARED_DATA can be found here: http://www.geoffchappell.com/studies/windows/km/ntoskrnl/structs/kuser_shared_data.htm
*/

BOOL SharedUserData_KernelDebugger()
{
	// The fixed user mode address of KUSER_SHARED_DATA
	const ULONG_PTR UserSharedData = 0x7FFE0000;

	// UserSharedData->KdDebuggerEnabled is a BOOLEAN according to ntddk.h, which gives the false impression that it is
	// either true or false. However, this field is actually a set of bit flags, and is only zero if no debugger is present.
	const UCHAR KdDebuggerEnabledByte = *(UCHAR*)(UserSharedData + 0x2D4); // 0x2D4 = the offset of the field

	// Extract the flags.
	// The meaning of these is the same as in NtQuerySystemInformation(SystemKernelDebuggerInformation).
	// Normally if a debugger is attached, KdDebuggerEnabled is true, KdDebuggerNotPresent is false and the byte is 0x3.
	const BOOLEAN KdDebuggerEnabled = (KdDebuggerEnabledByte & 0x1) == 0x1;
	const BOOLEAN KdDebuggerNotPresent = (KdDebuggerEnabledByte & 0x2) == 0;

	if (KdDebuggerEnabled || !KdDebuggerNotPresent)
		return TRUE;

	return FALSE;
}
