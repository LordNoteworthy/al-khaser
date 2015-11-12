#include "PEB_BeingDebugged.h"

/* 
The IsDebuggerPresent function is actually a wrapper around this code.
It directly access the PEB for the process and reads a byte value that signifies if the process is being debugged. 
*/


BOOL IsDebuggerPresentPEB()
{
#if defined (ENV64BIT)
	PPEB pPeb = (PPEB)__readgsqword(0x60);

#elif defined(ENV32BIT)
	PPEB pPeb = (PPEB)__readfsdword(0x30);

#endif

	if (pPeb->BeingDebugged == 1)
		return TRUE;
	else
		return FALSE;
}

