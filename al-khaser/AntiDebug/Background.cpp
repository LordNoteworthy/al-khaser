#include "pch.h"
#include "Background.h"

BOOL Background()
{
	STARTUPINFO si;
	GetStartupInfo(&si);
	if (si.dwX != 0 || si.dwY != 0 || si.dwFillAttribute != 0 || si.dwXSize != 0 || si.dwYSize != 0 || si.dwXCountChars != 0 || si.dwYCountChars != 0)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}
