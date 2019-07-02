#include "pch.h"

#include "SetHandleInformation_API.h"


BOOL SetHandleInformatiom_ProtectedHandle()
{
	/* some vars */
	HANDLE hMutex;

	/* Create a mutex so we can get a handle */
	hMutex = CreateMutex(NULL, FALSE, _T("Random name"));

	if (hMutex) {

		/* Protect our handle */
		SetHandleInformation(hMutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);


		__try {
			/* Then, let's try close it */
			CloseHandle(hMutex);
		}

		__except (EXCEPTION_EXECUTE_HANDLER) {
			return TRUE;
		}

	}

	return FALSE;

}
