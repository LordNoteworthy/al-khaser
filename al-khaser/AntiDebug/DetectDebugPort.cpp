#include "pch.h"
#include "DetectDebugPort.h"

typedef NTSTATUS(CALLBACK *NTQUERYINFORMATIONPROCESS)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS processInfo,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength OPTIONAL
	);

BOOL DetectDebugPort()
{
	BOOL bRet = FALSE;
	HMODULE hNtdll = NULL;
	NTQUERYINFORMATIONPROCESS pNtQueryInformationProcess = NULL;
	DWORD dwDebugPort = 0;

	__try
	{
		hNtdll = LoadLibraryW(L"ntdll.dll");
		if (NULL == hNtdll)
		{
			OutputDebugStringW(L"get ntdll handle failed!");
			__leave;
		}

		pNtQueryInformationProcess = (NTQUERYINFORMATIONPROCESS)GetProcAddress(hNtdll, "NtQueryInformationProcess");
		if (NULL == pNtQueryInformationProcess)
		{
			OutputDebugStringW(L"get NtQueryInformationProcess address failed!");
			__leave;
		}

		pNtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &dwDebugPort, sizeof(dwDebugPort), NULL);

		dwDebugPort == -1 ? bRet = TRUE : bRet = FALSE;
	}

	__finally
	{

	}

	return bRet;
}
