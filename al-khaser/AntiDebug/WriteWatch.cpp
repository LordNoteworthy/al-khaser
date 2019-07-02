#include "pch.h"
#include "WriteWatch.h"

/*
 * This check uses the MEM_WRITE_WATCH feature of VirtualAlloc to test for additional memory writes by debuggers, sandboxing, etc.
 * There are a few ways that we can exploit this:
 *  (1) Allocate a buffer, write it once, get the count, see if it's >1
 *  (2) Allocate a buffer, pass it to an API where we know the buffer isn't touched (e.g. call with invalid parameter) and see if the count is >0
 *  (3) Allocate a buffer, use it to store a result of a call we care about (e.g. IsDebuggerPresent) and see if the memory was hit exactly once
 *  (4) Allocate an executable buffer, copy a debug check routine to it, run the check, see if any writes were performed after ours.
 *
 * Reference: https://msdn.microsoft.com/en-us/library/windows/desktop/aa366887.aspx
 * GetWriteWatch: https://msdn.microsoft.com/en-us/library/windows/desktop/aa366573.aspx
 * 
 */

BOOL VirtualAlloc_WriteWatch_BufferOnly()
{
	ULONG_PTR hitCount;
	DWORD granularity;
	BOOL result = FALSE;

	PVOID* addresses = static_cast<PVOID*>(VirtualAlloc(NULL, 4096 * sizeof(PVOID), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
	if (addresses == NULL) {
		printf("VirtualAlloc failed. Last error: %u\n", GetLastError());
		return result;
	}

	int* buffer = static_cast<int*>(VirtualAlloc(NULL, 4096 * 4096, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE));
	if (buffer == NULL) {
		VirtualFree(addresses, 0, MEM_RELEASE);
		printf("VirtualAlloc failed. Last error: %u\n", GetLastError());
		return result;
	}

	// read the buffer once
	buffer[0] = 1234;
	
	hitCount = 4096;
	if (GetWriteWatch(0, buffer, 4096, addresses, &hitCount, &granularity) != 0)
	{
		printf("GetWriteWatch failed. Last error: %u\n", GetLastError());
		result = FALSE;
	}
	else
	{
		// should only have one read here
		result = hitCount != 1;
	}

	VirtualFree(addresses, 0, MEM_RELEASE);
	VirtualFree(buffer, 0, MEM_RELEASE);

	return result;
}

BOOL VirtualAlloc_WriteWatch_APICalls()
{
	ULONG_PTR hitCount;
	DWORD granularity;
	BOOL result = FALSE, error = FALSE;

	PVOID* addresses = static_cast<PVOID*>(VirtualAlloc(NULL, 4096 * sizeof(PVOID), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
	if (addresses == NULL) {
		printf("VirtualAlloc failed. Last error: %u\n", GetLastError());
		return result;
	}

	int* buffer = static_cast<int*>(VirtualAlloc(NULL, 4096 * 4096, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE));
	if (buffer == NULL) {
		VirtualFree(addresses, 0, MEM_RELEASE);
		printf("VirtualAlloc failed. Last error: %u\n", GetLastError());
		return result;
	}

	// make a bunch of calls where buffer *can* be written to, but isn't actually touched due to invalid parameters.
	// this can catch out API hooks whose return-by-parameter behaviour is different to that of regular APIs

	if (GlobalGetAtomName(INVALID_ATOM, (LPTSTR)buffer, 1) != FALSE)
	{
		printf("GlobalGetAtomName succeeded when it should've failed... not sure what happened!\n");
		result = FALSE;
		error = TRUE;
	}
	if (GetEnvironmentVariable(L"%ThisIsAnInvalidEnvironmentVariableName?[]<>@\\;*!-{}#:/~%", (LPWSTR)buffer, 4096*4096) != FALSE)
	{
		printf("GetEnvironmentVariable succeeded when it should've failed... not sure what happened!\n");
		result = FALSE;
		error = TRUE;
	}
	if (GetBinaryType(L"%ThisIsAnInvalidFileName?[]<>@\\;*!-{}#:/~%", (LPDWORD)buffer) != FALSE)
	{
		printf("GetBinaryType succeeded when it should've failed... not sure what happened!\n");
		result = FALSE;
		error = TRUE;
	}
	if (HeapQueryInformation(0, (HEAP_INFORMATION_CLASS)69, buffer, 4096, NULL) != FALSE)
	{
		printf("HeapQueryInformation succeeded when it should've failed... not sure what happened!\n");
		result = FALSE;
		error = TRUE;
	}
	if (ReadProcessMemory(INVALID_HANDLE_VALUE, (LPCVOID)0x69696969, buffer, 4096, NULL) != FALSE)
	{
		printf("ReadProcessMemory succeeded when it should've failed... not sure what happened!\n");
		result = FALSE;
		error = TRUE;
	}
	if (GetThreadContext(INVALID_HANDLE_VALUE, (LPCONTEXT)buffer) != FALSE)
	{
		printf("GetThreadContext succeeded when it should've failed... not sure what happened!\n");
		result = FALSE;
		error = TRUE;
	}
	if (GetWriteWatch(0, &VirtualAlloc_WriteWatch_APICalls, 0, NULL, NULL, (PULONG)buffer) == 0)
	{
		printf("GetWriteWatch succeeded when it should've failed... not sure what happened!\n");
		result = FALSE;
		error = TRUE;
	}

	if (error == FALSE)
	{
		// APIs failed as they should have! :)

		hitCount = 4096;
		if (GetWriteWatch(0, buffer, 4096, addresses, &hitCount, &granularity) != 0)
		{
			printf("GetWriteWatch failed. Last error: %u\n", GetLastError());
			result = FALSE;
		}
		else
		{
			// should have zero reads here because GlobalGetAtomName doesn't probe the buffer until other checks have succeeded
			// if there's an API hook or debugger in here it'll probably try to probe the buffer, which will be caught here
			result = hitCount != 0;
		}
	}
	else
	{
		printf("Write watch API check skipped, ignore the result as it is inconclusive.\n");
	}

	VirtualFree(addresses, 0, MEM_RELEASE);
	VirtualFree(buffer, 0, MEM_RELEASE);

	return result;
}

BOOL VirtualAlloc_WriteWatch_IsDebuggerPresent()
{
	ULONG_PTR hitCount;
	DWORD granularity;
	BOOL result = FALSE;

	PVOID* addresses = static_cast<PVOID*>(VirtualAlloc(NULL, 4096 * sizeof(PVOID), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
	if (addresses == NULL) {
		printf("VirtualAlloc failed. Last error: %u\n", GetLastError());
		return result;
	}

	int* buffer = static_cast<int*>(VirtualAlloc(NULL, 4096 * 4096, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE));
	if (buffer == NULL) {
		VirtualFree(addresses, 0, MEM_RELEASE);
		printf("VirtualAlloc failed. Last error: %u\n", GetLastError());
		return result;
	}

	buffer[0] = IsDebuggerPresent();

	hitCount = 4096;
	if (GetWriteWatch(0, buffer, 4096, addresses, &hitCount, &granularity) != 0)
	{
		printf("GetWriteWatch failed. Last error: %u\n", GetLastError());
		result = FALSE;
	}
	else
	{
		// should only have one write here
		result = (hitCount != 1) | (buffer[0] == TRUE);
	}

	VirtualFree(addresses, 0, MEM_RELEASE);
	VirtualFree(buffer, 0, MEM_RELEASE);

	return result;
}

BOOL VirtualAlloc_WriteWatch_CodeWrite()
{
	ULONG_PTR hitCount;
	DWORD granularity;
	BOOL result = FALSE;

	PVOID* addresses = static_cast<PVOID*>(VirtualAlloc(NULL, 4096 * sizeof(PVOID), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
	if (addresses == NULL) {
		printf("VirtualAlloc failed. Last error: %u\n", GetLastError());
		return result;
	}

	byte* buffer = static_cast<byte*>(VirtualAlloc(NULL, 4096 * 4096, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_EXECUTE_READWRITE));
	if (buffer == NULL) {
		VirtualFree(addresses, 0, MEM_RELEASE);
		printf("VirtualAlloc failed. Last error: %u\n", GetLastError());
		return result;
	}
	
	// construct a call to isDebuggerPresent in assembly
	ULONG_PTR isDebuggerPresentAddr = (ULONG_PTR)&IsDebuggerPresent;

#ifndef _WIN32
#ifndef _WIN64
#error Architecture must be WIN32 or WIN64
#endif
#endif


#if _WIN64
	/*
	 * 64-bit
	 *
		0:  51                              push   rcx
		1:  48 b9 ef cd ab 90 78 56 34 12   movabs rcx, 0x1234567890abcdef
		b:  ff d1                           call   rcx
		d:  59                              pop    rcx
	    e:  c3                              ret
	 */
	int pos = 0;
	buffer[pos++] = 0x51; // push rcx
	buffer[pos++] = 0x48; // movabs rcx, ...
	buffer[pos++] = 0xB9; // ^ ...
	int offset = 0;
	for (int n = 0; n < 8; n++)
	{
		buffer[pos++] = (isDebuggerPresentAddr >> offset) & 0xFF;
		offset += 8;
	}
	buffer[pos++] = 0xFF; // call rcx
	buffer[pos++] = 0xD1; // ^
	buffer[pos++] = 0x59; // pop rcx
	buffer[pos  ] = 0xC3; // ret

#else
	/*
	 * 32-bit
	 *
	0:  51                      push   ecx
	1:  b9 78 56 34 12          mov    ecx, 0x12345678
	6:  ff d1                   call   ecx
	8:  59                      pop    ecx
	9:  c3                      ret
	*/
	int pos = 0;
	buffer[pos++] = 0x51; // push ecx
	buffer[pos++] = 0xB9; // mov ecx, ...
	int offset = 0;
	for (int n = 0; n < 4; n++)
	{
		buffer[pos++] = (isDebuggerPresentAddr >> offset) & 0xFF;
		offset += 8;
	}
	buffer[pos++] = 0xFF; // call ecx
	buffer[pos++] = 0xD1; // ^
	buffer[pos++] = 0x59; // pop ecx
	buffer[pos] = 0xC3; // ret

#endif

	ResetWriteWatch(buffer, 4096 * 4096);

	// cool, now exec the code
	BOOL(*foo)(VOID) = (BOOL(*)(VOID))buffer;
	if (foo() == TRUE)
	{
		result = TRUE;
	}
	
	if (result == FALSE)
	{
		hitCount = 4096;
		if (GetWriteWatch(0, buffer, 4096, addresses, &hitCount, &granularity) != 0)
		{
			printf("GetWriteWatch failed. Last error: %u\n", GetLastError());
			result = FALSE;
		}
		else
		{
			result = hitCount != 0;
		}
	}

	VirtualFree(addresses, 0, MEM_RELEASE);
	VirtualFree(buffer, 0, MEM_RELEASE);

	return result;
}
