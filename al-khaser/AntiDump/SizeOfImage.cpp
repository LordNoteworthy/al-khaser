#include "pch.h"

#include "SizeOfImage.h"

// Any unreasonably large value will work say for example 0x100000 or 100,000h

VOID SizeOfImage()
{

#if defined (ENV64BIT)
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif defined(ENV32BIT)
	PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

	_tprintf(_T("[*] Increasing SizeOfImage in PE Header to: 0x100000\n"));
	PLDR_DATA_TABLE_ENTRY tableEntry = (PLDR_DATA_TABLE_ENTRY)(pPeb->Ldr->InMemoryOrderModuleList.Flink);
	tableEntry->DllBase = (PVOID)((INT_PTR)tableEntry->DllBase + 0x100000);
}
