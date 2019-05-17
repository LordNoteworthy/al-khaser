#include "pch.h"

#include "HeapTail.h"

BOOL IsHeapTail()
{
	DWORD dwRet = 0;
	int flag[] = { 0xabababab, 0xabababab };
	LPVOID buff = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 32);
	int temp = 0;

	temp = (int)buff + 32;

	// 堆末尾的8个字节是数据ABABABABABABABAB
	dwRet = memcmp((LPVOID)temp, (LPVOID)flag, 8);

	return dwRet == 0;
}
