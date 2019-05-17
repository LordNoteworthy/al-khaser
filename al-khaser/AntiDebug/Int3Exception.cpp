#include "pch.h"
#include "Int3Exception.h"

int Int3Exception()
{
//#ifdef _X86_
//	__asm
//	{
//		// __try{}__exception{}的汇编形式
//		push   offset exception_handler; //set exception handler
//		push  dword ptr fs : [0h]
//			mov    dword ptr fs : [0h], esp
//			xor   eax, eax;//reset EAX invoke int3
//		int    3h
//			pop    dword ptr fs : [0h];//restore exception handler
//		add   esp, 4
//
//			test   eax, eax;// check the flag 
//		je    rt_label
//			jmp    rf_label
//
//	exception_handler :
//		mov   eax, dword ptr[esp + 0xc];//EAX = ContextRecord
//		mov    dword ptr[eax + 0xb0], 0xffffffff;//set flag (ContextRecord.EAX)
//		inc   dword ptr[eax + 0xb8];//set ContextRecord.EIP
//		xor   eax, eax
//			retn
//
//			rt_label :
//		xor eax, eax
//			inc eax
//			mov esp, ebp
//			pop ebp
//			retn
//			rf_label :
//		xor eax, eax
//			mov esp, ebp
//			pop ebp
//			retn
//	}
//#endif
	return 69;
}
// TODO: need fix, does not work
BOOL isInt3Exception() {
	/*if (*(BYTE*)Int3Exception == 0xCC || *(BYTE*)Int3Exception == 0x64)
	{
		return FALSE;
	}
	else if (Int3Exception())
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}*/
	return TRUE;
}