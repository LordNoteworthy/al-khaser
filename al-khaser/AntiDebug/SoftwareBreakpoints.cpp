#include "pch.h"

#include "SoftwareBreakpoints.h"


/*
Software breakpoints aka INT 3 represented in the IA-32 instruction set with the opcode CC (0xCC).
Given a memory addresse and size, it is relatively simple to scan for the byte 0xCC -> if(pTmp[i] == 0xCC)
An obfuscated method would be to check if our memory byte xored with 0x55 is equal 0x99 for example ... 
*/

VOID My_Critical_Function()
{
	int a = 1;
	int b = 2;
	int c = a + b;
	_tprintf(_T("I am critical function, you should protect against int3 bps %d"), c);
}


VOID Myfunction_Adresss_Next()
{
	My_Critical_Function();
	/*
	There is no guaranteed way of determining the size of a function at run time(and little reason to do so)
	however if you assume that the linker located functions that are adjacent in the source code sequentially in memory,
	then the following may give an indication of the size of a function Critical_Function by using :
	int Critical_Function_length = (int)Myfunction_Adresss_Next - (int)Critical_Function
	Works only if you compile the file in Release mode.
	*/
};

BOOL SoftwareBreakpoints()
{
	//NOTE this check might not work on x64 because of alignment 0xCC bytes
	size_t sSizeToCheck = (size_t)(Myfunction_Adresss_Next)-(size_t)(My_Critical_Function);
	PUCHAR Critical_Function = (PUCHAR)My_Critical_Function;

	for (size_t i = 0; i < sSizeToCheck; i++) {
		if (Critical_Function[i] == 0xCC) // Adding another level of indirection : 0xCC xor 0x55 = 0x99
			return TRUE;
	}
	return FALSE;
}
