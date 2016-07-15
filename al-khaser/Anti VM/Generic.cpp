#include "Generic.h"

/*
Check of following dll are loaded
 - sbiedll.dll (Sandboxie)
 - dbghelp.dll (vmware)
 - api_log.dll (SunBelt SandBox)
 - dir_watch.dll (SunBelt SandBox)
 - pstorec.dll (SunBelt Sandbox)
 - vmcheck.dll (Virtual PC)
 - wpespy.dll (WPE Pro)
*/
VOID loaded_dlls()
{
	/* Some vars */
	HMODULE hDll;

	/* Array of strings of blacklisted dlls */
	TCHAR* szDlls[] = {
		_T("sbiedll.dll"),
		_T("dbghelp.dll"),
		_T("api_log.dll"),
		_T("dir_watch.dll"),
		_T("pstorec.dll"),
		_T("vmcheck.dll"),
		_T("wpespy.dll"),

	};

	WORD dwlength = sizeof(szDlls) / sizeof(szDlls[0]);
	for (int i = 0; i < dwlength; i++)
	{
		_tprintf(TEXT("[*] Checking if process loaded modules contains: %s "), szDlls[i]);

		/* Check if process loaded modules contains the blacklisted dll */
		hDll = GetModuleHandle(szDlls[i]);
		if (hDll == NULL)
			print_not_detected();
		else
			print_detected();	
	}
}


/*
Number of Processors in VM
*/

BOOL NumberOfProcessors()
{
#if defined (ENV64BIT)
	PULONG ulNumberProcessors = (PULONG)(__readgsqword(0x30) + 0xB8);

#elif defined(ENV32BIT)
	PULONG ulNumberProcessors = (PULONG)(__readfsdword(0x30) + 0x64) ;

#endif

	if (*ulNumberProcessors < 2)
		return TRUE;
	else
		return FALSE;
}


/*
This trick  involves looking at pointers to critical operating system tables
that are typically relocated on a virtual machine. One such table is the
Interrupt Descriptor Table (IDT), which tells the system where various operating
system interrupt handlers are located in memory. On real machines, the IDT is
located lower in memory than it is on guest (i.e., virtual) machines
*/
BOOL idt_trick()
{
	UINT idt_base = get_idt_base();
	if ((idt_base >> 24) == 0xff) 
		return TRUE;

	else
		return FALSE;
}

/*
Same for Local Descriptor Table (LDT) */
BOOL ldt_trick()
{
	UINT ldt_base = get_ldtr_base();

	if (ldt_base == 0xdead0000) 
		return FALSE;
	else 
		return TRUE; // VMWare detected	
}

