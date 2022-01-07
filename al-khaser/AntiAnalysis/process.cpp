#include "pch.h"
#pragma once
#include "process.h"

/*
Check for process list
*/

VOID analysis_tools_process()
{
	const TCHAR *szProcesses[] = {
		_T("ollydbg.exe"),			// OllyDebug debugger
		_T("ProcessHacker.exe"),	// Process Hacker
		_T("tcpview.exe"),			// Part of Sysinternals Suite
		_T("autoruns.exe"),			// Part of Sysinternals Suite
		_T("autorunsc.exe"),		// Part of Sysinternals Suite
		_T("filemon.exe"),			// Part of Sysinternals Suite
		_T("procmon.exe"),			// Part of Sysinternals Suite
		_T("regmon.exe"),			// Part of Sysinternals Suite
		_T("procexp.exe"),			// Part of Sysinternals Suite
		_T("idaq.exe"),				// IDA Pro Interactive Disassembler
		_T("idaq64.exe"),			// IDA Pro Interactive Disassembler
		_T("ImmunityDebugger.exe"), // ImmunityDebugger
		_T("Wireshark.exe"),		// Wireshark packet sniffer
		_T("dumpcap.exe"),			// Network traffic dump tool
		_T("HookExplorer.exe"),		// Find various types of runtime hooks
		_T("ImportREC.exe"),		// Import Reconstructor
		_T("PETools.exe"),			// PE Tool
		_T("LordPE.exe"),			// LordPE
		_T("SysInspector.exe"),		// ESET SysInspector
		_T("proc_analyzer.exe"),	// Part of SysAnalyzer iDefense
		_T("sysAnalyzer.exe"),		// Part of SysAnalyzer iDefense
		_T("sniff_hit.exe"),		// Part of SysAnalyzer iDefense
		_T("windbg.exe"),			// Microsoft WinDbg
		_T("joeboxcontrol.exe"),	// Part of Joe Sandbox
		_T("joeboxserver.exe"),		// Part of Joe Sandbox
		_T("joeboxserver.exe"),		// Part of Joe Sandbox
		_T("ResourceHacker.exe"),	// Resource Hacker
		_T("x32dbg.exe"),			// x32dbg
		_T("x64dbg.exe"),			// x64dbg
		_T("Fiddler.exe"),			// Fiddler
		_T("httpdebugger.exe"),		// Http Debugger
	};

	WORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
	for (int i = 0; i < iLength; i++)
	{
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking process of malware analysis tool: %s "), szProcesses[i]);
		if (GetProcessIdFromName(szProcesses[i]))
			print_results(TRUE, msg);
		else
			print_results(FALSE, msg);
	}
}

int HijackParentProcess() {

	DWORD dwProcessId = 0;
	STARTUPINFOEX sie = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	SIZE_T cbAttributeListSize = 0;
	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
	HANDLE hParentProcess = NULL;

	/* Get Process ID from Process name */
	dwProcessId = GetProcessIdFromName(_T("notepad.exe"));
	if (dwProcessId == NULL) {
		return FALSE;
	}
	_tprintf(_T("\t[+] Getting proc id: %u\n"), dwProcessId);

	/* Get the size of the thread attribute list */
	InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttributeListSize);
	pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, cbAttributeListSize);
	if (NULL == pAttributeList)
	{
		print_last_error(_T("HeapAlloc"));
		goto Cleanup;
	}

	/* Make another call to effectively initialize the thread attribute list */
	if (!InitializeProcThreadAttributeList(pAttributeList, 1, 0, &cbAttributeListSize))
	{
		print_last_error(_T("InitializeProcThreadAttributeList error"));
		goto Cleanup;
	}

	/* Obtain debug privileges */
	SetPrivilege(GetCurrentProcess(), SE_DEBUG_NAME, TRUE);
	
	/* Obtain a handle the process */
	hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (NULL == hParentProcess)
	{
		print_last_error(_T("OpenProcess"));
		goto Cleanup;
	}

	if (!UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
			&hParentProcess, sizeof(HANDLE), NULL, NULL))
	{
		print_last_error(_T("UpdateProcThreadAttribute"));
		goto Cleanup;
	}

	sie.lpAttributeList = pAttributeList;

	if (!CreateProcess(NULL, (LPWSTR)_T("calc.exe"), NULL, NULL, FALSE,
			EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &sie.StartupInfo, &pi))
	{
		print_last_error(_T("CreateProcess"));
		goto Cleanup;
	}

	_tprintf(_T("Process created: %d\n"), pi.dwProcessId);

Cleanup:
	if (pAttributeList) DeleteProcThreadAttributeList(pAttributeList);
	if (hParentProcess) CloseHandle(hParentProcess);
	
	return 0;
}