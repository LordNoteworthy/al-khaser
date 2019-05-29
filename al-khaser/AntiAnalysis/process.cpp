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
		_T("HxD.exe"),				// HxD - Freeware Hex Editor and Disk Editor
		_T("ResourceHacker.exe"),	// Resource Hacker
		_T("httpdebugger.exe"),		// Http Debugger
		_T("windowrenamer.exe"),	// Window Renamer
		_T("PerfWatson2.exe"),		// Visual Studio
		_T("devenv.exe"),			// Visual Studio
		_T("ServiceHub.Host.Node.x86.exe"), // Visual Studio
		_T("ServiceHub.VSDetouredHost.exe"), // Visual Studio
		_T("ServiceHub.IdentityHost.exe"), // Visual Studio
		_T("ServiceHub.SettingsHost.exe"), // Visual Studio
		_T("ServiceHub.Host.CLR.x86.exe"), // Visual Studio
		_T("x32dbg.exe"),			// x32dbg
		_T("x64dbg.exe"),			// x64dbg
		_T("HttpAnalyzerStdV7.exe")	// HttpAnalyzerStdV7
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
