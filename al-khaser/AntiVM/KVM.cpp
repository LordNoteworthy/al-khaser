#include "pch.h"


/*
Check against kvm registry keys
*/
VOID kvm_reg_keys()
{
	/* Array of strings of blacklisted registry keys */
	const TCHAR* szKeys[] = {
		_T("SYSTEM\\ControlSet001\\Services\\vioscsi"),
		_T("SYSTEM\\ControlSet001\\Services\\viostor"),
		_T("SYSTEM\\ControlSet001\\Services\\VirtIO-FS Service"),
		_T("SYSTEM\\ControlSet001\\Services\\VirtioSerial"),
		_T("SYSTEM\\ControlSet001\\Services\\BALLOON"),
		_T("SYSTEM\\ControlSet001\\Services\\BalloonService"),
		_T("SYSTEM\\ControlSet001\\Services\\netkvm"),
	};

	WORD dwlength = sizeof(szKeys) / sizeof(szKeys[0]);

	/* Check one by one */
	for (int i = 0; i < dwlength; i++)
	{
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking reg key %s "), szKeys[i]);
		if (Is_RegKeyExists(HKEY_LOCAL_MACHINE, szKeys[i]))
			print_results(TRUE, msg);
		else
			print_results(FALSE, msg);
	}
}

/*
Check against kvm blacklisted files
*/
VOID kvm_files()
{
	/* Array of strings of blacklisted paths */
	const TCHAR* szPaths[] = {
		_T("System32\\drivers\\balloon.sys"), 
		_T("System32\\drivers\\netkvm.sys"),
		_T("System32\\drivers\\pvpanic.sys"),
		_T("System32\\drivers\\viofs.sys"),
		_T("System32\\drivers\\viogpudo.sys"),
		_T("System32\\drivers\\vioinput.sys"),
		_T("System32\\drivers\\viorng.sys"),
		_T("System32\\drivers\\vioscsi.sys"),
		_T("System32\\drivers\\vioser.sys"),
		_T("System32\\drivers\\viostor.sys"),
	
	};

	/* Getting Windows Directory */
	WORD dwlength = sizeof(szPaths) / sizeof(szPaths[0]);
	TCHAR szWinDir[MAX_PATH] = _T("");
	TCHAR szPath[MAX_PATH] = _T("");
	PVOID OldValue = NULL;

	GetWindowsDirectory(szWinDir, MAX_PATH);

	if (IsWoW64()) {
		Wow64DisableWow64FsRedirection(&OldValue);
	}

	/* Check one by one */
	for (int i = 0; i < dwlength; i++)
	{
		PathCombine(szPath, szWinDir, szPaths[i]);
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking file %s "), szPath);
		if (is_FileExists(szPath))
			print_results(TRUE, msg);
		else
			print_results(FALSE, msg);
	}

	if (IsWoW64()) {
		Wow64RevertWow64FsRedirection(&OldValue);
	}
}

/*
Check against kvm blacklisted directories
*/
BOOL kvm_dir()
{
	TCHAR szProgramFile[MAX_PATH];
	TCHAR szPath[MAX_PATH] = _T("");
	TCHAR szTarget[MAX_PATH] = _T("Virtio-Win\\");

	if (IsWoW64())
		ExpandEnvironmentStrings(_T("%ProgramW6432%"), szProgramFile, ARRAYSIZE(szProgramFile));
	else
		SHGetSpecialFolderPath(NULL, szProgramFile, CSIDL_PROGRAM_FILES, FALSE);

	PathCombine(szPath, szProgramFile, szTarget);
	return is_DirectoryExists(szPath);
}