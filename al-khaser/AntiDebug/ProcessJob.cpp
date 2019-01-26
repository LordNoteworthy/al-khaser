#include "pch.h"

#include "ProcessJob.h"

/*
 * ProcessJob  -  Contributed by Graham Sutherland (https://github.com/gsuberland)
 * 
 * Checks whether the process is part of a job object and, if so, any non-whitelisted processes are part of that job.
 * 
 * Debuggers and other analysis applications usually place processes inside a job so that child processes will exit
 * when the parent process exits.
 * You can observe this with Visual Studio by running al-khaser with Debug -> Start Without Debugging.
 *
 */

BOOL ProcessJob()
{
	BOOL foundProblem = FALSE;

	DWORD jobProcessStructSize = sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + sizeof(ULONG_PTR) * 1024;
	JOBOBJECT_BASIC_PROCESS_ID_LIST* jobProcessIdList = static_cast<JOBOBJECT_BASIC_PROCESS_ID_LIST*>(malloc(jobProcessStructSize));

	if (jobProcessIdList) {

		SecureZeroMemory(jobProcessIdList, jobProcessStructSize);

		jobProcessIdList->NumberOfProcessIdsInList = 1024;

		if (QueryInformationJobObject(NULL, JobObjectBasicProcessIdList, jobProcessIdList, jobProcessStructSize, NULL))
		{
			int ok_processes = 0;
			for (DWORD i = 0; i < jobProcessIdList->NumberOfAssignedProcesses; i++)
			{
				ULONG_PTR processId = jobProcessIdList->ProcessIdList[i];

				// is this the current process? if so that's ok
				if (processId == (ULONG_PTR)GetCurrentProcessId())
				{
					ok_processes++;
				}
				else
				{

					// find the process name for this job process
					HANDLE hJobProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)processId);
					if (hJobProcess != NULL)
					{
						const int processNameBufferSize = 4096;
						LPTSTR processName = static_cast<LPTSTR>(malloc(sizeof(TCHAR) * processNameBufferSize));
						if (processName) {
							SecureZeroMemory(processName, sizeof(TCHAR) * processNameBufferSize);

							if (GetProcessImageFileName(hJobProcess, processName, processNameBufferSize) > 0)
							{
								String pnStr(processName);

								// ignore conhost.exe (this hosts the al-khaser executable in a console)
								if (pnStr.find(String(L"\\Windows\\System32\\conhost.exe")) != std::string::npos)
								{
									ok_processes++;
								}
							}

							free(processName);
						}
						CloseHandle(hJobProcess);
					}
				}
			}

			// if we found other processes in the job other than the current process and conhost, report a problem
			foundProblem = ok_processes != jobProcessIdList->NumberOfAssignedProcesses;
		}

		free(jobProcessIdList);
	}
	return foundProblem;
}
