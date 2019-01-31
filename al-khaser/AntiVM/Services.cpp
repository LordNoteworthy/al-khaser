#include "pch.h"

#include "Services.h"

BOOL VMDriverServices()
{
	const int KnownServiceCount = 13;
	const TCHAR* KnownVMServices[KnownServiceCount] = {
		L"VBoxWddm",
		L"VBoxSF", //VirtualBox Shared Folders
		L"VBoxMouse", //VirtualBox Guest Mouse
		L"VBoxGuest", //VirtualBox Guest Driver
		L"vmci", //VMWare VMCI Bus Driver
		L"vmhgfs", //VMWare Host Guest Control Redirector
		L"vmmouse",
		L"vmmemctl", //VMWare Guest Memory Controller Driver
		L"vmusb",
		L"vmusbmouse",
		L"vmx_svga",
		L"vmxnet",
		L"vmx86"
	};

	SC_HANDLE hSCM = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
	if (hSCM != NULL)
	{
		ENUM_SERVICE_STATUS_PROCESS* services = NULL;
		DWORD serviceCount = 0;
		if (get_services(hSCM, SERVICE_DRIVER, &services, &serviceCount))
		{
			bool ok = true;

			for (DWORD i = 0; i < serviceCount; i++)
			{
				for (int s = 0; s < KnownServiceCount; s++)
				{
					if (StrCmpIW(services[i].lpServiceName, KnownVMServices[s]) == 0)
					{
						ok = false;
						break;
					}
				}
			}

			free(services);

			if (ok)
			{
				CloseServiceHandle(hSCM);
				return FALSE;
			}
			
		}
		else
		{
			printf("Failed to get services list.\n");
		}
		CloseServiceHandle(hSCM);
	}
	else
	{
		printf("Failed to get SCM handle.\n");
	}

	return TRUE;
}

BOOL get_services(_In_ SC_HANDLE hServiceManager, _In_ DWORD serviceType, _Out_ ENUM_SERVICE_STATUS_PROCESS** servicesBuffer, _Out_ DWORD* serviceCount)
{
	DWORD serviceBufferSize = 1024 * sizeof(ENUM_SERVICE_STATUS_PROCESS);
	ENUM_SERVICE_STATUS_PROCESS* services = static_cast<ENUM_SERVICE_STATUS_PROCESS*>(malloc(serviceBufferSize));

	if (serviceCount) //assume failure
		*serviceCount = 0;

	if (services) {

		SecureZeroMemory(services, serviceBufferSize);

		DWORD remainderBufferSize = 0;
		DWORD resumeHandle = 0;
		if (EnumServicesStatusEx(hServiceManager, SC_ENUM_PROCESS_INFO, serviceType, SERVICE_STATE_ALL, (LPBYTE)services, serviceBufferSize, &remainderBufferSize, serviceCount, &resumeHandle, NULL) != 0)
		{
			// success and we enumerated all the services
			*servicesBuffer = services;
			return TRUE;
		}

		DWORD lastError = GetLastError();
		if (lastError == ERROR_MORE_DATA)
		{
			// we didn't get all the services, so we'll just re-enumerate all to make things easy
			serviceBufferSize += remainderBufferSize;

			ENUM_SERVICE_STATUS_PROCESS* tmp;

			tmp = static_cast<ENUM_SERVICE_STATUS_PROCESS*>(realloc(services, serviceBufferSize));
			if (tmp) {
				services = tmp;
				SecureZeroMemory(services, serviceBufferSize);
				if (EnumServicesStatusEx(hServiceManager, SC_ENUM_PROCESS_INFO, serviceType, SERVICE_STATE_ALL, (LPBYTE)services, serviceBufferSize, &remainderBufferSize, serviceCount, NULL, NULL) != 0)
				{
					*servicesBuffer = services;
					return TRUE;
				}
			}
		}
		else
		{
			printf("ERROR: %u\n", lastError);
		}
		
		free(services);

	}
	return FALSE;
}
