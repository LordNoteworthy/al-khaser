#pragma once

BOOL NtQueryInformationProcess_ProcessDebugObject();

#define STATUS_PORT_NOT_SET ((NTSTATUS)0xC0000353L)
