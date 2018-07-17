#pragma once

static volatile HANDLE tls_callback_thread_event;
static volatile HANDLE tls_callback_process_event;
static volatile UINT32 tls_callback_thread_data;
static volatile UINT32 tls_callback_process_data;

VOID WINAPI tls_callback(PVOID hModule, DWORD dwReason, PVOID pContext);
BOOL TLSCallbackThread();
BOOL TLSCallbackProcess();
