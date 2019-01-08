#include "pch.h"
#include "WUDF_IsDebuggerPresent.h"

BOOL WUDF_IsAnyDebuggerPresent()
{
	if (API::IsAvailable(API_IDENTIFIER::API_WudfIsAnyDebuggerPresent))
	{
		auto WudfIsAnyDebuggerPresent = static_cast<pWudfIsAnyDebuggerPresent>(API::GetAPI(API_IDENTIFIER::API_WudfIsAnyDebuggerPresent));
		return WudfIsAnyDebuggerPresent() == 0 ? FALSE : TRUE;
	}
	else
		return FALSE;
}

BOOL WUDF_IsKernelDebuggerPresent()
{
	if (API::IsAvailable(API_IDENTIFIER::API_WudfIsKernelDebuggerPresent))
	{
		auto WudfIsKernelDebuggerPresent = static_cast<pWudfIsKernelDebuggerPresent>(API::GetAPI(API_IDENTIFIER::API_WudfIsKernelDebuggerPresent));
		return WudfIsKernelDebuggerPresent() == 0 ? FALSE : TRUE;
	}
	else
		return FALSE;
}

BOOL WUDF_IsUserDebuggerPresent()
{
	if (API::IsAvailable(API_IDENTIFIER::API_WudfIsUserDebuggerPresent))
	{
		auto WudfIsUserDebuggerPresent = static_cast<pWudfIsKernelDebuggerPresent>(API::GetAPI(API_IDENTIFIER::API_WudfIsUserDebuggerPresent));
		return WudfIsUserDebuggerPresent() == 0 ? FALSE : TRUE;
	}
	else
		return FALSE;
}
