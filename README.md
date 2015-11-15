al-khaser is a PoC malware with good intentions that aimes to stress your anti-malware system.
It performs a bunch of nowadays malwares tricks and the goal is to see if you catch them all.

# Possible uses :
- You are making an anti-debug plugin and you want to check its effectiveness.
- You want to ensure that your sandbox solution is hidden enough.
- Or you want to ensure that your malware analysis environement is well hidden.


Please, if you encounter any of the anti-analysis tricks which you have seen in a malware, don't hesitate to contribute.

# Anti-debugging attacks
- IsDebuggerPresent
- Process Environement Block (BeingDebugged)
- Process Environement Block (NtGlobalFlag)
- ProcessHeap (Flags)
- ProcessHeap (ForceFlags)
- NtQueryInformationProcess (ProcessDebugPort)
- NtQueryInformationProcess (ProcessDebugFlags)
- NtQueryInformationProcess (ProcessDebugObject)
- CloseHanlde (NtClose) Invalide Handle
- UnhandledExceptionFilter
- OutputDebugString (GetLastError())
- NtSetInformationThread (HideThreadFromDebugger)


