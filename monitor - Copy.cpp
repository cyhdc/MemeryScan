#include "monitor.h"

// 全局静态实例，用于在静态回调函数中访问成员变量
static AdvancedBehaviorMonitor* g_monitorInstance = nullptr;

// 获取调用进程的PID
static DWORD GetCallingProcessId() {
    return GetCurrentProcessId();
}

// 通用的内联钩子安装函数
bool AdvancedBehaviorMonitor::HookSyscall(LPCSTR name, PVOID originalFunc, PVOID hookFunc) {
    if (originalFunc == nullptr || hookFunc == nullptr) {
        return false;
    }

    int tableIndex = -1;
    for (int i = 0; i < m_syscallTableCount; ++i) {
        if (strcmp(m_syscallTable[i].Name, name) == 0) {
            tableIndex = i;
            break;
        }
    }
    if (tableIndex == -1) {
        std::cerr << "[-] HookSyscall: Syscall entry not found for " << name << std::endl;
        return false;
    }

    PVOID pTrampoline = VirtualAlloc(NULL, JMP_SIZE * 2, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pTrampoline == nullptr) {
        std::cerr << "[-] Failed to allocate memory for trampoline for " << name << "." << std::endl;
        return false;
    }

    memcpy(pTrampoline, originalFunc, JMP_SIZE);
    *(BYTE*)((char*)pTrampoline + JMP_SIZE) = 0xE9;
    DWORD_PTR jmpOffset = (DWORD_PTR)originalFunc - (DWORD_PTR)pTrampoline - JMP_SIZE;
    *(DWORD*)((char*)pTrampoline + JMP_SIZE + 1) = (DWORD)(jmpOffset);
    m_syscallTable[tableIndex].Trampoline = pTrampoline;

    DWORD oldProtect;
    if (!VirtualProtect(originalFunc, JMP_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << "[-] Failed to change memory protection for hooking " << name << "." << std::endl;
        VirtualFree(pTrampoline, 0, MEM_RELEASE);
        return false;
    }
    memcpy(m_syscallTable[tableIndex].OriginalBytes, originalFunc, JMP_SIZE);

    *(BYTE*)originalFunc = 0xE9;
    DWORD_PTR detourOffset = (DWORD_PTR)hookFunc - (DWORD_PTR)originalFunc - JMP_SIZE;
    *(DWORD*)((char*)originalFunc + 1) = (DWORD)(detourOffset);

    VirtualProtect(originalFunc, JMP_SIZE, oldProtect, &oldProtect);

    std::cout << "[+] Hook for " << name << " installed." << std::endl;
    return true;
}

// 钩取函数实现
NTSTATUS NTAPI AdvancedBehaviorMonitor::HookedNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {
    PFN_NtCreateFile originalFunc = nullptr;
    for (int i = 0; i < g_monitorInstance->m_syscallTableCount; ++i) {
        if (strcmp(g_monitorInstance->m_syscallTable[i].Name, "NtCreateFile") == 0) {
            originalFunc = (PFN_NtCreateFile)g_monitorInstance->m_syscallTable[i].Trampoline;
            break;
        }
    }
    if (!originalFunc) return STATUS_UNSUCCESSFUL;
    if (g_monitorInstance->IsTargetProcessOrChild(GetCallingProcessId())) {
        std::string filePath = "Unknown Path";
        if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            filePath = converter.to_bytes(ObjectAttributes->ObjectName->Buffer);
        }
        g_monitorInstance->LogEvent("HOOK_CREATE_FILE", "Path: " + filePath, GetCallingProcessId());
    }
    return originalFunc(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

NTSTATUS NTAPI AdvancedBehaviorMonitor::HookedNtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {
    PFN_NtOpenFile originalFunc = nullptr;
    for (int i = 0; i < g_monitorInstance->m_syscallTableCount; ++i) {
        if (strcmp(g_monitorInstance->m_syscallTable[i].Name, "NtOpenFile") == 0) {
            originalFunc = (PFN_NtOpenFile)g_monitorInstance->m_syscallTable[i].Trampoline;
            break;
        }
    }
    if (!originalFunc) return STATUS_UNSUCCESSFUL;
    if (g_monitorInstance->IsTargetProcessOrChild(GetCallingProcessId())) {
        std::string filePath = "Unknown Path";
        if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            filePath = converter.to_bytes(ObjectAttributes->ObjectName->Buffer);
        }
        g_monitorInstance->LogEvent("HOOK_OPEN_FILE", "Path: " + filePath, GetCallingProcessId());
    }
    return originalFunc(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

NTSTATUS NTAPI AdvancedBehaviorMonitor::HookedNtReadFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    PFN_NtReadFile originalFunc = nullptr;
    for (int i = 0; i < g_monitorInstance->m_syscallTableCount; ++i) {
        if (strcmp(g_monitorInstance->m_syscallTable[i].Name, "NtReadFile") == 0) {
            originalFunc = (PFN_NtReadFile)g_monitorInstance->m_syscallTable[i].Trampoline;
            break;
        }
    }
    if (!originalFunc) return STATUS_UNSUCCESSFUL;
    if (g_monitorInstance->IsTargetProcessOrChild(GetCallingProcessId())) {
        g_monitorInstance->LogEvent("HOOK_READ_FILE", "Handle: " + g_monitorInstance->GetObjectName(FileHandle) + ", Length: " + std::to_string(Length), GetCallingProcessId());
    }
    return originalFunc(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

NTSTATUS NTAPI AdvancedBehaviorMonitor::HookedNtWriteFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    PFN_NtWriteFile originalFunc = nullptr;
    for (int i = 0; i < g_monitorInstance->m_syscallTableCount; ++i) {
        if (strcmp(g_monitorInstance->m_syscallTable[i].Name, "NtWriteFile") == 0) {
            originalFunc = (PFN_NtWriteFile)g_monitorInstance->m_syscallTable[i].Trampoline;
            break;
        }
    }
    if (!originalFunc) return STATUS_UNSUCCESSFUL;
    if (g_monitorInstance->IsTargetProcessOrChild(GetCallingProcessId())) {
        g_monitorInstance->LogEvent("HOOK_WRITE_FILE", "Handle: " + g_monitorInstance->GetObjectName(FileHandle) + ", Length: " + std::to_string(Length), GetCallingProcessId());
    }
    return originalFunc(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

NTSTATUS NTAPI AdvancedBehaviorMonitor::HookedNtCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition) {
    PFN_NtCreateKey originalFunc = nullptr;
    for (int i = 0; i < g_monitorInstance->m_syscallTableCount; ++i) {
        if (strcmp(g_monitorInstance->m_syscallTable[i].Name, "NtCreateKey") == 0) {
            originalFunc = (PFN_NtCreateKey)g_monitorInstance->m_syscallTable[i].Trampoline;
            break;
        }
    }
    if (!originalFunc) return STATUS_UNSUCCESSFUL;
    if (g_monitorInstance->IsTargetProcessOrChild(GetCallingProcessId())) {
        std::string keyPath = "Unknown Path";
        if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            keyPath = converter.to_bytes(ObjectAttributes->ObjectName->Buffer);
        }
        g_monitorInstance->LogEvent("HOOK_CREATE_KEY", "Path: " + keyPath, GetCallingProcessId());
    }
    return originalFunc(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
}

NTSTATUS NTAPI AdvancedBehaviorMonitor::HookedNtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    PFN_NtOpenKey originalFunc = nullptr;
    for (int i = 0; i < g_monitorInstance->m_syscallTableCount; ++i) {
        if (strcmp(g_monitorInstance->m_syscallTable[i].Name, "NtOpenKey") == 0) {
            originalFunc = (PFN_NtOpenKey)g_monitorInstance->m_syscallTable[i].Trampoline;
            break;
        }
    }
    if (!originalFunc) return STATUS_UNSUCCESSFUL;
    if (g_monitorInstance->IsTargetProcessOrChild(GetCallingProcessId())) {
        std::string keyPath = "Unknown Path";
        if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            keyPath = converter.to_bytes(ObjectAttributes->ObjectName->Buffer);
        }
        g_monitorInstance->LogEvent("HOOK_OPEN_KEY", "Path: " + keyPath, GetCallingProcessId());
    }
    return originalFunc(KeyHandle, DesiredAccess, ObjectAttributes);
}

NTSTATUS NTAPI AdvancedBehaviorMonitor::HookedNtDeleteKey(HANDLE KeyHandle) {
    PFN_NtDeleteKey originalFunc = nullptr;
    for (int i = 0; i < g_monitorInstance->m_syscallTableCount; ++i) {
        if (strcmp(g_monitorInstance->m_syscallTable[i].Name, "NtDeleteKey") == 0) {
            originalFunc = (PFN_NtDeleteKey)g_monitorInstance->m_syscallTable[i].Trampoline;
            break;
        }
    }
    if (!originalFunc) return STATUS_UNSUCCESSFUL;
    if (g_monitorInstance->IsTargetProcessOrChild(GetCallingProcessId())) {
        g_monitorInstance->LogEvent("HOOK_DELETE_KEY", "Handle: " + g_monitorInstance->GetObjectName(KeyHandle), GetCallingProcessId());
    }
    return originalFunc(KeyHandle);
}

NTSTATUS NTAPI AdvancedBehaviorMonitor::HookedNtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize) {
    PFN_NtSetValueKey originalFunc = nullptr;
    for (int i = 0; i < g_monitorInstance->m_syscallTableCount; ++i) {
        if (strcmp(g_monitorInstance->m_syscallTable[i].Name, "NtSetValueKey") == 0) {
            originalFunc = (PFN_NtSetValueKey)g_monitorInstance->m_syscallTable[i].Trampoline;
            break;
        }
    }
    if (!originalFunc) return STATUS_UNSUCCESSFUL;
    if (g_monitorInstance->IsTargetProcessOrChild(GetCallingProcessId())) {
        std::string valueName = "Unknown Name";
        if (ValueName && ValueName->Buffer) {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            valueName = converter.to_bytes(ValueName->Buffer);
        }
        g_monitorInstance->LogEvent("HOOK_SET_VALUE_KEY", "Handle: " + g_monitorInstance->GetObjectName(KeyHandle) + ", Value: " + valueName, GetCallingProcessId());
    }
    return originalFunc(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
}

NTSTATUS NTAPI AdvancedBehaviorMonitor::HookedNtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    PFN_NtQueryValueKey originalFunc = nullptr;
    for (int i = 0; i < g_monitorInstance->m_syscallTableCount; ++i) {
        if (strcmp(g_monitorInstance->m_syscallTable[i].Name, "NtQueryValueKey") == 0) {
            originalFunc = (PFN_NtQueryValueKey)g_monitorInstance->m_syscallTable[i].Trampoline;
            break;
        }
    }
    if (!originalFunc) return STATUS_UNSUCCESSFUL;
    if (g_monitorInstance->IsTargetProcessOrChild(GetCallingProcessId())) {
        std::string valueName = "Unknown Name";
        if (ValueName && ValueName->Buffer) {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            valueName = converter.to_bytes(ValueName->Buffer);
        }
        g_monitorInstance->LogEvent("HOOK_QUERY_VALUE_KEY", "Handle: " + g_monitorInstance->GetObjectName(KeyHandle) + ", Value: " + valueName, GetCallingProcessId());
    }
    return originalFunc(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
}

NTSTATUS NTAPI AdvancedBehaviorMonitor::HookedNtCreateProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, BOOLEAN InheritObjectTable, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort) {
    PFN_NtCreateProcess originalFunc = nullptr;
    for (int i = 0; i < g_monitorInstance->m_syscallTableCount; ++i) {
        if (strcmp(g_monitorInstance->m_syscallTable[i].Name, "NtCreateProcess") == 0) {
            originalFunc = (PFN_NtCreateProcess)g_monitorInstance->m_syscallTable[i].Trampoline;
            break;
        }
    }
    if (!originalFunc) return STATUS_UNSUCCESSFUL;
    if (g_monitorInstance->IsTargetProcessOrChild(GetCallingProcessId())) {
        std::string procPath = "Unknown Path";
        if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            procPath = converter.to_bytes(ObjectAttributes->ObjectName->Buffer);
        }
        g_monitorInstance->LogEvent("HOOK_CREATE_PROCESS", "Path: " + procPath, GetCallingProcessId());
    }
    return originalFunc(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort);
}

NTSTATUS NTAPI AdvancedBehaviorMonitor::HookedNtCreateProcessEx(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, BOOLEAN InJob) {
    PFN_NtCreateProcessEx originalFunc = nullptr;
    for (int i = 0; i < g_monitorInstance->m_syscallTableCount; ++i) {
        if (strcmp(g_monitorInstance->m_syscallTable[i].Name, "NtCreateProcessEx") == 0) {
            originalFunc = (PFN_NtCreateProcessEx)g_monitorInstance->m_syscallTable[i].Trampoline;
            break;
        }
    }
    if (!originalFunc) return STATUS_UNSUCCESSFUL;
    if (g_monitorInstance->IsTargetProcessOrChild(GetCallingProcessId())) {
        std::string procPath = "Unknown Path";
        if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            procPath = converter.to_bytes(ObjectAttributes->ObjectName->Buffer);
        }
        g_monitorInstance->LogEvent("HOOK_CREATE_PROCESS_EX", "Path: " + procPath, GetCallingProcessId());
    }
    return originalFunc(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort, InJob);
}

NTSTATUS NTAPI AdvancedBehaviorMonitor::HookedNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    PFN_NtOpenProcess originalFunc = nullptr;
    for (int i = 0; i < g_monitorInstance->m_syscallTableCount; ++i) {
        if (strcmp(g_monitorInstance->m_syscallTable[i].Name, "NtOpenProcess") == 0) {
            originalFunc = (PFN_NtOpenProcess)g_monitorInstance->m_syscallTable[i].Trampoline;
            break;
        }
    }
    if (!originalFunc) return STATUS_UNSUCCESSFUL;
    if (g_monitorInstance->IsTargetProcessOrChild(GetCallingProcessId())) {
        g_monitorInstance->LogEvent("HOOK_OPEN_PROCESS", "PID: " + std::to_string((DWORD)(ULONG_PTR)ClientId->UniqueProcess), GetCallingProcessId());
    }
    return originalFunc(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS NTAPI AdvancedBehaviorMonitor::HookedNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus) {
    PFN_NtTerminateProcess originalFunc = nullptr;
    for (int i = 0; i < g_monitorInstance->m_syscallTableCount; ++i) {
        if (strcmp(g_monitorInstance->m_syscallTable[i].Name, "NtTerminateProcess") == 0) {
            originalFunc = (PFN_NtTerminateProcess)g_monitorInstance->m_syscallTable[i].Trampoline;
            break;
        }
    }
    if (!originalFunc) return STATUS_UNSUCCESSFUL;
    if (g_monitorInstance->IsTargetProcessOrChild(GetCallingProcessId())) {
        g_monitorInstance->LogEvent("HOOK_TERMINATE_PROCESS", "Handle: " + g_monitorInstance->GetObjectName(ProcessHandle), GetCallingProcessId());
    }
    return originalFunc(ProcessHandle, ExitStatus);
}

NTSTATUS NTAPI AdvancedBehaviorMonitor::HookedNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList) {
    PFN_NtCreateThreadEx originalFunc = nullptr;
    for (int i = 0; i < g_monitorInstance->m_syscallTableCount; ++i) {
        if (strcmp(g_monitorInstance->m_syscallTable[i].Name, "NtCreateThreadEx") == 0) {
            originalFunc = (PFN_NtCreateThreadEx)g_monitorInstance->m_syscallTable[i].Trampoline;
            break;
        }
    }
    if (!originalFunc) return STATUS_UNSUCCESSFUL;
    if (g_monitorInstance->IsTargetProcessOrChild(GetCallingProcessId())) {
        g_monitorInstance->LogEvent("HOOK_CREATE_THREAD_EX", "StartRoutine: " + std::to_string((ULONG_PTR)StartRoutine) + ", ProcessHandle: " + g_monitorInstance->GetObjectName(ProcessHandle), GetCallingProcessId());
    }
    return originalFunc(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

NTSTATUS NTAPI AdvancedBehaviorMonitor::HookedNtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    PFN_NtOpenThread originalFunc = nullptr;
    for (int i = 0; i < g_monitorInstance->m_syscallTableCount; ++i) {
        if (strcmp(g_monitorInstance->m_syscallTable[i].Name, "NtOpenThread") == 0) {
            originalFunc = (PFN_NtOpenThread)g_monitorInstance->m_syscallTable[i].Trampoline;
            break;
        }
    }
    if (!originalFunc) return STATUS_UNSUCCESSFUL;
    if (g_monitorInstance->IsTargetProcessOrChild(GetCallingProcessId())) {
        g_monitorInstance->LogEvent("HOOK_OPEN_THREAD", "Thread PID: " + std::to_string((DWORD)(ULONG_PTR)ClientId->UniqueThread), GetCallingProcessId());
    }
    return originalFunc(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS NTAPI AdvancedBehaviorMonitor::HookedNtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus) {
    PFN_NtTerminateThread originalFunc = nullptr;
    for (int i = 0; i < g_monitorInstance->m_syscallTableCount; ++i) {
        if (strcmp(g_monitorInstance->m_syscallTable[i].Name, "NtTerminateThread") == 0) {
            originalFunc = (PFN_NtTerminateThread)g_monitorInstance->m_syscallTable[i].Trampoline;
            break;
        }
    }
    if (!originalFunc) return STATUS_UNSUCCESSFUL;
    if (g_monitorInstance->IsTargetProcessOrChild(GetCallingProcessId())) {
        g_monitorInstance->LogEvent("HOOK_TERMINATE_THREAD", "Handle: " + g_monitorInstance->GetObjectName(ThreadHandle), GetCallingProcessId());
    }
    return originalFunc(ThreadHandle, ExitStatus);
}

NTSTATUS NTAPI AdvancedBehaviorMonitor::HookedNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    PFN_NtAllocateVirtualMemory originalFunc = nullptr;
    for (int i = 0; i < g_monitorInstance->m_syscallTableCount; ++i) {
        if (strcmp(g_monitorInstance->m_syscallTable[i].Name, "NtAllocateVirtualMemory") == 0) {
            originalFunc = (PFN_NtAllocateVirtualMemory)g_monitorInstance->m_syscallTable[i].Trampoline;
            break;
        }
    }
    if (!originalFunc) return STATUS_UNSUCCESSFUL;
    if (g_monitorInstance->IsTargetProcessOrChild(GetCallingProcessId())) {
        g_monitorInstance->LogEvent("HOOK_ALLOCATE_VIRTUAL_MEMORY", "Size: " + std::to_string(*RegionSize), GetCallingProcessId());
    }
    return originalFunc(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS NTAPI AdvancedBehaviorMonitor::HookedNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {
    PFN_NtProtectVirtualMemory originalFunc = nullptr;
    for (int i = 0; i < g_monitorInstance->m_syscallTableCount; ++i) {
        if (strcmp(g_monitorInstance->m_syscallTable[i].Name, "NtProtectVirtualMemory") == 0) {
            originalFunc = (PFN_NtProtectVirtualMemory)g_monitorInstance->m_syscallTable[i].Trampoline;
            break;
        }
    }
    if (!originalFunc) return STATUS_UNSUCCESSFUL;
    if (g_monitorInstance->IsTargetProcessOrChild(GetCallingProcessId())) {
        g_monitorInstance->LogEvent("HOOK_PROTECT_VIRTUAL_MEMORY", "BaseAddress: " + std::to_string((ULONG_PTR)*BaseAddress) + ", NewProtect: " + std::to_string(NewProtect), GetCallingProcessId());
    }
    return originalFunc(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

NTSTATUS NTAPI AdvancedBehaviorMonitor::HookedNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength) {
    PFN_NtDeviceIoControlFile originalFunc = nullptr;
    for (int i = 0; i < g_monitorInstance->m_syscallTableCount; ++i) {
        if (strcmp(g_monitorInstance->m_syscallTable[i].Name, "NtDeviceIoControlFile") == 0) {
            originalFunc = (PFN_NtDeviceIoControlFile)g_monitorInstance->m_syscallTable[i].Trampoline;
            break;
        }
    }
    if (!originalFunc) return STATUS_UNSUCCESSFUL;
    if (g_monitorInstance->IsTargetProcessOrChild(GetCallingProcessId())) {
        std::string objectName = g_monitorInstance->GetObjectName(FileHandle);
        if (objectName.find("\\Device\\Tcp") != std::string::npos ||
            objectName.find("\\Device\\Udp") != std::string::npos) {
            std::ostringstream ss;
            ss << "Handle: 0x" << std::hex << (ULONG_PTR)FileHandle << ", ControlCode: 0x" << IoControlCode;
            g_monitorInstance->LogEvent("HOOK_NETWORK_IOCTL", ss.str(), GetCallingProcessId());
        }
    }
    return originalFunc(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
}

AdvancedBehaviorMonitor::AdvancedBehaviorMonitor()
    : m_traceHandle(0), m_traceProperties(nullptr), m_engineHandle(nullptr), m_targetProcess(INVALID_HANDLE_VALUE),
    m_targetPid(0), m_monitorDuration(60), m_enableETW(true), m_enableNetworkFilter(true), m_enableHooking(true),
    m_isMonitoring(false), m_syscallTableCount(0) {
    g_monitorInstance = this;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        std::cerr << "[-] Failed to get handle for ntdll.dll" << std::endl;
        return;
    }

    // 初始化系统调用表
    m_syscallTable[m_syscallTableCount++] = { "NtCreateFile", (PVOID)GetProcAddress(hNtdll, "NtCreateFile"), (PVOID)&HookedNtCreateFile, FALSE };
    m_syscallTable[m_syscallTableCount++] = { "NtOpenFile", (PVOID)GetProcAddress(hNtdll, "NtOpenFile"), (PVOID)&HookedNtOpenFile, FALSE };
    m_syscallTable[m_syscallTableCount++] = { "NtReadFile", (PVOID)GetProcAddress(hNtdll, "NtReadFile"), (PVOID)&HookedNtReadFile, FALSE };
    m_syscallTable[m_syscallTableCount++] = { "NtWriteFile", (PVOID)GetProcAddress(hNtdll, "NtWriteFile"), (PVOID)&HookedNtWriteFile, FALSE };
    m_syscallTable[m_syscallTableCount++] = { "NtCreateKey", (PVOID)GetProcAddress(hNtdll, "NtCreateKey"), (PVOID)&HookedNtCreateKey, FALSE };
    m_syscallTable[m_syscallTableCount++] = { "NtOpenKey", (PVOID)GetProcAddress(hNtdll, "NtOpenKey"), (PVOID)&HookedNtOpenKey, FALSE };
    m_syscallTable[m_syscallTableCount++] = { "NtDeleteKey", (PVOID)GetProcAddress(hNtdll, "NtDeleteKey"), (PVOID)&HookedNtDeleteKey, FALSE };
    m_syscallTable[m_syscallTableCount++] = { "NtSetValueKey", (PVOID)GetProcAddress(hNtdll, "NtSetValueKey"), (PVOID)&HookedNtSetValueKey, FALSE };
    m_syscallTable[m_syscallTableCount++] = { "NtQueryValueKey", (PVOID)GetProcAddress(hNtdll, "NtQueryValueKey"), (PVOID)&HookedNtQueryValueKey, FALSE };
    m_syscallTable[m_syscallTableCount++] = { "NtCreateProcess", (PVOID)GetProcAddress(hNtdll, "NtCreateProcess"), (PVOID)&HookedNtCreateProcess, FALSE };
    m_syscallTable[m_syscallTableCount++] = { "NtCreateProcessEx", (PVOID)GetProcAddress(hNtdll, "NtCreateProcessEx"), (PVOID)&HookedNtCreateProcessEx, FALSE };
    m_syscallTable[m_syscallTableCount++] = { "NtOpenProcess", (PVOID)GetProcAddress(hNtdll, "NtOpenProcess"), (PVOID)&HookedNtOpenProcess, FALSE };
    m_syscallTable[m_syscallTableCount++] = { "NtTerminateProcess", (PVOID)GetProcAddress(hNtdll, "NtTerminateProcess"), (PVOID)&HookedNtTerminateProcess, FALSE };
    m_syscallTable[m_syscallTableCount++] = { "NtCreateThreadEx", (PVOID)GetProcAddress(hNtdll, "NtCreateThreadEx"), (PVOID)&HookedNtCreateThreadEx, FALSE };
    m_syscallTable[m_syscallTableCount++] = { "NtOpenThread", (PVOID)GetProcAddress(hNtdll, "NtOpenThread"), (PVOID)&HookedNtOpenThread, FALSE };
    m_syscallTable[m_syscallTableCount++] = { "NtTerminateThread", (PVOID)GetProcAddress(hNtdll, "NtTerminateThread"), (PVOID)&HookedNtTerminateThread, FALSE };
    m_syscallTable[m_syscallTableCount++] = { "NtAllocateVirtualMemory", (PVOID)GetProcAddress(hNtdll, "NtAllocateVirtualMemory"), (PVOID)&HookedNtAllocateVirtualMemory, FALSE };
    m_syscallTable[m_syscallTableCount++] = { "NtProtectVirtualMemory", (PVOID)GetProcAddress(hNtdll, "NtProtectVirtualMemory"), (PVOID)&HookedNtProtectVirtualMemory, FALSE };
    m_syscallTable[m_syscallTableCount++] = { "NtDeviceIoControlFile", (PVOID)GetProcAddress(hNtdll, "NtDeviceIoControlFile"), (PVOID)&HookedNtDeviceIoControlFile, FALSE };
}

AdvancedBehaviorMonitor::~AdvancedBehaviorMonitor() {
    StopMonitoring();
    g_monitorInstance = nullptr;
}

bool AdvancedBehaviorMonitor::StartMonitoring(const std::string& targetProcess, const std::string& arguments) {
    if (m_isMonitoring) {
        std::cerr << "[-] Monitoring is already in progress." << std::endl;
        return false;
    }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    std::string commandLine = "\"" + targetProcess + "\" " + arguments;
    std::vector<char> cmdLineBuf(commandLine.begin(), commandLine.end());
    cmdLineBuf.push_back('\0');

    if (!CreateProcessA(targetProcess.c_str(), cmdLineBuf.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        std::cerr << "[-] Failed to start process: " << GetLastError() << std::endl;
        return false;
    }

    m_targetProcess = pi.hProcess;
    m_targetPid = pi.dwProcessId;
    m_targetName = PathFindFileNameA(targetProcess.c_str());
    m_targetPath = targetProcess;
    m_isMonitoring = true;

    m_events.clear();
    m_childProcesses.clear();
    m_childProcesses.insert(m_targetPid);

    if (m_enableHooking) {
        InstallSyscallHooks(); // Note: We no longer check the return value and exit.
    }

    if (m_enableETW) {
        if (!StartETWTracing()) {
            std::cerr << "[-] ETW tracing setup failed" << std::endl;
        }
    }
    if (m_enableNetworkFilter) {
        if (!SetupNetworkFilter()) {
            std::cerr << "[-] Network filter setup failed" << std::endl;
        }
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    std::thread monitorThread(&AdvancedBehaviorMonitor::MonitoringMain, this);
    monitorThread.detach();

    return true;
}

void AdvancedBehaviorMonitor::StopMonitoring() {
    if (!m_isMonitoring) return;
    m_isMonitoring = false;

    if (m_enableHooking) {
        RemoveSyscallHooks();
    }
    if (m_etwThread.joinable()) {
        StopETWTracing();
        m_etwThread.join();
    }
    CleanupNetworkFilter();
    TerminateAllMonitoredProcesses();

    if (m_traceProperties) {
        free(m_traceProperties);
        m_traceProperties = nullptr;
    }
    if (m_targetProcess != INVALID_HANDLE_VALUE) {
        CloseHandle(m_targetProcess);
        m_targetProcess = INVALID_HANDLE_VALUE;
    }
}

bool AdvancedBehaviorMonitor::InstallSyscallHooks() {
    bool success = true;
    for (int i = 0; i < m_syscallTableCount; ++i) {
        if (m_syscallTable[i].OriginalFunction == nullptr) {
            std::cerr << "[-] Warning: Failed to find address for " << m_syscallTable[i].Name << ". Skipping hook." << std::endl;
            success = false;
            continue;
        }
        if (!HookSyscall(m_syscallTable[i].Name, m_syscallTable[i].OriginalFunction, m_syscallTable[i].HookFunction)) {
            std::cerr << "[-] Warning: Failed to install hook for " << m_syscallTable[i].Name << ". Skipping." << std::endl;
            success = false;
        }
        else {
            m_syscallTable[i].Hooked = TRUE;
        }
    }
    return success;
}

bool AdvancedBehaviorMonitor::RemoveSyscallHooks() {
    for (int i = 0; i < m_syscallTableCount; ++i) {
        if (m_syscallTable[i].Hooked) {
            PVOID pTarget = m_syscallTable[i].OriginalFunction;
            DWORD oldProtect;
            if (VirtualProtect(pTarget, JMP_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                memcpy(pTarget, m_syscallTable[i].OriginalBytes, JMP_SIZE);
                VirtualProtect(pTarget, JMP_SIZE, oldProtect, &oldProtect);
                VirtualFree(m_syscallTable[i].Trampoline, 0, MEM_RELEASE);
            }
            m_syscallTable[i].Hooked = FALSE;
            m_syscallTable[i].Trampoline = nullptr;
        }
    }
    return true;
}

// ETW 函数实现
bool AdvancedBehaviorMonitor::StartETWTracing() {
    m_traceProperties = (EVENT_TRACE_PROPERTIES*)calloc(sizeof(EVENT_TRACE_PROPERTIES) + MAX_PATH, 1);
    if (m_traceProperties == nullptr) {
        return false;
    }
    m_traceProperties->Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + MAX_PATH;
    m_traceProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    m_traceProperties->Wnode.ClientContext = 1;
    m_traceProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    m_traceProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    m_traceHandle = 0;

    ULONG status = StartTraceW(&m_traceHandle, KERNEL_LOGGER_NAME, m_traceProperties);
    if (status != ERROR_SUCCESS) {
        return false;
    }

    status = EnableTraceEx(
        &FileIoProviderGuid,
        NULL,
        m_traceHandle,
        1,
        0,
        0,
        0,
        0,
        NULL
    );
    if (status != ERROR_SUCCESS) {
        return false;
    }

    m_etwThread = std::thread(&AdvancedBehaviorMonitor::ETWThread, this);
    return true;
}

void AdvancedBehaviorMonitor::StopETWTracing() {
    if (m_traceHandle != 0) {
        StopTraceW(m_traceHandle, KERNEL_LOGGER_NAME, m_traceProperties);
    }
}

DWORD WINAPI AdvancedBehaviorMonitor::ETWThread(LPVOID lpParam) {
    g_monitorInstance->ProcessETWEvents();
    return 0;
}

void AdvancedBehaviorMonitor::ProcessETWEvents() {
    EVENT_TRACE_LOGFILEW logFile;
    ZeroMemory(&logFile, sizeof(logFile));
    logFile.LoggerName = (LPWSTR)KERNEL_LOGGER_NAME;
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    logFile.EventRecordCallback = ETWEventCallback;
    logFile.Context = this;

    TRACEHANDLE hTrace = OpenTraceW(&logFile);
    if (hTrace == INVALID_PROCESSTRACE_HANDLE) {
        return;
    }
    ProcessTrace(&hTrace, 1, NULL, NULL);
    CloseTrace(hTrace);
}

void WINAPI AdvancedBehaviorMonitor::ETWEventCallback(PEVENT_RECORD eventRecord) {
    if (g_monitorInstance) {
        g_monitorInstance->LogEvent("ETW_EVENT", "Event received", eventRecord->EventHeader.ProcessId);
        if (IsEqualGUID(eventRecord->EventHeader.ProviderId, FileIoProviderGuid)) {
            g_monitorInstance->HandleFileIoEvent(eventRecord);
        }
        else if (IsEqualGUID(eventRecord->EventHeader.ProviderId, RegistryProviderGuid)) {
            g_monitorInstance->HandleRegistryEvent(eventRecord);
        }
        else if (IsEqualGUID(eventRecord->EventHeader.ProviderId, TcpIpProviderGuid)) {
            g_monitorInstance->HandleNetworkEvent(eventRecord);
        }
    }
}

void AdvancedBehaviorMonitor::HandleFileIoEvent(PEVENT_RECORD eventRecord) {
    // 简单的日志记录，可以根据需要解析
    LogEvent("ETW_FILE_IO", "File I/O activity detected", eventRecord->EventHeader.ProcessId);
}
void AdvancedBehaviorMonitor::HandleRegistryEvent(PEVENT_RECORD eventRecord) {
    LogEvent("ETW_REGISTRY", "Registry activity detected", eventRecord->EventHeader.ProcessId);
}
void AdvancedBehaviorMonitor::HandleNetworkEvent(PEVENT_RECORD eventRecord) {
    LogEvent("ETW_NETWORK", "Network activity detected", eventRecord->EventHeader.ProcessId);
}

// 网络过滤函数实现
bool AdvancedBehaviorMonitor::SetupNetworkFilter() {
    // 简单的网络过滤，仅作示例
    return FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &m_engineHandle) == ERROR_SUCCESS;
}

void AdvancedBehaviorMonitor::CleanupNetworkFilter() {
    if (m_engineHandle) {
        FwpmEngineClose0(m_engineHandle);
        m_engineHandle = nullptr;
    }
}

// 辅助函数
std::string AdvancedBehaviorMonitor::GetObjectName(HANDLE hObject) {
    if (hObject == INVALID_HANDLE_VALUE) return "";
    std::string objectName;
    PVOID pBuffer = nullptr;
    ULONG bufferSize = 256;
    NTSTATUS status;
    PFN_NtQueryObject NtQueryObject = (PFN_NtQueryObject)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
    if (!NtQueryObject) return "";
    do {
        pBuffer = realloc(pBuffer, bufferSize);
        if (pBuffer == nullptr) return "";
        status = NtQueryObject(hObject, ObjectNameInformation, pBuffer, bufferSize, &bufferSize);
        if (status == 0xC0000004 /*STATUS_INFO_LENGTH_MISMATCH*/) continue;
        else if (status != 0) {
            if (pBuffer) free(pBuffer);
            return "";
        }
    } while (status == 0xC0000004);
    POBJECT_NAME_INFORMATION pNameInfo = (POBJECT_NAME_INFORMATION)pBuffer;
    if (pNameInfo && pNameInfo->Name.Buffer) {
        std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
        objectName = converter.to_bytes(pNameInfo->Name.Buffer);
    }
    if (pBuffer) free(pBuffer);
    return objectName;
}

std::string AdvancedBehaviorMonitor::GetProcessName(DWORD pid) {
    if (pid == 0) return "System Idle Process";
    if (pid == 4) return "System";

    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) return "";

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return "";
    }
    std::string processName = "Unknown";
    do {
        if (pe32.th32ProcessID == pid) {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            processName = converter.to_bytes(pe32.szExeFile);
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));
    CloseHandle(hProcessSnap);
    return processName;
}

std::string AdvancedBehaviorMonitor::GetCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    struct tm timeInfo;
    localtime_s(&timeInfo, &in_time_t);
    ss << std::put_time(&timeInfo, "%Y-%m-%d %X");
    return ss.str();
}

void AdvancedBehaviorMonitor::LogEvent(const std::string& type, const std::string& details, DWORD pid) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    BehaviorEvent event;
    event.timestamp = GetCurrentTimestamp();
    event.type = type;
    event.details = details;
    event.processId = pid;
    event.processName = GetProcessName(pid);
    m_events.push_back(event);
}

bool AdvancedBehaviorMonitor::IsTargetProcessOrChild(DWORD pid) {
    return (m_childProcesses.find(pid) != m_childProcesses.end());
}

void AdvancedBehaviorMonitor::TerminateAllMonitoredProcesses() {
    for (DWORD pid : m_childProcesses) {
        if (pid == m_targetPid) {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            if (hProcess) {
                TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
            }
        }
    }
}

void AdvancedBehaviorMonitor::GenerateReport(const std::string& filename) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    std::ofstream report(filename);
    if (!report.is_open()) {
        std::cerr << "[-] Failed to create report file" << std::endl;
        return;
    }

    report << "Advanced Behavior Monitoring Report\n";
    report << "===================================\n\n";
    report << "Target Process: " << m_targetName << " (PID: " << m_targetPid << ")\n";
    report << "Monitoring Duration: " << m_monitorDuration << " seconds\n";
    report << "Total Events Recorded: " << m_events.size() << "\n\n";

    std::unordered_map<std::string, int> eventCounts;
    for (const auto& event : m_events) {
        eventCounts[event.type]++;
    }

    report << "Event Statistics:\n";
    report << "----------------\n";
    for (const auto& count : eventCounts) {
        report << count.first << ": " << count.second << " events\n";
    }
    report << "\n";

    report << "Detailed Events:\n";
    report << "---------------\n";
    for (const auto& event : m_events) {
        report << "[" << event.timestamp << "] [" << event.processName << " (" << event.processId << ")] " << event.type << ": " << event.details << "\n";
    }
}

void AdvancedBehaviorMonitor::MonitoringMain() {
    // 监控主线程
    std::cout << "[+] Monitoring for " << m_monitorDuration << " seconds..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(m_monitorDuration));
    StopMonitoring();
}