#pragma once

#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_

#include <iostream>
#include <vector>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <locale>
#include <codecvt>
#include <functional>

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#include <tlhelp32.h>
#include <psapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <fwpmu.h>
#include <initguid.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <sddl.h>
#include <shlwapi.h>
#include <intrin.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

// ETW Provider GUIDs
const GUID FileIoProviderGuid = { 0x90cbdc39, 0x4a3e, 0x11d1, { 0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3 } };
const GUID TcpIpProviderGuid = { 0x9a280ac0, 0xc8e0, 0x11d1, { 0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2 } };
const GUID RegistryProviderGuid = { 0xae53722e, 0xc863, 0x11d2, { 0x86, 0x59, 0x00, 0xc0, 0x4f, 0xa3, 0x21, 0xa1 } };

#ifndef KERNEL_LOGGER_NAME
#define KERNEL_LOGGER_NAME L"NT Kernel Logger"
#endif

// 定义内联钩取需要的常量和数据结构
#define JMP_SIZE 5
#define MAX_SYSCALL_HOOKS 30

typedef LONG NTSTATUS;
#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

// NT函数声明
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectNameInformation = 1,
} OBJECT_INFORMATION_CLASS;

typedef enum _KEY_VALUE_INFORMATION_CLASS
{
    KeyValueBasicInformation, // KEY_VALUE_BASIC_INFORMATION
    KeyValueFullInformation, // KEY_VALUE_FULL_INFORMATION
    KeyValuePartialInformation, // KEY_VALUE_PARTIAL_INFORMATION
    KeyValueFullInformationAlign64, // KEY_VALUE_FULL_INFORMATION_ALIGN64
    KeyValuePartialInformationAlign64,  // KEY_VALUE_PARTIAL_INFORMATION_ALIGN64
    KeyValueLayerInformation, // KEY_VALUE_LAYER_INFORMATION
    MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI* PFN_NtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* PFN_NtOpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
typedef NTSTATUS(NTAPI* PFN_NtReadFile)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS(NTAPI* PFN_NtWriteFile)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS(NTAPI* PFN_NtCreateKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);
typedef NTSTATUS(NTAPI* PFN_NtOpenKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* PFN_NtDeleteKey)(HANDLE);
typedef NTSTATUS(NTAPI* PFN_NtSetValueKey)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* PFN_NtQueryValueKey)(HANDLE, PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* PFN_NtCreateProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, BOOLEAN, HANDLE, HANDLE, HANDLE);
typedef NTSTATUS(NTAPI* PFN_NtCreateProcessEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, BOOLEAN);
typedef NTSTATUS(NTAPI* PFN_NtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(NTAPI* PFN_NtTerminateProcess)(HANDLE, NTSTATUS);
typedef NTSTATUS(NTAPI* PFN_NtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS(NTAPI* PFN_NtOpenThread)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(NTAPI* PFN_NtTerminateThread)(HANDLE, NTSTATUS);
typedef NTSTATUS(NTAPI* PFN_NtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* PFN_NtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* PFN_NtDeviceIoControlFile)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* PFN_NtQueryObject)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

// 系统调用钩子相关
typedef struct _SYSCALL_ENTRY {
    LPCSTR Name;
    PVOID OriginalFunction;
    PVOID HookFunction;
    BOOLEAN Hooked;
    char OriginalBytes[JMP_SIZE];
    PVOID Trampoline;
} SYSCALL_ENTRY, * PSYSCALL_ENTRY;

class AdvancedBehaviorMonitor {
public:
    AdvancedBehaviorMonitor();
    ~AdvancedBehaviorMonitor();

    bool StartMonitoring(const std::string& targetProcess, const std::string& arguments = "");
    void StopMonitoring();
    void GenerateReport(const std::string& filename);

    void SetMonitoringDuration(int seconds) { m_monitorDuration = seconds; }
    void EnableETWMonitoring(bool enable) { m_enableETW = enable; }
    void EnableNetworkFilter(bool enable) { m_enableNetworkFilter = enable; }
    void EnableHooking(bool enable) { m_enableHooking = enable; }

private:
    struct BehaviorEvent {
        std::string timestamp;
        std::string type;
        std::string details;
        std::string processName;
        DWORD processId;
    };

    bool InstallSyscallHooks();
    bool RemoveSyscallHooks();
    bool HookSyscall(LPCSTR name, PVOID originalFunc, PVOID hookFunc);

    // 完整的钩取函数声明
    static NTSTATUS NTAPI HookedNtCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    static NTSTATUS NTAPI HookedNtOpenFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
    static NTSTATUS NTAPI HookedNtReadFile(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
    static NTSTATUS NTAPI HookedNtWriteFile(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
    static NTSTATUS NTAPI HookedNtCreateKey(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);
    static NTSTATUS NTAPI HookedNtOpenKey(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    static NTSTATUS NTAPI HookedNtDeleteKey(HANDLE);
    static NTSTATUS NTAPI HookedNtSetValueKey(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
    static NTSTATUS NTAPI HookedNtQueryValueKey(HANDLE, PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    static NTSTATUS NTAPI HookedNtCreateProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, BOOLEAN, HANDLE, HANDLE, HANDLE);
    static NTSTATUS NTAPI HookedNtCreateProcessEx(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, BOOLEAN);
    static NTSTATUS NTAPI HookedNtOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
    static NTSTATUS NTAPI HookedNtTerminateProcess(HANDLE, NTSTATUS);
    static NTSTATUS NTAPI HookedNtCreateThreadEx(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
    static NTSTATUS NTAPI HookedNtOpenThread(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
    static NTSTATUS NTAPI HookedNtTerminateThread(HANDLE, NTSTATUS);
    static NTSTATUS NTAPI HookedNtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    static NTSTATUS NTAPI HookedNtProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    static NTSTATUS NTAPI HookedNtDeviceIoControlFile(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);

    // ETW, 网络过滤, 进程信息等其他成员
    bool StartETWTracing();
    void StopETWTracing();
    void ProcessETWEvents();
    static DWORD WINAPI ETWThread(LPVOID lpParam);
    static void WINAPI ETWEventCallback(PEVENT_RECORD eventRecord);
    void HandleFileIoEvent(PEVENT_RECORD eventRecord);
    void HandleRegistryEvent(PEVENT_RECORD eventRecord);
    void HandleNetworkEvent(PEVENT_RECORD eventRecord);

    bool SetupNetworkFilter();
    void CleanupNetworkFilter();

    void MonitoringMain();
    void TerminateAllMonitoredProcesses();
    std::string GetProcessName(DWORD pid);
    std::string GetCurrentTimestamp();
    void LogEvent(const std::string& type, const std::string& details, DWORD pid = 0);
    bool IsTargetProcessOrChild(DWORD pid);
    std::string GetObjectName(HANDLE hObject);

    TRACEHANDLE m_traceHandle;
    EVENT_TRACE_PROPERTIES* m_traceProperties;
    std::thread m_etwThread;
    HANDLE m_engineHandle;
    std::vector<UINT64> m_filterIds;
    HANDLE m_targetProcess;
    DWORD m_targetPid;
    std::string m_targetName;
    std::string m_targetPath;
    std::vector<BehaviorEvent> m_events;
    std::unordered_set<DWORD> m_childProcesses;
    std::mutex m_dataMutex;
    int m_monitorDuration;
    bool m_enableETW;
    bool m_enableNetworkFilter;
    bool m_enableHooking;
    bool m_isMonitoring;

    SYSCALL_ENTRY m_syscallTable[MAX_SYSCALL_HOOKS];
    int m_syscallTableCount;
};