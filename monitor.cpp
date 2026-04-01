#include "monitor.h"

// 全局静态实例，用于在静态回调函数中访问成员变量
static AdvancedBehaviorMonitor* g_monitorInstance = nullptr;
static const GUID TcpIpProviderGuid =
{ 0x7dd42a49, 0x5329, 0x4832, { 0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88 } };

// ETW Kernel Network Trace 全局变量
static const wchar_t* ETW_SESSION_NAME = L"MonitorKernelSession_ETW_v1";
static TRACEHANDLE g_SessionHandle = 0;
static TRACEHANDLE g_TraceHandle = 0;
static std::thread g_etwThread;
static std::atomic<bool> g_etwRunning(false);
static AdvancedBehaviorMonitor* g_currentMonitor = nullptr;

AdvancedBehaviorMonitor::AdvancedBehaviorMonitor()
    : m_traceHandle(0), m_traceProperties(nullptr),
    m_engineHandle(nullptr), m_targetProcess(INVALID_HANDLE_VALUE),
    m_targetPid(0), m_monitorDuration(60), m_enableETW(true),
    m_enableNetworkFilter(false), m_enableProcessMonitoring(true),
    m_isMonitoring(false), m_stopETW(false), m_stopProcessMonitoring(false) {
    g_monitorInstance = this;
}

AdvancedBehaviorMonitor::~AdvancedBehaviorMonitor() {
    StopMonitoring();
    g_monitorInstance = nullptr;
}

bool AdvancedBehaviorMonitor::StartMonitoring(const std::string& targetProcess, const std::string& arguments) {
    if (m_isMonitoring.load()) {
        std::cerr << "[-] Monitoring is already in progress." << std::endl;
        return false;
    }

    // 创建目标进程
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    std::string commandLine = "\"" + targetProcess + "\"";
    if (!arguments.empty()) {
        commandLine += " " + arguments;
    }

    std::vector<char> cmdLineBuf(commandLine.begin(), commandLine.end());
    cmdLineBuf.push_back('\0');

    if (!CreateProcessA(
        targetProcess.c_str(),
        cmdLineBuf.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_SUSPENDED,
        nullptr,
        nullptr,
        &si,
        &pi)) {
        std::cerr << "[-] Failed to start process: " << GetLastError() << std::endl;
        return false;
    }

    m_targetProcess = pi.hProcess;
    m_targetPid = pi.dwProcessId;
    m_targetName = PathFindFileNameA(targetProcess.c_str());
    m_targetPath = targetProcess;
    m_isMonitoring = true;
    m_stopETW = false;
    m_stopProcessMonitoring = false;

    std::cout << "[+] Target process created: " << m_targetName
        << " (PID: " << m_targetPid << ")" << std::endl;

    // 清理并初始化数据
    {
        std::lock_guard<std::mutex> lock(m_dataMutex);
        m_events.clear();
        m_childProcesses.clear();
        m_childProcesses.insert(m_targetPid);
        m_eventStats.clear();
    }

    // 启动ETW监控
    if (m_enableETW) {
        g_currentMonitor = this; // 设置全局指针用于ETW回调
        if (!StartETWTracing()) {
            std::cerr << "[-] ETW tracing setup failed" << std::endl;
        }
        else {
            std::cout << "[+] ETW tracing started successfully" << std::endl;
        }
    }

    // 设置网络过滤器
    if (m_enableNetworkFilter) {
        if (!SetupNetworkFilter()) {
            std::cerr << "[-] Network filter setup failed" << std::endl;
        }
        else {
            std::cout << "[+] Network filter setup successfully" << std::endl;
        }
    }

    // 启动进程监控线程
    if (m_enableProcessMonitoring) {
        m_processMonitorThread = std::thread(&AdvancedBehaviorMonitor::ProcessMonitoringThread, this);
        std::cout << "[+] Process monitoring started" << std::endl;
    }

    // 启动主监控线程
    std::thread monitorThread(&AdvancedBehaviorMonitor::MonitoringMain, this);
    monitorThread.detach();

    // 恢复目标进程
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    return true;
}

void AdvancedBehaviorMonitor::StopMonitoring() {
    if (!m_isMonitoring.load()) return;

    std::cout << "[+] Stopping monitoring..." << std::endl;
    m_isMonitoring = false;
    m_stopETW = true;
    m_stopProcessMonitoring = true;

    // 停止ETW追踪
    if (m_etwThread.joinable()) {
        StopETWTracing();
        m_etwThread.join();
    }

    g_currentMonitor = nullptr; // 清理全局指针

    // 停止进程监控
    if (m_processMonitorThread.joinable()) {
        m_processMonitorThread.join();
    }

    // 清理网络过滤器
    CleanupNetworkFilter();

    // 终止被监控的进程
    TerminateAllMonitoredProcesses();

    // 清理ETW资源
    SafeFreeEventTraceProperties();

    std::cout << "[+] Monitoring stopped" << std::endl;
}

bool AdvancedBehaviorMonitor::StartETWTracing() {
    if (!InitializeEventTraceProperties()) {
        return false;
    }

    ULONG status = StartTraceW(&m_traceHandle, KERNEL_LOGGER_NAME, m_traceProperties);
    if (status == ERROR_ALREADY_EXISTS) {
        std::cout << "[!] ETW trace session already exists, stopping existing session..." << std::endl;
        StopTraceW(m_traceHandle, KERNEL_LOGGER_NAME, m_traceProperties);
        status = StartTraceW(&m_traceHandle, KERNEL_LOGGER_NAME, m_traceProperties);
    }

    if (status != ERROR_SUCCESS) {
        std::cerr << "[-] StartTrace failed: " << status << std::endl;
        SafeFreeEventTraceProperties();
        return false;
    }

    m_etwThread = std::thread(&AdvancedBehaviorMonitor::ProcessETWEvents, this);

    // Start kernel network trace
    if (!StartKernelNetworkTrace()) {
        std::cerr << "[-] Failed to start kernel network trace" << std::endl;
    }

    return true;
}

bool AdvancedBehaviorMonitor::InitializeEventTraceProperties() {
    const wchar_t* loggerName = KERNEL_LOGGER_NAME;
    ULONG bufferSize = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(loggerName) + 1) * sizeof(wchar_t));

    m_traceProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    if (!m_traceProperties) {
        std::cerr << "[-] Failed to allocate memory for ETW properties." << std::endl;
        return false;
    }

    ZeroMemory(m_traceProperties, bufferSize);
    m_traceProperties->Wnode.BufferSize = bufferSize;
    m_traceProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    m_traceProperties->Wnode.ClientContext = 1;
    m_traceProperties->Wnode.Guid = SystemTraceControlGuid;
    m_traceProperties->EnableFlags = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD |
        EVENT_TRACE_FLAG_FILE_IO | EVENT_TRACE_FLAG_REGISTRY |
        EVENT_TRACE_FLAG_NETWORK_TCPIP;
    m_traceProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    m_traceProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    wcsncpy_s((wchar_t*)((char*)m_traceProperties + m_traceProperties->LoggerNameOffset),
        (bufferSize - sizeof(EVENT_TRACE_PROPERTIES)) / sizeof(wchar_t),
        loggerName, wcslen(loggerName));

    return true;
}

void AdvancedBehaviorMonitor::SafeFreeEventTraceProperties() {
    if (m_traceProperties) {
        free(m_traceProperties);
        m_traceProperties = nullptr;
    }
}

void AdvancedBehaviorMonitor::StopETWTracing() {
    if (m_traceHandle != 0 && m_traceProperties) {
        StopTraceW(m_traceHandle, KERNEL_LOGGER_NAME, m_traceProperties);
        m_traceHandle = 0;
    }

    // Stop kernel network trace
    StopKernelNetworkTrace();
}

void AdvancedBehaviorMonitor::ProcessETWEvents() {
    EVENT_TRACE_LOGFILE logFile;
    ZeroMemory(&logFile, sizeof(logFile));
    logFile.LoggerName = (LPWSTR)KERNEL_LOGGER_NAME;
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = &AdvancedBehaviorMonitor::ETWEventCallback;
    logFile.Context = this;

    TRACEHANDLE traceHandle = OpenTraceW(&logFile);
    if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        std::cerr << "[-] OpenTraceW failed: " << GetLastError() << std::endl;
        return;
    }

    TRACEHANDLE traceHandles[1] = { traceHandle };
    ULONG status = ProcessTrace(traceHandles, 1, nullptr, nullptr);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
        std::cerr << "[-] ProcessTrace failed: " << status << std::endl;
    }

    CloseTrace(traceHandle);
}

void WINAPI AdvancedBehaviorMonitor::ETWEventCallback(PEVENT_RECORD eventRecord) {
    if (!g_monitorInstance || g_monitorInstance->m_stopETW.load()) return;

    try {
        if (IsEqualGUID(eventRecord->EventHeader.ProviderId, FileIoProviderGuid)) {
            g_monitorInstance->HandleFileIoEvent(eventRecord);
        }
        else if (IsEqualGUID(eventRecord->EventHeader.ProviderId, RegistryProviderGuid)) {
            g_monitorInstance->HandleRegistryEvent(eventRecord);
        }
        else if (IsEqualGUID(eventRecord->EventHeader.ProviderId, TcpIpProviderGuid)) {
            g_monitorInstance->HandleNetworkEvent(eventRecord);
        }
        else if (IsEqualGUID(eventRecord->EventHeader.ProviderId, ProcessProviderGuid)) {
            g_monitorInstance->HandleProcessEvent(eventRecord);
        }
        else if (IsEqualGUID(eventRecord->EventHeader.ProviderId, ThreadProviderGuid)) {
            g_monitorInstance->HandleThreadEvent(eventRecord);
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[-] Exception in ETW callback: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "[-] Unknown exception in ETW callback" << std::endl;
    }
}

void AdvancedBehaviorMonitor::HandleFileIoEvent(PEVENT_RECORD eventRecord) {
    if (!IsTargetProcessOrChild(eventRecord->EventHeader.ProcessId)) return;

    DWORD pid = eventRecord->EventHeader.ProcessId;
    DWORD tid = eventRecord->EventHeader.ThreadId; // 获取线程ID
    WORD id = eventRecord->EventHeader.EventDescriptor.Id;
    UCHAR opcode = eventRecord->EventHeader.EventDescriptor.Opcode;

    std::string evtType = "FILE_IO";
    std::string filePath = "<unknown>";

    // Map common opcodes to operations
    switch (opcode) {
    case 32: evtType = "FILE_CREATE"; break;
    case 35: evtType = "FILE_DELETE"; break;
    case 64: evtType = "FILE_READ"; break;
    case 65: evtType = "FILE_WRITE"; break;
    case 67: evtType = "FILE_OPEN"; break;
    case 68: evtType = "FILE_CLEANUP"; break;
    case 71: evtType = "FILE_DELETE"; break;
    case 72: evtType = "FILE_RENAME"; break;
    default: evtType = "FILE_IO_" + std::to_string(opcode); break;
    }

    // Try to extract file path from UserData
    if (eventRecord->UserData && eventRecord->UserDataLength > 0) {
        try {
            // 文件I/O事件的数据结构通常包含一个FILE_OBJECT指针和文件名
            // 文件名通常在数据的某个偏移处，而不是开头

            // 对于不同的事件类型，偏移可能不同
            // 这里提供一个通用的方法，但可能需要根据具体事件调整

            // 首先尝试查找常见的文件名偏移
            const BYTE* data = static_cast<const BYTE*>(eventRecord->UserData);
            ULONG dataLen = eventRecord->UserDataLength;

            // 查找可能的Unicode字符串（宽字符）
            for (ULONG i = 0; i < dataLen - 2; i++) {
                // 检查是否可能是有效的宽字符字符串开头
                if (data[i] != 0 && data[i + 1] == 0) {
                    const wchar_t* potentialPath = reinterpret_cast<const wchar_t*>(data + i);

                    // 验证字符串长度和内容
                    size_t maxLen = (dataLen - i) / sizeof(wchar_t);
                    size_t strLen = 0;

                    while (strLen < maxLen && strLen < 260 && potentialPath[strLen] != L'\0') {
                        strLen++;
                    }

                    // 如果找到合理的字符串长度
                    if (strLen > 1 && strLen < 260) {
                        std::wstring wPath(potentialPath, strLen);

                        // 转换为UTF-8
                        char utf8Path[1024];
                        WideCharToMultiByte(CP_UTF8, 0, wPath.c_str(), -1, utf8Path, sizeof(utf8Path), NULL, NULL);

                        filePath = utf8Path;
                        break;
                    }
                }
            }

            // 如果上述方法失败，尝试更直接的方法
            if (filePath == "<unknown>" && dataLen >= 8) {
                // 某些文件事件在偏移8处有文件名
                const wchar_t* pathPtr = reinterpret_cast<const wchar_t*>(data + 8);
                size_t maxLen = (dataLen - 8) / sizeof(wchar_t);

                size_t len = 0;
                while (len < maxLen && len < 260 && pathPtr[len] != L'\0') {
                    len++;
                }

                if (len > 0 && len < 260) {
                    std::wstring wPath(pathPtr, len);

                    // 转换为UTF-8
                    char utf8Path[1024];
                    WideCharToMultiByte(CP_UTF8, 0, wPath.c_str(), -1, utf8Path, sizeof(utf8Path), NULL, NULL);

                    filePath = utf8Path;
                }
            }
        }
        catch (...) {
            // Fallback to showing raw data info
            filePath = "<parse_error>";
        }
    }

    LogEvent(evtType, "Path: " + filePath, pid, tid); // 传递线程ID
}

void AdvancedBehaviorMonitor::HandleRegistryEvent(PEVENT_RECORD eventRecord) {
    if (!IsTargetProcessOrChild(eventRecord->EventHeader.ProcessId)) return;

    DWORD pid = eventRecord->EventHeader.ProcessId;
    UCHAR opcode = eventRecord->EventHeader.EventDescriptor.Opcode;

    std::string evtType;
    switch (opcode) {
    case 33: evtType = "REG_CREATE_KEY"; break;
    case 34: evtType = "REG_OPEN_KEY"; break;
    case 35: evtType = "REG_DELETE_KEY"; break;
    case 36: evtType = "REG_SET_VALUE"; break;
    case 37: evtType = "REG_QUERY_VALUE"; break;
    case 38: evtType = "REG_DELETE_VALUE"; break;
    default: evtType = "REG_OP_" + std::to_string(opcode); break;
    }

    std::string regPath = "<unknown>";
    DWORD status = ERROR_SUCCESS;
    PTRACE_EVENT_INFO pInfo = nullptr;
    DWORD bufferSize = 0;

    // 获取事件信息
    status = TdhGetEventInformation(eventRecord, 0, nullptr, pInfo, &bufferSize);
    if (status == ERROR_INSUFFICIENT_BUFFER) {
        pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
        status = TdhGetEventInformation(eventRecord, 0, nullptr, pInfo, &bufferSize);
    }

    if (status != ERROR_SUCCESS) {
        LogEvent(evtType, "Key: <error_getting_info>", pid);
        if (pInfo) free(pInfo);
        return;
    }

    // 查找 "KeyName" 属性
    PROPERTY_DATA_DESCRIPTOR dataDescriptor;
    dataDescriptor.PropertyName = (ULONGLONG)L"KeyName";
    dataDescriptor.ArrayIndex = ULONG_MAX;

    DWORD propertySize = 0;
    status = TdhGetPropertySize(eventRecord, 0, nullptr, 1, &dataDescriptor, &propertySize);
    if (status != ERROR_SUCCESS) {
        regPath = "<no_keyname>";
    }
    else {
        PBYTE pData = (PBYTE)malloc(propertySize);
        status = TdhGetProperty(eventRecord, 0, nullptr, 1, &dataDescriptor, propertySize, pData);
        if (status == ERROR_SUCCESS) {
            // KeyName 是 Unicode 字符串
            regPath = WStringToString((wchar_t*)pData);
        }
        else {
            regPath = "<error_extracting>";
        }
        free(pData);
    }

    if (pInfo) free(pInfo);
    LogEvent(evtType, "Key: " + regPath, pid);
}

void AdvancedBehaviorMonitor::HandleNetworkEvent(PEVENT_RECORD eventRecord)
{
    if (eventRecord->EventHeader.ProviderId != TcpIpProviderGuid)
        return;

    BYTE* data = (BYTE*)eventRecord->UserData;
    ULONG pid = 0;
    std::string remote;

    if (eventRecord->EventHeader.EventDescriptor.Id == EVENT_TCP_CONNECT_V4)
    {
        if (eventRecord->UserDataLength < 16) return;

        USHORT dstPort = *(USHORT*)(data + 2);
        ULONG dstAddr = *(ULONG*)(data + 8);
        pid = *(ULONG*)(data + 12);

        char ip[INET_ADDRSTRLEN] = { 0 };
        InetNtopA(AF_INET, &dstAddr, ip, sizeof(ip));
        remote = std::string(ip) + ":" + std::to_string(ntohs(dstPort));
    }
    else if (eventRecord->EventHeader.EventDescriptor.Id == EVENT_TCP_CONNECT_V6)
    {
        if (eventRecord->UserDataLength < 37) return;

        USHORT dstPort = *(USHORT*)(data + 2);
        IN6_ADDR* dstAddr = (IN6_ADDR*)(data + 20);
        pid = *(ULONG*)(data + 36);

        char ip[INET6_ADDRSTRLEN] = { 0 };
        InetNtopA(AF_INET6, dstAddr, ip, sizeof(ip));
        remote = std::string(ip) + ":" + std::to_string(ntohs(dstPort));
    }
    else
        return;

    LogNetworkEvent("[NETWORK CONNECT] ", " Remote:" + remote, pid, eventRecord->EventHeader.ThreadId);
}

void AdvancedBehaviorMonitor::HandleProcessEvent(PEVENT_RECORD eventRecord) {
    std::string operation;
    std::string details;

    switch (eventRecord->EventHeader.EventDescriptor.Opcode) {
    case 1: // Process Start
        operation = "PROCESS_START";
        break;
    case 2: // Process End
        operation = "PROCESS_END";
        break;
    default:
        return;
    }

    // 检查是否是子进程
    DWORD pid = eventRecord->EventHeader.ProcessId;
    if (operation == "PROCESS_START") {
        // 可能需要添加到子进程列表
        std::lock_guard<std::mutex> lock(m_dataMutex);
        if (m_childProcesses.find(pid) == m_childProcesses.end()) {
            // 这可能是一个新的子进程，但需要进一步验证父进程关系
            details = "New process detected: PID " + std::to_string(pid);
        }
    }

    if (IsTargetProcessOrChild(pid) || operation == "PROCESS_START") {
        LogEvent(operation, details, pid, eventRecord->EventHeader.ThreadId);
    }
}

void AdvancedBehaviorMonitor::HandleThreadEvent(PEVENT_RECORD eventRecord) {
    if (!IsTargetProcessOrChild(eventRecord->EventHeader.ProcessId)) return;

    std::string operation;
    switch (eventRecord->EventHeader.EventDescriptor.Opcode) {
    case 1: operation = "THREAD_START"; break;
    case 2: operation = "THREAD_END"; break;
    default: return;
    }

    LogEvent(operation, "TID: " + std::to_string(eventRecord->EventHeader.ThreadId),
        eventRecord->EventHeader.ProcessId, eventRecord->EventHeader.ThreadId);
}

bool AdvancedBehaviorMonitor::SetupNetworkFilter() {
    FWPM_SESSION0 session;
    ZeroMemory(&session, sizeof(session));
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    DWORD status = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &m_engineHandle);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[-] FwpmEngineOpen0 failed: " << status << std::endl;
        return false;
    }

    status = FwpmTransactionBegin0(m_engineHandle, 0);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[-] FwpmTransactionBegin0 failed: " << status << std::endl;
        FwpmEngineClose0(m_engineHandle);
        m_engineHandle = nullptr;
        return false;
    }

    // 创建子层
    FWPM_SUBLAYER0 sublayer;
    ZeroMemory(&sublayer, sizeof(sublayer));
    sublayer.subLayerKey = { 0x56a65529, 0xc10c, 0x4896, {0x8f, 0x42, 0x8a, 0x22, 0x2f, 0x4e, 0x3f, 0x4b} };
    sublayer.displayData.name = (wchar_t*)L"Advanced Behavior Monitor Sublayer";
    sublayer.displayData.description = (wchar_t*)L"Sublayer for monitoring a specific process's network activity.";
    sublayer.weight = 0x100;

    status = FwpmSubLayerAdd0(m_engineHandle, &sublayer, nullptr);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[-] FwpmSubLayerAdd0 failed: " << status << std::endl;
        FwpmTransactionAbort0(m_engineHandle);
        FwpmEngineClose0(m_engineHandle);
        m_engineHandle = nullptr;
        return false;
    }

    // 设置过滤条件
    FWPM_FILTER_CONDITION0 conditions[1];
    ZeroMemory(&conditions, sizeof(conditions));
    conditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;

    std::wstring wProcessPath = StringToWString(m_targetPath);
    FWP_BYTE_BLOB* pathBlob = nullptr;
    status = FwpmGetAppIdFromFileName0(wProcessPath.c_str(), &pathBlob);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[-] FwpmGetAppIdFromFileName0 failed: " << status << std::endl;
        FwpmTransactionAbort0(m_engineHandle);
        FwpmEngineClose0(m_engineHandle);
        m_engineHandle = nullptr;
        return false;
    }
    conditions[0].conditionValue.byteBlob = pathBlob;

    // 创建过滤器
    FWPM_FILTER0 filter;
    ZeroMemory(&filter, sizeof(filter));
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = sublayer.subLayerKey;
    filter.weight.type = FWP_EMPTY;
    filter.action.type = FWP_ACTION_PERMIT;
    filter.displayData.name = (wchar_t*)L"Monitor Target Process Network";
    filter.numFilterConditions = 1;
    filter.filterCondition = conditions;

    UINT64 filterId;
    status = FwpmFilterAdd0(m_engineHandle, &filter, nullptr, &filterId);
    FwpmFreeMemory0((void**)&pathBlob);

    if (status != ERROR_SUCCESS) {
        std::cerr << "[-] FwpmFilterAdd0 failed: " << status << std::endl;
        FwpmTransactionAbort0(m_engineHandle);
        FwpmEngineClose0(m_engineHandle);
        m_engineHandle = nullptr;
        return false;
    }

    m_filterIds.push_back(filterId);

    status = FwpmTransactionCommit0(m_engineHandle);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[-] FwpmTransactionCommit0 failed: " << status << std::endl;
        FwpmEngineClose0(m_engineHandle);
        m_engineHandle = nullptr;
        return false;
    }

    return true;
}

void AdvancedBehaviorMonitor::CleanupNetworkFilter() {
    if (m_engineHandle) {
        FwpmTransactionBegin0(m_engineHandle, 0);
        for (auto filterId : m_filterIds) {
            FwpmFilterDeleteById0(m_engineHandle, filterId);
        }
        FwpmTransactionCommit0(m_engineHandle);
        FwpmEngineClose0(m_engineHandle);
        m_engineHandle = nullptr;
    }
    m_filterIds.clear();
}

void AdvancedBehaviorMonitor::MonitoringMain() {
    auto startTime = std::chrono::steady_clock::now();

    while (m_isMonitoring.load()) {
        auto currentTime = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime).count();

        // 检查监控持续时间
        if (elapsed >= m_monitorDuration && m_monitorDuration > 0) {
            std::cout << "[!] Monitoring duration reached. Stopping." << std::endl;
            break;
        }

        // 检查目标进程是否仍在运行
        if (m_targetProcess != INVALID_HANDLE_VALUE) {
            DWORD exitCode;
            if (GetExitCodeProcess(m_targetProcess, &exitCode) && exitCode != STILL_ACTIVE) {
                std::cout << "[!] Target process has exited. Stopping monitoring." << std::endl;
                break;
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    StopMonitoring();
}

void AdvancedBehaviorMonitor::ProcessMonitoringThread() {
    while (!m_stopProcessMonitoring.load() && m_isMonitoring.load()) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);

            if (Process32First(hSnapshot, &pe32)) {
                do {
                    std::lock_guard<std::mutex> lock(m_dataMutex);

                    // 检查是否是已知进程的子进程
                    if (m_childProcesses.find(pe32.th32ParentProcessID) != m_childProcesses.end()) {
                        if (m_childProcesses.find(pe32.th32ProcessID) == m_childProcesses.end()) {
                            m_childProcesses.insert(pe32.th32ProcessID);

                            std::wstring wExeFile(pe32.szExeFile);
                            std::string exeFile = WStringToString(wExeFile);

                            LogEvent("PROCESS_CREATE",
                                "Child process created: " + exeFile +
                                " (PID: " + std::to_string(pe32.th32ProcessID) +
                                ", Parent PID: " + std::to_string(pe32.th32ParentProcessID) + ")",
                                pe32.th32ProcessID);
                        }
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

void AdvancedBehaviorMonitor::TerminateAllMonitoredProcesses() {
    std::lock_guard<std::mutex> lock(m_dataMutex);

    // 先终止子进程，再终止主进程
    for (DWORD pid : m_childProcesses) {
        if (pid != m_targetPid) {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            if (hProcess) {
                if (TerminateProcess(hProcess, 0)) {
                    std::cout << "[+] Terminated child process with PID: " << pid << std::endl;
                }
                else {
                    std::cerr << "[-] Failed to terminate child process with PID " << pid
                        << ", Error: " << GetLastError() << std::endl;
                }
                CloseHandle(hProcess);
            }
        }
    }

    // 终止主目标进程
    if (m_targetProcess != INVALID_HANDLE_VALUE) {
        if (TerminateProcess(m_targetProcess, 0)) {
            std::cout << "[+] Terminated target process with PID: " << m_targetPid << std::endl;
        }
        else {
            std::cerr << "[-] Failed to terminate target process with PID " << m_targetPid
                << ", Error: " << GetLastError() << std::endl;
        }
        CloseHandle(m_targetProcess);
        m_targetProcess = INVALID_HANDLE_VALUE;
        m_targetPid = 0;
    }
}

void AdvancedBehaviorMonitor::LogEvent(const std::string& type, const std::string& details, DWORD pid, DWORD tid) {
    std::lock_guard<std::mutex> lock(m_dataMutex);

    BehaviorEvent event;
    event.timestamp = GetCurrentTimestamp();
    event.type = type;
    event.details = details;
    event.processId = (pid == 0) ? m_targetPid : pid;
    event.processName = GetProcessName(event.processId);
    event.threadId = (tid == 0) ? "" : std::to_string(tid);

    m_events.push_back(event);
    m_eventStats[type]++;

    // 实时输出重要事件
    if (type.rfind("FILE", 0) == 0 || type.rfind("REGISTRY", 0) == 0 ||
        type.rfind("NETWORK", 0) == 0 || type.rfind("PROCESS", 0) == 0) {
        std::cout << "[" << event.timestamp << "] " << event.processName
            << " (" << event.processId;
        if (!event.threadId.empty()) {
            std::cout << ":" << event.threadId;
        }
        std::cout << ") " << type << " -> " << event.details << std::endl;
    }
}

bool AdvancedBehaviorMonitor::IsTargetProcessOrChild(DWORD pid) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    return m_childProcesses.find(pid) != m_childProcesses.end();
}

std::string AdvancedBehaviorMonitor::GetProcessName(DWORD pid) {
    if (pid == m_targetPid) return m_targetName;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess) {
        char processName[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameA(hProcess, 0, processName, &size)) {
            CloseHandle(hProcess);
            return PathFindFileNameA(processName);
        }
        CloseHandle(hProcess);
    }
    return "Unknown";
}

std::string AdvancedBehaviorMonitor::GetProcessPath(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess) {
        char processPath[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameA(hProcess, 0, processPath, &size)) {
            CloseHandle(hProcess);
            return std::string(processPath);
        }
        CloseHandle(hProcess);
    }
    return "Unknown";
}

std::string AdvancedBehaviorMonitor::GetCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::tm timeInfo;
    if (localtime_s(&timeInfo, &in_time_t) == 0) {
        std::stringstream ss;
        ss << std::put_time(&timeInfo, "%Y-%m-%d %H:%M:%S");
        ss << "." << std::setfill('0') << std::setw(3) << ms.count();
        return ss.str();
    }
    return "Timestamp Error";
}

std::wstring AdvancedBehaviorMonitor::StringToWString(const std::string& str) {
    if (str.empty()) return std::wstring();

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

std::string AdvancedBehaviorMonitor::WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

void AdvancedBehaviorMonitor::GenerateReport(const std::string& filename) {
    std::lock_guard<std::mutex> lock(m_dataMutex);

    std::ofstream report(filename);
    if (!report.is_open()) {
        std::cerr << "[-] Failed to create report file: " << filename << std::endl;
        return;
    }

    report << "Advanced Behavior Monitoring Report\n";
    report << "===================================\n\n";
    report << "Target Process: " << m_targetName << " (PID: " << m_targetPid << ")\n";
    report << "Target Path: " << m_targetPath << "\n";
    report << "Monitoring Duration: " << m_monitorDuration << " seconds\n";
    report << "Total Events Recorded: " << m_events.size() << "\n";
    report << "Child Processes Monitored: " << (m_childProcesses.size() - 1) << "\n\n";

    // 事件统计
    report << "Event Statistics:\n";
    report << "----------------\n";
    for (const auto& stat : m_eventStats) {
        report << stat.first << ": " << stat.second << " events\n";
    }
    report << "\n";

    // 监控的进程列表
    report << "Monitored Processes:\n";
    report << "-------------------\n";
    for (DWORD pid : m_childProcesses) {
        report << "PID " << pid << ": " << GetProcessName(pid);
        if (pid == m_targetPid) {
            report << " (Target Process)";
        }
        report << "\n";
    }
    report << "\n";

    // 详细事件日志
    report << "Detailed Event Log:\n";
    report << "------------------\n";
    for (const auto& event : m_events) {
        report << "[" << event.timestamp << "] "
            << event.processName << " (" << event.processId;
        if (!event.threadId.empty()) {
            report << ":" << event.threadId;
        }
        report << ") " << event.type << " -> " << event.details << "\n";
    }

    // 生成摘要分析
    report << "\n\nSummary Analysis:\n";
    report << "----------------\n";

    size_t fileEvents = m_eventStats["FILE_CREATE"] + m_eventStats["FILE_DELETE"] +
        m_eventStats["FILE_READ"] + m_eventStats["FILE_WRITE"];
    size_t regEvents = m_eventStats["REGISTRY_CREATE_KEY"] + m_eventStats["REGISTRY_DELETE_KEY"] +
        m_eventStats["REGISTRY_SET_VALUE"] + m_eventStats["REGISTRY_QUERY_VALUE"];
    size_t netEvents = m_eventStats["NETWORK_TCP_CONNECT_V4"] + m_eventStats["NETWORK_TCP_CONNECT_V6"] +
        m_eventStats["NETWORK_TCP_DISCONNECT_V4"];
    size_t procEvents = m_eventStats["PROCESS_CREATE"] + m_eventStats["PROCESS_START"] +
        m_eventStats["PROCESS_END"];

    report << "File system activity: " << fileEvents << " events\n";
    report << "Registry activity: " << regEvents << " events\n";
    report << "Network activity: " << netEvents << " events\n";
    report << "Process/Thread activity: " << procEvents << " events\n";

    if (netEvents > 0) {
        report << "\n[!] Network activity detected - process may be communicating externally\n";
    }
    if (regEvents > 10) {
        report << "[!] High registry activity detected - process may be making system changes\n";
    }
    if (procEvents > 1) {
        report << "[!] Child process creation detected - process may be spawning additional programs\n";
    }

    report.close();
    std::cout << "[+] Report generated: " << filename << std::endl;
    std::cout << "[+] Total events captured: " << m_events.size() << std::endl;
}

// ================== ETW Kernel Network Trace Implementation ===================

static void safe_print(const char* fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);
}

static void PrintTcpIpEvent(PEVENT_RECORD eventRecord, AdvancedBehaviorMonitor* monitor) {
    DWORD pid = eventRecord->EventHeader.ProcessId;
    DWORD tid = eventRecord->EventHeader.ThreadId;
    WORD id = eventRecord->EventHeader.EventDescriptor.Id;
    UCHAR opcode = eventRecord->EventHeader.EventDescriptor.Opcode;

    BYTE* data = (BYTE*)eventRecord->UserData;
    ULONG len = eventRecord->UserDataLength;
    if (len < 12) return; // Need at least basic IP/port data

    // TcpIp events typically have IP addresses and ports in the first bytes
    try {
        DWORD srcAddr = *(DWORD*)(data + 0);
        DWORD destAddr = *(DWORD*)(data + 4);
        USHORT srcPort = ntohs(*(USHORT*)(data + 8));
        USHORT destPort = ntohs(*(USHORT*)(data + 10));

        char srcStr[INET_ADDRSTRLEN] = { 0 };
        char destStr[INET_ADDRSTRLEN] = { 0 };
        inet_ntop(AF_INET, &srcAddr, srcStr, sizeof(srcStr));
        inet_ntop(AF_INET, &destAddr, destStr, sizeof(destStr));

        std::string evtType;
        switch (opcode) {
        case 10: evtType = "TCP_CONNECT"; break;
        case 11: evtType = "TCP_ACCEPT"; break;
        case 12: evtType = "TCP_RECONNECT"; break;
        case 13: evtType = "TCP_DISCONNECT"; break;
        case 16: evtType = "TCP_CLOSE"; break;
        case 17: evtType = "UDP_SEND"; break;
        case 18: evtType = "UDP_RECV"; break;
        default: evtType = "NETWORK_EVENT"; break;
        }

        std::ostringstream oss;
        oss << srcStr << ":" << srcPort << " -> " << destStr << ":" << destPort;

        if (monitor) {
            monitor->LogNetworkEvent(evtType, oss.str(), pid, tid); // 传递正确的TID
        }
        else {
            safe_print("[ETW][%s] PID=%u TID=%u %s\n", evtType.c_str(), pid, tid, oss.str().c_str()); // 输出中也添加TID
        }
    }
    catch (...) {
        // Fallback for parsing errors
        if (monitor) {
            monitor->LogNetworkEvent("NETWORK_EVENT", "Parse error in TCP/IP event", pid, tid);
        }
    }
}

static ULONG WINAPI NetworkEventRecordCallback(PEVENT_RECORD eventRecord) {
    if (!eventRecord) return ERROR_INVALID_PARAMETER;

    // Check if this is a TcpIp provider event
    if (IsEqualGUID(eventRecord->EventHeader.ProviderId, TcpIpProviderGuid)) {
        PrintTcpIpEvent(eventRecord, g_currentMonitor);
    }

    return ERROR_SUCCESS;
}

static void EtwNetworkWorkerThread() {
    EVENT_TRACE_LOGFILEW trace = { 0 };
    trace.LoggerName = const_cast<LPWSTR>(ETW_SESSION_NAME);
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.EventRecordCallback = (PEVENT_RECORD_CALLBACK)NetworkEventRecordCallback;

    g_TraceHandle = OpenTraceW(&trace);
    if (g_TraceHandle == INVALID_PROCESSTRACE_HANDLE) {
        safe_print("[ETW] OpenTraceW failed: %u\n", GetLastError());
        g_etwRunning = false;
        return;
    }

    safe_print("[+] ETW network trace started\n");
    ULONG status = ProcessTrace(&g_TraceHandle, 1, NULL, NULL);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
        safe_print("[ETW] ProcessTrace failed: %u\n", status);
    }

    if (g_TraceHandle != 0 && g_TraceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_TraceHandle);
    }
    g_TraceHandle = 0;
    g_etwRunning = false;
    safe_print("[+] ETW network trace stopped\n");
}

bool AdvancedBehaviorMonitor::StartKernelNetworkTrace() {
    if (g_etwRunning.load()) return true;

    // Prepare EVENT_TRACE_PROPERTIES
    ULONG propsSize = sizeof(EVENT_TRACE_PROPERTIES) +
        (DWORD)((wcslen(ETW_SESSION_NAME) + 1) * sizeof(WCHAR));
    auto props = (EVENT_TRACE_PROPERTIES*)malloc(propsSize);
    if (!props) {
        safe_print("[ETW] Failed to allocate properties buffer\n");
        return false;
    }

    ZeroMemory(props, propsSize);
    props->Wnode.BufferSize = propsSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1; // QPC clock resolution
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->EnableFlags = EVENT_TRACE_FLAG_NETWORK_TCPIP; // Enable TCP/IP kernel events
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceW(&g_SessionHandle, ETW_SESSION_NAME, props);
    free(props);

    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) {
        safe_print("[ETW] StartTraceW failed: %u\n", status);
        return false;
    }

    if (status == ERROR_ALREADY_EXISTS) {
        safe_print("[ETW] Session already exists, attempting to attach\n");
    }

    g_etwRunning = true;
    g_etwThread = std::thread(EtwNetworkWorkerThread);
    return true;
}

bool AdvancedBehaviorMonitor::StopKernelNetworkTrace() {
    if (!g_etwRunning.load()) return true;

    // Stop the trace session
    if (g_SessionHandle != 0) {
        ULONG status = ControlTraceW(g_SessionHandle, ETW_SESSION_NAME, NULL, EVENT_TRACE_CONTROL_STOP);
        if (status != ERROR_SUCCESS && status != ERROR_INVALID_HANDLE) {
            safe_print("[ETW] ControlTraceW stop returned: %u\n", status);
        }
    }

    // Wait for worker thread to finish
    if (g_etwThread.joinable()) {
        g_etwThread.join();
    }

    g_SessionHandle = 0;
    g_etwRunning = false;
    return true;
}