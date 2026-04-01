#include "monitor.h"
#include "MemeryScan.h"
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <csignal>

// 全局监控器实例，用于信号处理
static AdvancedBehaviorMonitor* g_monitor = nullptr;

// 信号处理函数
void signalHandler(int signal) {
    std::cout << "\n[!] Received signal " << signal << ". Stopping monitoring..." << std::endl;
    if (g_monitor) {
        g_monitor->StopMonitoring();
    }
    exit(0);
}

void printUsage(const char* programName) {
    std::cout << "Advanced Behavior Monitor v2.0\n";
    std::cout << "===============================\n\n";
    std::cout << "Usage: " << programName << " <target_executable> [options]\n\n";
    std::cout << "Parameters:\n";
    std::cout << "  target_executable    Path to the executable to monitor\n\n";
    std::cout << "Options:\n";
    std::cout << "  -a, --args <args>    Arguments to pass to target executable\n";
    std::cout << "  -d, --duration <sec> Monitoring duration in seconds (default: 60, 0 = infinite)\n";
    std::cout << "  -o, --output <file>  Output report filename (default: behavior_report.txt)\n";
    std::cout << "  --no-etw             Disable ETW (Event Tracing for Windows) monitoring\n";
    std::cout << "  --enable-network     Enable network filtering (requires admin privileges)\n";
    std::cout << "  --no-process         Disable process creation monitoring\n";
    std::cout << "  -h, --help           Show this help message\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << programName << " notepad.exe\n";
    std::cout << "  " << programName << " malware.exe -d 120 -o malware_analysis.txt\n";
    std::cout << "  " << programName << " \"C:\\Program Files\\App\\app.exe\" --args \"--verbose\" --enable-network\n\n";
    std::cout << "Note: This tool requires administrator privileges for full functionality.\n";
    std::cout << "      Network filtering requires Windows Filtering Platform access.\n";
}

bool checkAdminPrivileges() {
    BOOL isAdmin = FALSE;
    PSID administratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administratorsGroup)) {
        if (!CheckTokenMembership(NULL, administratorsGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(administratorsGroup);
    }

    return isAdmin == TRUE;
}

int main(int argc, char* argv[]) {

    // 检查参数
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    // 检查帮助参数
    std::string firstArg = argv[1];
    if (firstArg == "-h" || firstArg == "--help") {
        printUsage(argv[0]);
        return 0;
    }

    // 检查管理员权限
    if (!checkAdminPrivileges()) {
        std::cout << "[!] Warning: Running without administrator privileges.\n";
        std::cout << "    Some monitoring features may be limited.\n\n";
    }
    else {
        std::cout << "[+] Running with administrator privileges.\n\n";
    }

    // 解析参数
    std::string targetExecutable = argv[1];
    std::string arguments;
    int duration = 60;
    std::string outputFile = "behavior_report.txt";
    bool enableETW = true;
    bool enableNetwork = false;
    bool enableProcess = true;

    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-a" || arg == "--args") {
            if (i + 1 < argc) {
                arguments = argv[++i];
            }
            else {
                std::cerr << "[-] Error: " << arg << " requires an argument\n";
                return 1;
            }
        }
        else if (arg == "-d" || arg == "--duration") {
            if (i + 1 < argc) {
                try {
                    duration = std::stoi(argv[++i]);
                    if (duration < 0) {
                        std::cerr << "[-] Error: Duration must be non-negative\n";
                        return 1;
                    }
                }
                catch (const std::exception&) {
                    std::cerr << "[-] Error: Invalid duration value\n";
                    return 1;
                }
            }
            else {
                std::cerr << "[-] Error: " << arg << " requires an argument\n";
                return 1;
            }
        }
        else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) {
                outputFile = argv[++i];
            }
            else {
                std::cerr << "[-] Error: " << arg << " requires an argument\n";
                return 1;
            }
        }
        else if (arg == "--no-etw") {
            enableETW = false;
        }
        else if (arg == "--enable-network") {
            enableNetwork = true;
        }
        else if (arg == "--no-process") {
            enableProcess = false;
        }
        else {
            std::cerr << "[-] Error: Unknown option " << arg << "\n";
            printUsage(argv[0]);
            return 1;
        }
    }

    // 验证目标文件存在
    DWORD fileAttributes = GetFileAttributesA(targetExecutable.c_str());
    if (fileAttributes == INVALID_FILE_ATTRIBUTES) {
        std::cerr << "[-] Error: Target executable not found: " << targetExecutable << std::endl;
        return 1;
    }

    // 显示配置信息
    std::cout << "Configuration:\n";
    std::cout << "  Target: " << targetExecutable << "\n";
    if (!arguments.empty()) {
        std::cout << "  Arguments: " << arguments << "\n";
    }
    std::cout << "  Duration: " << (duration == 0 ? "Infinite" : std::to_string(duration) + " seconds") << "\n";
    std::cout << "  Output File: " << outputFile << "\n";
    std::cout << "  ETW Monitoring: " << (enableETW ? "Enabled" : "Disabled") << "\n";
    std::cout << "  Network Filtering: " << (enableNetwork ? "Enabled" : "Disabled") << "\n";
    std::cout << "  Process Monitoring: " << (enableProcess ? "Enabled" : "Disabled") << "\n\n";

    if (enableNetwork && !checkAdminPrivileges()) {
        std::cout << "[!] Warning: Network filtering enabled but running without admin privileges.\n";
        std::cout << "    Network filtering may fail.\n\n";
    }

    // 设置信号处理
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    // 创建并配置监控器
    AdvancedBehaviorMonitor monitor;
    g_monitor = &monitor;
    g_isMaliciousDetected = false;

    monitor.SetMonitoringDuration(duration);
    monitor.EnableETWMonitoring(enableETW);
    monitor.EnableNetworkFilter(enableNetwork);
    monitor.EnableProcessMonitoring(enableProcess);

    std::cout << "[+] Starting advanced behavior monitoring...\n";
    std::cout << "[+] Press Ctrl+C to stop monitoring early\n\n";

    // 开始监控
    if (!monitor.StartMonitoring(targetExecutable, arguments)) {
        std::cerr << "[-] Failed to start monitoring" << std::endl;
        return 1;
    }

    // 监控状态循环
    auto startTime = std::chrono::steady_clock::now();
    size_t lastEventCount = 0;

    while (monitor.IsMonitoring()) {
        std::this_thread::sleep_for(std::chrono::seconds(5));

        auto currentTime = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime).count();
        size_t currentEventCount = monitor.GetEventCount();

        // 显示进度信息
        std::cout << "[*] Monitoring... Elapsed: " << elapsed << "s, Events: "
            << currentEventCount << " (+[+" << (currentEventCount - lastEventCount) << "])\r\n" << std::flush;
        lastEventCount = currentEventCount;

        if (!g_isMaliciousDetected) {
            MemeryScan(argv[1]);
        }
        else {
            printf("[*] MALICIOUS already detected - skip memory scan...\n");
        }

        if (g_isMaliciousDetected) {
            printf("[!!!] MALICIOUS DETECTED - stop further scans, waiting for monitoring end...\n");
        }

        // 检查是否超时
        if (duration > 0 && elapsed >= duration) {
            std::cout << "\n[!] Monitoring duration reached." << std::endl;
            break;
        }
    }

    if (g_isMaliciousDetected) {
        printf("\n[!!!] Monitoring finished - MALICIOUS PE INJECTION DETECTED!\n");
    }
    else {
        printf("\n[+] Monitoring finished - NO MALICIOUS PE INJECTION DETECTED\n");
    }

    std::cout << "\n\n[+] Monitoring completed. Generating report..." << std::endl;

    // 生成报告
    monitor.GenerateReport(outputFile);

    std::cout << "[+] Advanced behavior monitoring completed successfully!" << std::endl;
    std::cout << "[+] Report saved to: " << outputFile << std::endl;

    // 显示最终统计
    std::cout << "\nFinal Statistics:\n";
    std::cout << "  Total Events Captured: " << monitor.GetEventCount() << "\n";
    std::cout << "  Monitoring Duration: " << std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - startTime).count() << " seconds\n";

    g_monitor = nullptr;
    return 0;
}