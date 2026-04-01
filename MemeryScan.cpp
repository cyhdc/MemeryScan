#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <stdio.h>
#include <ctype.h>
#include "MemeryScan.h"

#pragma comment(lib, "ntdll.lib")

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation = 0,
    MemoryWorkingSetList,
    MemorySectionName = 2,
    MemoryBasicVlmInformation
} MEMORY_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI* PFN_ZwQueryVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
    );

PFN_ZwQueryVirtualMemory ZwQueryVirtualMemory = NULL;

BOOL IsExecutable(DWORD protect);
BOOL IsStringInMem(HANDLE hProc, LPVOID base, SIZE_T size, const char* searchStr);
BOOL IsPEFile(HANDLE hProc, LPVOID base, SIZE_T size);
VOID ScanForInjection(HANDLE hProc);
VOID DumpSuspiciousRegion(HANDLE hProcess, LPVOID base, SIZE_T size, const char* reason);
int ScanAllProcessesByName(const char* processName);
int ScanSingleProcess(DWORD pid);
int GetSuspiciousRegionCount(HANDLE hProc);

bool g_isMaliciousDetected = false;

const CHAR* suspiciousStringsA[] = {
    "Started service %s on %s"
};

const WCHAR* suspiciousStringsW[] = {
    L"C:\\Windows\\System32\\notepad.exe@C:\\Windows\\SysWOW64\\notepad.exe"
};

SIZE_T NUM_SUSPICIOUS_STRINGS_A = sizeof(suspiciousStringsA) / sizeof(suspiciousStringsA[0]);

SIZE_T NUM_SUSPICIOUS_STRINGS_W = sizeof(suspiciousStringsW) / sizeof(suspiciousStringsW[0]);

BOOL EnableDebugPrivilege(BOOL bEnable) {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) { return FALSE; }
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) { CloseHandle(hToken); return FALSE; }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) { CloseHandle(hToken); return FALSE; }
    CloseHandle(hToken);
    return TRUE;
}

VOID MemeryScan(const char* fileName)
{
    if (g_isMaliciousDetected) {
        return;
    }

    // Initialize ZwQueryVirtualMemory once
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] GetModuleHandleA failed.\n");
        return;
    }
    ZwQueryVirtualMemory = (PFN_ZwQueryVirtualMemory)GetProcAddress(hNtdll, "ZwQueryVirtualMemory");
    if (!ZwQueryVirtualMemory) {
        printf("[-] GetProcAddress ZwQueryVirtualMemory failed.\n");
        return ;
    }

    printf("Start Memery Scan ...\n");
    
    ScanAllProcessesByName(fileName);
}

int ScanSingleProcess(DWORD pid) {
    // 检测到恶意时直接返回
    if (g_isMaliciousDetected) {
        return 0;
    }

    printf("[+] Scanning process PID %u for potential PE injection...\n", pid);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        printf("[-] OpenProcess(%u) failed: %u\n", pid, GetLastError());
        return 1;
    }

    ScanForInjection(hProc);
    CloseHandle(hProc);
    return 0;
}

int ScanAllProcessesByName(const char* processName) {
    // 检测到恶意时直接返回，不扫描
    if (g_isMaliciousDetected) {
        printf("[*] Malicious already detected - skip process scan\n");
        return 0;
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        printf("[-] CreateToolhelp32Snapshot failed with error: %u\n", GetLastError());
        return 1;
    }

    PROCESSENTRY32 pe = { sizeof(pe) };
    int processesFound = 0;

    // 将输入的char*参数转换为WCHAR，以便与PROCESSENTRY32的szExeFile匹配
    wchar_t wProcessName[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, processName, -1, wProcessName, MAX_PATH);

    if (Process32First(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, wProcessName) == 0) {
                printf("[+] Found process: %s (PID: %u)\n", processName, pe.th32ProcessID);
                ScanSingleProcess(pe.th32ProcessID);
                processesFound++;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);

    if (processesFound == 0) {
        printf("[-] No processes found with the name '%s'.\n", processName);
        return 1;
    }

    return 0;
}

BOOL IsExecutable(DWORD protect) {
    // Check for executable permissions (RX or RWX or WCX)
    return (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE
        | PAGE_EXECUTE_WRITECOPY | PAGE_GUARD)) != 0;
}

BOOL IsStringInMemA(HANDLE hProc, LPVOID base, SIZE_T size,
    const CHAR** searchStrs, SIZE_T strCount) {
    if (size == 0 || !searchStrs || strCount == 0) {
        return FALSE;
    }

    // Limit the read size to prevent processing large memory regions, up to 10MB
    SIZE_T maxReadSize = min(size, 1024 * 1024 * 10);

    // Read memory by chunk for search
    SIZE_T chunkSize = 4096; // 4KB
    BYTE chunk[4096 + 256]; // Add an overlap region to prevent strings from spanning chunks

    for (SIZE_T offset = 0; offset < maxReadSize; offset += chunkSize) {
        SIZE_T bytesToRead = min(maxReadSize - offset, chunkSize + 256);
        SIZE_T bytesRead = 0;

        if (!ReadProcessMemory(hProc, (LPVOID)((ULONG_PTR)base + offset), chunk, bytesToRead, &bytesRead)) {
            // Read failed, possible permission issue, stop searching

            return FALSE;

        }

        if (bytesRead < 1) {
            break; // Memory block too small, unable to continue searching

        }

        // Iterate through all suspicious strings

        for (SIZE_T strIndex = 0; strIndex < strCount; strIndex++) {
            const char* searchStr = searchStrs[strIndex];

            SIZE_T searchLen = strlen(searchStr);

            if (bytesRead < searchLen) {
                continue; // Memory block shorter than current search string, skip

            }

            // Perform a case-insensitive search in the current memory block

            for (SIZE_T i = 0; i <= bytesRead - searchLen; i++) {
                BOOL match = TRUE;
                for (SIZE_T j = 0; j < searchLen; j++) {
                    if (tolower(chunk[i + j]) != tolower(searchStr[j])) {
                        match = FALSE;
                        break;
                    }
                }
                if (match) {
                    return TRUE; // Found any string, immediately returns TRUE
                }
            }
        }
    }

    return FALSE; // Entire region search completed, no string found
}

BOOL IsStringInMemW(HANDLE hProc, LPVOID base, SIZE_T size, const wchar_t** searchStrs, SIZE_T strCount) {
    if (size == 0 || !searchStrs || strCount == 0) {
        return FALSE;
    }

    SIZE_T maxReadSize = min(size, 1024 * 1024 * 10);
    SIZE_T chunkSize = 4096;
    wchar_t chunk[4096 / sizeof(wchar_t) + 256 / sizeof(wchar_t)];

    for (SIZE_T offset = 0; offset < maxReadSize; offset += chunkSize) {
        SIZE_T bytesToRead = min(maxReadSize - offset, chunkSize + 256);
        SIZE_T bytesRead = 0;

        if (!ReadProcessMemory(hProc, (LPVOID)((ULONG_PTR)base + offset), chunk, bytesToRead, &bytesRead)) {
            return FALSE;
        }

        SIZE_T wc_count = bytesRead / sizeof(wchar_t);
        if (wc_count < 1) {
            break;
        }

        for (SIZE_T strIndex = 0; strIndex < strCount; strIndex++) {
            const wchar_t* searchStr = searchStrs[strIndex];
            SIZE_T searchLen = wcslen(searchStr);

            if (wc_count < searchLen) {
                continue;
            }

            for (SIZE_T i = 0; i <= wc_count - searchLen; i++) {
                BOOL match = TRUE;
                for (SIZE_T j = 0; j < searchLen; j++) {
                    if (towlower(chunk[i + j]) != towlower(searchStr[j])) {
                        match = FALSE;
                        break;
                    }
                }
                if (match) {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

BOOL IsStringInMem(HANDLE hProc, LPVOID base, SIZE_T size)
{
    if (IsStringInMemA(hProc, base, size, suspiciousStringsA, NUM_SUSPICIOUS_STRINGS_A) ||
        IsStringInMemW(hProc, base, size, suspiciousStringsW, NUM_SUSPICIOUS_STRINGS_W)) {
        return TRUE;
    }

    return FALSE;
}

BOOL IsPEFile(HANDLE hProc, LPVOID base, SIZE_T size) {
    const SIZE_T BUFFER_SIZE = 4096;
    BYTE buffer[4096];
    SIZE_T currentOffset = 0;

    // 循环扫描整个内存区域
    while (currentOffset < size) {
        SIZE_T bytesRead = 0;
        SIZE_T bytesToRead = min(size - currentOffset, BUFFER_SIZE);

        // 1. 读取内存块
        if (!ReadProcessMemory(hProc, (BYTE*)base + currentOffset, buffer, bytesToRead, &bytesRead) || bytesRead < 2) {
            // 如果读取失败或剩余字节不足以构成 MZ 头，则停止后续扫描
            break;
        }

        // 2. 在当前 buffer 内遍历寻找 'MZ'
        // 注意：循环只到 bytesRead - 1，防止 buffer[i+1] 越界
        for (SIZE_T i = 0; i < bytesRead - 1; i++) {

            // 检查 MZ 签名
            if (buffer[i] == 'M' && buffer[i + 1] == 'Z') {

                // 找到了疑似 MZ 头，开始严格验证
                // 我们需要读取 PE 头偏移量 (e_lfanew)，它位于 MZ 头开始后的 0x3C (60) 字节处

                DWORD e_lfanew = 0;
                BOOL readLfanewSuccess = FALSE;

                // 优化：尝试直接从 buffer 中获取 e_lfanew，避免额外的 API 调用
                if (i + 0x3C + sizeof(DWORD) <= bytesRead) {
                    e_lfanew = *(DWORD*)&buffer[i + 0x3C];
                    readLfanewSuccess = TRUE;
                }
                else {
                    // 如果 buffer 不够长（MZ 在块末尾），则从远程内存读取
                    SIZE_T rw = 0;
                    if (ReadProcessMemory(hProc, (BYTE*)base + currentOffset + i + 0x3C, &e_lfanew, sizeof(DWORD), &rw)) {
                        readLfanewSuccess = TRUE;
                    }
                }

                if (readLfanewSuccess) {
                    // 简单的合理性检查：e_lfanew 不应过大或为0
                    if (e_lfanew > 0 && e_lfanew < 0x10000000) { // 这里上限可以根据需求调整，通常 PE 头不会离 DOS 头太远

                        // 计算 PE 签名的绝对地址：Base + CurrentOffset + i (MZ位置) + e_lfanew
                        // 我们需要验证这里是不是 "PE\0\0" (0x00004550)

                        DWORD peSig = 0;
                        BOOL readSigSuccess = FALSE;

                        // 优化：如果 PE 签名也在当前 buffer 内，直接比对
                        if (i + e_lfanew + sizeof(DWORD) <= bytesRead) {
                            peSig = *(DWORD*)&buffer[i + e_lfanew];
                            readSigSuccess = TRUE;
                        }
                        else {
                            // 否则读取远程内存
                            SIZE_T rw = 0;
                            if (ReadProcessMemory(hProc, (BYTE*)base + currentOffset + i + e_lfanew, &peSig, sizeof(DWORD), &rw)) {
                                readSigSuccess = TRUE;
                            }
                        }

                        if (readSigSuccess) {
                            // 检查 PE 签名 (Little Endian: 'P' 'E' \0 \0 => 0x00004550)
                            if (peSig == 0x00004550) {
                                return TRUE; // 成功找到完整的 PE 文件，立即返回
                            }
                        }
                    }
                }

                // 如果代码走到这里，说明虽然找到了 'MZ'，但后续验证失败（不是 PE 文件）。
                // 循环将继续执行 (i++)，寻找 buffer 中的下一个 'MZ'。
            }
        }

        // 3. 准备读取下一个块
        // 这里的关键是处理边界问题：如果 'M' 在当前块的最后一个字节，'Z' 在下一个块的第一个字节怎么办？
        // 解决方法：将 currentOffset 向前移动时，回退 1 个字节（overlap）。
        currentOffset += bytesRead - 1;

        // 防止死循环（如果 bytesRead 为 0 或 1，上面的逻辑可能导致 offset 不变）
        if (bytesRead <= 1) break;
    }

    // 扫描完整个区域都没有返回 TRUE，说明不是 PE 文件
    return FALSE;
}

VOID ScanForInjection(HANDLE hProc) 
{
    // 检测到恶意时直接返回
    if (g_isMaliciousDetected) {
        return;
    }

    SIZE_T offset = 0;
    MEMORY_BASIC_INFORMATION64 mbi64;
    BOOL foundSuspicious = FALSE;


    while (TRUE) {

        NTSTATUS status = ZwQueryVirtualMemory(hProc, (PVOID)offset, MemoryBasicInformation,
            &mbi64, sizeof(mbi64), NULL);
        if (status != 0) break;  // STATUS_SUCCESS == 0

        // Check if memory is committed and executable
        if (mbi64.State == MEM_COMMIT && IsExecutable(mbi64.Protect)) {
            const char* memType = (mbi64.Type == MEM_PRIVATE) ? "Private" :
                (mbi64.Type == MEM_MAPPED) ? "Mapped" : "Unknown";

            // Check if this region contains a PE file
            if (IsPEFile(hProc, (LPVOID)mbi64.BaseAddress, mbi64.RegionSize)) {
                if (IsStringInMem(hProc, (LPVOID)mbi64.BaseAddress, mbi64.RegionSize)) {
                    printf("    [!] There is a special string, suspected CS characteristic!\n");
                }
                g_isMaliciousDetected = true;
                printf("    [!] SUSPICIOUS: PE file detected in %s executable memory!\n", memType);
                printf("        Base=0x%llx Size=0x%llx Protect=0x%x\n",
                    mbi64.BaseAddress, mbi64.RegionSize, mbi64.Protect);
                printf("        This could indicate process injection!\n");

                char reason[256];
                sprintf(reason, "PE_in_%s_memory_0x%llx", memType, mbi64.BaseAddress);
                DumpSuspiciousRegion(hProc, (LPVOID)mbi64.BaseAddress, mbi64.RegionSize, reason);
                foundSuspicious = TRUE;
            }
        }

        // Move to next region
        SIZE_T nextOffset = (SIZE_T)mbi64.BaseAddress + mbi64.RegionSize;
        if (nextOffset <= offset) break;  // Prevent infinite loop
        offset = nextOffset;
    }

    if (!foundSuspicious) {
        printf("[+] No suspicious PE injection detected in this process's executable memory.\n");
    }
}

int GetSuspiciousRegionCount(HANDLE hProc) {
    SIZE_T offset = 0;
    int suspiciousCount = 0;
    MEMORY_BASIC_INFORMATION64 mbi64;

    while (TRUE) {
        NTSTATUS status = ZwQueryVirtualMemory(hProc, (PVOID)offset, MemoryBasicInformation,
            &mbi64, sizeof(mbi64), NULL);
        if (status != 0) break;

        if (mbi64.State == MEM_COMMIT && IsExecutable(mbi64.Protect)) {
            if (IsPEFile(hProc, (LPVOID)mbi64.BaseAddress, mbi64.RegionSize)) {
                suspiciousCount++;
            }
        }

        SIZE_T nextOffset = (SIZE_T)mbi64.BaseAddress + mbi64.RegionSize;
        if (nextOffset <= offset) break;
        offset = nextOffset;
    }

    return suspiciousCount;
}

VOID DumpSuspiciousRegion(HANDLE hProcess, LPVOID base, SIZE_T size, const char* reason) {
    // Limit dump size to prevent huge files
    SIZE_T dumpSize = min(size, 1024 * 1024); // Max 1MB dump

    BYTE* buffer = (BYTE*)malloc(dumpSize);
    if (!buffer) {
        printf("    [-] Failed to allocate memory for dump\n");
        return;
    }

    SIZE_T bytesRead = 0;
    if (ReadProcessMemory(hProcess, base, buffer, dumpSize, &bytesRead) && bytesRead > 0) {
        char filename[MAX_PATH];
        sprintf(filename, "suspicious_%s.bin", reason);

        FILE* fp = fopen(filename, "wb");
        if (fp) {
            fwrite(buffer, 1, bytesRead, fp);
            fclose(fp);
            printf("    [+] Dumped %llu bytes to %s\n", (unsigned long long)bytesRead, filename);
        }
        else {
            printf("    [-] Failed to create dump file %s\n", filename);
        }
    }
    else {
        printf("    [-] Failed to read memory for dump\n");
    }

    free(buffer);
}