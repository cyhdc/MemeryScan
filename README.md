# Advanced Behavior Monitor

## 核心功能: 内存扫描与 进程 注入检测

本工具的核心功能是检测进程内存中的 **进程注入攻击**，这是一种常见的恶意代码技术，攻击者将恶意 PE 文件注入到合法进程的内存中执行，以逃避检测。

### 内存扫描特性

#### 1. PE 文件特征检测
- 扫描进程所有可执行内存区域 (PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE 等)
- 通过 MZ 头和 PE 签名 (0x00004550) 识别注入的 PE 文件
- 支持检测 Private、Mapped 等不同类型的内存区域

#### 2. 可疑字符串检测
- 在检测到 PE 特征的内存区域中搜索已知恶意特征字符串
- 支持 ANSI 和 Unicode 字符串匹配
- 可扩展的特征字符串库

#### 3. 内存转储
- 自动将可疑内存区域导出为 `.bin` 文件
- 最大转储大小 1MB，便于后续分析
- 文件命名包含内存类型和基地址信息

#### 4. 多进程扫描
- 支持按进程名扫描所有匹配的进程实例
- 使用 `ZwQueryVirtualMemory` 进行高效的内存枚举

---

## 辅助功能: 行为监控 (ETW)

### 文件 I/O 监控
- 跟踪文件的创建、读取、写入、删除和重命名操作

### 注册表监控
- 监控注册表键的创建、打开、删除和值操作

### 网络监控
- 捕获 TCP/IPv4 和 TCP/IPv6 连接事件
- 显示源/目标 IP 和端口

### 进程/线程监控
- 监控进程创建、启动和退出事件
- 跟踪子进程创建
- 跟踪线程的启动和结束

### 网络过滤 (可选)
- 基于 Windows Filtering Platform (WFP) 的网络过滤

### 报告生成
- 自动生成详细的监控报告
- 包含事件统计和摘要分析

## 系统要求

- **操作系统**: Windows 10/11 或 Windows Server 2016+
- **权限**: 管理员权限 (推荐，部分功能必需)
- **编译环境**: Visual Studio 2019+ (支持 C++17)

## 编译方法

### 使用 Visual Studio

1. 打开 `monitor.sln` 解决方案文件
2. 选择 Release 或 Debug 配置
3. 选择 x64 平台
4. 构建项目 (Ctrl+Shift+B)

### 依赖库

项目依赖以下 Windows 库 (已在代码中通过 `#pragma comment` 链接):

- `shlwapi.lib` - Shell 轻量级工具 API
- `iphlpapi.lib` - IP Helper API
- `ws2_32.lib` - Windows Sockets
- `fwpuclnt.lib` - Windows Filtering Platform
- `secur32.lib` - 安全支持提供程序接口
- `advapi32.lib` - 高级 Windows API
- `tdh.lib` - 事件跟踪帮助程序

## 使用方法

### 基本语法

```
monitor.exe <target_executable> [options]
```

### 命令行参数

| 参数 | 说明 |
|------|------|
| `target_executable` | 要监控的目标可执行文件路径 |
| `-a, --args <args>` | 传递给目标程序的参数 |
| `-d, --duration <sec>` | 监控持续时间(秒)，默认60秒，0表示无限 |
| `-o, --output <file>` | 输出报告文件名，默认为 `behavior_report.txt` |
| `--no-etw` | 禁用 ETW 监控 |
| `--enable-network` | 启用网络过滤 (需要管理员权限) |
| `--no-process` | 禁用进程创建监控 |
| `-h, --help` | 显示帮助信息 |

### 使用示例

```bash
# 基本监控
monitor.exe notepad.exe

# 指定监控时长和输出文件
monitor.exe malware.exe -d 120 -o malware_analysis.txt

# 带参数运行并启用网络过滤
monitor.exe "C:\Program Files\App\app.exe" --args "--verbose" --enable-network

# 无限时长监控
monitor.exe suspicious.exe -d 0
```

## 输出说明

### PE 注入检测输出 (核心功能)

当检测到可疑的 PE 注入时，会输出警告:

```
[+] Scanning process PID 1234 for potential PE injection...
[+] Found process: notepad.exe (PID: 1234)
    [!] SUSPICIOUS: PE file detected in Private executable memory!
        Base=0x12340000 Size=0x10000 Protect=0x40
        This could indicate process injection!
    [!] There is a special string, suspected CS characteristic!
    [+] Dumped 65536 bytes to suspicious_PE_in_Private_memory_0x12340000.bin
```

#### 检测结果说明

| 输出 | 含义 |
|------|------|
| `PE file detected in Private executable memory` | 在私有可执行内存中发现 PE 文件 |
| `PE file detected in Mapped executable memory` | 在映射可执行内存中发现 PE 文件 |
| `There is a special string, suspected CS characteristic` | 检测到可疑特征字符串 (如 Cobalt Strike 特征) |
| `Base=0x...` | 可疑内存区域基地址 |
| `Size=0x...` | 可疑内存区域大小 |
| `Protect=0x...` | 内存保护属性 |

#### 内存保护属性参考

| 值 | 含义 |
|----|------|
| 0x20 | PAGE_EXECUTE_READWRITE |
| 0x40 | PAGE_EXECUTE_READ |
| 0x10 | PAGE_EXECUTE |
| 0x80 | PAGE_EXECUTE_WRITECOPY |

### 行为监控输出

程序运行时会实时输出监控到的事件:

```
[2024-01-15 10:30:45.123] notepad.exe (1234:5678) FILE_CREATE -> Path: C:\Temp\test.txt
[2024-01-15 10:30:46.456] notepad.exe (1234:5678) REG_SET_VALUE -> Key: HKCU\Software\Test
[2024-01-15 10:30:47.789] notepad.exe (1234:5678) TCP_CONNECT -> 192.168.1.1:80 -> 10.0.0.1:443
```

### 报告文件

监控结束后会生成详细的报告文件，包含:

1. **监控概览**: 目标进程信息、监控时长、事件总数
2. **事件统计**: 各类事件的数量统计
3. **进程列表**: 被监控的所有进程 (包括子进程)
4. **详细日志**: 所有捕获事件的完整记录
5. **摘要分析**: 对行为的简要安全分析

## 项目结构

```
monitor/
├── main.cpp                # 程序入口，命令行解析，监控循环
├── monitor.h               # ETW 方案 - AdvancedBehaviorMonitor 类声明
├── monitor.cpp             # ETW 方案 - 行为监控实现 (当前使用)
├── monitor - Copy.h        # Hook 方案 - Syscall Hook 类声明 (备用)
├── monitor - Copy.cpp      # Hook 方案 - Inline Hook 实现备用)
├── MemeryScan.h            # 内存扫描模块声明 (核心)
├── MemeryScan.cpp          # PE 注入检测实现 (核心)
├── monitor.sln             # Visual Studio 解决方案
├── monitor.vcxproj         # Visual Studio 项目文件
├── monitor.vcxproj.filters # VS 项目筛选器
├── monitor.vcxproj.user    # VS 用户配置
└── README.md               # 本文档
```

### 文件说明

| 文件 | 类型 | 说明 |
|------|------|------|
| `main.cpp` | 源码 | 程序入口点，参数解析，监控主循环，调用内存扫描 |
| `monitor.h` | 头文件 | **ETW 方案** - AdvancedBehaviorMonitor 类声明 |
| `monitor.cpp` | 源码 | **ETW 方案** - ETW 监控、网络过滤、报告生成 (当前使用) |
| `monitor - Copy.h` | 备用 | **Hook 方案** - 包含 Syscall Hook 相关结构体和 NT API 声明 |
| `monitor - Copy.cpp` | 备用 | **Hook 方案** - 19 个 NT API 的 Inline Hook 实现 |
| `MemeryScan.h` | 头文件 | 内存扫描模块声明 (核心功能) |
| `MemeryScan.cpp` | 源码 | PE 注入检测、内存转储实现 (核心功能) |

### 两套方案对比

| 特性 | ETW 方案 | Hook 方案 |
|------|------------------|-------------------|
| 实现文件 | `monitor.h/cpp` | `monitor - Copy.h/cpp` |
| 监控机制 | Windows 内核事件跟踪 | 用户态 API 钩取 |
| 侵入性 | 低 (被动接收事件) | 高 (修改目标进程代码) |
| 稳定性 | 高 | 中 (可能被检测/绕过) |
| 事件详细度 | 依赖 Provider | 可自定义捕获内容 |
| 性能影响 | 低 | 中 |
| 兼容性 | Windows 内置 | 需要处理 ASLR/CFG 等 |

#### Hook 方案支持的 NT API

Hook 方案 (`monitor - Copy.cpp`) 钩取以下系统调用:

| 类别 | 函数 |
|------|------|
| 文件操作 | `NtCreateFile`, `NtOpenFile`, `NtReadFile`, `NtWriteFile` |
| 注册表操作 | `NtCreateKey`, `NtOpenKey`, `NtDeleteKey`, `NtSetValueKey`, `NtQueryValueKey` |
| 进程操作 | `NtCreateProcess`, `NtCreateProcessEx`, `NtOpenProcess`, `NtTerminateProcess` |
| 线程操作 | `NtCreateThreadEx`, `NtOpenThread`, `NtTerminateThread` |
| 内存操作 | `NtAllocateVirtualMemory`, `NtProtectVirtualMemory` |
| 网络操作 | `NtDeviceIoControlFile` |

## 核心模块说明

### MemeryScan 模块 (核心)

内存扫描和 PE 注入检测的主要实现:

| 函数 | 说明 |
|------|------|
| `MemeryScan()` | 扫描入口，初始化并启动扫描 |
| `ScanAllProcessesByName()` | 按名称查找并扫描所有匹配进程 |
| `ScanSingleProcess()` | 扫描单个进程的内存 |
| `ScanForInjection()` | 遍历进程内存区域，检测 PE 注入 |
| `IsPEFile()` | 验证内存中是否存在有效的 PE 文件 (MZ + PE 签名) |
| `IsExecutable()` | 检查内存保护属性是否可执行 |
| `IsStringInMemA/W()` | 在内存中搜索可疑特征字符串 |
| `DumpSuspiciousRegion()` | 导出可疑内存区域到文件 |
| `EnableDebugPrivilege()` | 启用调试权限以访问目标进程 |

#### PE 检测算法

1. 枚举进程所有内存区域 (`ZwQueryVirtualMemory`)
2. 筛选已提交且可执行的内存区域
3. 在内存中搜索 MZ 签名 (0x4D5A)
4. 读取 e_lfanew 偏移量 (0x3C 处)
5. 验证 PE 签名 (0x00004550)
6. 可选: 搜索可疑特征字符串
7. 转储可疑区域到文件

### AdvancedBehaviorMonitor 类 (辅助)

ETW 行为监控控制器:
- 创建和管理目标进程
- 配置和启动 ETW 跟踪会话
- 处理文件/注册表/网络/进程事件回调
- 设置 Windows Filtering Platform 网络过滤器
- 监控子进程创建
- 生成监控报告

### ETW Provider GUIDs

| Provider | GUID | 用途 |
|----------|------|------|
| FileIo | 90cbdc39-4a3e-11d1-84f4-0000f80464e3 | 文件 I/O 事件 |
| Registry | ae53722e-c863-11d2-8659-00c04fa321a1 | 注册表事件 |
| Process | 3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c | 进程事件 |
| Thread | 3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c | 线程事件 |
| TcpIp | 7dd42a49-5329-4832-8dfd-43d979153a88 | 网络 TCP/IP 事件 |

## 安全分析指标

报告中的摘要分析会根据以下指标发出警告:

- **网络活动**: 检测到网络连接事件
- **高注册表活动**: 注册表操作超过 10 次
- **子进程创建**: 检测到子进程

## 注意事项

1. **权限要求**: 建议以管理员身份运行以获得完整的监控能力
2. **防病毒软件**: 可能被某些安全软件误报，需要添加白名单
3. **系统影响**: ETW 监控对系统性能影响较小
4. **目标进程**: 监控结束后会终止目标进程及其子进程

## 用途场景

- **进程注入检测**: 检测 PE 注入、DLL 注入、进程镂空等攻击技术
- **恶意软件分析**: 分析可疑程序的行为特征
- **威胁狩猎**: 在系统中查找潜在的恶意进程
- **内存取证**: 转储可疑内存区域进行离线分析
- **安全研究**: 研究进程注入技术和检测方法
- **EDR/XDR 补充**: 作为终端检测的辅助工具

## 技术细节

### 内存扫描流程

```
┌─────────────────────────────────────────────────────────┐
│                    内存扫描流程                          │
├─────────────────────────────────────────────────────────┤
│  1. 启用 SeDebugPrivilege 调试权限                      │
│          ↓                                              │
│  2. 获取 ZwQueryVirtualMemory 函数地址                  │
│          ↓                                              │
│  3. 按进程名枚举所有目标进程                             │
│          ↓                                              │
│  4. 对每个进程:                                         │
│     ├─ 遍历所有内存区域                                 │
│     ├─ 筛选 MEM_COMMIT + 可执行属性                     │
│     ├─ 在内存中搜索 MZ 签名                             │
│     ├─ 验证 PE 签名 (e_lfanew -> PE\0\0)               │
│     ├─ 搜索可疑特征字符串                               │
│     └─ 转储可疑区域到文件                               │
└─────────────────────────────────────────────────────────┘
```

### 可检测的注入类型

| 注入类型 | 检测原理 |
|----------|----------|
| PE 注入 | 检测私有内存中的完整 PE 文件 |
| 进程镂空 | 检测内存区域与磁盘文件不一致 |
| 内存模块加载 | 检测手动映射的 PE 文件 |
| Shellcode 注入 | 检测可执行内存中的代码模式 |

## 许可证

本项目仅供安全研究和教育目的使用。

## 免责声明

本工具仅用于合法的安全分析和研究目的。用户需自行承担使用本工具的所有风险和责任。开发者不对任何滥用行为负责。
