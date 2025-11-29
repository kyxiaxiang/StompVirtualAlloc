# StompVirtualAlloc

[English](#english) | [中文](#中文)

---

## English

### Overview

**StompVirtualAlloc** is a stealthy memory allocation library that serves as a drop-in replacement for Windows `VirtualAlloc`/`VirtualFree` APIs. Instead of directly calling `VirtualAlloc` (which is heavily monitored by AV/EDR solutions), it cleverly allocates memory from the `.text` sections of legitimate system DLLs, making the allocated memory appear to belong to trusted modules.

### Key Features

**Fully Compatible API** - Drop-in replacement for `VirtualAlloc`/`VirtualFree`  
**Native API Integration** - Uses `NtProtectVirtualMemory` instead of `VirtualProtect` to bypass API hooks  
**Multi-DLL Pool Management** - Automatically expands capacity by loading additional DLLs when needed  
**Legitimate Module Attribution** - Allocated memory appears to belong to system DLLs  
**Smart Memory Alignment** - Automatically aligns allocations to 16-byte boundaries  
**Automatic Cleanup** - Properly frees loaded DLLs on destruction  

### Why This Matters: Stack Trace Evasion

**Critical Advantage**: Since the allocated memory resides within legitimate system DLL modules, this technique provides significant defense against stack trace analysis commonly employed by modern EDR solutions.

**Stack Trace Evasion with PIC Code**:
When you combine this allocator with Position Independent Code (PIC), you can achieve a higher level of stealth:

1. **Legitimate Module Attribution**: The memory address belongs to a trusted system DLL (e.g., `Chakra.dll` or `mshtml.dll`)
2. **Clean Call Stack**: When EDR performs stack unwinding, the execution appears to originate from within a legitimate module
3. **Reduced Suspicion**: No anomalous heap allocations or suspicious memory regions flagged by memory scanners
4. **Evasion of Memory Scanning**: Security products scanning for shellcode in suspicious regions will overlook code residing in trusted module space

**Example Scenario**:
```
Traditional VirtualAlloc:
[SUSPICIOUS] Call Stack: 
  -> UnknownRegion+0x1234 (RWX memory, no module)
  -> SuspiciousProcess.exe+0x5678

StompVirtualAlloc with PIC:
[LEGITIMATE] Call Stack:
  -> Chakra.dll+0x1234 (trusted system module)
  -> mshtml.dll+0x5678 (trusted system module)
```

**PIC Code Benefits**:
- No reliance on absolute addresses
- Can be loaded anywhere in memory
- When combined with this allocator, execution appears to originate from legitimate system modules
- Significantly harder for EDR to distinguish from normal system behavior  

### How It Works

1. **DLL Pool Initialization**: Loads candidate system DLLs (Chakra.dll, mshtml.dll, etc.)
2. **Text Section Discovery**: Locates the `.text` section within each loaded DLL
3. **Memory Allocation**: Carves out memory from the `.text` section
4. **Protection Modification**: Uses Native API `NtProtectVirtualMemory` to set desired memory protections
5. **Legitimate Attribution**: The allocated memory now appears to belong to a trusted system DLL

### Architecture

```
┌─────────────────────────────────────────────────┐
│          StompVirtualAlloc Interface            │
│  (Compatible with VirtualAlloc/VirtualFree)     │
└─────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│           Memory Allocator Core                 │
│  - Multi-DLL Pool Management                    │
│  - Smart Allocation Strategy                    │
│  - Automatic Capacity Expansion                 │
└─────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│              DLL Memory Pools                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐        │
│  │ Chakra   │ │ mshtml   │ │ ieframe  │ ...    │
│  │  .text   │ │  .text   │ │  .text   │        │
│  └──────────┘ └──────────┘ └──────────┘        │
└─────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│         Native API Layer                        │
│  NtProtectVirtualMemory (from ntdll.dll)        │
└─────────────────────────────────────────────────┘
```

### Candidate DLLs

The system automatically attempts to use the following DLLs in order:

- `Chakra.dll` - Microsoft's JavaScript engine
- `mshtml.dll` - Internet Explorer rendering engine
- `Windows.UI.Xaml.dll` - Windows UI framework
- `ieframe.dll` - Internet Explorer frame
- `edgehtml.dll` - Microsoft Edge rendering engine
- `mstscax.dll` - Remote Desktop Client Control

### Usage

#### Basic Usage

```cpp
#include "MyVirtualAlloc.h"

// Allocate executable memory
LPVOID memory = StompVirtualAlloc(
    NULL,                      // Let system choose address
    4096,                      // Size in bytes
    MEM_COMMIT | MEM_RESERVE,  // Allocation type
    PAGE_EXECUTE_READWRITE     // Protection
);

if (memory != NULL) {
    // Use the memory...
    
    // Free the memory when done
    StompVirtualFree(memory, 0, MEM_RELEASE);
}
```

#### Shellcode Loader Example

```cpp
#include "MyVirtualAlloc.h"
#include <vector>

// Load shellcode from file
std::vector<unsigned char> shellcode = LoadFromFile("payload.bin");

// Allocate memory
LPVOID execMemory = StompVirtualAlloc(
    NULL,
    shellcode.size(),
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);

// Copy shellcode
memcpy(execMemory, shellcode.data(), shellcode.size());

// Execute
typedef void (*ShellcodeFunc)();
ShellcodeFunc execute = (ShellcodeFunc)execMemory;
execute();

// Cleanup
StompVirtualFree(execMemory, 0, MEM_RELEASE);
```

### Building

#### Requirements

- Windows 10/11
- Visual Studio 2019 or later (with C++17 support)
- Windows SDK

#### Compilation

```bash
# Using Visual Studio Developer Command Prompt
cl /EHsc /std:c++17 Demo.cpp MyVirtualAlloc.cpp

# Or using MSBuild (if you have a .sln file)
msbuild MyVirtualAlloc.sln /p:Configuration=Release
```

### Demo Application

The included `Demo.cpp` demonstrates loading and executing shellcode from a file:

```bash
Demo.exe shellcode.bin
```

**Features:**
- Loads raw binary shellcode from file
- Displays shellcode preview (first 32 bytes)
- Allocates memory using StompVirtualAlloc
- Executes the shellcode
- Properly cleans up memory

### API Reference

#### StompVirtualAlloc

```cpp
LPVOID StompVirtualAlloc(
    LPVOID lpAddress,       // Reserved (ignored, always allocates new address)
    SIZE_T dwSize,          // Number of bytes to allocate
    DWORD flAllocationType, // Allocation type (ignored in this implementation)
    DWORD flProtect         // Memory protection (PAGE_EXECUTE_READWRITE, etc.)
);
```

**Returns:** Pointer to allocated memory, or `NULL` on failure.

#### StompVirtualFree

```cpp
BOOL StompVirtualFree(
    LPVOID lpAddress,      // Address to free
    SIZE_T dwSize,         // Size (ignored in this implementation)
    DWORD dwFreeType       // Free type (ignored in this implementation)
);
```

**Returns:** `TRUE` on success, `FALSE` on failure.

### Security Considerations

⚠️ **For Educational/Research Purposes Only**

This tool is designed for:
- Security research
- Red team operations
- Understanding AV/EDR evasion techniques
- Malware analysis

**Warning:** Using this in unauthorized systems may be illegal. Always obtain proper authorization before testing.

### Limitations

- Allocated memory is not truly "new" - it overwrites portions of DLL `.text` sections
- May cause instability if the overwritten code is executed by the system
- Pool capacity depends on available candidate DLLs
- Not suitable for large allocations (limited by DLL `.text` section sizes)

### Detection Considerations

While this technique is stealthy, potential detection vectors include:

- **Memory Integrity Checks**: EDR may verify DLL `.text` section integrity
- **Anomalous Memory Patterns**: Unusual RWX permissions in DLL regions
- **Native API Monitoring**: Advanced EDRs may hook Native APIs
- **Behavioral Analysis**: Suspicious memory access patterns

### Advanced Evasion Techniques

To further enhance stealth and evade sophisticated detection mechanisms, consider the following improvements:

#### 1. Replace Remaining Windows APIs

The current implementation still uses some standard Windows APIs that may be monitored. Consider replacing:

**Current Implementation:**
- `GetModuleHandleA` - Can be hooked
- `LoadLibraryA` - Heavily monitored by EDR
- `GetProcAddress` - Function resolution monitoring
- `FreeLibrary` - Module unload tracking

**Safer Alternatives:**

```cpp
// Instead of GetModuleHandleA/LoadLibraryA
// Use manual PEB walking to find loaded modules
HMODULE GetModuleByHash(DWORD hash) {
    // Walk PEB->Ldr->InLoadOrderModuleList
    // Compare hashed module names
}

// Instead of GetProcAddress
// Use manual export table parsing
FARPROC GetProcAddressByHash(HMODULE hModule, DWORD hash) {
    // Parse PE headers
    // Walk export directory
    // Compare hashed function names
}
```

#### 2. Syscall Direct Invocation

Instead of calling `NtProtectVirtualMemory` through `ntdll.dll`, use direct syscalls:

```cpp
// Direct syscall implementation
NTSTATUS SysNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) {
    // Dynamically resolve syscall number
    // Execute syscall instruction directly
    // Bypasses all usermode hooks
}
```

#### 3. API Hashing

Replace string-based API resolution with hash-based lookups to avoid static string detection:

```cpp
#define HASH_NTDLL              0x1edab0ed
#define HASH_NTPROTECTVIRTUALMEMORY  0x50e92888

// No visible API strings in binary
```

#### 4. Timing and Jitter

Add random delays and jitter to avoid behavioral pattern detection:

```cpp
// Random sleep between operations
Sleep(rand() % 1000 + 500);

// Randomize allocation order
std::random_shuffle(dllCandidates.begin(), dllCandidates.end());
```

#### 5. Memory Permissions Staging

Avoid directly setting RWX permissions. Instead, stage permissions:

```cpp
// Stage 1: Allocate as RW
NtProtectMemory(addr, size, PAGE_READWRITE, &old);

// Stage 2: Write payload
memcpy(addr, payload, size);

// Stage 3: Change to RX only when executing
NtProtectMemory(addr, size, PAGE_EXECUTE_READ, &old);
```

#### 6. Module Stomping Enhancement

Instead of using `.text` sections, consider:
- `.rdata` sections (less suspicious for RX)
- Unused code caves in legitimate modules
- Overwriting cold/unused functions

### Implementation Recommendations

For maximum stealth in production environments:

1. **Remove all standard API calls** - Use PEB walking and manual parsing only
2. **Implement direct syscalls** - Bypass all usermode hooks completely
3. **Use API hashing** - Eliminate static strings from your binary
4. **Add polymorphism** - Randomize implementation details per build
5. **Implement sleep obfuscation** - Use alternative timing mechanisms
6. **Memory permission staging** - Never use RWX directly

### Current Implementation Status

**Already Implemented:**
- Native API integration (`NtProtectVirtualMemory` instead of `VirtualProtect`)
- Memory allocation in legitimate system module space
- Multi-DLL pool management with automatic expansion
- Memory alignment and proper cleanup

**Recommended Future Enhancements:**
- PEB walking for module enumeration (replace `GetModuleHandleA`/`LoadLibraryA`)
- Direct syscalls (replace Native API calls through ntdll.dll)
- API hashing (eliminate string-based lookups)
- Memory permission staging (avoid direct RWX)
- Polymorphic code generation per build

### Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

### License

This project is provided as-is for educational purposes. Use responsibly and ethically.

---

## 中文

### 概述

**StompVirtualAlloc** 是一个隐蔽的内存分配库，可作为 Windows `VirtualAlloc`/`VirtualFree` API 的直接替代品。它不直接调用 `VirtualAlloc`（该函数被 AV/EDR 重点监控），而是巧妙地从合法系统 DLL 的 `.text` 段中分配内存，使分配的内存看起来属于受信任的模块。

### 核心特性

**完全兼容的 API** - 可直接替换 `VirtualAlloc`/`VirtualFree`  
**原生 API 集成** - 使用 `NtProtectVirtualMemory` 而非 `VirtualProtect` 来绕过 API 钩子  
**多 DLL 池管理** - 需要时自动加载额外的 DLL 来扩展容量  
**合法模块归属** - 分配的内存看起来属于系统 DLL  
**智能内存对齐** - 自动对齐到 16 字节边界  
**自动清理** - 析构时正确释放加载的 DLL  

### 核心优势：堆栈回溯规避

**关键优势**：由于申请的内存位于合法的系统 DLL 模块中，这一技术为对抗现代 EDR 解决方案常用的堆栈跟踪分析提供了显著的防御能力。

**使用 PIC 代码进行堆栈跟踪规避**：
当你将此分配器与位置无关代码（PIC）结合使用时，可以实现更高级别的隐蔽性：

1. **合法模块归属**：内存地址属于受信任的系统 DLL（例如 `Chakra.dll` 或 `mshtml.dll`）
2. **干净的调用堆栈**：当 EDR 执行堆栈展开时，执行看起来源自合法模块内部
3. **降低可疑性**：没有异常的堆分配或可疑的内存区域被内存扫描器标记
4. **逃避内存扫描**：安全产品扫描可疑区域中的 shellcode 时，会忽略位于受信任模块空间中的代码

**示例场景**：
```
传统的 VirtualAlloc：
[可疑] 调用堆栈：
  -> 未知区域+0x1234 (RWX 内存，无模块)
  -> 可疑进程.exe+0x5678

StompVirtualAlloc 配合 PIC：
[合法] 调用堆栈：
  -> Chakra.dll+0x1234 (受信任的系统模块)
  -> mshtml.dll+0x5678 (受信任的系统模块)
```

**PIC 代码的好处**：
- 不依赖绝对地址
- 可以在内存中的任何位置加载
- 与此分配器结合时，执行看起来源自合法的系统模块
- EDR 更难区分正常系统行为  

### 工作原理

1. **DLL 池初始化**：加载候选系统 DLL（Chakra.dll、mshtml.dll 等）
2. **文本段发现**：定位每个已加载 DLL 中的 `.text` 段
3. **内存分配**：从 `.text` 段中切出内存
4. **保护修改**：使用原生 API `NtProtectVirtualMemory` 设置所需的内存保护属性
5. **合法归属**：分配的内存现在看起来属于受信任的系统 DLL

### 架构

```
┌─────────────────────────────────────────────────┐
│          StompVirtualAlloc 接口                 │
│  (兼容 VirtualAlloc/VirtualFree)                │
└─────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│             内存分配器核心                       │
│  - 多 DLL 池管理                                │
│  - 智能分配策略                                 │
│  - 自动容量扩展                                 │
└─────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│              DLL 内存池                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐        │
│  │ Chakra   │ │ mshtml   │ │ ieframe  │ ...    │
│  │  .text   │ │  .text   │ │  .text   │        │
│  └──────────┘ └──────────┘ └──────────┘        │
└─────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│         原生 API 层                             │
│  NtProtectVirtualMemory (来自 ntdll.dll)        │
└─────────────────────────────────────────────────┘
```
<img width="1783" height="705" alt="image" src="https://github.com/user-attachments/assets/8541723a-0e9c-4379-a87b-5e6f8c4e9ab8" />

### 候选 DLL

系统会按顺序自动尝试使用以下 DLL：

- `Chakra.dll` - 微软的 JavaScript 引擎
- `mshtml.dll` - Internet Explorer 渲染引擎
- `Windows.UI.Xaml.dll` - Windows UI 框架
- `ieframe.dll` - Internet Explorer 框架
- `edgehtml.dll` - Microsoft Edge 渲染引擎
- `mstscax.dll` - 远程桌面客户端控件

### 使用方法

#### 基本用法

```cpp
#include "MyVirtualAlloc.h"

// 分配可执行内存
LPVOID memory = StompVirtualAlloc(
    NULL,                      // 让系统选择地址
    4096,                      // 大小（字节）
    MEM_COMMIT | MEM_RESERVE,  // 分配类型
    PAGE_EXECUTE_READWRITE     // 保护属性
);

if (memory != NULL) {
    // 使用内存...
    
    // 使用完毕后释放
    StompVirtualFree(memory, 0, MEM_RELEASE);
}
```

#### Shellcode 加载器示例

```cpp
#include "MyVirtualAlloc.h"
#include <vector>

// 从文件加载 shellcode
std::vector<unsigned char> shellcode = LoadFromFile("payload.bin");

// 分配内存
LPVOID execMemory = StompVirtualAlloc(
    NULL,
    shellcode.size(),
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);

// 复制 shellcode
memcpy(execMemory, shellcode.data(), shellcode.size());

// 执行
typedef void (*ShellcodeFunc)();
ShellcodeFunc execute = (ShellcodeFunc)execMemory;
execute();

// 清理
StompVirtualFree(execMemory, 0, MEM_RELEASE);
```

### 编译

#### 要求

- Windows 10/11
- Visual Studio 2019 或更高版本（支持 C++17）
- Windows SDK

#### 编译方法

```bash
# 使用 Visual Studio 开发者命令提示符
cl /EHsc /std:c++17 Demo.cpp MyVirtualAlloc.cpp

# 或使用 MSBuild（如果有 .sln 文件）
msbuild MyVirtualAlloc.sln /p:Configuration=Release
```

### 演示应用

包含的 `Demo.cpp` 演示了从文件加载并执行 shellcode：

```bash
Demo.exe shellcode.bin
```

**功能：**
- 从文件加载原始二进制 shellcode
- 显示 shellcode 预览（前 32 字节）
- 使用 StompVirtualAlloc 分配内存
- 执行 shellcode
- 正确清理内存

### API 参考

#### StompVirtualAlloc

```cpp
LPVOID StompVirtualAlloc(
    LPVOID lpAddress,       // 保留（忽略，总是分配新地址）
    SIZE_T dwSize,          // 要分配的字节数
    DWORD flAllocationType, // 分配类型（本实现中忽略）
    DWORD flProtect         // 内存保护（PAGE_EXECUTE_READWRITE 等）
);
```

**返回值：** 指向分配内存的指针，失败时返回 `NULL`。

#### StompVirtualFree

```cpp
BOOL StompVirtualFree(
    LPVOID lpAddress,      // 要释放的地址
    SIZE_T dwSize,         // 大小（本实现中忽略）
    DWORD dwFreeType       // 释放类型（本实现中忽略）
);
```

**返回值：** 成功返回 `TRUE`，失败返回 `FALSE`。

### 安全注意事项

⚠️ **仅用于教育/研究目的**

此工具设计用于：
- 安全研究
- 红队行动
- 理解 AV/EDR 规避技术
- 恶意软件分析

**警告：** 在未经授权的系统上使用可能是非法的。测试前务必获得适当授权。

### 局限性

- 分配的内存不是真正"新"的 - 它会覆盖 DLL `.text` 段的部分内容
- 如果被覆盖的代码被系统执行，可能导致不稳定
- 池容量取决于可用的候选 DLL
- 不适合大内存分配（受 DLL `.text` 段大小限制）

### 检测考虑

虽然此技术较为隐蔽，但潜在的检测途径包括：

- **内存完整性检查**：EDR 可能验证 DLL `.text` 段的完整性
- **异常内存模式**：DLL 区域中不寻常的 RWX 权限
- **原生 API 监控**：高级 EDR 可能钩住原生 API
- **行为分析**：可疑的内存访问模式

### 高级规避技术

为了进一步增强隐蔽性并规避复杂的检测机制，请考虑以下改进方案：

#### 1. 替换剩余的 Windows API

当前实现仍使用一些可能被监控的标准 Windows API。考虑替换：

**当前实现：**
- `GetModuleHandleA` - 可能被钩住
- `LoadLibraryA` - 被 EDR 严密监控
- `GetProcAddress` - 函数解析监控
- `FreeLibrary` - 模块卸载跟踪

**更安全的替代方案：**

```cpp
// 替代 GetModuleHandleA/LoadLibraryA
// 使用手动 PEB 遍历查找已加载模块
HMODULE GetModuleByHash(DWORD hash) {
    // 遍历 PEB->Ldr->InLoadOrderModuleList
    // 比对模块名称哈希值
}

// 替代 GetProcAddress
// 使用手动导出表解析
FARPROC GetProcAddressByHash(HMODULE hModule, DWORD hash) {
    // 解析 PE 头
    // 遍历导出目录
    // 比对函数名称哈希值
}
```

#### 2. 系统调用直接调用

不通过 `ntdll.dll` 调用 `NtProtectVirtualMemory`，而是使用直接系统调用：

```cpp
// 直接系统调用实现
NTSTATUS SysNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) {
    // 动态解析系统调用号
    // 直接执行 syscall 指令
    // 绕过所有用户模式钩子
}
```

#### 3. API 哈希

用基于哈希的查找替代基于字符串的 API 解析，避免静态字符串检测：

```cpp
#define HASH_NTDLL              0x1edab0ed
#define HASH_NTPROTECTVIRTUALMEMORY  0x50e92888

// 二进制文件中没有可见的 API 字符串
```

#### 4. 时序和抖动

添加随机延迟和抖动以避免行为模式检测：

```cpp
// 操作之间随机休眠
Sleep(rand() % 1000 + 500);

// 随机化分配顺序
std::random_shuffle(dllCandidates.begin(), dllCandidates.end());
```

#### 5. 内存权限分阶段设置

避免直接设置 RWX 权限。相反，分阶段设置权限：

```cpp
// 阶段 1：分配为 RW
NtProtectMemory(addr, size, PAGE_READWRITE, &old);

// 阶段 2：写入载荷
memcpy(addr, payload, size);

// 阶段 3：执行时才改为 RX
NtProtectMemory(addr, size, PAGE_EXECUTE_READ, &old);
```

#### 6. 模块踩踏增强

不使用 `.text` 段，考虑：
- `.rdata` 段（RX 权限更不可疑）
- 合法模块中未使用的代码洞
- 覆盖冷门/未使用的函数

### 实现建议

为了在生产环境中实现最大隐蔽性：

1. **移除所有标准 API 调用** - 仅使用 PEB 遍历和手动解析
2. **实现直接系统调用** - 完全绕过所有用户模式钩子
3. **使用 API 哈希** - 从二进制文件中消除静态字符串
4. **添加多态性** - 每次构建随机化实现细节
5. **实现休眠混淆** - 使用替代的计时机制
6. **内存权限分阶段** - 永远不要直接使用 RWX

### 当前实现状态

**已实现：**
- 原生 API 集成（使用 `NtProtectVirtualMemory` 而非 `VirtualProtect`）
- 在合法系统模块空间中分配内存
- 多 DLL 池管理及自动扩展
- 内存对齐和正确清理

**建议的未来增强：**
- PEB 遍历进行模块枚举（替换 `GetModuleHandleA`/`LoadLibraryA`）
- 直接系统调用（替换通过 ntdll.dll 的原生 API 调用）
- API 哈希（消除基于字符串的查找）
- 内存权限分阶段（避免直接 RWX）
- 每次构建的多态代码生成

### 贡献

欢迎贡献！请随时提交 pull request 或开启 issue。

### 许可证

本项目按原样提供，仅用于教育目的。请负责任且合乎道德地使用。

---

**Last Updated | 最后更新**: 2025-11-28  
**Version | 版本**: 1.0.0

