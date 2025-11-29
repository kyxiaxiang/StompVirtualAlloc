#include <iostream>
#include <Windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include "MyVirtualAlloc.h"

using namespace std;

enum ProtectionType { R = 1, W = 2, X = 4, RW = 3, RX = 5, WX = 6, RWX = 7 };

// ==================== Native API Definitions ====================
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef LONG NTSTATUS;

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

// Global function pointer for NtProtectVirtualMemory
pNtProtectVirtualMemory g_NtProtectVirtualMemory = nullptr;

// Initialize Native API function pointer
bool InitializeNativeAPI() {
    if (g_NtProtectVirtualMemory != nullptr) {
        return true;  // Already initialized
    }

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        return false;
    }

    g_NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    if (g_NtProtectVirtualMemory == nullptr) {
        return false;
    }

    return true;
}

// Wrapper function for NtProtectVirtualMemory to match VirtualProtect style
bool NtProtectMemory(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    if (g_NtProtectVirtualMemory == nullptr) {
        if (!InitializeNativeAPI()) {
            return false;
        }
    }

    PVOID baseAddress = lpAddress;
    SIZE_T regionSize = dwSize;
    ULONG oldProtect = 0;

    NTSTATUS status = g_NtProtectVirtualMemory(
        GetCurrentProcess(),
        &baseAddress,
        &regionSize,
        flNewProtect,
        &oldProtect
    );

    if (lpflOldProtect != nullptr) {
        *lpflOldProtect = oldProtect;
    }

    return NT_SUCCESS(status);
}

// ==================== Available DLL Candidate List ====================
const char* CANDIDATE_DLLS[] = {
    "Chakra.dll",
    "mshtml.dll",
    "Windows.UI.Xaml.dll",
    "ieframe.dll",
    "edgehtml.dll",
    "mstscax.dll"
};
const int CANDIDATE_DLL_COUNT = sizeof(CANDIDATE_DLLS) / sizeof(CANDIDATE_DLLS[0]);

// ==================== Memory Block Management Structure ====================
struct MemoryBlock {
    void* address;          // Memory block address
    size_t size;           // Memory block size
    bool isFree;           // Whether it's free
    DWORD oldProtect;      // Original protection attributes
    int dllPoolIndex;      // Owning DLL pool index
};

// ==================== DLL Memory Pool Structure ====================
struct DLLMemoryPool {
    HMODULE hModule;           // DLL handle
    string dllName;            // DLL name
    BYTE* textBase;            // .text section base address
    size_t textSize;           // .text section size
    size_t textOffset;         // .text current offset
    bool isActive;             // Whether it's active
    bool loadedByUs;           // Whether loaded by us (for cleanup)
    
    DLLMemoryPool() : hModule(nullptr), textBase(nullptr), textSize(0), 
                      textOffset(0), isActive(false), loadedByUs(false) {}
};

// ==================== Perfect Multi-DLL Memory Manager ====================
class MemoryAllocator {
private:
    vector<MemoryBlock> allocatedBlocks;
    vector<DLLMemoryPool> dllPools;
    int currentDllIndex;
    bool initialized;

    // Initialize a DLL pool
    bool InitializeDLLPool(const char* dllName) {
        // Check if already loaded
        HMODULE hModule = GetModuleHandleA(dllName);
        bool loadedByUs = false;
        
        if (hModule == NULL) {
            hModule = LoadLibraryA(dllName);
            if (hModule == NULL) {
                return false;
            }
            loadedByUs = true;
        }

        BYTE* moduleBase = (BYTE*)hModule;
        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)moduleBase;

        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            if (loadedByUs) FreeLibrary(hModule);
            return false;
        }

        IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(moduleBase + dosHeader->e_lfanew);
        
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            if (loadedByUs) FreeLibrary(hModule);
            return false;
        }

        IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        int numberOfSections = ntHeaders->FileHeader.NumberOfSections;

        // Find .text section
        for (int i = 0; i < numberOfSections; i++) {
            char sectionName[9] = { 0 };
            memcpy(sectionName, sectionHeader[i].Name, 8);
            
            if (strcmp(sectionName, ".text") == 0) {
                DLLMemoryPool pool;
                pool.hModule = hModule;
                pool.dllName = dllName;
                pool.textBase = moduleBase + sectionHeader[i].VirtualAddress;
                pool.textSize = sectionHeader[i].Misc.VirtualSize;
                pool.textOffset = 0;
                pool.isActive = true;
                pool.loadedByUs = loadedByUs;
                
                dllPools.push_back(pool);

                return true;
            }
        }

        if (loadedByUs) FreeLibrary(hModule);
        return false;
    }

    // Automatically load next DLL when space is insufficient
    bool ExpandPoolCapacity() {
        
        // Try to load next DLL from candidate list
        for (int i = 0; i < CANDIDATE_DLL_COUNT; i++) {
            // Check if already loaded
            bool alreadyLoaded = false;
            for (const auto& pool : dllPools) {
                if (pool.dllName == CANDIDATE_DLLS[i]) {
                    alreadyLoaded = true;
                    break;
                }
            }
            
            if (!alreadyLoaded) {
                if (InitializeDLLPool(CANDIDATE_DLLS[i])) {
                    currentDllIndex = dllPools.size() - 1;
                    return true;
                }
            }
        }
        
        return false;
    }

    // Allocate memory from specified DLL pool
    void* AllocateFromPool(int poolIndex, size_t size, ProtectionType protectionType) {
        if (poolIndex < 0 || poolIndex >= (int)dllPools.size()) {
            return nullptr;
        }

        DLLMemoryPool& pool = dllPools[poolIndex];
        
        // Check if the pool has enough space
        if (pool.textOffset + size > pool.textSize) {
            return nullptr;
        }

        // Calculate allocation address
        void* allocatedAddress = pool.textBase + pool.textOffset;
        pool.textOffset += size;

        // Set memory protection attributes using Native API
        DWORD protection = ConvertProtection(protectionType);
        DWORD oldProtect;
        
        if (!NtProtectMemory(allocatedAddress, size, protection, &oldProtect)) {
            pool.textOffset -= size;  // Rollback
            return nullptr;
        }

        // Record the allocated memory block
        MemoryBlock block;
        block.address = allocatedAddress;
        block.size = size;
        block.isFree = false;
        block.oldProtect = oldProtect;
        block.dllPoolIndex = poolIndex;
        allocatedBlocks.push_back(block);

        return allocatedAddress;
    }

    // Convert protection type
    DWORD ConvertProtection(ProtectionType protectionType) {
        switch (protectionType) {
        case R:   return PAGE_READONLY;
        case W:   return PAGE_WRITECOPY;
        case X:   return PAGE_EXECUTE;
        case RW:  return PAGE_READWRITE;
        case RX:  return PAGE_EXECUTE_READ;
        case WX:  return PAGE_EXECUTE_WRITECOPY;
        case RWX: return PAGE_EXECUTE_READWRITE;
        default:  return PAGE_NOACCESS;
        }
    }

public:
    MemoryAllocator() : currentDllIndex(-1), initialized(false) {}

    ~MemoryAllocator() {
        // Cleanup: free DLLs loaded by us
        for (auto& pool : dllPools) {
            if (pool.loadedByUs && pool.hModule) {
                FreeLibrary(pool.hModule);
            }
        }
    }

    // Initialize memory allocator
    bool Initialize() {
        if (initialized) return true;

        // Initialize Native API function pointers
        if (!InitializeNativeAPI()) {
            return false;
        }

        // Load the first DLL
        if (!InitializeDLLPool(CANDIDATE_DLLS[0])) {
            return false;
        }

        currentDllIndex = 0;
        initialized = true;
        return true;
    }

    // Smart memory allocation (automatically handles expansion)
    void* Allocate(size_t size, ProtectionType protectionType) {
        if (!initialized) {
            return nullptr;
        }

        if (size == 0) return nullptr;

        // Align to 16-byte boundary
        size = (size + 15) & ~15;

        // Try to allocate from current DLL pool
        void* result = AllocateFromPool(currentDllIndex, size, protectionType);
        if (result != nullptr) {
            return result;
        }

        // Current pool is insufficient, try to allocate from other loaded pools
        for (int i = 0; i < (int)dllPools.size(); i++) {
            if (i != currentDllIndex) {
                result = AllocateFromPool(i, size, protectionType);
                if (result != nullptr) {
                    currentDllIndex = i;
                    return result;
                }
            }
        }

        // All existing pools are insufficient, try to expand
        if (ExpandPoolCapacity()) {
            return AllocateFromPool(currentDllIndex, size, protectionType);
        }

        return nullptr;
    }

    // Free memory
    bool Free(void* address) {
        if (!address) return false;

        for (auto& block : allocatedBlocks) {
            if (block.address == address && !block.isFree) {
                // First, clear memory (while still having write permission)
                memset(block.address, 0, block.size);
                
                // Then restore original protection attributes using Native API
                DWORD temp;
                NtProtectMemory(block.address, block.size, block.oldProtect, &temp);
                
                // Mark as freed
                block.isFree = true;

                // Reclaim space to corresponding pool
                if (block.dllPoolIndex >= 0 && block.dllPoolIndex < (int)dllPools.size()) {
                    DLLMemoryPool& pool = dllPools[block.dllPoolIndex];
                    // If it's the last allocated block in this pool, can roll back offset
                    if ((BYTE*)block.address + block.size == pool.textBase + pool.textOffset) {
                        pool.textOffset -= block.size;
                    }
                }

                return true;
            }
        }

        return false;
    }

    // Get statistics
    void GetStatistics(int& totalBlocks, int& freeBlocks, size_t& totalAllocated, 
                       size_t& totalCapacity, int& activePools) {
        totalBlocks = allocatedBlocks.size();
        freeBlocks = 0;
        totalAllocated = 0;

        for (const auto& block : allocatedBlocks) {
            if (block.isFree) {
                freeBlocks++;
            } else {
                totalAllocated += block.size;
            }
        }

        // Calculate total capacity and remaining space of all pools
        totalCapacity = 0;
        activePools = 0;
        for (const auto& pool : dllPools) {
            if (pool.isActive) {
                totalCapacity += pool.textSize;
                activePools++;
            }
        }
    }

    // Get DLL pool count
    int GetPoolCount() const {
        return dllPools.size();
    }
};

// ==================== Global Memory Allocator Instance ====================
MemoryAllocator g_allocator;

// ==================== Helper Function: Convert Windows Protection Flags to Internal Type ====================
ProtectionType ConvertWindowsProtectionToInternal(DWORD flProtect) {
    switch (flProtect) {
    case PAGE_READONLY:
        return R;
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
        return RW;
    case PAGE_EXECUTE:
        return X;
    case PAGE_EXECUTE_READ:
        return RX;
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return RWX;
    default:
        return RWX;  // Default read-write-execute
    }
}

// ==================== Fully Compatible VirtualAlloc Interface ====================
LPVOID StompVirtualAlloc(
    LPVOID lpAddress,      // Ignored parameter, always allocate new address
    SIZE_T dwSize,         // Number of bytes to allocate
    DWORD flAllocationType, // Ignored parameter (MEM_COMMIT/MEM_RESERVE)
    DWORD flProtect        // Memory protection attributes
) {
    // Ensure initialization
    if (!g_allocator.Initialize()) {
        return nullptr;
    }
    
    // Convert Windows protection flags to internal type
    ProtectionType protType = ConvertWindowsProtectionToInternal(flProtect);
    
    // Call internal allocator
    return g_allocator.Allocate(dwSize, protType);
}

// ==================== Fully Compatible VirtualFree Interface ====================
BOOL StompVirtualFree(
    LPVOID lpAddress,     // Memory address to free
    SIZE_T dwSize,        // Ignored parameter
    DWORD dwFreeType      // Ignored parameter (MEM_RELEASE/MEM_DECOMMIT)
) {
    return g_allocator.Free(lpAddress) ? TRUE : FALSE;
}
