#pragma once
#include <Windows.h>

/*
 * StompVirtualAlloc - Perfect replacement implementation for VirtualAlloc
 * 
 * Core Features:
 * 1. Fully compatible with VirtualAlloc/VirtualFree API
 * 2. Does not use VirtualAlloc, bypasses AV/EDR monitoring
 * 3. Multi-DLL pool management with automatic capacity expansion
 * 4. Memory has legitimate module attribution
 */

// ==================== Function Declarations ====================

// Fully compatible VirtualAlloc interface
LPVOID StompVirtualAlloc(
    LPVOID lpAddress,       // Reserved address (ignored in this implementation, always allocates new address)
    SIZE_T dwSize,          // Number of bytes to allocate
    DWORD flAllocationType, // Allocation type (ignored in this implementation: MEM_COMMIT/MEM_RESERVE)
    DWORD flProtect         // Memory protection attributes (PAGE_EXECUTE_READWRITE, etc.)
);

// Fully compatible VirtualFree interface
BOOL StompVirtualFree(
    LPVOID lpAddress,      // Memory address to free
    SIZE_T dwSize,         // Size to free (ignored in this implementation)
    DWORD dwFreeType       // Free type (ignored in this implementation: MEM_RELEASE/MEM_DECOMMIT)
);
