
#define UMDF_USING_NTSTATUS
#define WIN32_NO_STATUS

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>

#pragma comment(lib, "ntdll.lib")

// Forward declarations
typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
);

typedef NTSTATUS (NTAPI *NtReadVirtualMemory_t)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    OUT PVOID Buffer,
    IN SIZE_T BufferSize,
    OUT PSIZE_T NumberOfBytesRead OPTIONAL
);

// Global variables
static HMODULE hNtdll = NULL;
static NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = NULL;
static NtReadVirtualMemory_t pNtReadVirtualMemory = NULL;

// Initialize function pointers
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (hNtdll) {
                pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
                pNtReadVirtualMemory = (NtReadVirtualMemory_t)GetProcAddress(hNtdll, "NtReadVirtualMemory");
            }
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

// Wrapper functions
__declspec(dllexport) LPVOID __stdcall AllocateMemory(HANDLE hProcess, SIZE_T dwSize) {
    PVOID baseAddress = NULL;
    SIZE_T regionSize = dwSize;
    
    NTSTATUS status = pNtAllocateVirtualMemory(
        hProcess,
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    return NT_SUCCESS(status) ? baseAddress : NULL;
}

__declspec(dllexport) BOOL __stdcall ReadMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize) {
    SIZE_T bytesRead;
    
    NTSTATUS status = pNtReadVirtualMemory(
        hProcess,
        (PVOID)lpBaseAddress,
        lpBuffer,
        nSize,
        &bytesRead
    );
    
    return NT_SUCCESS(status);
}
