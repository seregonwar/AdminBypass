
#define UMDF_USING_NTSTATUS
#define WIN32_NO_STATUS

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>

#pragma comment(lib, "ntdll.lib")

// Registry information class
typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64,
    KeyValueLayerInformation,
    MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

// Registry value information structure
typedef struct _KEY_VALUE_FULL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataOffset;
    ULONG DataLength;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)

// Forward declarations
typedef NTSTATUS (NTAPI *NtOpenKey_t)(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (NTAPI *NtQueryValueKey_t)(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName,
    IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    OUT PVOID KeyValueInformation,
    IN ULONG Length,
    OUT PULONG ResultLength
);

typedef NTSTATUS (NTAPI *NtSetValueKey_t)(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName,
    IN ULONG TitleIndex OPTIONAL,
    IN ULONG Type,
    IN PVOID Data,
    IN ULONG DataSize
);

// Global variables
static HMODULE hNtdll = NULL;
static NtOpenKey_t pNtOpenKey = NULL;
static NtQueryValueKey_t pNtQueryValueKey = NULL;
static NtSetValueKey_t pNtSetValueKey = NULL;

// Initialize function pointers
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (hNtdll) {
                pNtOpenKey = (NtOpenKey_t)GetProcAddress(hNtdll, "NtOpenKey");
                pNtQueryValueKey = (NtQueryValueKey_t)GetProcAddress(hNtdll, "NtQueryValueKey");
                pNtSetValueKey = (NtSetValueKey_t)GetProcAddress(hNtdll, "NtSetValueKey");
            }
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

// Wrapper functions
__declspec(dllexport) HANDLE __stdcall OpenRegistryKey(LPCWSTR lpSubKey, DWORD dwDesiredAccess) {
    HANDLE hKey = NULL;
    OBJECT_ATTRIBUTES oa = {sizeof(OBJECT_ATTRIBUTES)};
    UNICODE_STRING usKeyName;
    RtlInitUnicodeString(&usKeyName, lpSubKey);
    oa.ObjectName = &usKeyName;
    
    if (pNtOpenKey) {
        pNtOpenKey(&hKey, dwDesiredAccess, &oa);
    }
    return hKey;
}

__declspec(dllexport) LPVOID __stdcall ReadRegistryValue(HANDLE hKey, LPCWSTR lpValueName) {
    if (!pNtQueryValueKey) return NULL;
    
    UNICODE_STRING usValueName;
    RtlInitUnicodeString(&usValueName, lpValueName);
    
    // First query to get size
    ULONG resultLength = 0;
    NTSTATUS status = pNtQueryValueKey(
        hKey,
        &usValueName,
        KeyValueFullInformation,
        NULL,
        0,
        &resultLength
    );
    
    if (status != STATUS_BUFFER_TOO_SMALL) return NULL;
    
    // Allocate buffer
    PKEY_VALUE_FULL_INFORMATION kvfi = (PKEY_VALUE_FULL_INFORMATION)malloc(resultLength);
    if (!kvfi) return NULL;
    
    // Get value data
    status = pNtQueryValueKey(
        hKey,
        &usValueName,
        KeyValueFullInformation,
        kvfi,
        resultLength,
        &resultLength
    );
    
    if (!NT_SUCCESS(status)) {
        free(kvfi);
        return NULL;
    }
    
    // Copy data to new buffer
    LPVOID data = malloc(kvfi->DataLength + sizeof(DWORD));
    if (!data) {
        free(kvfi);
        return NULL;
    }
    
    *(DWORD*)data = kvfi->DataLength;
    memcpy((BYTE*)data + sizeof(DWORD), 
           (BYTE*)kvfi + kvfi->DataOffset,
           kvfi->DataLength);
    
    free(kvfi);
    return data;
}

__declspec(dllexport) BOOL __stdcall WriteRegistryValue(HANDLE hKey, LPCWSTR lpValueName, DWORD dwType, LPCVOID lpData, DWORD cbData) {
    if (!pNtSetValueKey) return FALSE;
    
    UNICODE_STRING usValueName;
    RtlInitUnicodeString(&usValueName, lpValueName);
    
    NTSTATUS status = pNtSetValueKey(hKey, &usValueName, 0, dwType, (PVOID)lpData, cbData);
    return NT_SUCCESS(status);
}
