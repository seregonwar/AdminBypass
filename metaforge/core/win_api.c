
#define UMDF_USING_NTSTATUS
#define WIN32_NO_STATUS

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>

#pragma comment(lib, "ntdll.lib")

// Wrapper functions
__declspec(dllexport) HANDLE __stdcall OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    return OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

__declspec(dllexport) HANDLE __stdcall OpenRegistryKey(LPCWSTR lpSubKey, DWORD dwDesiredAccess) {
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, lpSubKey, 0, dwDesiredAccess, &hKey) == ERROR_SUCCESS) {
        return hKey;
    }
    return NULL;
}

__declspec(dllexport) BOOL __stdcall WriteRegistryValue(HANDLE hKey, LPCWSTR lpValueName, DWORD dwType, LPCVOID lpData, DWORD cbData) {
    return RegSetValueExW((HKEY)hKey, lpValueName, 0, dwType, (const BYTE*)lpData, cbData) == ERROR_SUCCESS;
}
