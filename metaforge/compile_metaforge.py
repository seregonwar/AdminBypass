import os
import subprocess
from pathlib import Path
import sys

def generate_c_code(mf_file, output_dir):
    """Generate C code from MetaForge file"""
    source = Path(mf_file).read_text(encoding='utf-8')
    output_file = output_dir / f"{Path(mf_file.stem)}.c"
    
    # Scegli il template in base al tipo di file
    if mf_file.name == "win_api.mf":
        c_code = """
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
"""
    elif mf_file.name == "memory.mf":
        c_code = """
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
"""
    elif mf_file.name == "registry.mf":
        c_code = """
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
"""
    else:  # registry.mf
        c_code = """
#define UMDF_USING_NTSTATUS
#define WIN32_NO_STATUS

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>

#pragma comment(lib, "ntdll.lib")

// Forward declarations
typedef NTSTATUS (NTAPI *NtOpenKey_t)(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
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
static NtSetValueKey_t pNtSetValueKey = NULL;

// Initialize function pointers
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (hNtdll) {
                pNtOpenKey = (NtOpenKey_t)GetProcAddress(hNtdll, "NtOpenKey");
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

__declspec(dllexport) BOOL __stdcall WriteRegistryValue(HANDLE hKey, LPCWSTR lpValueName, DWORD dwType, LPCVOID lpData, DWORD cbData) {
    if (!pNtSetValueKey) return FALSE;
    
    UNICODE_STRING usValueName;
    RtlInitUnicodeString(&usValueName, lpValueName);
    
    NTSTATUS status = pNtSetValueKey(hKey, &usValueName, 0, dwType, (PVOID)lpData, cbData);
    return NT_SUCCESS(status);
}
"""
    
    output_file.write_text(c_code)
    return output_file

def compile_metaforge():
    """Compile MetaForge wrappers to DLL"""
    # Base paths
    metaforge_path = Path("metaforge")
    
    # Create all required directories
    directories = {
        "core": metaforge_path / "core",
        "crypto": metaforge_path / "crypto",
        "exploit": metaforge_path / "exploit"
    }
    
    for dir_path in directories.values():
        dir_path.mkdir(parents=True, exist_ok=True)
    
    # Find SDK and VS paths
    sdk_path = r"C:\Program Files (x86)\Windows Kits\10"
    sdk_include = os.path.join(sdk_path, "Include", "10.0.22621.0")
    sdk_lib = os.path.join(sdk_path, "Lib", "10.0.22621.0")
    
    vs_path = r"C:\Program Files\Microsoft Visual Studio\2022\Community"
    vs_include = os.path.join(vs_path, "VC", "Tools", "MSVC", "14.38.33135", "include")
    vs_lib = os.path.join(vs_path, "VC", "Tools", "MSVC", "14.38.33135", "lib", "x64")
    
    ucrt_include = os.path.join(sdk_include, "ucrt")
    ucrt_lib = os.path.join(sdk_lib, "ucrt", "x64")
    
    # Files to compile with their output directories
    files_to_compile = {
        "core": ["win_api.mf", "memory.mf", "registry.mf"],
        "crypto": ["hash.mf", "cipher.mf"],
        "exploit": ["privilege.mf", "injection.mf", "bypass.mf"]
    }
    
    # Common compiler settings
    include_paths = [
        f"/I\"{ucrt_include}\"",
        f"/I\"{vs_include}\"",
        f"/I\"{os.path.join(sdk_include, 'shared')}\"",
        f"/I\"{os.path.join(sdk_include, 'um')}\"",
        f"/I\"{os.path.join(sdk_include, 'km')}\"",
        f"/I\"{os.path.join(sdk_include, 'wdf')}\""
    ]
    
    lib_paths = [
        f"/LIBPATH:\"{ucrt_lib}\"",
        f"/LIBPATH:\"{vs_lib}\"",
        f"/LIBPATH:\"{os.path.join(sdk_lib, 'um', 'x64')}\"",
        f"/LIBPATH:\"{os.path.join(sdk_lib, 'km', 'x64')}\""
    ]
    
    # Compile each module
    for module, files in files_to_compile.items():
        module_dir = directories[module]
        
        for file in files:
            source = module_dir / file
            print(f"Creating wrapper for {module}/{file}...")
            
            try:
                if not source.exists():
                    raise FileNotFoundError(f"Source file not found: {source}")
                
                # Generate wrapper
                wrapper_file = generate_c_code(source, module_dir)
                output = module_dir / file.replace(".mf", ".dll")
                
                compile_cmd = [
                    "cl.exe",
                    "/LD",  # Create DLL
                    "/MD",  # Use multi-threaded DLL runtime
                    "/Fe:" + str(output),  # Output file
                    *include_paths,
                    "/O2",  # Optimize for speed
                    "/GS-",  # Disable buffer security check
                    "/D", "WIN32",
                    "/D", "_WINDOWS",
                    "/D", "_USRDLL",
                    "/D", "NDEBUG",
                    "/D", "_UNICODE",
                    "/D", "UNICODE",
                    str(wrapper_file),
                    "/link",
                    "/NODEFAULTLIB:libcmt.lib",
                    *lib_paths,
                    "ntdll.lib",
                    "kernel32.lib",
                    "advapi32.lib",
                    "ucrt.lib",
                    "vcruntime.lib",
                    "msvcrt.lib"
                ]
                
                # Create compilation batch file
                batch_file = module_dir / "compile.bat"
                with open(batch_file, "w") as f:
                    f.write(f'@echo off\n')
                    f.write(f'call "{vs_path}\\VC\\Auxiliary\\Build\\vcvars64.bat"\n')
                    f.write(" ".join(compile_cmd))
                
                # Run compilation
                subprocess.run([str(batch_file)], check=True)
                print(f"Successfully compiled {module}/{file}")
                
            except Exception as e:
                print(f"Error compiling {module}/{file}: {str(e)}")
                continue
    
    print("\nCompilation complete!")

if __name__ == "__main__":
    try:
        compile_metaforge()
    except Exception as e:
        print(f"\nError during compilation: {str(e)}")
        sys.exit(1) 