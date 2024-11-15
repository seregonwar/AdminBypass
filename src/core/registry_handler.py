import winreg
import os

class RegistryHandler:
    def __init__(self):
        self.sam_path = r"SYSTEM\CurrentControlSet\Control\SAM"
    
    def backup_sam(self):
        """Create backup of SAM file"""
        try:
            os.system('reg save HKLM\SAM sam.bak')
            return True
        except Exception as e:
            raise Exception(f"Failed to backup SAM: {str(e)}")
    
    def modify_registry(self, key_path, value_name, value_data):
        """Modify registry key"""
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, 
                                winreg.KEY_ALL_ACCESS)
            winreg.SetValueEx(key, value_name, 0, winreg.REG_BINARY, value_data)
            winreg.CloseKey(key)
        except Exception as e:
            raise Exception(f"Failed to modify registry: {str(e)}") 