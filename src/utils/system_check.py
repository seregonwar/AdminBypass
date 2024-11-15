import os
import platform
import subprocess

def check_requirements():
    """Check only basic system compatibility"""
    if platform.system() != 'Windows':
        return False
    return True 