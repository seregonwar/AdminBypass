import os
import sys
import subprocess
import venv
from pathlib import Path
from compile_metaforge import compile_metaforge

def setup_virtual_environment():
    """Create and configure virtual environment"""
    venv_path = Path("venv")
    
    # Create virtual environment
    print("Creating virtual environment...")
    venv.create(venv_path, with_pip=True)
    
    # Get path to python executable in venv
    if sys.platform == "win32":
        python_path = venv_path / "Scripts" / "python.exe"
        pip_path = venv_path / "Scripts" / "pip.exe"
    else:
        python_path = venv_path / "bin" / "python"
        pip_path = venv_path / "bin" / "pip"

    # Upgrade pip
    print("Upgrading pip...")
    subprocess.run([str(python_path), "-m", "pip", "install", "--upgrade", "pip"])

    # Install requirements
    print("Installing requirements...")
    subprocess.run([str(pip_path), "install", "-r", "requirements.txt"])

    # Compile MetaForge files
    print("\nCompiling MetaForge modules...")
    compile_metaforge()

    print("\nSetup complete! To activate the virtual environment:")
    if sys.platform == "win32":
        print("    venv\\Scripts\\activate.bat")
    else:
        print("    source venv/bin/activate")

if __name__ == "__main__":
    setup_virtual_environment() 