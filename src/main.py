#!/usr/bin/env python3

import sys
import os

try:
    import psutil
except ImportError:
    print("Error: Required module 'psutil' not found. Please run: pip install psutil==5.9.0")
    sys.exit(1)

try:
    from config import PROJECT_ROOT
    sys.path.append(os.path.join(PROJECT_ROOT, 'src'))

    from core.password_reset import WindowsPasswordReset
    from utils.system_check import check_requirements
    from ui.cli import CLI
except ImportError as e:
    print(f"Error loading required modules: {str(e)}")
    print("Please install all required dependencies with: pip install -r requirements.txt")
    sys.exit(1)

def main():
    # Check if running with admin privileges
    if not check_requirements():
        print("Error: This program must be run as administrator")
        sys.exit(1)

    cli = CLI()
    reset_tool = WindowsPasswordReset()
    
    try:
        cli.start(reset_tool)
    except KeyboardInterrupt:
        print("\nProgram terminated by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 