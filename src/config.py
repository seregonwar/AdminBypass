import os
import sys

# Add the project root directory to Python path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)

# Configuration constants
DEBUG = True
SAM_BACKUP_PATH = os.path.join(PROJECT_ROOT, 'backups')

# Ensure backup directory exists
os.makedirs(SAM_BACKUP_PATH, exist_ok=True) 