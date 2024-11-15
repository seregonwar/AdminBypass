import os
import logging
from .sam_parser import SAMParser

class WindowsPasswordReset:
    def __init__(self):
        self.sam_parser = SAMParser()
    
    def list_users(self):
        """List all Windows users"""
        try:
            return self.sam_parser.get_users()
        except Exception as e:
            logging.error(f"Failed to list users: {str(e)}")
            return []
    
    def reset_password(self, username):
        """Reset password for specified user"""
        try:
            # First try to get password hash
            password_info = self.sam_parser.get_password_info(username)
            if password_info:
                return {
                    'success': True,
                    'hash': password_info['hash'],
                    'message': 'Password hash extracted'
                }
            
            # If hash extraction fails, try to reset password
            if self.sam_parser.clear_password(username):
                self.sam_parser.modify_user_privileges(username)
                return {
                    'success': True,
                    'hash': None,
                    'message': 'Password reset successful'
                }
            
            return {
                'success': False,
                'hash': None,
                'message': 'Failed to reset password'
            }
        except Exception as e:
            logging.error(f"Error resetting password: {str(e)}")
            return {
                'success': False,
                'hash': None,
                'message': str(e)
            } 