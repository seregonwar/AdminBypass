class CLI:
    def __init__(self):
        self.menu_options = {
            '1': 'List Users',
            '2': 'Reset Password',
            '3': 'Extract Password Hash',
            '4': 'Exit'
        }

    def display_menu(self):
        print("\nWindows Password Recovery Tool")
        print("-----------------------------")
        for key, value in self.menu_options.items():
            print(f"{key}. {value}")

    def start(self, reset_tool):
        while True:
            self.display_menu()
            choice = input("\nSelect an option: ")
            
            if choice == '1':
                users = reset_tool.list_users()
                print("\nAvailable users:")
                for user in users:
                    print(f"- {user}")
            
            elif choice == '2':
                username = input("Enter username: ")
                result = reset_tool.reset_password(username)
                if result['success']:
                    if result['hash']:
                        print(f"Password hash for {username}: {result['hash']}")
                    else:
                        print(f"Password reset successful for {username}")
                else:
                    print(f"Password reset failed: {result['message']}")
            
            elif choice == '3':
                username = input("Enter username: ")
                info = reset_tool.sam_parser.get_password_info(username)
                if info and info['hash']:
                    print(f"\nPassword hash for {username}:")
                    print(f"NTLM Hash: {info['hash']}")
                    print("\nYou can use this hash with tools like hashcat or john the ripper")
                else:
                    print(f"Failed to extract hash for {username}")
            
            elif choice == '4':
                print("Exiting...")
                break 