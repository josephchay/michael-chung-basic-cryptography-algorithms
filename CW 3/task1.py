import os
import json
import getpass
import bcrypt

# Constants
USER_DB_FILE = "users.json"              # File to store registered users and their hashed passwords
PLAINTEXT_FILE = "password_plain.txt"    # File to store plaintext passwords (for cracking demo only)
EXPORT_HASH = "export_hash.txt"          # File to export hash of a specific user (for Task 3)
MAX_TRIES = 3                            # Maximum allowed login attempts

class UserAuthManager:
    
    def __init__(self, user_db_file=USER_DB_FILE, hash_export_file=EXPORT_HASH, plaintext_file=PLAINTEXT_FILE):
        # Initialize file paths and load existing users from file
        self.user_db_file = user_db_file
        self.hash_export_file = hash_export_file
        self.plaintext_file = plaintext_file
        self.users = self.load_users()

    def is_username_taken(self, username):
        # Check if a username is already registered.        
        return username in self.users

    def load_users(self):
        # Load users from JSON file if it exists
        if os.path.exists(self.user_db_file):
            with open(self.user_db_file, "r") as f:
                return json.load(f)
            
        return {}

    def save_users(self):
        # Save user data to the JSON file
        with open(self.user_db_file, "w") as f:
            json.dump(self.users, f, indent=4)

    def register_user(self, username, password):
        # Register a new user with hashed password
        if self.is_username_taken(username):
            print(f"Username '{username}' already exists.")
            return False

        try:
            # Generate bcrypt salt and hash the password
            salt = bcrypt.gensalt(rounds=12)
            hashed = bcrypt.hashpw(password.encode(), salt).decode()

            # Store the username and hashed password
            self.users[username] = hashed
            self.save_users()

            # Store username and plaintext password for cracking simulation 
            '''
            TODO : REMOVE before submission
            '''
            with open(self.plaintext_file, "a") as f:
                f.write(f"{username}:{password}\n")

            print(f"\nUser '{username}' registered. Password securely hashed using bcrypt.")
            return True
        
        except Exception as e:
            # Handle error
            print(f"Registration failed: {e}")
            return False

    def login_user(self):
        # Login a user by checking password hash
        if not self.users:
            print("No registered users found.")
            return

        username = input("\nEnter username: ").strip()
        
        if username not in self.users:
            print("Username not found.")
            return

        stored_hash = self.users[username].encode()

        for attempt in range(1, MAX_TRIES + 1):
            # Prompt user to enter password
            password_attempt = getpass.getpass(f"Attempt {attempt}/{MAX_TRIES} - Enter password: ").strip()

            try:
                # Check password against stored bcrypt hash
                if bcrypt.checkpw(password_attempt.encode(), stored_hash):
                    print("Login successful. Signing in...\n")
                    return
                else:
                    print("Incorrect password.")
                    
            except Exception as e:
                print(f"Verification failed: {e}")
                return
        # Reached max attempts
        print("\nToo many failed attempts. Exiting.\n")
        
    def prompt_confirm_password(self):
        # Repeatedly ask for password confirmation until they match
        while True:
            password = getpass.getpass("Enter a password: ").strip()
            confirm = getpass.getpass("Confirm your password: ").strip()
            
            if password == confirm:
                return password
            
            print("Passwords do not match. Try again.\n")


    def export_hash_for_cracking(self):
        # Main interface to export hashes for JtR. Prompts user and coordinates export.
        if not self.users:
            print("No users found.")
            return
    
        usernames_to_export = self.get_export_usernames()
    
        if usernames_to_export is None:
            print("Returning to main menu.")
            return
    
        if not usernames_to_export:
            print("No valid usernames to export.")
            return
    
        self.write_export_file(usernames_to_export)
    
    
    def get_export_usernames(self):
        # Prompts user for export type and returns list of valid usernames.
        # Returns None if user selects 'back to menu'.
        print(f"\nHow many? [{len(self.users)} user(s) available to export]")
        print("1. All")
        print("2. Specific")
        print("3. Back to main menu")

        choice = input("Select an option (1, 2, or 3): ").strip()

        if choice == "1":
            return list(self.users.keys())

        elif choice == "2":
            print("\nAvailable users:")
            for i, username in enumerate(self.users.keys(), 1):
                print(f"{i}. {username}")

            print("\nEnter usernames to export (comma-separated):")
            input_usernames = input("Usernames: ").strip().split(",")
            valid_usernames = []

            for name in input_usernames:
                username = name.strip()
                if username in self.users:
                    valid_usernames.append(username)
                else:
                    print(f"Username '{username}' not found.")

            return valid_usernames

        elif choice == "3":
            return None

        else:
            print("Invalid choice.")
            return None

    def write_export_file(self, usernames):
        # Writes selected usernames and their bcrypt hashes to the export file.
        print("\nChoose export mode:")
        print("1. Overwrite existing file")
        print("2. Append to file")
        mode_choice = input("Select export mode (1 or 2): ").strip()

        mode = "w" if mode_choice == "1" else "a"

        try:
            with open(self.hash_export_file, mode) as out:
                for username in usernames:
                    out.write(f"{username}:{self.users[username]}\n")

            action = "Appended" if mode == "a" else "Exported"
            print(f"{action} {len(usernames)} hash(es) to '{self.hash_export_file}' (John the Ripper compatible).")

        except Exception as e:
            print(f"Export failed: {e}")




def main():
    
    auth_manager = UserAuthManager()

    while True:
        
        print("\n--- [ Bcrypt Authentication System ] ---")
        print("1. Register")
        print("2. Login")
        print("3. Export user hash for cracking")
        print("4. Exit")

        choice = input("Select an option (1-4): ").strip()

        if choice == "1":
            # Register user
            while True:
                username = input("\nEnter a username: ").strip()

                if auth_manager.is_username_taken(username):

                    print("Username already taken.")
                    print("Please choose a different one.")

                else:
                    break
                
            password = auth_manager.prompt_confirm_password()
            auth_manager.register_user(username, password)
 
        elif choice == "2":
            # Login user
            auth_manager.login_user()

        elif choice == "3":
            # Export bcrypt hash for offline cracking
            auth_manager.export_hash_for_cracking()

        elif choice == "4":
            # Exit program
            print("\nGoodbye!\n")
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
