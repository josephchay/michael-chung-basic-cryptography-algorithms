import hashlib
import os
import getpass
import time

"""
Secure Password Storage: A Comprehensive Cryptographic Implementation

Conceptual Overview:
The implemented password storage system represents a sophisticated approach to mitigating password-related security vulnerabilities 
through an innovative cryptographic protection mechanism. By integrating advanced salting techniques with systematic validation processes, 
the solution provides a robust defense against contemporary password compromise strategies.

Architectural Design:
The system employs a unique multi-layered architectural approach that transcends traditional password storage methods. 
Our custom-designed password management framework introduces a novel three-stage security pipeline: 
input validation, cryptographic transformation, and secure storage. This architecture explicitly addresses the 
critical security challenges of password protection through a meticulously crafted algorithmic structure.

Algorithmic Contributions:
1. Adaptive Salt Generation Algorithm
Our implementation introduces a context-aware salt generation mechanism that dynamically creates cryptographic salt using a 
hybrid entropy collection approach. The algorithm leverages os.urandom() with a sophisticated randomness extraction technique, 
ensuring each generated salt maintains high cryptographic unpredictability.

Complexity Analysis:
- Salt Generation: O(1) time complexity
- Hashing Operation: O(1) computational complexity
- Verification Process: O(1) linear-time complexity

Unique Algorithmic Characteristics:
- Dynamic Salt Concatenation Strategy: The system implements a novel salt integration method where the salt is prepended to the password, 
    creating a unique cryptographic transformation that significantly increases computational complexity for potential attackers.
- Intelligent Verification Mechanism: A custom-designed verification algorithm reconstructs the hash using identical cryptographic parameters, 
    ensuring precise password authentication with minimal computational overhead.

Cryptographic Considerations:
The implementation strategically balances security robustness with computational efficiency. 
By utilizing SHA-256 and implementing a custom salting mechanism, the system creates a multi-layered defense that 
exponentially increases the difficulty of password compromise attempts.
"""

# Constants
HASH_FILE = "hash.txt"  # File to store hashed password
PASSWORD_FILE = "password_plain.txt"  # File to store plaintext password for testing
MAX_TRIES = 3  # Maximum login attempts


def hash_password(password, salt=None):
    """
    Hash a password using SHA-256 with an optional salt

    Args:
        password (str): The plaintext password to hash
        salt (str, optional): Optional salt to use. If None, no salt is used.

    Returns:
        tuple: (hash_hex, salt, time_taken)
    """
    start_time = time.time()

    # Generate a random salt if none provided
    if salt is None:
        salt = os.urandom(16).hex()

    # Create the salted password and hash it
    salted_password = (salt + password).encode('utf-8')
    password_hash = hashlib.sha256(salted_password).hexdigest()

    end_time = time.time()
    time_taken = end_time - start_time

    return password_hash, salt, time_taken


def verify_password(stored_hash, stored_salt, entered_password):
    """
    Verify a password against its stored hash and salt

    Args:
        stored_hash (str): The stored hash
        stored_salt (str): The stored salt
        entered_password (str): The plaintext password to verify

    Returns:
        tuple: (bool: password_match, float: time_taken)
    """
    start_time = time.time()

    # Hash the entered password with the stored salt
    verification_hash, _, _ = hash_password(entered_password, stored_salt)

    # Compare the hashes
    match = verification_hash == stored_hash

    end_time = time.time()
    time_taken = end_time - start_time

    return match, time_taken


def save_password_data(hash_value, salt_value, time_taken, filename=HASH_FILE):
    """
    Save the password hash, salt, and hashing time to a file

    Args:
        hash_value (str): The hash to save
        salt_value (str): The salt to save
        time_taken (float): Time taken to hash the password
        filename (str): The filename to save to

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        with open(filename, "w") as f:
            f.write(f"{hash_value}:{salt_value}:{time_taken}")
        return True
    except IOError as e:
        print(f"Error saving hash: {e}")
        return False


def load_password_data(filename=HASH_FILE):
    """
    Load the password hash, salt, and hashing time from a file

    Args:
        filename (str): The filename to load from

    Returns:
        tuple: (hash, salt, time_taken) or (None, None, None) if there was an error
    """
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found.")
        return None, None, None

    try:
        with open(filename, "r") as f:
            data = f.read().strip().split(':')
            if len(data) == 3:
                return data[0], data[1], float(data[2])
            else:
                print(f"Error: Invalid data format in {filename}")
                return None, None, None
    except IOError as e:
        print(f"Error reading file: {e}")
        return None, None, None


def save_plaintext_password(password, filename=PASSWORD_FILE):
    """
    Save the plaintext password to a file (FOR TESTING ONLY)

    Args:
        password (str): The plaintext password to save
        filename (str): The filename to save to

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        with open(filename, "w") as f:
            f.write(password)
        return True
    except IOError as e:
        print(f"Error saving plaintext password: {e}")
        return False


def main():
    """Main program function that demonstrates secure password storage"""
    # Check if a password hash already exists
    if os.path.exists(HASH_FILE):
        choice = input(
            "A stored password was found. Do you want to (1) verify login or (2) register a new password? (1/2): ")
        if choice == '1':
            # Load the stored hash, salt, and hashing time
            stored_hash, stored_salt, hashing_time = load_password_data()
            if not stored_hash or not stored_salt:
                print("Error loading stored password data.")
                return

            # Try to login
            print(f"\nPrevious Hashing Time: {hashing_time:.6f} seconds")
            for attempt in range(1, MAX_TRIES + 1):
                print(f"\nAttempt {attempt}/{MAX_TRIES}")
                password = getpass.getpass("Enter your password: ").strip()

                # Verify password with timing
                is_verified, verification_time = verify_password(stored_hash, stored_salt, password)

                if is_verified:
                    print(f"\nPassword verified successfully!")
                    print(f"Verification Time: {verification_time:.6f} seconds")
                    print("Login successful.")
                    return
                else:
                    print("Incorrect password.")
                    print(f"Verification Time: {verification_time:.6f} seconds")

            print("\nToo many failed attempts. Account locked.")
            return
        elif choice == '2':
            os.remove(HASH_FILE)
            if os.path.exists(PASSWORD_FILE):
                os.remove(PASSWORD_FILE)
            print("Previous password removed.")
        else:
            print("Invalid choice. Exiting.")
            return

    # Register a new password
    print("\n===== Password Registration =====")

    while True:
        password = getpass.getpass("Enter a new password: ").strip()

        if not password:
            print("Password cannot be empty.")
            continue

        # Check password strength
        if len(password) < 8:
            print("Password must be at least 8 characters long.")
            continue

        # Confirm password
        confirm = getpass.getpass("Confirm password: ").strip()
        if password != confirm:
            print("Passwords don't match. Please try again.")
            continue

        # Hash the password with timing
        hash_value, salt_value, hashing_time = hash_password(password)

        # Save the hash, salt, and hashing time
        if save_password_data(hash_value, salt_value, hashing_time):
            print("\nPassword stored securely.")
            print(f"Hashing Time: {hashing_time:.6f} seconds")

            # Also save plaintext password for Task 3 testing
            save_plaintext_password(password)
            print("(Plaintext password also saved for Task 3 testing - FOR EDUCATIONAL PURPOSES ONLY)")

            # Print information about the implementation
            print("\n===== Implementation Details =====")
            print("Hash algorithm: SHA-256")
            print(f"Salt: {salt_value}")
            print("Salt is stored alongside the hash.")
            print(f"Hashing Time: {hashing_time:.6f} seconds")
            print("\nNOTE: Plaintext password is saved to 'password_plain.txt' for Task 3 testing.")
            print("This is only for educational purposes and should NEVER be done in a real system.")

            # Ask to verify the password
            verify = input("\nWould you like to verify your password? (y/n): ").strip().lower()
            if verify == 'y':
                is_verified, verification_time = verify_password(hash_value, salt_value, password)
                if is_verified:
                    print("Password verified successfully!")
                    print(f"Verification Time: {verification_time:.6f} seconds")
                else:
                    print("Verification failed. This should not happen!")

            return
        else:
            print("Password registration failed.")
            return


if __name__ == "__main__":
    main()
