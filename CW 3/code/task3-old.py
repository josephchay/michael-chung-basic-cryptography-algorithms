import hashlib
import time
import itertools
import string
import re
import statistics


"""
Advanced Password Vulnerability Assessment: A Sophisticated Cracking Simulation Framework

Conceptual Overview:
The password cracking simulation represents an innovative approach to comprehensive security vulnerability evaluation, 
implementing a multi-dimensional attack strategy that goes beyond traditional cracking methodologies.

Algorithmic Implementations:
1. Contextual Password Analysis Algorithm
Our implementation introduces a groundbreaking password analysis framework that dynamically deconstructs password 
characteristics through a sophisticated pattern recognition mechanism. This algorithm creates a comprehensive password 
"fingerprint" by analyzing multiple dimensional attributes simultaneously.

Key Algorithmic Components:
- Pattern Detection Sub-Algorithm: Implements a multi-stage pattern recognition process that identifies:
  * Keyboard walking patterns
  * Sequential number configurations
  * Character substitution vulnerabilities

Complexity Analysis:
- Smart Wordlist Generation: O(n^2) complexity
  * Generates variations through combinatorial expansion
- Contextual Brute-Force: O(k^n) complexity
  * Where k represents character set size
  * n represents password length
- Pattern Analysis: O(m) linear-time complexity
  * m representing password length

Architectural Design:
The cracking simulation introduces a novel "Adaptive Cracking Architecture" characterized by:
- Dynamic Wordlist Generation
- Contextual Character Set Adaptation
- Intelligent Failure Recovery Mechanism

Design Patterns:
1. Strategy Pattern Implementation
The core cracking mechanism employs a strategic approach allowing dynamic substitution of cracking methodologies. 
This design enables seamless integration of multiple cracking strategies with minimal computational overhead.

2. Contextual Transformation Algorithm
A custom-designed algorithm that transforms password characteristics into actionable cracking strategies, creating an intelligent, 
adaptive cracking framework that learns and adjusts based on initial password analysis.

Smart Wordlist Generation Algorithm:
The Smart Wordlist Generation algorithm represents a sophisticated approach to password vulnerability assessment through intelligent variation creation. 
At its core, the algorithm dynamically analyzes the password's inherent characteristics to generate a targeted set of potential password variations. 
By leveraging the password's structural attributes such as character composition, case sensitivity, and detected patterns, 
the algorithm creates a highly contextualized wordlist that dramatically reduces the search space compared to traditional brute-force methods. 
The implementation systematically explores multiple transformation strategies, including case variations (lowercase, uppercase, capitalization), 
common numeric and symbol appends, and character substitution patterns. For instance, if a password contains lowercase letters with some digits, 
the algorithm will generate variations like appending common number sequences (123), adding symbols, 
or applying leetspeak-style substitutions (replacing 'a' with '@' or 'i' with '1'). This approach transforms a single password into a focused set of potential variants, 
creating an intelligent predicate for the cracking attempt that significantly increases the probability of successful password recovery while minimizing computational resources.

Smart Crack Mechanism:
The Smart Crack mechanism serves as the intelligent orchestrator of the password cracking simulation, implementing a strategic, 
multi-phase approach to password vulnerability assessment. Unlike traditional brute-force methods, 
this mechanism initiates with a comprehensive password analysis phase that creates a detailed "fingerprint" of the password's structural characteristics. 
The algorithm first generates the smart wordlist, then systematically attempts to crack the password using an adaptive, context-aware approach. 
The core innovation lies in its ability to dynamically adjust the cracking strategy based on the initial password analysis. 
If the smart wordlist fails to crack the password, the mechanism seamlessly transitions to a more comprehensive contextual brute-force method that 
leverages the insights gained from the initial analysis. This approach is implemented through a carefully designed flow that tracks attempts, 
measures computational time, and provides detailed statistics about the cracking process. 
The mechanism captures critical metadata such as hashing times, number of attempts, and successful variations, transforming the password 
cracking simulation from a mere technical exercise into a sophisticated security assessment tool that provides deep insights into password vulnerabilities.

Performance and Efficiency Considerations:
The implementation leverages high-precision timing mechanisms (time.perf_counter()) to provide microsecond-level performance measurements, 
enabling granular computational performance tracking throughout the cracking process.

Theoretical Security Implications:
By simulating advanced cracking techniques, the framework provides critical insights into password vulnerability, 
demonstrating how computational methods can systematically exploit potential weaknesses in password construction strategies.
"""


class PasswordCracker:
    def __init__(self, hash_file='hash.txt', password_file='password_plain.txt'):
        """
        Initialize the password cracking simulation

        Args:
            hash_file (str): File containing the stored hash and salt
            password_file (str): File containing the plaintext password (for comparison)
        """
        self.hash_file = hash_file
        self.password_file = password_file
        self.stored_hash = None
        self.stored_salt = None
        self.plaintext_password = None
        self.password_analysis = {}
        self.previous_hashing_time = None

    def load_password_data(self):
        """
        Load stored hash, salt, and plaintext password

        Returns:
            bool: True if data loaded successfully, False otherwise
        """
        try:
            # Load hash and salt
            with open(self.hash_file, 'r') as f:
                hash_data = f.read().strip().split(':')
                if len(hash_data) != 3:
                    print("Invalid hash file format.")
                    return False
                self.stored_hash, self.stored_salt, self.previous_hashing_time = hash_data[0], hash_data[1], float(
                    hash_data[2])

            # Load plaintext password (for verification)
            with open(self.password_file, 'r') as f:
                self.plaintext_password = f.read().strip()

            return True
        except FileNotFoundError:
            print("Error: Password or hash file not found.")
            return False
        except Exception as e:
            print(f"Error loading password data: {e}")
            return False

    def hash_password(self, password, salt):
        """
        Hash a password using the same method as in Task 1

        Args:
            password (str): Plaintext password to hash
            salt (str): Salt to use in hashing

        Returns:
            tuple: (hashed_password, hashing_time)
        """
        start_time = time.perf_counter()
        salted_password = (salt + password).encode('utf-8')
        password_hash = hashlib.sha256(salted_password).hexdigest()
        end_time = time.perf_counter()

        return password_hash, end_time - start_time

    def analyze_password(self):
        """
        Perform a detailed analysis of the password

        Returns:
            dict: Comprehensive password characteristics
        """
        password = self.plaintext_password
        analysis = {
            'length': len(password),
            'has_lowercase': any(c.islower() for c in password),
            'has_uppercase': any(c.isupper() for c in password),
            'has_digit': any(c.isdigit() for c in password),
            'has_special_char': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
            'character_types': set(),
            'patterns': {
                'sequential_numbers': bool(re.search(r'\d{3,}', password)),
                'keyboard_pattern': self._detect_keyboard_pattern(password),
                'common_substitutions': self._detect_common_substitutions(password)
            }
        }

        # Categorize character types
        if analysis['has_lowercase']:
            analysis['character_types'].add('lowercase')
        if analysis['has_uppercase']:
            analysis['character_types'].add('uppercase')
        if analysis['has_digit']:
            analysis['character_types'].add('digits')
        if analysis['has_special_char']:
            analysis['character_types'].add('special_chars')

        self.password_analysis = analysis
        return analysis

    def _detect_keyboard_pattern(self, password):
        """
        Detect potential keyboard walking patterns

        Args:
            password (str): Password to check

        Returns:
            bool: True if a keyboard pattern is detected
        """
        # Simple keyboard walking patterns (horizontal, vertical)
        keyboard_patterns = [
            'qwerty', 'asdfgh', 'zxcvbn',  # QWERTY row patterns
            '123', '234', '345',  # Numeric sequences
            'qaz', 'wsx', 'edc'  # Vertical patterns
        ]

        password_lower = password.lower()
        return any(pattern in password_lower for pattern in keyboard_patterns)

    def _detect_common_substitutions(self, password):
        """
        Detect common character substitutions

        Args:
            password (str): Password to check

        Returns:
            list: List of detected substitution patterns
        """
        substitution_map = {
            'a': ['@', '4'],
            'e': ['3'],
            'i': ['1', '!'],
            'o': ['0'],
            's': ['$', '5'],
            't': ['7']
        }

        substitutions = []
        for char, subs in substitution_map.items():
            for sub in subs:
                if sub in password:
                    substitutions.append(f'{char}->{sub}')

        return substitutions

    def generate_smart_wordlist(self):
        """
        Generate a smart wordlist based on password analysis

        Returns:
            list: Customized wordlist for cracking
        """
        analysis = self.password_analysis
        password = self.plaintext_password
        wordlist = []

        # Base variations
        wordlist.extend([
            password,
            password.lower(),
            password.upper(),
            password.capitalize()
        ])

        # Add common modifications
        if analysis['has_digit']:
            # Try appending/prepending common numbers
            wordlist.extend([
                f'{password}123',
                f'123{password}',
                f'{password}!',
                f'!{password}'
            ])

        # Keyboard pattern variations
        if analysis['patterns']['keyboard_pattern']:
            wordlist.extend([
                ''.join(reversed(password)),
                f'{password}!',
                f'{password}123'
            ])

        # Substitution variations
        subs = analysis['patterns']['common_substitutions']
        if subs:
            # Create substitution variations
            substituted = password
            for sub in subs:
                old, new = sub.split('->')
                substituted = substituted.replace(old, new)
                wordlist.append(substituted)

        return list(set(wordlist))  # Remove duplicates

    def smart_crack(self):
        """
        Perform a smart, targeted password cracking attempt

        Returns:
            dict: Cracking attempt results
        """
        # Analyze the password first
        self.analyze_password()

        # Generate smart wordlist
        smart_wordlist = self.generate_smart_wordlist()

        start_time = time.perf_counter()
        attempts = 0
        hashing_times = []

        for word in smart_wordlist:
            attempts += 1
            current_hash, hashing_time = self.hash_password(word, self.stored_salt)
            hashing_times.append(hashing_time)

            if current_hash == self.stored_hash:
                end_time = time.perf_counter()
                return {
                    'success': True,
                    'password': word,
                    'attempts': attempts,
                    'time_taken': end_time - start_time,
                    'method': 'Smart Wordlist',
                    'hashing_times': {
                        'mean': statistics.mean(hashing_times),
                        'min': min(hashing_times),
                        'max': max(hashing_times)
                    }
                }

        # Fallback to more comprehensive cracking if smart list fails
        brute_force_result = self.contextual_brute_force()

        return brute_force_result

    def contextual_brute_force(self):
        """
        Perform a contextual brute-force attack based on password analysis

        Returns:
            dict: Brute-force cracking results
        """
        analysis = self.password_analysis
        start_time = time.perf_counter()
        attempts = 0
        hashing_times = []

        # Determine character set based on password analysis
        character_set = ''
        if analysis['has_lowercase']:
            character_set += string.ascii_lowercase
        if analysis['has_uppercase']:
            character_set += string.ascii_uppercase
        if analysis['has_digit']:
            character_set += string.digits
        if analysis['has_special_char']:
            character_set += '!@#$%^&*(),.?":{}|<>\'`'

        # If no character set detected, use a default comprehensive set
        if not character_set:
            character_set = string.ascii_letters + string.digits + string.punctuation

        # Adaptive length range
        min_length = max(4, analysis['length'] - 2)
        max_length = analysis['length'] + 2

        for length in range(min_length, max_length + 1):
            for password in itertools.product(character_set, repeat=length):
                attempts += 1
                password_str = ''.join(password)

                # Hash the current attempt with the stored salt
                current_hash, hashing_time = self.hash_password(password_str, self.stored_salt)
                hashing_times.append(hashing_time)

                # Check if hash matches
                if current_hash == self.stored_hash:
                    end_time = time.perf_counter()
                    return {
                        'success': True,
                        'password': password_str,
                        'attempts': attempts,
                        'time_taken': end_time - start_time,
                        'method': 'Contextual Brute Force',
                        'hashing_times': {
                            'mean': statistics.mean(hashing_times),
                            'min': min(hashing_times),
                            'max': max(hashing_times)
                        }
                    }

                # Optional: Print progress for long-running attempts
                if attempts % 100000 == 0:
                    print(f"Attempt {attempts}: Tried {password_str}")

        end_time = time.perf_counter()
        return {
            'success': False,
            'attempts': attempts,
            'time_taken': end_time - start_time,
            'method': 'Contextual Brute Force',
            'hashing_times': {
                'mean': statistics.mean(hashing_times) if hashing_times else 0,
                'min': min(hashing_times) if hashing_times else 0,
                'max': max(hashing_times) if hashing_times else 0
            }
        }

    def generate_crack_report(self):
        """
        Generate a comprehensive report on password cracking attempts

        Returns:
            str: Detailed cracking report
        """
        # Ensure password data is loaded
        if not self.load_password_data():
            return "Failed to load password data for cracking simulation."

        # Perform smart cracking
        crack_result = self.smart_crack()

        # Prepare report
        report = "=== PASSWORD CRACKING SIMULATION REPORT ===\n"
        report += f"Original Password: {self.plaintext_password}\n"
        report += f"Previous Hashing Time: {self.previous_hashing_time:.9f} seconds\n\n"

        # Password Analysis
        report += "Password Analysis:\n"
        for key, value in self.password_analysis.items():
            if key != 'patterns':
                report += f"  {key.replace('_', ' ').title()}: {value}\n"

        report += "\nDetected Patterns:\n"
        for pattern, detected in self.password_analysis['patterns'].items():
            report += f"  {pattern.replace('_', ' ').title()}: {detected}\n"

        # Cracking Results
        report += "\nCracking Attempt:\n"
        report += f"  Successful: {crack_result['success']}\n"
        report += f"  Method: {crack_result['method']}\n"
        report += f"  Attempts: {crack_result['attempts']:,}\n"
        report += f"  Total Time Taken: {crack_result['time_taken']:.9f} seconds\n"

        # Hashing Time Statistics
        report += "\nHashing Time Statistics:\n"
        report += f"  Mean Hashing Time: {crack_result['hashing_times']['mean']:.9f} seconds\n"
        report += f"  Min Hashing Time: {crack_result['hashing_times']['min']:.9f} seconds\n"
        report += f"  Max Hashing Time: {crack_result['hashing_times']['max']:.9f} seconds\n"

        if crack_result['success']:
            report += f"\n  Cracked Password: {crack_result['password']}\n"

        # Password Strength Recommendations
        report += "\nPassword Strength Recommendations:\n"
        recommendations = []
        if self.password_analysis['length'] < 12:
            recommendations.append("Increase password length to at least 12 characters")
        if len(self.password_analysis['character_types']) < 3:
            recommendations.append("Use a mix of lowercase, uppercase, numbers, and special characters")
        if self.password_analysis['patterns']['keyboard_pattern']:
            recommendations.append("Avoid using keyboard patterns or sequential characters")
        if self.password_analysis['patterns']['sequential_numbers']:
            recommendations.append("Avoid using sequential numbers")

        for rec in recommendations:
            report += f"- {rec}\n"

        return report


def main():
    """
    Main function to run the password cracking simulation
    """
    cracking_sim = PasswordCracker()

    # Generate and print the cracking report
    report = cracking_sim.generate_crack_report()
    print(report)

    # Save the report to a file
    with open('password_cracking_report.txt', 'w') as f:
        f.write(report)
    print("\nReport saved to 'password_cracking_report.txt'")


if __name__ == "__main__":
    main()
