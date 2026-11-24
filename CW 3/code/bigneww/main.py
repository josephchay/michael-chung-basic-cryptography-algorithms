import sys
import os
import hashlib
import base64
import json
import time
import random
import string
import subprocess
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, 
                            QFormLayout, QMessageBox, QFileDialog, QProgressBar, QGroupBox)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt5.QtGui import QFont, QPixmap


import pyotp
import qrcode
from io import BytesIO

# File to store user credentials
CREDENTIAL_FILE = "user_credentials.json"

class PasswordHashingTab(QWidget):
    """Tab for Task 1: Secure Password Storage (Hashing and Salting)"""
    
    def __init__(self):
        super().__init__()
        self.initUI()
        
    def initUI(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Task 1: Secure Password Storage")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont('Arial', 14, QFont.Bold))
        layout.addWidget(title)
        
        # Registration section
        reg_group = QGroupBox("User Registration")
        reg_layout = QFormLayout()
        
        self.reg_username = QLineEdit()
        self.reg_password = QLineEdit()
        self.reg_password.setEchoMode(QLineEdit.Password)
        
        reg_layout.addRow(QLabel("Username:"), self.reg_username)
        reg_layout.addRow(QLabel("Password:"), self.reg_password)
        
        self.register_btn = QPushButton("Register")
        self.register_btn.clicked.connect(self.register_user)
        reg_layout.addRow("", self.register_btn)
        
        reg_group.setLayout(reg_layout)
        
        # Login section
        login_group = QGroupBox("User Login")
        login_layout = QFormLayout()
        
        self.login_username = QLineEdit()
        self.login_password = QLineEdit()
        self.login_password.setEchoMode(QLineEdit.Password)
        
        login_layout.addRow(QLabel("Username:"), self.login_username)
        login_layout.addRow(QLabel("Password:"), self.login_password)
        
        self.login_btn = QPushButton("Login")
        self.login_btn.clicked.connect(self.login_user)
        login_layout.addRow("", self.login_btn)
        
        login_group.setLayout(login_layout)
        
        # Hash details section
        hash_group = QGroupBox("Password Hash Details")
        hash_layout = QFormLayout()
        
        self.salt_display = QLineEdit()
        self.salt_display.setReadOnly(True)
        
        self.hash_display = QLineEdit()
        self.hash_display.setReadOnly(True)
        
        hash_layout.addRow(QLabel("Salt (Base64):"), self.salt_display)
        hash_layout.addRow(QLabel("Hash (Base64):"), self.hash_display)
        
        hash_group.setLayout(hash_layout)
        
        # Add sections to main layout
        layout.addWidget(reg_group)
        layout.addWidget(login_group)
        layout.addWidget(hash_group)
        
        # Explanation section
        explanation = QTextEdit()
        explanation.setReadOnly(True)
        explanation.setPlainText(
            "Security Implementation Details:\n\n"
            "- Algorithm: PBKDF2-HMAC-SHA256 with 100,000 iterations\n"
            "- Salt: 16 random bytes, unique for each user\n"
            "- Storage: Base64-encoded salt and hash\n\n"
            "Why salting is important:\n"
            "- Prevents rainbow table attacks\n"
            "- Ensures identical passwords have different hashes\n"
            "- Makes brute-force attacks more difficult\n"
            "- Protects against database leaks"
        )
        layout.addWidget(QLabel("Explanation:"))
        layout.addWidget(explanation)
        
        self.setLayout(layout)
        
    def hash_password(self, password, salt=None):
        """Hash a password using PBKDF2-HMAC-SHA256"""
        if salt is None:
            salt = os.urandom(16)
        
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return base64.b64encode(salt).decode(), base64.b64encode(pwd_hash).decode()
        
    def verify_password(self, stored_salt, stored_hash, password_attempt):
        """Verify a password against a stored hash and salt"""
        salt_bytes = base64.b64decode(stored_salt)
        _, attempt_hash = self.hash_password(password_attempt, salt_bytes)
        return stored_hash == attempt_hash
        
    def load_credentials(self):
        """Load credentials from JSON file"""
        try:
            with open(CREDENTIAL_FILE, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
            
    def save_credentials(self, credentials):
        """Save credentials to JSON file"""
        with open(CREDENTIAL_FILE, "w") as f:
            json.dump(credentials, f, indent=4)
            
    def register_user(self):
        """Register a new user"""
        username = self.reg_username.text().strip()
        password = self.reg_password.text()
        
        if not username or not password:
            QMessageBox.warning(self, "Input Error", "Username and password are required")
            return
            
        credentials = self.load_credentials()
        
        if username in credentials:
            QMessageBox.warning(self, "Registration Error", "Username already exists")
            return
            
        salt, hashed_password = self.hash_password(password)
        
        credentials[username] = {
            "salt": salt,
            "hash": hashed_password
        }
        
        self.save_credentials(credentials)
        
        self.salt_display.setText(salt)
        self.hash_display.setText(hashed_password)
        
        QMessageBox.information(self, "Success", "User registered successfully")
        
    def login_user(self):
        """Authenticate a user"""
        username = self.login_username.text().strip()
        password = self.login_password.text()
        
        if not username or not password:
            QMessageBox.warning(self, "Input Error", "Username and password are required")
            return
            
        credentials = self.load_credentials()
        
        if username not in credentials:
            QMessageBox.warning(self, "Login Error", "Username not found")
            return
            
        user_data = credentials[username]
        
        if self.verify_password(user_data["salt"], user_data["hash"], password):
            self.salt_display.setText(user_data["salt"])
            self.hash_display.setText(user_data["hash"])
            QMessageBox.information(self, "Success", "Login successful")
        else:
            QMessageBox.warning(self, "Login Error", "Incorrect password")


class MFATab(QWidget):
    """Tab for Task 2: Multi-Factor Authentication with Google/Microsoft Authenticator"""
    
    def __init__(self):
        super().__init__()
        self.initUI()
        
    def initUI(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Task 2: Multi-Factor Authentication (TOTP)")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont('Arial', 14, QFont.Bold))
        layout.addWidget(title)
        
        # Registration section
        reg_group = QGroupBox("Step 1: Register with Authenticator App")
        reg_layout = QVBoxLayout()
        
        form_layout = QFormLayout()
        self.username = QLineEdit()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        
        form_layout.addRow(QLabel("Username:"), self.username)
        form_layout.addRow(QLabel("Password:"), self.password)
        
        self.register_btn = QPushButton("Register & Generate QR Code")
        self.register_btn.clicked.connect(self.register_user)
        
        # QR Code display
        self.qr_label = QLabel("Scan this QR code with Google/Microsoft Authenticator")
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.qr_image = QLabel()
        self.qr_image.setAlignment(Qt.AlignCenter)
        self.qr_image.setMinimumSize(200, 200)
        
        # Secret key display (as backup)
        self.secret_key = QLineEdit()
        self.secret_key.setReadOnly(True)
        self.secret_key.setPlaceholderText("Your secret key will appear here")
        
        reg_layout.addLayout(form_layout)
        reg_layout.addWidget(self.register_btn)
        reg_layout.addWidget(self.qr_label)
        reg_layout.addWidget(self.qr_image)
        reg_layout.addWidget(QLabel("Secret Key (if QR doesn't work):"))
        reg_layout.addWidget(self.secret_key)
        
        reg_group.setLayout(reg_layout)
        
        # Login section
        login_group = QGroupBox("Step 2: Verify with Authenticator Code")
        login_layout = QFormLayout()
        
        self.login_username = QLineEdit()
        self.login_password = QLineEdit()
        self.login_password.setEchoMode(QLineEdit.Password)
        self.login_code = QLineEdit()
        self.login_code.setPlaceholderText("Enter 6-digit code from authenticator app")
        
        login_layout.addRow(QLabel("Username:"), self.login_username)
        login_layout.addRow(QLabel("Password:"), self.login_password)
        login_layout.addRow(QLabel("Authenticator Code:"), self.login_code)
        
        self.login_btn = QPushButton("Verify & Login")
        self.login_btn.clicked.connect(self.verify_login)
        login_layout.addRow("", self.login_btn)
        
        login_group.setLayout(login_layout)
        
        # Status section
        status_group = QGroupBox("Authentication Status")
        status_layout = QVBoxLayout()
        
        self.auth_status = QLabel("Not authenticated")
        self.auth_status.setAlignment(Qt.AlignCenter)
        self.auth_status.setFont(QFont('Arial', 12))
        
        status_layout.addWidget(self.auth_status)
        
        status_group.setLayout(status_layout)
        
        # Add sections to main layout
        layout.addWidget(reg_group)
        layout.addWidget(login_group)
        layout.addWidget(status_group)
        
        # Explanation section
        explanation = QTextEdit()
        explanation.setReadOnly(True)
        explanation.setPlainText(
            "Multi-Factor Authentication with TOTP Explanation:\n\n"
            "This MFA implementation uses:\n"
            "1. Something you know (password)\n"
            "2. Something you have (Time-based One-Time Password via Google/Microsoft Authenticator)\n\n"
            "Security benefits of TOTP-based MFA:\n"
            "- Time-based codes expire quickly (typically 30 seconds)\n"
            "- Each code can only be used once\n"
            "- Works offline without requiring SMS or email\n"
            "- Industry standard implementation (RFC 6238)\n"
            "- Protection against phishing, replay attacks, and password theft\n"
            "- Used by major organizations worldwide for secure authentication\n\n"
            "This implementation uses the same TOTP algorithm as Google and Microsoft Authenticator apps."
        )
        layout.addWidget(QLabel("Explanation:"))
        layout.addWidget(explanation)
        
        self.setLayout(layout)
        
    def generate_qr_code(self, totp_uri):
        """Generate QR code image from TOTP URI"""
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert PIL image to QPixmap for display
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        pixmap = QPixmap()
        pixmap.loadFromData(buffer.getvalue())
        return pixmap
        
    def hash_password(self, password, salt=None):
        """Hash a password using PBKDF2-HMAC-SHA256"""
        if salt is None:
            salt = os.urandom(16)
        
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return base64.b64encode(salt).decode(), base64.b64encode(pwd_hash).decode()
        
    def verify_password(self, stored_salt, stored_hash, password_attempt):
        """Verify a password against a stored hash and salt"""
        salt_bytes = base64.b64decode(stored_salt)
        _, attempt_hash = self.hash_password(password_attempt, salt_bytes)
        return stored_hash == attempt_hash
        
    def load_credentials(self):
        """Load credentials from JSON file"""
        try:
            with open(CREDENTIAL_FILE, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
            
    def save_credentials(self, credentials):
        """Save credentials to JSON file"""
        with open(CREDENTIAL_FILE, "w") as f:
            json.dump(credentials, f, indent=4)
            
    def register_user(self):
        """Register a new user with TOTP"""
        username = self.username.text().strip()
        password = self.password.text()
        
        if not username or not password:
            QMessageBox.warning(self, "Input Error", "Username and password are required")
            return
            
        credentials = self.load_credentials()
        
        # Generate TOTP secret
        totp_secret = pyotp.random_base32()
        
        # Create authenticator URI
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=username,
            issuer_name="COMP3028 Security Demo"
        )
        
        # Generate and display QR code
        pixmap = self.generate_qr_code(totp_uri)
        self.qr_image.setPixmap(pixmap.scaled(200, 200, Qt.KeepAspectRatio))
        self.secret_key.setText(totp_secret)
        
        # Hash password
        salt, hashed_password = self.hash_password(password)
        
        # Save user with TOTP secret
        credentials[username] = {
            "salt": salt,
            "hash": hashed_password,
            "totp_secret": totp_secret
        }
        
        self.save_credentials(credentials)
        
        QMessageBox.information(self, "Success", 
                              "User registered successfully.\n\n"
                              "Please scan the QR code with Google Authenticator or Microsoft Authenticator app.")
        
    def verify_login(self):
        """Verify login with password and TOTP"""
        username = self.login_username.text().strip()
        password = self.login_password.text()
        totp_code = self.login_code.text().strip()
        
        if not username or not password or not totp_code:
            QMessageBox.warning(self, "Input Error", "Username, password and authenticator code are required")
            return
            
        credentials = self.load_credentials()
        
        if username not in credentials:
            QMessageBox.warning(self, "Login Error", "Username not found")
            return
            
        user_data = credentials[username]
        
        # Verify password (first factor)
        if not self.verify_password(user_data["salt"], user_data["hash"], password):
            QMessageBox.warning(self, "Login Error", "Incorrect password")
            return
            
        # Verify TOTP code (second factor)
        if "totp_secret" not in user_data:
            QMessageBox.warning(self, "Login Error", "User not set up for TOTP authentication")
            return
            
        totp = pyotp.TOTP(user_data["totp_secret"])
        if not totp.verify(totp_code):
            QMessageBox.warning(self, "Login Error", "Incorrect authenticator code")
            return
            
        # Both factors verified
        self.auth_status.setText("Authentication successful! Both factors verified.")
        self.auth_status.setStyleSheet("color: green; font-weight: bold;")
        QMessageBox.information(self, "Success", "Authentication successful!")


class CrackingThread(QThread):
    """Thread for running password cracking simulation using Hashcat"""
    progress_update = pyqtSignal(str)
    completed = pyqtSignal(dict)
    
    def __init__(self, hash_file, wordlist):
        super().__init__()
        self.hash_file = hash_file
        self.wordlist = wordlist
        self.hashcat_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                                       "tools", "hashcat-6.2.6", "hashcat.exe")
        self.hashcat_dir = os.path.dirname(self.hashcat_path)
    
    def run(self):
        self.progress_update.emit("Starting password cracking simulation with Hashcat...")
        self.progress_update.emit(f"Using Hashcat from: {self.hashcat_path}")
        
        start_time = time.time()
        
        # Check if Hashcat executable exists
        if not os.path.exists(self.hashcat_path):
            self.progress_update.emit(f"ERROR: Hashcat executable not found at {self.hashcat_path}")
            self.completed.emit({"error": "Hashcat not found"})
            return
            
        # First, convert hashes to Hashcat format
        self.progress_update.emit("Converting hashes to Hashcat format...")
        hashcat_hash_file = self.convert_hashes_for_hashcat()
        if not hashcat_hash_file:
            self.progress_update.emit("ERROR: Failed to convert hashes")
            self.completed.emit({"error": "Hash conversion failed"})
            return
        
        # Run Hashcat
        try:
            self.progress_update.emit(f"Running Hashcat with wordlist: {self.wordlist}")
            self.progress_update.emit("This may take some time...")
            
            # Create output file for cracked passwords
            output_file = "hashcat_cracked.txt"
            if os.path.exists(output_file):
                os.remove(output_file)
            
            # Use -m 10900 for PBKDF2-SHA256
            # Adding --potfile-disable to ensure we get fresh results
            result = subprocess.run([
                self.hashcat_path, 
                "-m", "10900",    # PBKDF2-SHA256 mode
                "-a", "0",        # Dictionary attack mode
                "-o", output_file, # Output file for cracked passwords
                "--outfile-format=3", # Format: hash:salt:password
                "--status",       # Show status
                "--force",        # Ignore warnings
                hashcat_hash_file, 
                self.wordlist
            ], 
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.hashcat_dir,
            text=True)
            
            self.progress_update.emit("Hashcat completed")
            
            # Output any errors to help with debugging
            if result.stderr:
                self.progress_update.emit(f"Hashcat stderr: {result.stderr}")
            
            # Parse the output file to get results
            cracked_results = self.parse_hashcat_results(output_file)
            
        except subprocess.SubprocessError as e:
            self.progress_update.emit(f"Error running Hashcat: {e}")
            self.completed.emit({"error": str(e)})
            return
            
        elapsed_time = time.time() - start_time
        
        # Process results
        self.progress_update.emit("Analyzing results...")
        cracked_count = len(cracked_results)
        
        self.progress_update.emit(f"Cracking completed in {elapsed_time:.2f} seconds")
        self.progress_update.emit(f"Passwords cracked: {cracked_count}")
        
        # Display cracked passwords
        for username, password in cracked_results.items():
            self.progress_update.emit(f"Cracked: {username} = {password}")
                
        # Return results
        results = {
            "time": elapsed_time,
            "cracked_count": cracked_count,
            "total_count": self.get_total_count(),
            "cracked_passwords": cracked_results
        }
        
        self.completed.emit(results)
    
    def convert_hashes_for_hashcat(self):
        """Convert the hashes to Hashcat format for PBKDF2-SHA256"""
        try:
            hashcat_file = "hashcat_hashes.txt"
            
            # Read credentials from original file
            with open(CREDENTIAL_FILE, 'r') as f:
                credentials = json.load(f)
            
            # Write in Hashcat format
            with open(hashcat_file, 'w') as f:
                for username, data in credentials.items():
                    # Format for mode 10900: hash:salt:iterations
                    f.write(f"{data['hash']}:{data['salt']}:100000\n")
            
            # Also create a mapping file to match hashes back to usernames
            with open("hash_username_map.json", 'w') as f:
                username_map = {}
                for username, data in credentials.items():
                    username_map[data['hash']] = username
                json.dump(username_map, f)
            
            self.progress_update.emit(f"Created {hashcat_file} with {len(credentials)} entries")
            return hashcat_file
        except Exception as e:
            self.progress_update.emit(f"Error converting hashes: {str(e)}")
            return None
    
    def parse_hashcat_results(self, output_file):
        """Parse the hashcat output file to get cracked passwords"""
        cracked = {}
        try:
            # Load the hash to username mapping
            with open("hash_username_map.json", 'r') as f:
                hash_to_username = json.load(f)
            
            # Check if output file exists
            if not os.path.exists(output_file):
                self.progress_update.emit(f"Warning: Output file {output_file} not found")
                return cracked
            
            # Read the cracked passwords
            with open(output_file, 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 3:
                        # Format is hash:salt:password
                        hash_val = parts[0]
                        password = parts[-1]
                        
                        # Look up the username
                        if hash_val in hash_to_username:
                            username = hash_to_username[hash_val]
                            cracked[username] = password
                        else:
                            self.progress_update.emit(f"Warning: Could not find username for hash: {hash_val}")
            
            return cracked
        except Exception as e:
            self.progress_update.emit(f"Error parsing results: {str(e)}")
            return cracked
        
    def get_total_count(self):
        """Get total number of password hashes"""
        try:
            with open(CREDENTIAL_FILE, 'r') as f:
                credentials = json.load(f)
                return len(credentials)
        except:
            return 0


class PasswordCrackingTab(QWidget):
    """Tab for Task 3: Password Cracking Simulation"""
    
    def __init__(self):
        super().__init__()
        self.cracking_results = None
        self.initUI()
        
    def initUI(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Task 3: Password Cracking Simulation")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont('Arial', 14, QFont.Bold))
        layout.addWidget(title)
        
        # Configuration section
        config_group = QGroupBox("Configuration")
        config_layout = QFormLayout()
        
        self.wordlist_path = QLineEdit()
        self.wordlist_path.setText("rockyou.txt")
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_wordlist)
        
        wordlist_layout = QHBoxLayout()
        wordlist_layout.addWidget(self.wordlist_path)
        wordlist_layout.addWidget(browse_btn)
        
        config_layout.addRow(QLabel("Wordlist:"), wordlist_layout)
        
        self.prepare_btn = QPushButton("Prepare Hashes for Cracking")
        self.prepare_btn.clicked.connect(self.prepare_hashes)
        config_layout.addRow("", self.prepare_btn)
        
        self.run_btn = QPushButton("Run Password Cracking")
        self.run_btn.clicked.connect(self.run_cracking)
        self.run_btn.setEnabled(False)
        config_layout.addRow("", self.run_btn)
        
        config_group.setLayout(config_layout)
        
        # Progress section
        progress_group = QGroupBox("Cracking Progress")
        progress_layout = QVBoxLayout()
        
        self.progress_log = QTextEdit()
        self.progress_log.setReadOnly(True)
        
        progress_layout.addWidget(self.progress_log)
        
        progress_group.setLayout(progress_layout)
        
        # Results section
        results_group = QGroupBox("Results Analysis")
        results_layout = QVBoxLayout()
        
        # Matplotlib figure
        self.figure = plt.figure(figsize=(5, 4))
        self.canvas = FigureCanvas(self.figure)
        
        results_layout.addWidget(self.canvas)
        
        # Summary text
        self.results_summary = QTextEdit()
        self.results_summary.setReadOnly(True)
        
        results_layout.addWidget(self.results_summary)
        
        results_group.setLayout(results_layout)
        
        # Add sections to main layout
        layout.addWidget(config_group)
        layout.addWidget(progress_group)
        layout.addWidget(results_group)
        
        self.setLayout(layout)
        
    def log_message(self, message):
        """Add a message to the progress log"""
        self.progress_log.append(message)
        
    def browse_wordlist(self):
        """Browse for wordlist file"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            self.wordlist_path.setText(file_path)
            
    def prepare_hashes(self):
        """Prepare hashes for Hashcat"""
        self.log_message("Preparing password hashes for cracking...")
        
        try:
            # Check if credentials file exists
            if not os.path.exists(CREDENTIAL_FILE):
                self.log_message("ERROR: Credentials file not found. Please register users in Task 1 first.")
                return
                
            # Read credentials
            with open(CREDENTIAL_FILE, 'r') as f:
                credentials = json.load(f)
                
            self.log_message(f"Found {len(credentials)} user credentials to process")
            
            hashcat_file = "hashcat_hashes.txt"
            with open(hashcat_file, 'w') as f:
                for username, data in credentials.items():
                    # Format: username:$pbkdf2-hmac-sha256$iterations$salt$hash
                    f.write(f"{username}:$pbkdf2-hmac-sha256$100000${data['salt']}${data['hash']}\n")
                    
            self.log_message(f"Successfully created {hashcat_file} with {len(credentials)} password hashes")
            self.log_message("Ready for password cracking")
            
            self.hash_file = hashcat_file
            self.run_btn.setEnabled(True)
            
        except Exception as e:
            self.log_message(f"ERROR: {str(e)}")
            
    def run_cracking(self):
        """Run password cracking simulation"""
        wordlist = self.wordlist_path.text()
        
        if not os.path.exists(wordlist):
            QMessageBox.warning(self, "File Error", "Wordlist file not found")
            return
            
        if not hasattr(self, 'hash_file') or not os.path.exists(self.hash_file):
            QMessageBox.warning(self, "File Error", "Hash file not found. Please prepare hashes first.")
            return
            
        self.log_message("\n--- Starting Password Cracking Simulation ---")
        
        # Disable buttons during cracking
        self.run_btn.setEnabled(False)
        self.prepare_btn.setEnabled(False)
        
        # Start cracking thread
        self.cracking_thread = CrackingThread(self.hash_file, wordlist)
        self.cracking_thread.progress_update.connect(self.log_message)
        self.cracking_thread.completed.connect(self.process_results)
        self.cracking_thread.start()
        
    def process_results(self, results):
        """Process and display cracking results"""
        self.log_message("--- Cracking Simulation Complete ---")
        
        # Re-enable buttons
        self.run_btn.setEnabled(True)
        self.prepare_btn.setEnabled(True)
        
        if "error" in results:
            self.log_message(f"ERROR: {results['error']}")
            return
            
        self.cracking_results = results
        
        # Create visualization
        self.figure.clear()
        ax = self.figure.add_subplot(111)
        
        cracked = results["cracked_count"]
        uncracked = results["total_count"] - cracked
        
        ax.bar(["Cracked", "Uncracked"], [cracked, uncracked], color=["red", "green"])
        ax.set_title("Password Cracking Results")
        ax.set_ylabel("Number of Passwords")
        
        self.canvas.draw()
        
        # Create summary
        cracked_percent = (cracked / results["total_count"]) * 100 if results["total_count"] > 0 else 0
        
        if cracked_percent > 75:
            strength = "Very Weak"
        elif cracked_percent > 50:
            strength = "Weak"
        elif cracked_percent > 25:
            strength = "Moderate"
        elif cracked_percent > 0:
            strength = "Strong"
        else:
            strength = "Very Strong"
            
        summary = f"""
Password Cracking Analysis:
---------------------------
Time taken: {results['time']:.2f} seconds
Total passwords: {results['total_count']}
Cracked passwords: {cracked} ({cracked_percent:.1f}%)
Password strength: {strength}

Recommendations for Improving Password Policies:
-----------------------------------------------
1. Require longer passwords (minimum 12 characters)
2. Enforce a mix of character types (uppercase, lowercase, numbers, symbols)
3. Check passwords against common password lists
4. Implement account lockout after failed attempts
5. Require periodic password changes
6. Use modern hashing algorithms like Argon2 or bcrypt
7. Increase PBKDF2 iterations to at least 310,000 (OWASP recommendation)
8. Educate users about creating strong, unique passwords
        """
        
        self.results_summary.setPlainText(summary)
        

class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle("COMP3028 Computer Security - Password Security Suite")
        self.setGeometry(100, 100, 900, 700)
        
        # Create tab widget
        tabs = QTabWidget()
        
        # Create tabs for each task
        tab1 = PasswordHashingTab()
        tab2 = MFATab()
        tab3 = PasswordCrackingTab()
        
        # Add tabs
        tabs.addTab(tab1, "Task 1: Password Storage")
        tabs.addTab(tab2, "Task 2: Multi-Factor Auth")
        tabs.addTab(tab3, "Task 3: Password Cracking")
        
        self.setCentralWidget(tabs)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
