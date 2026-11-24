"""
Multi-Factor Authentication (MFA) System

This code implements a complete multi-factor authentication system with both CLI and GUI interfaces:
- Supports user registration with username, password, and phone number
- Implements TOTP (Time-based One-Time Password) according to RFC 6238
- Allows verification through either direct OTP display or authentication apps
- Features secure password storage with salt and hashing
- Provides QR code generation for easy authentication app setup
- Includes both command-line and graphical user interfaces

The system demonstrates proper implementation of two-factor authentication:
1. Something you know (password)
2. Something you have (OTP from mobile device or authentication app)

Usage:
- Run with no arguments for GUI mode
- Run with --cli argument for command-line mode

========= MFA Security Benefits =========
• MFA significantly improves security by requiring two different types of credentials.
• Even if an attacker obtains your password through a data breach or phishing attack,
  they still cannot access your account without the second factor (OTP).
• The OTP changes every 30 seconds, making it resistant to replay attacks.
• MFA mitigates risks from password-related vulnerabilities like:
    • Weak or reused passwords
    • Credential stuffing attacks
    • Phishing attacks
    • Keylogging malware
"""

# PIP REQUIREMENTS
# PyQt5==5.15.9
# pyotp==2.8.0
# qrcode==7.4.2
# pillow==9.5.0 

import time
import hashlib
import random
import datetime
import os
import sys
import io
import pyotp
import qrcode
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                           QStackedWidget, QMessageBox, QFrame, QRadioButton,
                           QButtonGroup, QGroupBox)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont, QPixmap
from PyQt5 import QtCore


class MFASystem:
    """
    Multi-Factor Authentication System implementing TOTP (Time-based One-Time Password)
    This class provides functionality for user registration and authentication using
    both password (first factor) and time-based OTP (second factor).
    """
    def __init__(self):
        self.users = {}  # username -> {password_hash, salt, secret_key, phone_number}
        self.otp_info = {}  # username -> {otp, expiration_time}
        
    def register_user(self, username, password, phone_number):
        """
        Register a new user with password and generate their OTP secret key
        
        Args:
            username: User's unique identifier
            password: User's password (will be hashed)
            phone_number: User's phone number
        Returns:
            secret_key: Base32 encoded secret key for OTP generation
        """
        # Generate a random salt (16 bytes)
        salt = os.urandom(16)
        salt_hex = salt.hex()
        
        # Hash the password with salt
        password_hash = hashlib.sha256(salt + password.encode()).hexdigest()
        
        # Generate a random secret key for OTP generation (160 bits = 20 bytes)
        # Using pyotp to ensure compatibility with authentication apps
        secret_key = pyotp.random_base32()
        
        # Store user information
        self.users[username] = {
            'password_hash': password_hash,
            'salt': salt_hex,
            'secret_key': secret_key,
            'phone_number': phone_number
        }
        
        return secret_key
    
    def verify_password(self, username, password):
        """
        Verify if the provided password is correct for the given username
        
        Args:
            username: User's identifier
            password: Password to verify
            
        Returns:
            bool: True if password matches, False otherwise
        """
        if username not in self.users:
            return False
        
        # Get the user's salt and convert from hex to bytes
        salt_hex = self.users[username]['salt']
        salt = bytes.fromhex(salt_hex)
        
        # Hash the provided password with the same salt
        password_hash = hashlib.sha256(salt + password.encode()).hexdigest()
        return password_hash == self.users[username]['password_hash']
    
    def generate_otp(self, secret_key):
        """
        Generate a 6-digit OTP based on time and secret key (TOTP algorithm - RFC 6238)
        
        Args:
            secret_key: Base32 encoded secret key
            
        Returns:
            tuple: (otp, expiration_datetime, time_remaining) - The 6-digit OTP, its expiration time, and seconds remaining
        """
        # Using pyotp for TOTP generation
        totp = pyotp.TOTP(secret_key)
        otp = totp.now()
        
        # Calculate expiration time (next 30-second boundary)
        interval = 30  # Standard TOTP time step in seconds
        current_time = int(time.time())
        time_remaining = interval - (current_time % interval)
        expiration_time = current_time + time_remaining
        expiration_datetime = datetime.datetime.fromtimestamp(expiration_time)
        
        return otp, expiration_datetime, time_remaining
    
    def generate_auth_app_uri(self, username, issuer="MFA Demo"):
        """
        Generate a URI for authentication apps like Google Authenticator
        
        Args:
            username: User's identifier
            issuer: The service provider name
            
        Returns:
            string: URI for QR code generation
        """
        if username not in self.users:
            return None
        
        secret = self.users[username]['secret_key']
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(username, issuer_name=issuer)
    
    def verify_otp(self, username, otp):
        """
        Verify if the provided OTP is correct for the given username
        
        Args:
            username: User's identifier
            otp: One-time password to verify
            
        Returns:
            tuple: (is_valid, is_expired) - Whether OTP is valid and whether it expired
        """
        if username not in self.users:
            return False, False
        
        # First try to validate with pyotp directly (for auth app validation)
        secret_key = self.users[username]['secret_key']
        totp = pyotp.TOTP(secret_key)
        if totp.verify(otp):
            return True, False
        
        # Then check stored OTP for SMS/display method
        if username in self.otp_info:
            stored_otp = self.otp_info[username]['otp']
            expiration_time = self.otp_info[username]['expiration_time']
            
            # Check if OTP has expired
            current_time = datetime.datetime.now()
            if current_time > expiration_time:
                return False, True  # OTP is incorrect and has expired
            
            # Check if OTP matches
            if otp == stored_otp:
                return True, False  # OTP is correct and has not expired
        
        return False, False  # OTP is incorrect


class MFAGui(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # Initialize MFA system
        self.mfa_system = MFASystem()
        
        # Setup UI
        self.setWindowTitle("MFA Authentication System")
        self.setMinimumSize(550, 500)
        
        # Create stacked widget to manage different screens
        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)
        
        # Create pages
        self.init_welcome_page()
        self.init_register_page()
        self.init_login_page()
        self.init_otp_page()
        self.init_success_page()
        self.init_qr_page()
        
        # Start with welcome page
        self.stacked_widget.setCurrentIndex(0)
        
    def init_welcome_page(self):
        welcome_widget = QWidget()
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Multi-Factor Authentication System")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 16, QFont.Bold))
        
        # Description
        description = QLabel("Secure your account with two-factor authentication")
        description.setAlignment(Qt.AlignCenter)
        description.setFont(QFont("Arial", 12))
        
        # Buttons
        register_btn = QPushButton("Register")
        login_btn = QPushButton("Login")
        
        register_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(1))
        login_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(2))
        
        # Layout
        layout.addStretch()
        layout.addWidget(title)
        layout.addWidget(description)
        layout.addSpacing(30)
        
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(register_btn)
        button_layout.addWidget(login_btn)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        layout.addStretch()
        
        welcome_widget.setLayout(layout)
        self.stacked_widget.addWidget(welcome_widget)
    
    def init_register_page(self):
        register_widget = QWidget()
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Register New Account")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 16, QFont.Bold))
        
        # Form
        form_layout = QVBoxLayout()
        
        username_label = QLabel("Username:")
        self.register_username = QLineEdit()
        
        password_label = QLabel("Password:")
        self.register_password = QLineEdit()
        self.register_password.setEchoMode(QLineEdit.Password)
        
        phone_label = QLabel("Phone Number:")
        self.register_phone = QLineEdit()
        
        # Buttons
        register_btn = QPushButton("Register")
        back_btn = QPushButton("Back")
        
        register_btn.clicked.connect(self.handle_register)
        back_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))
        
        # Add widgets to layout
        form_layout.addWidget(username_label)
        form_layout.addWidget(self.register_username)
        form_layout.addWidget(password_label)
        form_layout.addWidget(self.register_password)
        form_layout.addWidget(phone_label)
        form_layout.addWidget(self.register_phone)
        
        layout.addWidget(title)
        layout.addSpacing(20)
        layout.addLayout(form_layout)
        layout.addSpacing(20)
        
        button_layout = QHBoxLayout()
        button_layout.addWidget(back_btn)
        button_layout.addWidget(register_btn)
        
        layout.addLayout(button_layout)
        
        register_widget.setLayout(layout)
        self.stacked_widget.addWidget(register_widget)
    
    def init_login_page(self):
        login_widget = QWidget()
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Login")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 16, QFont.Bold))
        
        # Form
        form_layout = QVBoxLayout()
        
        username_label = QLabel("Username:")
        self.login_username = QLineEdit()
        
        password_label = QLabel("Password:")
        self.login_password = QLineEdit()
        self.login_password.setEchoMode(QLineEdit.Password)
        
        # Buttons
        login_btn = QPushButton("Login")
        back_btn = QPushButton("Back")
        
        login_btn.clicked.connect(self.handle_login)
        back_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))
        
        # Add widgets to layout
        form_layout.addWidget(username_label)
        form_layout.addWidget(self.login_username)
        form_layout.addWidget(password_label)
        form_layout.addWidget(self.login_password)
        
        layout.addWidget(title)
        layout.addSpacing(20)
        layout.addLayout(form_layout)
        layout.addSpacing(20)
        
        button_layout = QHBoxLayout()
        button_layout.addWidget(back_btn)
        button_layout.addWidget(login_btn)
        
        layout.addLayout(button_layout)
        
        login_widget.setLayout(layout)
        self.stacked_widget.addWidget(login_widget)
    
    def init_otp_page(self):
        otp_widget = QWidget()
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Enter OTP")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 16, QFont.Bold))
        
        # OTP method selection
        method_group = QGroupBox("OTP Verification Method")
        method_layout = QVBoxLayout()
        
        self.otp_method_group = QButtonGroup()
        self.direct_method = QRadioButton("Receive OTP directly")
        self.auth_app_method = QRadioButton("Use Authentication App")
        
        self.direct_method.setChecked(True)
        self.otp_method_group.addButton(self.direct_method)
        self.otp_method_group.addButton(self.auth_app_method)
        
        method_layout.addWidget(self.direct_method)
        method_layout.addWidget(self.auth_app_method)
        method_group.setLayout(method_layout)
        
        # OTP message
        self.otp_message = QLabel("Choose your OTP verification method")
        self.otp_message.setAlignment(Qt.AlignCenter)
        
        # Timer label
        self.timer_label = QLabel("Time remaining: 30s")
        self.timer_label.setAlignment(Qt.AlignCenter)
        
        # OTP input
        otp_label = QLabel("One-Time Password:")
        self.otp_input = QLineEdit()
        self.otp_input.setMaxLength(6)
        
        # Buttons
        verify_btn = QPushButton("Verify")
        self.get_otp_btn = QPushButton("Get OTP / QR Code")
        cancel_btn = QPushButton("Cancel")
        
        verify_btn.clicked.connect(self.handle_otp_verification)
        self.get_otp_btn.clicked.connect(self.handle_get_otp)
        cancel_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))
        
        # Add widgets to layout
        layout.addWidget(title)
        layout.addSpacing(10)
        layout.addWidget(method_group)
        layout.addWidget(self.otp_message)
        layout.addWidget(self.timer_label)
        layout.addSpacing(10)
        layout.addWidget(otp_label)
        layout.addWidget(self.otp_input)
        layout.addSpacing(10)
        
        button_layout = QHBoxLayout()
        button_layout.addWidget(cancel_btn)
        button_layout.addWidget(self.get_otp_btn)
        button_layout.addWidget(verify_btn)
        
        layout.addLayout(button_layout)
        
        otp_widget.setLayout(layout)
        self.stacked_widget.addWidget(otp_widget)
        
        # Timer for OTP expiration
        self.otp_timer = QTimer(self)
        self.otp_timer.timeout.connect(self.update_otp_timer)
        self.otp_time_remaining = 30
    
    def init_qr_page(self):
        qr_widget = QWidget()
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Scan QR Code with Authentication App")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 16, QFont.Bold))
        
        # QR code image
        self.qr_image = QLabel()
        self.qr_image.setAlignment(Qt.AlignCenter)
        self.qr_image.setMinimumSize(300, 300)
        
        # Instructions
        instructions = QLabel(
            "1. Open your authentication app (Google/Microsoft Authenticator)\n"
            "2. Scan this QR code\n"
            "3. The app will generate a 6-digit code every 30 seconds\n"
            "4. Return to verification page and enter the current code"
        )
        instructions.setAlignment(Qt.AlignCenter)
        
        # Back button
        back_btn = QPushButton("Return to OTP Verification")
        back_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(3))
        
        # Layout
        layout.addWidget(title)
        layout.addSpacing(20)
        layout.addWidget(self.qr_image)
        layout.addSpacing(20)
        layout.addWidget(instructions)
        layout.addSpacing(20)
        layout.addWidget(back_btn)
        
        qr_widget.setLayout(layout)
        self.stacked_widget.addWidget(qr_widget)
    
    def init_success_page(self):
        success_widget = QWidget()
        layout = QVBoxLayout()
        
        # Success message
        success_icon = QLabel("✓")
        success_icon.setAlignment(Qt.AlignCenter)
        success_icon.setFont(QFont("Arial", 48))
        
        success_msg = QLabel("Authentication Successful")
        success_msg.setAlignment(Qt.AlignCenter)
        success_msg.setFont(QFont("Arial", 16, QFont.Bold))
        
        # Security benefits
        security_frame = QFrame()
        security_frame.setFrameShape(QFrame.StyledPanel)
        security_layout = QVBoxLayout()
        
        security_title = QLabel("MFA Security Benefits")
        security_title.setFont(QFont("Arial", 12, QFont.Bold))
        
        security_points = [
            "• MFA significantly improves security by requiring two different types of credentials.",
            "• Even if an attacker obtains your password, they still cannot access your account without the OTP.",
            "• The OTP changes every 30 seconds, making it resistant to replay attacks.",
            "• MFA mitigates risks from weak passwords, credential stuffing, phishing, and keylogging."
        ]
        
        security_layout.addWidget(security_title)
        
        for point in security_points:
            security_layout.addWidget(QLabel(point))
        
        security_frame.setLayout(security_layout)
        
        # Button to return to home
        home_btn = QPushButton("Return to Home")
        home_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))
        
        # Add widgets to layout
        layout.addStretch()
        layout.addWidget(success_icon)
        layout.addWidget(success_msg)
        layout.addSpacing(20)
        layout.addWidget(security_frame)
        layout.addSpacing(20)
        layout.addWidget(home_btn)
        layout.addStretch()
        
        success_widget.setLayout(layout)
        self.stacked_widget.addWidget(success_widget)
    
    def handle_register(self):
        username = self.register_username.text()
        password = self.register_password.text()
        phone = self.register_phone.text()
        
        if not username or not password or not phone:
            QMessageBox.warning(self, "Registration Error", "All fields are required.")
            return
        
        if username in self.mfa_system.users:
            QMessageBox.warning(self, "Registration Error", "Username already exists.")
            return
        
        # Register user
        secret_key = self.mfa_system.register_user(username, password, phone)
        
        # Generate QR code for authentication apps
        totp_uri = self.mfa_system.generate_auth_app_uri(username)
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        # Convert to QPixmap
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_image = QPixmap()
        qr_image.loadFromData(buffer.getvalue())
        
        # Show secret key and QR code to user
        self.qr_image.setPixmap(qr_image.scaled(300, 300, QtCore.Qt.KeepAspectRatio))
        
        QMessageBox.information(self, "Registration Successful", 
                                f"Your account has been created!\n\n"
                                f"Secret Key: {secret_key}\n\n"
                                f"IMPORTANT: You can setup an authentication app now by viewing the QR code or store this key securely.")
        
        # Show the QR code page
        self.current_username = username
        self.stacked_widget.setCurrentIndex(5)  # QR code page
        
        # Clear form
        self.register_username.clear()
        self.register_password.clear()
        self.register_phone.clear()
    
    def handle_login(self):
        username = self.login_username.text()
        password = self.login_password.text()
        
        if not username or not password:
            QMessageBox.warning(self, "Login Error", "Username and password are required.")
            return
        
        if username not in self.mfa_system.users:
            QMessageBox.warning(self, "Login Error", "User not found.")
            return
        
        # Verify password
        if not self.mfa_system.verify_password(username, password):
            QMessageBox.warning(self, "Login Error", "Incorrect password.")
            return
        
        # Store current username for later use
        self.current_username = username
        
        # Reset OTP verification page
        self.direct_method.setChecked(True)
        self.otp_input.clear()
        self.otp_message.setText("Choose your OTP verification method")
        
        # Move to OTP verification page
        self.stacked_widget.setCurrentIndex(3)
    
    def handle_get_otp(self):
        # Check which verification method is selected
        if self.auth_app_method.isChecked():
            # Generate QR code and show it
            totp_uri = self.mfa_system.generate_auth_app_uri(self.current_username)
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(totp_uri)
            qr.make(fit=True)
            
            # Convert to QPixmap
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            qr_image = QPixmap()
            qr_image.loadFromData(buffer.getvalue())
            
            # Show QR code
            self.qr_image.setPixmap(qr_image.scaled(300, 300, QtCore.Qt.KeepAspectRatio))
            self.stacked_widget.setCurrentIndex(5)  # QR code page
        else:
            # Generate OTP directly
            user_secret_key = self.mfa_system.users[self.current_username]['secret_key']
            current_otp, expiration_time, time_remaining = self.mfa_system.generate_otp(user_secret_key)
            
            # Store OTP info
            self.mfa_system.otp_info[self.current_username] = {
                'otp': current_otp,
                'expiration_time': expiration_time
            }
            
            # Update OTP page with information
            self.otp_message.setText(f"OTP sent to: {self.mfa_system.users[self.current_username]['phone_number']}")
            
            # For demo purposes, show the OTP (in a real app, this would be sent via SMS)
            QMessageBox.information(self, "OTP Generated", 
                                   f"For demo purposes, your OTP is: {current_otp}\n"
                                   f"This would normally be sent to your phone.")
            
            # Start OTP timer with the exact remaining time
            self.otp_time_remaining = time_remaining
            self.timer_label.setText(f"Time remaining: {self.otp_time_remaining}s")
            self.timer_label.setVisible(True)
            self.otp_timer.start(1000)  # Update every second
    
    def update_otp_timer(self):
        self.otp_time_remaining -= 1
        self.timer_label.setText(f"Time remaining: {self.otp_time_remaining}s")
        
        if self.otp_time_remaining <= 0:
            self.otp_timer.stop()
            QMessageBox.warning(self, "OTP Expired", "Your OTP has expired. Please request a new OTP.")
            self.timer_label.setVisible(False)
    
    def handle_otp_verification(self):
        entered_otp = self.otp_input.text()
        
        if not entered_otp:
            QMessageBox.warning(self, "Verification Error", "Please enter the OTP.")
            return
        
        # Verify OTP
        otp_valid, is_expired = self.mfa_system.verify_otp(self.current_username, entered_otp)
        
        if is_expired:
            self.otp_timer.stop()
            QMessageBox.warning(self, "Verification Error", "OTP has expired. Please request a new one.")
            return
        
        if not otp_valid:
            QMessageBox.warning(self, "Verification Error", "Incorrect OTP.")
            return
        
        # OTP is valid, stop timer and move to success page
        self.otp_timer.stop()
        self.otp_input.clear()
        self.stacked_widget.setCurrentIndex(4)  # Success page


def simulate_mfa():
    """
    Simulate the MFA process with a demo user, including registration and authentication
    
    This function demonstrates the full MFA workflow:
    1. User registration with password
    2. Secret key generation for OTP
    3. Two-factor authentication (password + OTP)
    """
    # Create MFA system
    mfa = MFASystem()
    
    # === Registration Phase ===
    print("\n========= User Registration =========")
    username = input("Enter a username: ")
    password = input("Enter a password: ")
    phone_number = input("Enter a phone number: ")
    
    # Register user and get their OTP secret
    secret_key = mfa.register_user(username, password, phone_number)
    print(f"\nUser registered successfully!")
    print(f"SECRET KEY (store securely): {secret_key}")
    
    # === Authentication Phase ===
    print("\n========= Login Simulation =========")
    print("Now let's authenticate using MFA")
    
    # Ask for username during authentication
    auth_username = input("Enter your username: ")
    
    # Check if user exists
    if auth_username not in mfa.users:
        print("User not found! Authentication failed.")
        return
        
    # First factor: password
    auth_password = input("Enter your password: ")
    
    # Check password first and show error if wrong
    if not mfa.verify_password(auth_username, auth_password):
        print("Wrong password! Authentication failed.")
        return
    
    # Generate and send OTP if password is correct
    user_secret_key = mfa.users[auth_username]['secret_key']
    current_otp, expiration_time, time_remaining = mfa.generate_otp(user_secret_key)
    
    # Store the OTP and its expiration time
    mfa.otp_info[auth_username] = {
        'otp': current_otp,
        'expiration_time': expiration_time
    }
    
    print(f"OTP sent to your device: {current_otp} (expires in {time_remaining} seconds)")
    
    # Second factor: OTP
    auth_otp = input("Enter your OTP: ")
    
    # Verify OTP with expiration check
    otp_valid, is_expired = mfa.verify_otp(auth_username, auth_otp)
    
    if otp_valid:
        print("\nAuthentication successful! Access granted.")
    else:
        if is_expired:
            print("\nOTP has expired! Please request a new OTP.")
        else:
            print("\nIncorrect OTP. Authentication failed.")
    
    # === Security Explanation ===
    print("\n========= MFA Security Benefits =========")
    print("• MFA significantly improves security by requiring two different types of credentials.")
    print("• Even if an attacker obtains your password through a data breach or phishing attack,")
    print("  they still cannot access your account without the second factor (OTP).")
    print("• The OTP changes every 30 seconds, making it resistant to replay attacks.")
    print("• MFA mitigates risks from password-related vulnerabilities like:")
    print("  - Weak or reused passwords")
    print("  - Credential stuffing attacks")
    print("  - Phishing attacks")
    print("  - Keylogging malware")


def start_gui():
    """Launch the MFA GUI application"""
    app = QApplication(sys.argv)
    window = MFAGui()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    # Check command line arguments to determine whether to run GUI or CLI version
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        simulate_mfa()  # Run CLI version
    else:
        start_gui()  # Run GUI version by default 