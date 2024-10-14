Features of the PassSniper Script
PassSniper is a password-cracking tool designed with a graphical interface to perform brute-force and dictionary attacks on various network services using Hydra. The tool is built using Tkinter and offers a user-friendly environment with the following features:

1. User Interface with Tkinter
A professional and colorful graphical interface for easier use.
Easy-to-navigate layout for selecting usernames, passwords, and target IPs/subnets.
2. Multiple Service Attacks
Supports password attacks for various services:

SSH
FTP
Telnet
SMTP
Web Forms (HTTP/HTTPS)
3. Dictionary and Brute Force Attack Modes
Users can choose between:
Brute Force Attack: Try all possible combinations.
Dictionary Attack: Use predefined username and password lists.
4. Multiple IP and Subnet Scanning
Enter multiple IP addresses or an entire subnet range for mass attacks.
Automatically detects all hosts within a given subnet and performs the attack on each.
5. Google Drive Integration for Username/Password Files
Downloads username and password dictionaries from Google Drive.
The files are stored locally on the desktop and are not re-downloaded if they already exist, improving performance.
6. Manual Browsing of Files
Option to browse for local files to load usernames and passwords instead of using the default Google Drive sources.
7. Real-Time Attack Progress
Real-time attack progress is shown in a separate window.
The user can cancel the attack at any time with the Cancel button.
8. Password Suggestion
Upon finding valid credentials, the tool suggests a strong password to use in place of weak ones.
Displayed on the result page along with a security message.
9. Attack Logging and Credential Highlighting
All attack results are displayed in real-time.
Found credentials are highlighted to make them easy to spot.
10. Full-Screen Mode Support
Toggle fullscreen mode using F11 for better visibility and use during demonstrations or professional testing.
11. Error Handling and User Input Validation
Ensures valid inputs (e.g., correct IP formats, valid username/password files).
Displays helpful error messages when inputs are missing or incorrect.
12. Session Management and Multi-threading
Multi-threading for concurrent tasks to prevent the GUI from freezing during attacks.
Proper session management to handle multiple targets and services efficiently.
13. Customizable Attack Parameters
Fine-tuned for performance with Hydra's options like thread count (-t), retries, and verbosity.
Configurable number of threads (-t 64) for faster execution.
14. Hydra Integration
Automatically constructs and runs appropriate Hydra commands based on the selected attack type and service.
Displays Hydra’s output directly in the UI for real-time feedback.