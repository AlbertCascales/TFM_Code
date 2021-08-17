import subprocess

def start_process_monitor():
    command = "cd C:\\Users\\marti\\Downloads\\ProcessMonitor & Procmon.exe /AcceptEula /NoFilter /Minimized /BackingFile salida"
    subprocess.call(command, shell=True)


if __name__ == "__main__":
    start_process_monitor()

