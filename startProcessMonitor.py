from distutils import command
import subprocess

processMonitorCommand="cd C:\\Users\\marti\\Downloads\\ProcessMonitor & Procmon.exe /AcceptEula /NoFilter /Minimized /BackingFile salida"

#Arranco la herramienta Process Monitor
def start_process_monitor():
    command = processMonitorCommand
    #command = "cd C:\\Users\\marti\\Downloads\\ProcessMonitor & Procmon.exe /AcceptEula /NoFilter /Minimized /BackingFile salida"
    subprocess.call(command, shell=True)


if __name__ == "__main__":
    start_process_monitor()

