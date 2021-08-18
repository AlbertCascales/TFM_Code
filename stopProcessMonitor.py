import subprocess

def stop_process_monitor():
    command = "cd C:\\Users\\marti\\Downloads\\ProcessMonitor & Procmon.exe /Terminate"
    subprocess.call(command, shell=True)

def convertir_a_csv():
    command = "cd C:\\Users\\marti\\Downloads\\ProcessMonitor & Procmon.exe salida.PML /SaveAs salida.csv"
    subprocess.call(command, shell=True)

if __name__ == "__main__":
    stop_process_monitor()

