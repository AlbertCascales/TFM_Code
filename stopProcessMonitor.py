import subprocess

#Paro la herramienta Process Monitor
def stop_process_monitor():
    command = "cd C:\\Users\\marti\\Downloads\\ProcessMonitor & Procmon.exe /Terminate"
    subprocess.call(command, shell=True)

#Convierto el fichero generado por Process Monitor a CSV
def convertir_a_csv():
    command = "cd C:\\Users\\marti\\Downloads\\ProcessMonitor & Procmon.exe salida.PML /SaveAs salida.csv"
    subprocess.call(command, shell=True)

