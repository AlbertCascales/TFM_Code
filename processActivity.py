import psutil
import subprocess

#Función que comprueba si hay algún proceso ejecutándose en el sistema cuyo nombre es igual al pasado por parámetros
def checkIfProcessRunning(processName):
    '''
    Check if there is any running process that contains the given name processName.
    '''
    #Iterate over the all the running process
    for proc in psutil.process_iter():
        try:
            # Check if process name contains the given name string.
            if processName.lower() == proc.name().lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False

def guardar_historial_comandos():
    cmd_history = subprocess.check_output(["doskey", "/history"])
    with open("saved_commands.txt", "wb") as f:
        f.write(cmd_history) 

# Check if any chrome process was running or not.
while True:
    guardar_historial_comandos()
    if checkIfProcessRunning('Rar.exe'): 
        print('Un proceso WinRAR desde la linea de comandos se está ejecutando')
    elif checkIfProcessRunning('WinRAR.exe'):
        print('Un proceso WinRAR desde el entorno gráfico se está ejecutando')
    elif checkIfProcessRunning('7z.exe'):
        print('Un proceso 7-Zip desde la linea de comandos se está ejecutando')
    else:
        print('Ningún proceso comprometido se está ejecutando')