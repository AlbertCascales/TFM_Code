import psutil
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
    return False;

# Check if any chrome process was running or not.
while True:
    if checkIfProcessRunning('Rar.exe'): 
        print('Un proceso WinRAR desde la linea de comandos se está ejecutando')
    elif checkIfProcessRunning('WinRAR.exe'):
        print('Un proceso WinRAR desde el entorno gráfico se está ejecutando')
    else:
        print('Ningún proceso WinRAR se está ejecutando')