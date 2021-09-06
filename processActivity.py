import psutil
import subprocess

#Función que comprueba si hay algún proceso ejecutándose en el sistema cuyo nombre es igual al pasado como argumento
def checkIfProcessRunning(processName):
    for proc in psutil.process_iter():
        try:
            # Compruebo si el proceso analizado tiene el mismo nombre que el pasado como parámetro
            if (processName.lower() == proc.name().lower()):
                return 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return 0

def devolver_proceso_ejecutado():

    while (checkIfProcessRunning('Rar.exe') != 1 or checkIfProcessRunning('WinRAR.exe') != 1 or checkIfProcessRunning('7z.exe') != 1):

        if checkIfProcessRunning('Rar.exe'): 
            print('Un proceso WinRAR desde la linea de comandos se está ejecutando')
            proceso = "rar"
            return proceso
        elif checkIfProcessRunning('WinRAR.exe'):
            print('Un proceso WinRAR desde el entorno gráfico se está ejecutando')
            proceso = "rar"
            return proceso
        elif checkIfProcessRunning('7z.exe'):
            print('Un proceso 7-Zip desde la linea de comandos se está ejecutando')
            proceso = "7z"
            return proceso