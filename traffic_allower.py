import subprocess
import subprocess, ctypes, sys
from subprocess import DEVNULL

#Eliminación de las reglas de firewall
def remove_rule(rule_name):
    """ Add rule to Windows Firewall """
    subprocess.call(
        f"netsh advfirewall firewall delete rule name={rule_name}", 
        shell=True,
        stdout=DEVNULL, 
        stderr=DEVNULL
    )
    print(f"Regla {rule_name} eliminada")

#Ejecución del comando aceptado por el usuario
def volver_a_ejecutar_comando(directorio, comando):
    modificar_directorio = "cd " + directorio
    commando = modificar_directorio + " & " + comando
    subprocess.call(commando, shell=True)