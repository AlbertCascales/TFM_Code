import subprocess
import subprocess, ctypes, sys
from subprocess import DEVNULL

def remove_rule(rule_name):
    """ Add rule to Windows Firewall """
    subprocess.call(
        f"netsh advfirewall firewall delete rule name={rule_name}", 
        shell=True,
        stdout=DEVNULL, 
        stderr=DEVNULL
    )
    print(f"Rule {rule_name} deleted")

def volver_a_ejecutar_comando(directorio, comando):
    modificar_directorio = "cd " + directorio
    commando = modificar_directorio + " & " + comando
    subprocess.call(commando, shell=True)