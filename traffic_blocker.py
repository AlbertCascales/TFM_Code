import subprocess
import subprocess, ctypes, sys
from subprocess import DEVNULL

#Añado la regla al firewall
def add_rule(rule_name, file_path):
    subprocess.call(
        f"netsh advfirewall firewall add rule name={rule_name} dir=out action=block enable=yes program={file_path}", 
        shell=True,
        stdout=DEVNULL, 
        stderr=DEVNULL
    )
    print(f"Regla {rule_name} para el directorio {file_path} añadida")