import subprocess
import subprocess, ctypes, sys
from subprocess import DEVNULL

def add_rule(rule_name, file_path):
    """ Add rule to Windows Firewall """
    subprocess.call(
        f"netsh advfirewall firewall add rule name={rule_name} dir=out action=block enable=yes program={file_path}", 
        shell=True,
        stdout=DEVNULL, 
        stderr=DEVNULL
    )
    print(f"Rule {rule_name} for {file_path} added")