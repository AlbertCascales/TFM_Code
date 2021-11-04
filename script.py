#!/usr/bin/env python3

import subprocess

command = "cd C:\\Users\\marti\\Documents\\UC3M\\Master en Ingeniería Informática\\TFM_Code"
subprocess.call(command, shell=True)

command = "python networksniffer.py -i Wi-Fi & python startProcessMonitor.py"
subprocess.call(command, shell=True)

