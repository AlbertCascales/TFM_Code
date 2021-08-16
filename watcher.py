import os
os.system('''cd C:\\Users\\marti\\Downloads\\ProcessMonitor
Procmon.exe /AcceptEula /NoFilter /Minimized /BackingFile salida'''.replace('\n', '&')) # or use & for Windows

os.system('''Procmon.exe /Terminate'''.replace('\n', '&')) # or use & for Windows