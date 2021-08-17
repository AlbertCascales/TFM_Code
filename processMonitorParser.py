from procmon_parser import ProcmonLogsReader

f = open("C:\\Users\\marti\\Downloads\\ProcessMonitor\\salida.pml", "rb")
pml_reader = ProcmonLogsReader(f)
print(pml_reader)  # number of logs

for a in pml_reader:
    print(a)