from csv import reader
from scapy.config import CommandsList

ficheroCSVPath="C:\\Users\\marti\\Downloads\\ProcessMonitor\\salida.csv"

#Procesamiento del fichero csv generado por Process Monitor
def procesar_pml(variable):
    #Abro el fichero en modo lectura
    with open(ficheroCSVPath, 'r', encoding="utf8") as read_obj:
    #with open('C:\\Users\\marti\\Downloads\\ProcessMonitor\\salida.csv', 'r', encoding="utf8") as read_obj:
        #Obtengo el fichero como un objeto reader
        csv_reader = reader(read_obj)
        #Itero por cada una de las filas del fichero
        if (variable=="mega" or variable=="dropbox" or variable == "pcloud"):
            for row in csv_reader:
                #Obtengo el nombre del proceso y los detalles de la operación realizada
                nombre = row[1]
                detail = row[6]
                #Obtengo el comando ejecutado y el directorio sobre el que se ha realizado la operación
                if ("rclone.exe" in nombre and "Command line: rclone.exe" in detail):
                    comando_ejecutado = detail[detail.find('Command'):]
                    comando_ejecutado = comando_ejecutado[comando_ejecutado.find(':'):]
                    comando_ejecutado = comando_ejecutado[2:]
                    comando_ejecutado = comando_ejecutado.split(',', 1)[0]
                    directorio = detail[detail.find('Current'):]
                    directorio = directorio[directorio.find(':'):]
                    directorio = directorio[2:]
                    directorio = directorio.split(',', 1)[0]

                    #print( "La herramienta " + nombre + " ha ejecutado el comando: " + comando_ejecutado + " en el directorio: " + directorio)
                    resultado = comando_ejecutado + " " + directorio
                    return resultado
        elif (variable=="ftp"):
            for row in csv_reader:
                #Obtengo el nombre del proceso y los detalles de la operación realizada
                nombre = row[1]
                path = row[4]

                #Devuelvo el tipo de herramienta utilizada y el fichero que se ha intentado transmitir
                if ("filezilla.exe" in nombre and (".7z" in path or ".zip" in path or ".rar" in path)):
                    return "filezilla" + " " + path
                elif ("WinSCP.exe" in nombre and (".7z" in path)):
                    return "winscp" + " " + path
                
        elif (variable == "TLSMegaSync"):
            for row in csv_reader:
                #Obtengo el nombre del proceso y los detalles de la operación realizada
                nombre = row[1]
                path = row[4]

                #Devuelvo el tipo de herramienta utilizada y el fichero que se ha intentado transmitir
                if ("MEGAsync.exe" in nombre and (".zip" in path or ".rar" in path or ".7z" in path)):
                    return "megasync" + " " + path