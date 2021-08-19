from csv import reader

from scapy.config import CommandsList

def procesar_pml():
    # open file in read mode
    with open('C:\\Users\\marti\\Downloads\\ProcessMonitor\\salida.csv', 'r', encoding="utf8") as read_obj:
        # pass the file object to reader() to get the reader object
        csv_reader = reader(read_obj)
        # Iterate over each row in the csv using reader object
        for row in csv_reader:
            # row variable is a list that represents a row in csv
            nombre = row[1]
            path = row[4]
            detail = row[6]
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