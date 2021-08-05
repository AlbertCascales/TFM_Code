from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet

#Función que define el puerto y la interfaz del adaptador de red del que se obtienen los paquetes de red
def definir_interfaz(iface=None):
    if iface:
        sniff(filter="port 80", prn=extraer_informacion, iface=iface, store=False)
    else:
        # sniff with default interface
        sniff(filter="port 80", prn=extraer_informacion, store=False)

#Función que obtiene los datos más relevantes del paquete analizado
def extraer_informacion(paquete):
    if paquete.haslayer(HTTPRequest):
        #Obtener el dominio de la pagina web
        dominio = paquete[HTTPRequest].Host.decode()
        #Obtener el directorio del dominio de la pagina web
        directorio = paquete[HTTPRequest].Path.decode()
        #Obtener la IP origen del paquete
        ip_origen = paquete[IP].src
        #Obtener la IP destino del paquete
        ip_destino = paquete[IP].dst
        #Obtener método del paquete
        metodo = paquete[HTTPRequest].Method.decode()
        print(f"La máquina con IP origen [%s] ha establecido una conexión por medio del método [%s] a la IP [%s]"
        " y cuya URL es [%s].\n" % (ip_origen, metodo, ip_destino, dominio+directorio))

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Programa para snifar el tráfico red de la interfaz de red deseada.")
    parser.add_argument("-i", "--iface", help="Nombre de la interfaz que se quiere definir")
    # parse arguments
    args = parser.parse_args()
    iface = args.iface
    definir_interfaz(iface)