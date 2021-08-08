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
        #Junto el dominio y el directorio para formar la URL
        url = dominio + directorio
        #Obtener la IP origen del paquete
        ip_origen = paquete[IP].src
        #Obtener la IP destino del paquete
        ip_destino = paquete[IP].dst
        #Obtener método del paquete
        metodo = paquete[HTTPRequest].Method.decode()
        #Obtener el User_Agent que está realizando el envío del paquete
        user_agent = paquete[HTTPRequest].User_Agent.decode()
        #Obtener datos a transmitir
        if (datos_a_transmitir_en_crudo(paquete, metodo) == True):
            print("fichero transmitido")
        #Comprobación del tipo de 
        if (identificar_Protocolo(url) == True and identificador_agente_usuario(user_agent) == True):
            #print(paquete.show())
            print(f"La máquina con IP origen [%s] ha establecido una conexión por medio del método [%s] y agenete de usuario [%s] a la IP [%s]"
            " cuya URL es [%s].\n" % (ip_origen, metodo, user_agent, ip_destino, dominio+directorio))

def identificar_Protocolo(url):
    if "mega" in url:
        return True
    else:
        return False

def identificador_agente_usuario(agente_usuario):
    if "rclone" in agente_usuario:
        return True
    else:
        return False

def datos_a_transmitir_en_crudo(paquete, metodo):
    if (paquete.haslayer(Raw) and metodo =="POST"):
        load2 = paquete[Raw].load
        load3 = load2 + bytearray(b'\x00\x00\x00\x01')
        #print(load3)
        paquete[Raw].load = load3
        return True

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Programa para snifar el tráfico red de la interfaz de red deseada.")
    parser.add_argument("-i", "--iface", help="Nombre de la interfaz que se quiere definir")
    # parse arguments
    args = parser.parse_args()
    iface = args.iface
    definir_interfaz(iface)