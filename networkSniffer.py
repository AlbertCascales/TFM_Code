from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet
import subprocess, ctypes, os, sys
from subprocess import Popen, DEVNULL

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
        #Obtener el puerto origen
        puerto_origen = paquete[IP].sport
        #Obtener método del paquete
        metodo = paquete[HTTPRequest].Method.decode()
        #Obtener el User_Agent que está realizando el envío del paquete
        if (paquete[HTTPRequest].User_Agent is not None):
            user_agent = paquete[HTTPRequest].User_Agent.decode()
        else:
            user_agent = ""
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

def add_rule(rule_name, file_path):
    """ Add rule to Windows Firewall """
    subprocess.call(
        f"netsh advfirewall firewall add rule name={rule_name} dir=out action=block enable=no program={file_path}", 
        shell=True, 
        stdout=DEVNULL, 
        stderr=DEVNULL
    )
    print(f"Rule {rule_name} for {file_path} added")

def modify_rule(rule_name, state):
    """ Enable/Disable specific rule, 0 = Disable / 1 = Enable """
    state, message = ("yes", "Enabled") if state else ("no", "Disabled")
    subprocess.call(
        f"netsh advfirewall firewall set rule name={rule_name} new enable={state}", 
        shell=True, 
        stdout=DEVNULL, 
        stderr=DEVNULL
    )
    print(f"Rule {rule_name} {message}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Programa para snifar el tráfico red de la interfaz de red deseada.")
    parser.add_argument("-i", "--iface", help="Nombre de la interfaz que se quiere definir")
    # parse arguments
    args = parser.parse_args()
    iface = args.iface
    add_rule("Bloquear_tráfico", "C:\\Users\\marti\\Downloads\\rclone-v1.56.0-windows-amd64\\rclone-v1.56.0-windows-amd64\\rclone.exe")
    modify_rule("Bloquear_tráfico", 1)
    definir_interfaz(iface)