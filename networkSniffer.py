from typing import Protocol
from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet
import subprocess, ctypes, os, sys
from subprocess import Popen, DEVNULL
import tkinter as tk
from tkinter import messagebox
import subprocess

from stopProcessMonitor import convertir_a_csv, stop_process_monitor
from traffic_blocker import add_rule
from traffic_allower import remove_rule, volver_a_ejecutar_comando
from processMonitorParser import procesar_pml

comando = ""
ubicacion = ""


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
            #print(f"La máquina con IP origen [%s] ha establecido una conexión por medio del método [%s] y agenete de usuario [%s] a la IP [%s]"
            #" cuya URL es [%s].\n" % (ip_origen, metodo, user_agent, ip_destino, dominio+directorio))

            nombre_regla = "mega_blocker"

            add_rule(nombre_regla, "C:\\Users\\marti\\Downloads\\rclone-v1.56.0-windows-amd64\\rclone-v1.56.0-windows-amd64\\rclone.exe")

            stop_process_monitor()

            convertir_a_csv()

            resultado = procesar_pml()
            variable = resultado.rsplit(' ', 1)
            comando = variable[0]
            ubicacion = variable[1]

            if (cuadro_alerta() == True):
                remove_rule("mega_blocker")
                volver_a_ejecutar_comando(ubicacion, comando)
                ctypes.windll.user32.MessageBoxW(0, "Transferencia permitida", "Confirmación", 0)
            else:
                ctypes.windll.user32.MessageBoxW(0, "Transferencia bloqueada", "Confirmación", 0)

            #Terminar la ejecución del programa
            sys.exit()

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

def check_admin():
    """ Force to start application with admin rights """
    try:
        isAdmin = ctypes.windll.shell32.IsUserAnAdmin()
    except AttributeError:
        isAdmin = False
    if not isAdmin:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)

def cuadro_alerta():
    MsgBox = ctypes.windll.user32.MessageBoxW(None, "Se ha ejecutado el comando: {comando} ¿Deseas permitirlo?", "!!!ATENCIÓN!!!", 1)
    if MsgBox == 1:
        return True
    else:
        ctypes.windll.user32.MessageBoxW(0, "Transferencia detenida", "Confirmación", 0)
        return False

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Programa para snifar el tráfico red de la interfaz de red deseada.")
    parser.add_argument("-i", "--iface", help="Nombre de la interfaz que se quiere definir")
    # parse arguments
    args = parser.parse_args()
    iface = args.iface
    check_admin()
    remove_rule("mega_blocker")
    definir_interfaz(iface)