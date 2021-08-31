from typing import Protocol
from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers import *
import subprocess, ctypes, os, sys
from subprocess import Popen, DEVNULL
import tkinter as tk
from tkinter import messagebox
import subprocess
import argparse
import sys, os, traceback, types

from stopProcessMonitor import convertir_a_csv, stop_process_monitor
from traffic_blocker import add_rule
from traffic_allower import remove_rule, volver_a_ejecutar_comando
from processMonitorParser import procesar_pml

comando = ""
ubicacion = ""
nombre_regla = ""


#Función que define el puerto y la interfaz del adaptador de red que se monitoriza
def definir_interfaz(iface=None):
    if iface:
        sniff(filter="", prn=extraer_informacion, iface=iface, store=False)
        #sniff(filter="port 80", prn=extraer_informacion, iface=iface, store=False)
    else:
        # En caso que de que no se defina ninguna interfaz se toma la de por defecto
        #sniff(filter="port 80", prn=extraer_informacion, store=False)
        sniff(filter="", prn=extraer_informacion, store=False)

#Función que obtiene los datos más relevantes del paquete analizado
def extraer_informacion(paquete):
    #Si se trata de un establecimiento de conexión por medio del protocolo HTTP
    if paquete.haslayer(HTTPRequest):
        #Obtener el dominio de la pagina web
        dominio = paquete[HTTPRequest].Host.decode()
        #Obtener el directorio del dominio de la pagina web
        directorio = paquete[HTTPRequest].Path.decode()
        #Junto el dominio y el directorio para formar la URL
        url = dominio + directorio
        #Obtener el User_Agent que está realizando el envío del paquete
        if (paquete[HTTPRequest].User_Agent is not None):
            user_agent = paquete[HTTPRequest].User_Agent.decode()
        else:
            user_agent = ""
        #Comprobación del servicio y agente de usuario que están ejecutándose 
        if (identificar_Protocolo(url) != False and identificador_agente_usuario(user_agent) != False):
            
            #Defino el nombre de la regla para el firewall
            servicio = identificar_Protocolo(url)
            nombre_regla = servicio + "_blocker"

            #Añado la regla a la lista del firewall
            add_rule(nombre_regla, "C:\\Users\\marti\\Downloads\\rclone-v1.56.0-windows-amd64\\rclone-v1.56.0-windows-amd64\\rclone.exe")

            #Paro la captura de eventos por parte de Process Monitor
            stop_process_monitor()

            #Transformo el archivo (de pml a csv)
            convertir_a_csv()

            #Obtengo el comando ejecutado y el directorio sobre el que se ha ejecutado
            identificador = "mega"
            resultado = procesar_pml(identificador)
            variable = resultado.rsplit(' ', 1)
            comando = variable[0]
            ubicacion = variable[1]

            #Alerto al usuario del proceso detectado
            #Si confirma que lo ha hecho él, deshabilito la regla del firewall y vuelvo a ejecutar el comando
            #para que se lleve a cabo
            if (cuadro_alerta(comando, identificador) == True):
                remove_rule("mega_blocker")
                volver_a_ejecutar_comando(ubicacion, comando)
                ctypes.windll.user32.MessageBoxW(0, "Transferencia permitida", "Confirmación", 0)
            #En caso de que no haya sido ejecutado por él, se deja la regla del firewall
            else:
                ctypes.windll.user32.MessageBoxW(0, "Transferencia bloqueada", "Confirmación", 0)

            #Termina la ejecución del programa
            sys.exit()

    #Si se trata de un establecimiento de conexión por medio del protocolo TCP
    elif paquete.haslayer(TCP):
        #Y ademas el puerto destino es el 21 (FTP)
        if paquete[TCP].dport == 21:

            ip_destino = paquete[IP].dst

            #Defino el nombre de la regla para el firewall
            nombre_regla = "ftp_blocker"

            #Añado la regla a la lista del firewall
            add_rule(nombre_regla, "C:\\Users\\marti\\Downloads\\filezilla\\FileZillaFTPClient\\filezilla.exe")

            #Paro la captura de eventos por parte de Process Monitor
            stop_process_monitor()

            #Transformo el archivo (de pml a csv)
            convertir_a_csv()

            #Obtengo el directorio y fichero que se ha intentado transmitir por ftp
            identificador = "ftp"
            fichero_a_transferir = procesar_pml(identificador)

            #Alerto al usuario del proceso detectado
            #Si confirma que lo ha hecho él, deshabilito la regla del firewall y vuelvo a ejecutar el comando
            #para que se lleve a cabo
            


            


#Obtengo el servicio accedido en la petición HTTP
def identificar_Protocolo(url):
    if "mega" in url:
        return "mega"
    else:
        return False

#Obtengo el agente de usuario que ha realizado la petición HTTP
def identificador_agente_usuario(agente_usuario):
    if "rclone" in agente_usuario:
        return "rclone"
    else:
        return False

#Compruebo que el script se está ejecutando con permisos de administrador (necesario para añadir la regla al firewall)


#Generación de una ventana que alerta al usuario sobre la ejecución del comando
def cuadro_alerta(terminal, identificador):
    if (identificador == "mega"):
        MsgBox = ctypes.windll.user32.MessageBoxW(None, "Se ha ejecutado el comando: " + terminal + " ¿Deseas permitirlo?", "!!!ATENCIÓN!!!", 1)
        if MsgBox == 1:
            return True
        else:
            return False
    elif (identificador == "ftp"):
        print("Buenas tardes")


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Programa para snifar el tráfico red de la interfaz de red deseada.")
    parser.add_argument("-i", "--iface", help="Nombre de la interfaz que se quiere definir")
    # parse arguments
    args = parser.parse_args()
    iface = args.iface
    #Compruebo los permisos de administrador

    #Elimino las posibles reglas que hayan
    remove_rule("mega_blocker")
    remove_rule("ftp_blocker")
    #Llamo al capturador de eventos de las interfaces de red
    definir_interfaz(iface)