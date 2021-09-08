from tkinter.font import names
from typing import Protocol
#from dpkt.ssl import TLS, TLS12_V, TLSClientHello
from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers import *
from scapy.layers.tls.record import TLS
from scapy.layers.tls.extensions import *
import subprocess, ctypes, os, sys
from subprocess import Popen, DEVNULL
import tkinter as tk
from tkinter import Frame, messagebox
import subprocess
import argparse
import sys, os, traceback, types
import ftplib
import re

from stopProcessMonitor import convertir_a_csv, stop_process_monitor
from traffic_blocker import add_rule
from traffic_allower import remove_rule, volver_a_ejecutar_comando
from processMonitorParser import procesar_pml
from processActivity import devolver_proceso_ejecutado

comando = ""
ubicacion = ""
nombre_regla = ""
variableGlobal = ""
listaFTP = []
listaTLS = []

procesoCompresion = ""


#Función que define el puerto y la interfaz del adaptador de red que se monitoriza
def definir_interfaz(iface=None):
    if iface:
        sniff(filter="", prn=extraer_informacion, iface=iface, store=False)
    else:
        # En caso que de que no se defina ninguna interfaz se toma la de por defecto
        sniff(filter="", prn=extraer_informacion, store=False)

#Función que obtiene los datos más relevantes del paquete analizado
def extraer_informacion(paquete):

    #Comprobación de que previamente se ha ejecutado un proceso de compresión
    #if (procesoCompresion == "rar" or procesoCompresion == "7z"):

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

            #Si el puerto destino es el 443 (TLS)
            if paquete[TCP].dport == 443:
                #Si tiene una capa TLS
                if (paquete.haslayer(TLS)):
                    #Si se trata del handshake protocol
                    if (paquete[TLS].type == 22):
                        #Si el mensaje tiene un campo con extensiones
                        if (paquete[TLS].msg is not None):
                            listaTLS.append(paquete[TLS].msg)
                            #Convierto la lista en string
                            cadena = str(listaTLS)
                            #Si se está intentando acceder a un servicio de dropbox
                            if ("servernames" in cadena and "dropbox" in cadena):
                                stripped = re.sub(r'^.*?servernames=', '', cadena)
                                stripped2 = stripped.split(" ", 1)
                                nameserver = stripped2[0]
                                nameserver = nameserver[3:]
                                nameserver = nameserver[:len(nameserver) - 2]

                                #Bloqueo el tráfico
                                add_rule("dropbox_blocker", "C:\\Users\\marti\\Downloads\\rclone-v1.56.0-windows-amd64\\rclone-v1.56.0-windows-amd64\\rclone.exe")

                                #Paro la captura de eventos por parte de Process Monitor
                                stop_process_monitor()

                                #Transformo el archivo (de pml a csv)
                                convertir_a_csv()

                                #Obtengo el comando ejecutado y el directorio sobre el que se ha ejecutado
                                identificador = "dropbox"
                                resultado = procesar_pml(identificador)
                                variable = resultado.rsplit(' ', 1)
                                comando = variable[0]
                                ubicacion = variable[1]
                                

                                #Alerto al usuario del proceso detectado
                                #Si confirma que lo ha hecho él, deshabilito la regla del firewall y vuelvo a ejecutar el comando
                                #para que se lleve a cabo
                                if (cuadro_alerta(comando, identificador) == True):
                                    remove_rule("dropbox_blocker")
                                    volver_a_ejecutar_comando(ubicacion, comando)
                                    ctypes.windll.user32.MessageBoxW(0, "Transferencia permitida", "Confirmación", 0)
                                #En caso de que no haya sido ejecutado por él, se deja la regla del firewall
                                else:
                                    ctypes.windll.user32.MessageBoxW(0, "Transferencia bloqueada", "Confirmación", 0)

                                #Termina la ejecución del programa
                                sys.exit()


                                

            #Y ademas el puerto destino es el 21 (FTP)
            elif paquete[TCP].dport == 21:

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
                #Si confirma que lo ha hecho él, elimino la regla en el firewall y
                # vuelvo a solicitarle que introduzca los datos del servidor ftp
                if (cuadro_alerta(fichero_a_transferir, identificador) == True):

                    #Elimino la regla en el firewall
                    remove_rule("ftp_blocker")

                    #Recupero los datos del cliente en el servidor ftp
                    cuadro_dialogo_ftp()
                    direccionServidor = listaFTP[0]
                    nombreUsuario = listaFTP[1]
                    contraseñaUsuario = listaFTP[2]

                    #Establezco una nueva conexión ftp con el servidor
                    #validezCredenciales = False
                    #while (validezCredenciales == False):
                    try:
                        with ftplib.FTP(direccionServidor, nombreUsuario, contraseñaUsuario) as ftp:
                            validezCredenciales = True
                            #Subo el fichero previamente indicado
                            with open(fichero_a_transferir, 'rb') as file_object:
                                ftp.storbinary('STOR ficheroSubido.zip', file_object)
                                #Confirmo al usuario que se ha subido el fichero indicado
                                ctypes.windll.user32.MessageBoxW(0, "Transferencia permitida", "Confirmación", 0)
                    except:
                        print("Datos incorrectos")
                            #cuadro_dialogo_ftp()

                #En caso de que no haya sido ejecutado por él, se deja la regla del firewall
                else:
                    ctypes.windll.user32.MessageBoxW(0, "Transferencia bloqueada", "Confirmación", 0)

                #Termina la ejecución del programa
                sys.exit()


def cuadro_dialogo_ftp():

    root= tk.Tk()

    canvas1 = tk.Canvas(root, width = 400, height = 300,  relief = 'raised')
    canvas1.pack()

    label1 = tk.Label(root, text='Reintroduce los parámetros del servidor')
    label1.config(font=('helvetica', 14))
    canvas1.create_window(200, 25, window=label1)

    label2 = tk.Label(root, text='Dirección del servidor FTP:')
    label2.config(font=('helvetica', 10))
    canvas1.create_window(200, 75, window=label2)

    entry1 = tk.Entry (root)
    canvas1.create_window(200, 95, window=entry1)

    label3 = tk.Label(root, text='Username en el servidor FTP:')
    label3.config(font=('helvetica', 10))
    canvas1.create_window(200, 125, window=label3)

    entry2 = tk.Entry (root)
    canvas1.create_window(200, 145, window=entry2)

    label4 = tk.Label(root, text='Password en el servidor FTP:')
    label4.config(font=('helvetica', 10))
    canvas1.create_window(200, 175, window=label4)

    entry3 = tk.Entry (root)
    canvas1.create_window(200, 195, window=entry3)

    def confirmar_parametros():
        nombreServidor = entry1.get()
        nombreUsuario = entry2.get()
        contraseñaUsuario = entry3.get()
        lista.append(nombreServidor)
        lista.append(nombreUsuario)
        lista.append(contraseñaUsuario)

        root.destroy()
        

    button1 = tk.Button(text='Confirmar', command=confirmar_parametros, bg='brown', fg='white', font=('helvetica', 9, 'bold'))
    canvas1.create_window(200, 240, window=button1)

    root.mainloop()

    

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
    if (identificador == "dropbox"):
        MsgBox = ctypes.windll.user32.MessageBoxW(None, "Se ha ejecutado el comando: " + terminal + " ¿Deseas permitirlo?", "!!!ATENCIÓN!!!", 1)
        if MsgBox == 1:
            return True
        else:
            return False
    elif (identificador == "ftp"):
        MsgBox = ctypes.windll.user32.MessageBoxW(None, "Se está intentando transferir el fichero: " + terminal + " por FTP, ¿Deseas permitirlo?", "!!!ATENCIÓN!!!", 1)
        if MsgBox == 1:
            return True
        else:
            return False


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
    remove_rule("dropbox_blocker")
    #Sólo comienzo el sniffer de red cuando haya habido un proceso de compresión
    #procesoCompresion = devolver_proceso_ejecutado()
    #Llamo al capturador de eventos de las interfaces de red
    definir_interfaz(iface)