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
from csv import reader
from netaddr import IPNetwork


from stopProcessMonitor import convertir_a_csv, stop_process_monitor
from traffic_blocker import add_rule
from traffic_allower import remove_rule, volver_a_ejecutar_comando
from processMonitorParser import procesar_pml
from processActivity import devolver_proceso_ejecutado
import ipaddr
import time

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
            add_rule("mega_blocker", "C:\\Users\\marti\\Downloads\\rclone-v1.56.0-windows-amd64\\rclone-v1.56.0-windows-amd64\\rclone.exe")

            #Paro la captura de eventos por parte de Process Monitor
            stop_process_monitor()

            #Transformo el archivo (de pml a csv)
            convertir_a_csv()

            #Obtengo el comando ejecutado y el directorio sobre el que se ha ejecutado
            identificadorServicio = "mega"
            resultado = obtener_comando_y_directorio(identificadorServicio)
            comandoEjecutado = resultado[0]
            ubicacionDelEjecutable = resultado[1]

            nombreServicio = ""
            #Alerto al usuario del proceso detectado
            alertar_usuario(comandoEjecutado, identificadorServicio, ubicacionDelEjecutable, nombreServicio)

            entradaMegaSync = 0

            #Termina la ejecución del programa
            sys.exit()

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
                            
                            nombreServidor = nombre_servidor(cadena)


                            #Bloqueo el tráfico
                            add_rule("dropbox_blocker", "C:\\Users\\marti\\Downloads\\rclone-v1.56.0-windows-amd64\\rclone-v1.56.0-windows-amd64\\rclone.exe")

                            #Paro la captura de eventos por parte de Process Monitor
                            stop_process_monitor()

                            #Transformo el archivo (de pml a csv)
                            convertir_a_csv()

                            #Obtengo el comando ejecutado y el directorio sobre el que se ha ejecutado
                            identificadorServicio = "dropbox"
                            resultado = obtener_comando_y_directorio(identificadorServicio)
                            comandoEjecutado = resultado[0]
                            ubicacionDelEjecutable = resultado[1]
                            nombreServicio=""
                            

                            #Alerto al usuario del proceso detectado
                            alertar_usuario(comandoEjecutado, identificadorServicio, ubicacionDelEjecutable, nombreServicio)

                            entradaMegaSync = 0

                            #Termina la ejecución del programa
                            sys.exit()

                        elif ("pcloud" in cadena):
                            #Obtengo el nombre del servidor
                            nombreServidor = nombre_servidor(cadena)

                            #Bloqueo el tráfico
                            add_rule("pcloud_blocker", "C:\\Users\\marti\\Downloads\\rclone-v1.56.0-windows-amd64\\rclone-v1.56.0-windows-amd64\\rclone.exe")

                            #Paro la captura de eventos por parte de Process Monitor
                            stop_process_monitor()

                            #Transformo el archivo (de pml a csv)
                            convertir_a_csv()

                            #Obtengo el comando ejecutado y el directorio sobre el que se ha ejecutado
                            identificadorServicio = "pcloud"
                            resultado = obtener_comando_y_directorio(identificadorServicio)
                            comandoEjecutado = resultado[0]
                            ubicacionDelEjecutable = resultado[1]
                            nombreServicio=""

                            #Alerto al usuario del proceso detectado
                            alertar_usuario(comandoEjecutado, identificadorServicio, ubicacionDelEjecutable, nombreServicio)

                            entradaMegaSync = 0

                            #Termina la ejecución del programa
                            sys.exit()
                
            
                    
        #Y ademas el puerto destino es el 21 (FTP)
        elif paquete[TCP].dport == 21:

            #Defino el nombre de la regla para el firewall
            nombre_regla = "ftp_blocker"

            #Añado la regla a la lista del firewall
            add_rule(nombre_regla, "C:\\Users\\marti\\Downloads\\filezilla\\FileZillaFTPClient\\filezilla.exe")
            add_rule(nombre_regla, "C:\\Users\\marti\\Downloads\\winscp\\WinSCP\\WinSCP.exe")


            #Paro la captura de eventos por parte de Process Monitor
            stop_process_monitor()

            #Transformo el archivo (de pml a csv)
            convertir_a_csv()

            #Obtengo el directorio y fichero que se ha intentado transmitir por ftp
            identificadorServicio = "ftp"
            resultado = obtener_comando_y_directorio(identificadorServicio)
            herramientaUtilizada = resultado[0]
            ubicacionDelEjecutable = resultado[1]

            #Alerto al usuario del proceso detectado
            #Si confirma que lo ha hecho él, elimino la regla en el firewall y
            # vuelvo a solicitarle que introduzca los datos del servidor ftp
            if (cuadro_alerta(ubicacionDelEjecutable, identificadorServicio, herramientaUtilizada) == True):

                #Elimino la regla en el firewall
                remove_rule("ftp_blocker")

                #Recupero los datos del cliente en el servidor ftp
                cuadro_dialogo_ftp()
                direccionServidor = listaFTP[0]
                nombreUsuario = listaFTP[1]
                contraseñaUsuario = listaFTP[2]

                #Establezco una nueva conexión ftp con el servidor
                establecer_conexion_servidor_FTP(direccionServidor, nombreUsuario, contraseñaUsuario, ubicacionDelEjecutable)

            #En caso de que no haya sido ejecutado por él, se deja la regla del firewall
            else:
                ctypes.windll.user32.MessageBoxW(0, "Transferencia bloqueada", "Confirmación", 0)

            entradaMegaSync = 0

            #Termina la ejecución del programa
            sys.exit()

    else:
        if IP in paquete:
            #Obtengo la direccion IP destino
            ip_dst = paquete[IP].dst
            #Compruebo si dicha dirección pertenece a uno de los dominios de MEGA
            hayCoincidencia = procesar_direcciones_ip(ip_dst)

            if (hayCoincidencia == True):

                #Calculo el timestamp actual
                tiempoDeteccionIP = time.time()
                #Si el proceso de compresión se ha hecho hace menos de 5 segundos
                #Se alerta al usuario sobre una posible fuga de informacion sobre el fichero concreto
                if (tiempoDeteccionIP-tiempoProcesoCompresion < 300):
                    stop_process_monitor()
                    convertir_a_csv()

                    #Obtengo el directorio y fichero que se ha intentado transmitir por ftp
                    identificadorServicio = "TLSMegaSync"
                    resultado = obtener_comando_y_directorio(identificadorServicio)
                    herramientaUtilizada = resultado[0]
                    print(herramientaUtilizada)
                    ubicacionDelEjecutable = resultado[1]
                    nombreServicio = "MegaSync"
                    #Alerto al usuario del proceso detectado
                    alertar_usuario(herramientaUtilizada, identificadorServicio, ubicacionDelEjecutable, nombreServicio)

                    #Termina el programa
                    sys.exit()


def procesar_direcciones_ip(direccionIPDestino):
    #Leo el fichero con las direcciones IP de los servidores de mega
    with open("C:\\Users\\marti\\Documents\\UC3M\Master en Ingeniería Informática\\TFM_Code\\direccionesIPMega.txt") as file:
        while (line := file.readline().rstrip()):
            #Obtengo la dirección IP con su máscara
            direccionIP = ipaddr.IPv4Network(line)

            #Obtengo el rango completo de direcciones IP
            network = IPNetwork('/'.join([format(direccionIP.ip), format(direccionIP.netmask)]))
            generator = network.iter_hosts()

            for element in generator:
                #Compruebo si la direccion destino del paquete es una de las direcciones de MEGA
                if (direccionIPDestino == format(element)):
                    return True

    return False
                    


def establecer_conexion_servidor_FTP(direccionServer, nameUser, contraseñaUser, ubicacionFicheroTransmitido):
    #validezCredenciales = False
    #while (validezCredenciales == False):
    try:
        with ftplib.FTP(direccionServer, nameUser, contraseñaUser) as ftp:
            #validezCredenciales = True
            #Subo el fichero previamente indicado
            with open(ubicacionFicheroTransmitido, 'rb') as file_object:
                ftp.storbinary('STOR ficheroSubido.zip', file_object)
                #Confirmo al usuario que se ha subido el fichero indicado
                ctypes.windll.user32.MessageBoxW(0, "Transferencia permitida", "Confirmación", 0)
    except:
        print("Datos incorrectos")
            #cuadro_dialogo_ftp()

def nombre_servidor(cadena):
    stripped = re.sub(r'^.*?servernames=', '', cadena)
    stripped2 = stripped.split(" ", 1)
    nameserver = stripped2[0]
    nameserver = nameserver[3:]
    nameserver = nameserver[:len(nameserver) - 2]

def alertar_usuario(command, identificator, ubication, nombreServicio):
    if (identificator == "pcloud" or identificator =="mega" or identificator =="dropbox"):
        if (cuadro_alerta(command, identificator, nombreServicio) == True):
            remove_rule(identificator+"_blocker")
            volver_a_ejecutar_comando(ubication, command)
            ctypes.windll.user32.MessageBoxW(0, "Transferencia permitida", "Confirmación", 0)
        #En caso de que no haya sido ejecutado por él, se deja la regla del firewall
        else:
            ctypes.windll.user32.MessageBoxW(0, "Transferencia bloqueada", "Confirmación", 0)

    elif (identificator == "TLSMegaSync"):
        cuadro_alerta_megaSync(ubication, nombreServicio)

def cuadro_alerta_megaSync(ubi, nombreServicio):
    ctypes.windll.user32.MessageBoxW(None, "Se ha transferido el fichero: " + ubi + " a través de " + nombreServicio + " , ten cuidado porque se puede estar provocando una fuga de información", "!!!ATENCIÓN!!!", 1)


def obtener_comando_y_directorio(identificador):
    listaTemporal = []
    resultado = procesar_pml(identificador)
    variable = resultado.rsplit(' ', 1)
    comando = variable[0]
    ubicacion = variable[1]
    listaTemporal.append(comando)
    listaTemporal.append(ubicacion)
    return listaTemporal



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
        listaFTP.append(nombreServidor)
        listaFTP.append(nombreUsuario)
        listaFTP.append(contraseñaUsuario)

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
def cuadro_alerta(terminal, iden, nombreServicio):
    if (iden == "mega" or iden == "dropbox" or iden == "pcloud"):
        MsgBox = ctypes.windll.user32.MessageBoxW(None, "Se ha ejecutado el comando: " + terminal + " sobre un servidor de " + iden +" ¿Deseas permitirlo?", "!!!ATENCIÓN!!!", 1)
        if MsgBox == 1:
            return True
        else:
            return False
    elif (iden == "ftp"):
        MsgBox = ctypes.windll.user32.MessageBoxW(None, "Se está intentando transferir el fichero: " + terminal + " por FTP a través del programa " + nombreServicio +", ¿Deseas permitirlo?", "!!!ATENCIÓN!!!", 1)
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
    remove_rule("pcloud_blocker")
    #Sólo comienzo el sniffer de red cuando haya habido un proceso de compresión
    #procesoCompresion = devolver_proceso_ejecutado()
    #if (procesoCompresion == "rar" or procesoCompresion == "7z"):
    tiempoProcesoCompresion = time.time()
        #Llamo al capturador de eventos de las interfaces de red
    definir_interfaz(iface)