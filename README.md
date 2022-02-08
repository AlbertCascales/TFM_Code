Este proyecto contiene el código fuente del programa desarrollado por @AlbertCascales para evitar las fugas de información producidas por los ransomwares con "double extorsion techiniques".

# Modo de funcionamiento

El modo de funcionamiento básico del programa es el siguiente:

* Al arrancar el programa, una de las primeras tareas que se realiza consiste en la monitorización de los procesos que se encuentran activos en el sistema, con el fin de detectar un proceso de compesión (WinRAR o 7-Zip), ya que la mayoría de ransomwares utilizan estas herramientas antes de extraer la información.

* Al mismo tiempo, se pone en marcha tanto el sniffer de red, utilizando la librería *Scapy* de Python, como el programa que monitoriza la actividad de los ficheros del sistema, para lo que se utiliza la herramienta *Process Monitor*.

* A continuación, el programa entra en un blucle donde analiza cada paquete capturado a través de la interfaz de red. En este punto se buscan patrones en las cabeceras de los paquetes intercambiados, los cuales concuerden con las técnicas utilizadas por los ransomwares tratados en el trabajo.

* Una vez que se encuentra una coincidencia, lo primero que se realiza es el bloqueo del tráfico detectado mediante la introducción de una nueva regla en el firewall. Posteriormente se alerta al usuario sobre el patrón reconocido.

* En este punto el usuario puede permitir la transferencia ya que se trata de una comunicación realizada por el, o continuar bloqueándola por no conocer su origen. En el caso de que se desee permitir la transferencia, se borra la entrada en la tabla del firewall, y se vuelve a ejecutar el programa que ha generado la alerta. Si no se reconoce el orgien, la regla se deja en el firewall, impidiendo futuras transferencias.

* Para terminar, se escribe en un fichero de logs el comando que ha generado la alerta en el sistema para que pueda ser evaluada en un futuro de manera más detallada.

# Modo de ejecución

Para ejecutar el fichero que analiza los procesos de compresión, el comando es: python check_procesoCompresion.py

Para iniciar la monitorización a nivel de host, el comando utilizado es: python startProcessMonitor.py

Para iniciar la monitorización a nivel de red, el comando empleado es: python networkSniffer.py -i Wi-Fi
