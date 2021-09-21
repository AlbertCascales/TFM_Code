Este proyecto contiene el código fuente del programa desarrollado por @AlbertCascales para evitar las fugas de información producidas por los ransomwares con "double extorsion techiniques".

# Modo de funcionamiento

El modo de funcionamiento básico del programa es el siguiente:

* La fase inicial del programa consiste en la detección de algún proceso de compresión (WinRAR o 7-Zip). Tras la detección de uno de ellos, se inicia la fase principal de la herramienta.

* Tras lo anteriormente comentado, se realiza la puesta en marcha tanto del sniffer de red como del programa que monitoriza la actividad de los ficheros del sistema, para lo que se utiliza la herramienta Process Monitor.

* A continuación el programa entra en un blucle donde analiza cada paquete capturado a través de la interfaz de red. En este punto se buscan patrones en las capas de los paquetes las cuales concuerden con los portocolos de comunicación utilizados por los ransomwares analizados en el trabajo para la extracción de la información.

* Una vez que se encuentra una coincidencia, lo primero que se realiza es el bloqueo del tráfico detectado mediante la introducción de una nueva regla en el firewall. Posteriormente se alerta al usuario sobre el patrón reconocido.

* En este punto el usuario puede permitir la transferencia ya que se trata de una comunicación realizada por el, o continuar bloqueándola por no conocer su origen. En el caso de que se desee permitir la transferencia, se borra la entrada en la tabla del firewall, y se vuelve a ejecutar el programa que ha generado la alerta. Si no se reconoce el orgien, la regla se deja en el firewall, impidiendo futuras transferencias.
