from processActivity import devolver_proceso_ejecutado
import time

procesoCompresion = "noCompression"

if __name__ == "__main__":

    f = open("procesoCompresion.txt", "w")
    f.write("noCompression")
    f.write(time.time)
    f.close()

    procesoCompresion = devolver_proceso_ejecutado()
    if (procesoCompresion == "rar" or procesoCompresion == "7z"):
        f = open("procesoCompresion.txt", "w")
        f.write(procesoCompresion + "\n")
        f.write(time.time())
        f.close()