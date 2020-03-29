from request_maker import *
from crypto import *
from sys import exit
import argparse

#Código principal del cliente: Consume los argumentos y llama a los módulos según corresponda.
if __name__ == "__main__":

    #Argumentos
    parser = argparse.ArgumentParser(description="Cliente de SecureBox. Autores: Alejandro Bravo y Miguel González.")
    parser.add_argument('--create_id', nargs=2, help="Crea una identidad de usuario en el servidor",metavar=('nombre','email'))
    parser.add_argument('--search_id', help = "Busca un usuario cuyo nombre o correo contenga la cadena dada.", metavar='cadena')
    parser.add_argument('--delete_id', help = "Elimina un usuario dado su identificador.", metavar='identificador')
    parser.add_argument('--upload', help = "Sube un fichero al servidor, cifrado y firmado para que lo reciba un destinatario.", metavar='ruta')
    parser.add_argument('--source_id', help = "Identificador del emisor del fichero", metavar = 'identificador')
    parser.add_argument('--dest_id', help = "Identificador del destinatario del fichero", metavar = 'identificador')
    parser.add_argument('--list_files', help = "Muestra los archivos que se han subido", action = 'store_true')
    parser.add_argument('--download', help = "Descarga, descifra y comprueba firma del fichero deseado.", metavar = 'identificador')
    parser.add_argument('--delete_file', help = "Elimina del servidor el fichero de identificador dado.", metavar = 'identificador')
    parser.add_argument('--encrypt', help = "Cifra un fichero para que lo pueda descifrar otro usuario.", metavar = 'ruta')
    parser.add_argument('--sign', help = "Firma un fichero.", metavar = 'ruta')
    parser.add_argument('--enc_sign', help = "Cifra y firma un fichero", metavar = 'ruta')
    args = parser.parse_args()

    #Crear usuario
    if args.create_id != None:
        print("Creando identidad en el servidor...")
        if create_id(args.create_id[0],args.create_id[1]) == 0:
            exit ("Identidad creada con éxito.")
        exit ("Error creando identidad")

    #Buscar usuarios
    if args.search_id != None:
        print("Buscando la cadena: " + args.search_id)
        if search_id(args.search_id) == 0:
            exit("Búsqueda finalizada")
        exit ("Error durante la búsqueda")

    #Borrar usuario
    if args.delete_id != None:
        print("Eliminando usuario...")
        if delete_id(args.delete_id) == 0:
            exit("Usuario borrado con éxito")
        exit ("Error borrando usuario.")

    #Subir fichero
    if args.upload != None:
        print("Solicitado envio de fichero a SecureBox")
        if args.dest_id != None:
            if upload_file(args.upload, args.dest_id) == 0:
                exit("Operacion realizada con exito.")
            exit("Error subiendo el fichero")
        exit ("No se ha especificado ID de destinatario con --dest-id")

    #Listar ficheros
    if args.list_files == True:
        print("Solicitado listado de ficheros.")
        if list_files() == 0:
            exit ("Operacion realizada con exito")
        exit ("Error listando ficheros.")

    #Descargar fichero:
    if args.download != None:
        print("Solicitada descarga de fichero a SecureBox")
        if args.source_id != None:
            path = download_file(args.download, args.source_id)
            if  path != None:
                exit("Fichero descargado y verificado correctamente. Guardado en: " + path)
            exit("Error descargando el fichero")
        exit ("No se ha especificado ID del emisor con source_id.")

    #Eliminar fichero:
    if args.delete_file != None:
        print("Eliminando fichero...")
        if delete_file(args.delete_file) == 0:
            exit("Fichero borrado con éxito")
        exit ("Error eliminando fichero.")

    #Encriptar fichero
    if args.encrypt != None:
        print("Encriptando fichero localmente...")
        if args.dest_id != None:
            #TODO: Encriptar el fichero (IV + CLAVE AES CIFRADA + FICHERO CIFRADO) y guardarlo en un fichero 
            #Por ejemplo file.dat daria lugar a file_encrypted.dat.
            #Usar como publica para cifrar: args.dest_id. 
            #Seguramente haya que crear una funcion en el modulo de crypto que haga el cifrado hibrido sin firmar.
            pass
        exit ("No se ha especificado ID de destinatario con --dest-id")

    #Firmar fichero
    if args.sign != None:
        print("Firmando fichero localmente...")
        #Obtener clave publica
        privateKey = open("privateKey.pem", "rb")
        if privateKey == None:
            exit ("No existe la clave privada. Se debe crear una identidad con --create_id primero.")
        priv = privateKey.read()
        privateKey.close()
        #Firmar fichero
        fichero = open(args.sign, "rb")
        if fichero == None:
            exit ("Error abriendo fichero.")
        signed = sign(fichero.read(), priv)
        fichero.close()
        ficheroFirmado = open("SIGNED_" + args.sign, "wb")
        ficheroFirmado.write(signed)
        ficheroFirmado.close()
        exit("Operacion realizada con exito. Salida: " + "SIGNED_" + args.sign)

    #Firma + encriptado
    if args.enc_sign != None:
        print("Encriptando y firmando fichero localmente...")
        if args.dest_id != None:
            #Obtenemos la privada
            privateKey = open("privateKey.pem", "rb")
            if privateKey == None:
                exit ("No existe la clave privada. Se debe crear una identidad con --create_id primero.")
            priv = privateKey.read()
            privateKey.close()
            #Obtenemos la clave publica
            publ = get_public_key(args.dest_id)
            if publ == None:
                exit ("Error obteniendo clave pública")
            #Abrimos fichero
            fichero = open(args.enc_sign, "rb")
            if fichero == None:
                exit ("Error abriendo fichero.")
            encsigned = enc_sign(fichero.read(), priv, publ)
            fichero.close()
            #Escribimos
            ficheroFinal = open("ENCRYPTED_SIGNED_" + args.enc_sign, "wb")
            ficheroFinal.write(encsigned)
            ficheroFinal.close()
            exit("Operacion realizada con exito. Salida: " + "ENCRYPTED_SIGNED_" + args.enc_sign)
        exit ("No se ha especificado ID de destinatario con --dest-id")

    #Si se llego hasta aqui es que falta algo
    parser.print_help()