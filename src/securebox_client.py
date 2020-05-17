'''
    securebox_client.py   
    Programa principal para cifrar y firmar ficheros y comunicarse con securebox.
    @author Miguel Gonzalez, Alejandro Bravo.
    @version 1.0
    @date 22-03-2020
'''

from request_maker import *
from crypto import *
from sys import exit, argv
import argparse

#Código principal del cliente: Consume los argumentos y llama a los módulos según corresponda.
if __name__ == "__main__":

    #Argumentos
    parser = argparse.ArgumentParser(description="Cliente de SecureBox. Autores: Alejandro Bravo y Miguel González.")
    parser.add_argument('--create_id', nargs=2, help="Crea una identidad de usuario en el servidor",metavar=('nombre','email'))
    parser.add_argument('--register_token', nargs=2, help="Registra un token y lo encripta con una contraseña",metavar=('token','password'))
    parser.add_argument('--password', help="Contraseña del usuario para desencriptar su token.",metavar='password')
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
    parser.add_argument('--config_file', nargs = '?', const = "config.json", default = "config.json", help = "Indica que fichero de configuracion utilizar. Por defecto, se usara config.json", metavar = 'ruta')
    parser.add_argument('--generate_config', nargs = '?', const = "config.json", default = None, help = "Regenera el fichero de configuracion por defecto con el nombre indicado. Si no se indica, se usara config.json", metavar = 'ruta')
    args = parser.parse_args()

    #Generar fichero de configuracion:
    if args.generate_config != None:
        print("Generando fichero de configuracion por defecto en: " + args.generate_config)
        reset_config(args.generate_config)
        exit("Fichero de configuracion almacenado con exito en: " + args.generate_config +". Saliendo...")
    
    #Cargamos el fichero de configuracion:
    print("===================================")
    print("Leyendo fichero de configuracion...")
    retconfig = init_config(args.config_file)
    if retconfig == -1:
        print("Error leyendo fichero de configuracion.")
        print(">>> Si ha modificado el nombre del fichero, por favor indique cual es con --config_file.")
        print(">>> Si ha modificado o borrado erróneamente el fichero, puede generar otro con --generate_config. Mas información con --help.")
        exit("===================================")
    elif retconfig == -2:
        print("ADVERTENCIA: Se ha detectado que faltan campos en el fichero de configuracion. Es posible que algunas funcionalidades del cliente fallen.")
        print(">>> Puede generar un fichero de ejemplo con --generate_config para identificar los campos faltantes. Mas información con --help.")
    else:
        print(">>> Fichero cargado con exito")
    print("===================================")
    print()

    #Registra un token
    if args.register_token != None:
        print("Registrando token...")
        register_token(args.register_token[0],args.register_token[1], args.config_file)
        exit ("Se registro el token correctamente.")

    #Si introduce password
    if args.password != None:
        ret = password(args.password)
        if(ret == -1):
            exit("Contraseña introducida incorrecta. Puede volver a registrar el token con otra contraseña si ha sido extraviada.")
    elif(len(argv) > 1):
        exit("Introduzca contraseña por favor.")
    
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
        exit ("No se ha especificado ID de destinatario con --dest_id")

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
            #Obtenemos la clave publica
            publ = get_public_key(args.dest_id)
            if publ == None:
                exit ("Error obteniendo clave pública")
            #Abrimos fichero
            fichero = open(args.encrypt, "rb")
            if fichero == None:
                exit ("Error abriendo fichero.")
            enc = enc_sign(fichero.read(), None, publ, get_auth_token(), False)
            fichero.close()
            #Escribimos
            ficheroFinal = open(args.encrypt + "_ENCRYPTED", "wb")
            ficheroFinal.write(enc)
            ficheroFinal.close()
            exit("Operacion realizada con exito. Salida: " + args.encrypt + "_ENCRYPTED")
        exit ("No se ha especificado ID de destinatario con --dest_id")

    #Firmar fichero
    if args.sign != None:
        print("Firmando fichero localmente...")
        #Obtenemos la privada
        priv = get_private_key()
        if priv == None:
            exit ("No existe la clave privada. Se debe crear una identidad con --create_id primero.")
        #Firmar fichero
        fichero = open(args.sign, "rb")
        if fichero == None:
            exit ("Error abriendo fichero.")
        signed = sign(fichero.read(), priv, get_auth_token())
        fichero.close()
        ficheroFirmado = open(args.sign + "_SIGNED" , "wb")
        ficheroFirmado.write(signed)
        ficheroFirmado.close()
        exit("Operacion realizada con exito. Salida: " + args.sign + "_SIGNED")

    #Firma + encriptado
    if args.enc_sign != None:
        print("Encriptando y firmando fichero localmente...")
        if args.dest_id != None:
            #Obtenemos la privada
            priv = get_private_key()
            if priv == None:
                exit ("No existe la clave privada. Se debe crear una identidad con --create_id primero.")
            #Obtenemos la clave publica
            publ = get_public_key(args.dest_id)
            if publ == None:
                exit ("Error obteniendo clave pública")
            #Abrimos fichero
            fichero = open(args.enc_sign, "rb")
            if fichero == None:
                exit ("Error abriendo fichero.")
            encsigned = enc_sign(fichero.read(), priv, publ, get_auth_token())
            fichero.close()
            #Escribimos
            ficheroFinal = open(args.enc_sign + "_ENCRYPTED_SIGNED", "wb")
            ficheroFinal.write(encsigned)
            ficheroFinal.close()
            exit("Operacion realizada con exito. Salida: " + args.enc_sign + "_ENCRYPTED_SIGNED" )
        exit ("No se ha especificado ID de destinatario con --dest_id")

    #Si se llego hasta aqui es que falta algo
    print(">>> ADVERTENCIA: No se ha especificado ninguna accion a realizar. Estas son las banderas disponibles:\n")
    parser.print_help()
