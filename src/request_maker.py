'''
    request_maker.py
    Modulo que se comunica con el servidor para realizar las peticiones a SecureBox.
    @author Miguel Gonzalez, Alejandro Bravo.
    @version 1.0
    @date 20-03-2020
'''

import requests
from datetime import datetime #Para formateo de fechas
from crypto import create_key, sign, enc_sign, dec_sign
from io import BytesIO
import json #Json fichero de configuracion

config = dict() #Datos de configuracion.

def init_config(filename):
    '''
        Nombre: init_config
        Descripción: Prepara la configuracion del modulo.
        Argumentos:
            filename: Nombre del fichero de configuracion.
        Retorno:
            -2 si faltan campos, -1 en caso de error, 0 en caso correcto. 
    '''
    global config #Datos de configuracion

    #Cargamos el fichero
    try:
        with open(filename, "r") as file:
            config = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return -1
    #En caso de que pueda faltar algun campo, se devuelve -2 para advertir al usuario.
    if len(config) != 3 or config["endpoints"] == None or len(config["endpoints"]) != 8:
        return -2
    return 0

def reset_config(filename):
    '''
        Nombre: reset_config
        Descripción: Crea un fichero de configuracion con los valores por defecto.
        Argumentos:
            filename: Nombre del fichero de configuracion.
    '''
    default_config = dict()
    endpoints = dict()

    #Asignamos los valores por defecto.
    endpoints["create_id"] = "/users/register"
    endpoints["search_id"] = "/users/search"
    endpoints["delete_id"] = "/users/delete" 
    endpoints["get_public_key"] = "/users/getPublicKey"
    endpoints["upload_file"] = "/files/upload"          
    endpoints["download_file"] = "/files/download"
    endpoints["list_files"] = "/files/list"        
    endpoints["delete_file"] = "/files/delete"

    default_config["url"] = "https://tfg.eps.uam.es:8080/api"
    default_config["token"] = "EA840b1Bd65Cc3f2"
    default_config["endpoints"] = endpoints

    #Escribimos
    with open(filename, "w+") as file:
        json.dump(default_config, file, indent=4)
    

def get_auth_token():
    '''
        Nombre: get_auth_token
        Descripción: Devuelve el token de autorizacion para SecureBox.
        Retorno:
            Cadena con el token, o None si falla.
    '''
    return config["token"]
	
def get_private_key():
    '''
        Nombre: get_private_key
        Descripción: Devuelve la clave privada del usuario.
        Retorno:
            Clave en formato PEM como array de bytes o None si falla.
    '''
    try:
        f = open("privateKey.pem", "rb")
    except FileNotFoundError:
	    return None
    if f == None:
        return None
    key = f.read()
    f.close()
    return key

def make_post_request(endpoint,post_json,post_data,post_files,raw_answer = 0):
    '''
        Nombre: make_post_request
        Descripción: Funcion que, con los datos recibidos, realiza una peticion post al servidor.
        Argumentos:
            endpoint: Funcion de la API que se va a usar. Por ejemplo, /users/search
            post_json: Diccionario con los datos que se POSTearan en formato de estructura JSON.
            post_data: Diccionario con datos que se POSTearan en formato habitual.
            post_files: Diccionario cuyos valores son descriptores de fichero para enviar.
            Cualquiera de estos ultimos 3 argumentos puede ser None.
            raw_answer: 1 Si la respuesta debe devolverse 'como tal' (no en forma de diccionario).
        Retorno:
            Estructura JSON con los datos de la respuesta, o None si falla.
    '''
    url = config["url"] + endpoint
    token = get_auth_token()
    if token == None:
        print("Error obteniendo el token de autenticación. Por favor, vuelque el token en un fichero auth_token.dat.")
        return None
    #cabeceras
    cabeceras = dict()
    cabeceras['Authorization'] = "Bearer " + token

    try:
        r = requests.post(url, json = post_json, data=post_data, files = post_files, headers=cabeceras)
    except requests.exceptions.Timeout:
        print("Error enviando peticion: time out.")
        return None
    except requests.exceptions.TooManyRedirects:
        print("Error con la URL (TooManyRedirects).")
        return None
    except requests.exceptions.RequestException as e:
        print("Error fatal en la request: ")
        print(e)
        return None
    
    #Manejo de errores
    if r.status_code != 200:
        respuesta = r.json()
        print("Servidor reporta error: " + respuesta["description"])
        return None

    if raw_answer == 1:
        return r

    respuesta = r.json()
    return respuesta

def create_id(nombre, email):
    '''
        Nombre: create_id
        Descripción: Funcion que registra una nueva identidad en SecureBox.
        Argumentos:
            nombre: Nombre de usuario a registrar.
            email: email del usuario a registrar.
        Retorno:
            0 si todo es correcto, -1 en otro caso. Imprime por pantalla el resultado.
    '''

    keys = create_key()

    #datos
    datos = dict()
    datos['nombre'] = nombre
    datos['email'] = email
    datos['publicKey'] = keys[0].decode()

    #Se hace la peticion
    respuesta = make_post_request(config["endpoints"]["create_id"], datos, None, None)
    if respuesta == None:
        return -1

    fecha = datetime.utcfromtimestamp(respuesta["ts"]).strftime('%Y-%m-%d %H:%M:%S UTC')
    print("Usuario registrado correctamente con ID: " + respuesta["userID"] + " y timestamp: " + fecha)

    #Almacenamos la clave privada en disco. Solo hay un usuario por token
    f = open("privateKey.pem", "wb")
    f.write(keys[1])
    f.close()
    return 0
    
def search_id(cadena):
    '''
        Nombre: search_id
        Descripción: Funcion que busca un usuario cuyo nombre o correo contenga una cadena.
        Argumentos:
            cadena: texto a buscar.
        Retorno:
            0 si todo es correcto, -1 en otro caso. Imprime por pantalla el resultado.
    '''

    datos = dict()
    datos["data_search"] = cadena

    respuesta = make_post_request(config["endpoints"]["search_id"], datos, None, None)
    if respuesta == None:
        return -1

    results = ""
    i=0
    for user in respuesta:

        #Los usuarios que no han creado identidad, tienen campos faltantes. Los saltamos.
        if user["nombre"] == None:
            continue
        if user["email"] == None:
            continue
        if user["userID"] == None:
            continue
            
        results += "["+str(i+1)+"] " + user["nombre"]+", " + user["email"] + ", ID: " + user["userID"] + "\n"
        i+=1

    print(str(i) + " usuarios encontrados: ")
    print(results[:-1]) #Quito el \n final

    return 0

def delete_id(user_id):
    '''
        Nombre: delete_id
        Descripción: Funcion que elimina un usuario.
        Argumentos:
            user_id: cadena con la id del usuario a eliminar.
        Retorno:
            0 si todo es correcto, -1 en otro caso. Imprime por pantalla el resultado.
    '''

    datos = dict()
    datos["userID"] = user_id

    respuesta = make_post_request(config["endpoints"]["delete_id"], datos, None, None)
    if respuesta == None:
        return -1

    print("Usuario con ID: " + respuesta["userID"] + " eliminado con exito.")
    return 0

def get_public_key(user_id):
    '''
        Nombre: delete_id
        Descripción: Funcion que devuelve la clave publica de un usuario como cadena.
        Argumentos:
            user_id: Cadena con la id del usuario del que obtener la clave publica.
        Retorno:
            cadena con la clave publica, o bien None en caso de error.
    '''
    datos = dict()
    datos["userID"] = user_id

    respuesta = make_post_request(config["endpoints"]["get_public_key"], datos, None, None)
    if respuesta == None:
        return None

    return respuesta["publicKey"].encode()

def upload_file(path, dest_id):
    '''
        Nombre: upload_file
        Descripción: Funcion que permite subir un fichero al servidor.
        Argumentos:
            path: Nombre/ruta relativa del fichero que se va a subir.
            dest_id: ID del receptor para el cifrado y la firma.
        Retorno:
            0 si todo es correcto, -1 en otro caso. Imprime por pantalla el resultado.
    '''
    #Se abre el fichero
    f = open(path, "rb")
    
    if f == None:
        print("Error enviando fichero: " + path +". Fichero no encontrado.")
        return -1

    #Se carga la clave privada.
    priv = get_private_key()
    if priv == None:
        print("Error enviando fichero: no se ha encontrado clave privada. Debe crearse una identidad primero con --create_id.")
        return -1

    #Se carga la clave publica
    print("-> Recuperando clave pública de ID " + dest_id + "... ",end='')
    publ = get_public_key(dest_id)
    if publ == None:
        print("Error recuperando clave pública. Fichero no enviado.")
        return -1
    print("OK")

    #Se cifra+firma
    print("-> Cifrando y firmando fichero...",end='')
    final = enc_sign(f.read(), priv, publ)
    print("OK")

    #Cierre de recursos
    f.close()

    #Preparamos un descriptor con los datos
    final_file = BytesIO(final)
    final_file.name = f.name

    #Envio
    print("-> Subiendo fichero a servidor...", end='')
    files = dict()
    files["ufile"] = final_file

    respuesta = make_post_request(config["endpoints"]["upload_file"], None, None, files)
    if respuesta == None:
        print("Error subiendo fichero a servidor.")
        return -1
    
    f.close()

    print("OK")
    print("Subida realizada correctamente, ID del fichero: " + str(respuesta["file_id"]) + ". Tamaño subido: " + str(respuesta["file_size"])+".")
    return 0

def download_file(file_id, source_id, path = None):
    '''
        Nombre: download_file
        Descripción: Funcion que permite descargar un fichero del servidor.
        Argumentos:
            file_id: Cadena con el identificador del fichero.
            source_id: ID del que subio el fichero, para descifrado.
            path: Ruta donde se escribirá el fichero. Si existía previamente, será machacado.
            Si path se ajusta a None, se escribirá con el nombre de fichero que reporte el servidor.
        Retorno:
            Cadena con el path donde se escribió, o bien None en caso de error.
    '''

    #Se obtiene nuestra clave privada:
    priv = get_private_key()
    if priv == None:
        print("Error enviando fichero: no se ha encontrado clave privada. Debe crearse una identidad primero con --create_id.")
        return None

    #Se carga la clave publica. Asi evitamos bajarnos el fichero entero y no tener la clave.
    print("-> Recuperando clave pública de ID " + source_id + "... ",end='')
    publ = get_public_key(source_id)
    if publ == None:
        print("Error recuperando clave pública. Fichero no enviado.")
        return None
    print("OK")

    datos = dict()
    datos["file_id"] = file_id

    respuesta = make_post_request(config["endpoints"]["download_file"], datos, None, None,1)
    if respuesta == None:
        return None

    #Obtenemos el nombre del fichero
    if path == None:
        content_disposition = respuesta.headers["Content-Disposition"]
        if content_disposition == None:
            print("Error obteniendo nombre del fichero a través del servidor.")
            return None
        #El path vendra en la cabecera como filename="path". Lo obtenemos con splits:
        path = content_disposition.split("filename=\"")[1].split("\"")[0]
        if path == None:
            print("Error obteniendo nombre del fichero a través del servidor.")
            return None
    print("-> " + str(len(respuesta.content)) + " bytes descargados correctamente")

    #Desciframos el mensaje
    descifrado = dec_sign(respuesta.content, priv, publ)
    if(descifrado == None):
       return None

    f = open(path,"wb")
    f.write(descifrado)
    f.close()
    return path

def list_files():
    '''
        Nombre: list_files()
        Descripción: Imprime el listado con los ficheros del usuario del cliente (determinado por el token)
        Retorno:
           Imprime por pantalla los ficheros. Devuelve -1 en caso de error, 0 en caso contrario.
    '''

    respuesta = make_post_request(config["endpoints"]["list_files"], None, None, None)
    if respuesta == None:
        return -1

    print("Encontrados " + str(respuesta["num_files"]) + " ficheros.")
    i=0
    for fichero in respuesta["files_list"]:   
        print("["+str(i+1)+"] " + "Identificador: " + fichero["fileID"] + " Nombre: " + fichero["fileName"])
        i+=1

    return 0

def delete_file(file_id):
    '''
        Nombre: delete_file()
        Descripción: Elimina del servidor el fichero indicado.
        Argumentos:
            file_id: Cadena con el identificador del fichero.
        Retorno:
           Imprime por pantalla el resultado. Devuelve -1 en caso de error, 0 en caso contrario.
    '''
    datos = dict()
    datos["file_id"] = file_id

    respuesta = make_post_request(config["endpoints"]["delete_file"], datos, None, None)
    if respuesta == None:
        return -1

    print("Fichero con ID: " + respuesta["file_id"] + " eliminado con exito.")
    return 0
