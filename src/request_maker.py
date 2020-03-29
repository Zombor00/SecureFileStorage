'''
    request_maker.py
    Modulo que se comunica con el servidor para realizar las peticiones a SecureBox.
    Autor: Miguel Gonzalez y Alejandro Bravo (Grupo 2301)
    2020
'''
import requests
from datetime import datetime #Para formateo de fechas
from crypto import create_key, sign, enc_sign, dec_sign
from io import BytesIO

def get_auth_token():
    '''
        Nombre: get_auth_token
        Descripción: Devuelve el token de autorizacion para SecureBox.
        Retorno:
            Cadena con el token, o None si falla.
    '''
    f = open("auth_token.dat", "r")
    if f == None:
        return None
    auth = f.read()
    f.close()
    return auth

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
    url = "https://tfg.eps.uam.es:8080/api" + endpoint
    token = get_auth_token()
    if token == None:
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
    respuesta = make_post_request("/users/register", datos, None, None)
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

    respuesta = make_post_request("/users/search", datos, None, None)
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

    respuesta = make_post_request("/users/delete", datos, None, None)
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

    respuesta = make_post_request("/users/getPublicKey", datos, None, None)
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

    privateKey = open("privateKey.pem", "rb")
    if privateKey == None:
        print("Error enviando fichero: no se ha encontrado clave privada. Debe crearse una identidad primero con --create_id.")
        f.close()
        return -1
    
    #Se carga la clave privada
    priv = privateKey.read()

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
    privateKey.close()

    #Preparamos un descriptor con los datos
    final_file = BytesIO(final)
    final_file.name = f.name

    #Envio
    print("-> Subiendo fichero a servidor...", end='')
    files = dict()
    files["ufile"] = final_file

    respuesta = make_post_request("/files/upload", None, None, files)
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
    privateKey = open("privateKey.pem", "rb")
    if privateKey == None:
        print("Error enviando fichero: no se ha encontrado clave privada. Debe crearse una identidad primero con --create_id.")
        return None
    priv = privateKey.read()
    privateKey.close()

    #Se carga la clave publica. Asi evitamos bajarnos el fichero entero y no tener la clave.
    print("-> Recuperando clave pública de ID " + source_id + "... ",end='')
    publ = get_public_key(source_id)
    if publ == None:
        print("Error recuperando clave pública. Fichero no enviado.")
        return None
    print("OK")

    datos = dict()
    datos["file_id"] = file_id

    respuesta = make_post_request("/files/download", datos, None, None,1)
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

    respuesta = make_post_request("/files/list", None, None, None)
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

    respuesta = make_post_request("/files/delete", datos, None, None)
    if respuesta == None:
        return -1

    print("Fichero con ID: " + respuesta["file_id"] + " eliminado con exito.")
    return 0