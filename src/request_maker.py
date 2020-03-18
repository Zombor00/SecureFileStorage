'''
    request_maker.py
    Modulo que se comunica con el servidor para realizar las peticiones a SecureBox.
    Autor: Miguel Gonzalez y Alejandro Bravo (Grupo 2301)
    2020
'''
import requests
from datetime import datetime #Para formateo de fechas

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

def make_post_request(endpoint,datos):
    '''
        Nombre: make_post_request
        Descripción: Funcion que, con los datos recibidos, realiza una peticion post al servidor.
        Argumentos:
            endpoint: Funcion de la API que se va a usar. Por ejemplo, /users/search
            datos: Diccionario con los datos.
        Retorno:
            Estructura JSON con los datos de la respuesta, o None si falla.
    '''
    url = "https://vega.ii.uam.es:8080/api" + endpoint
    token = get_auth_token()
    if token == None:
        return None
    #cabeceras
    cabeceras = dict()
    cabeceras['Authorization'] = "Bearer " + token

    try:
        r = requests.post(url, json = datos, headers=cabeceras)
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
    
    respuesta = r.json()
    if r.status_code != 200:
        print("Servidor reporta error: " + respuesta["description"])
        return None
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

    keys = ["publickeyplaceholder","privatekeyplaceholder"] #TODO llamar a la funcion del modulo de cripto para obtener las claves.

    #datos
    datos = dict()
    datos['nombre'] = nombre
    datos['email'] = email
    datos['publicKey'] = keys[0]

    #Se hace la peticion
    respuesta = make_post_request("/users/register", datos)
    if respuesta == None:
        return -1

    fecha = datetime.utcfromtimestamp(respuesta["ts"]).strftime('%Y-%m-%d %H:%M:%S UTC')
    print("Usuario registrado correctamente con nombre: " + respuesta["nombre"] + " y timestamp: " + fecha)

    #Almacenamos la clave privada en disco. Solo hay un usuario por token
    f = open("privateKey.dat", "w")
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

    respuesta = make_post_request("/users/search", datos)
    if respuesta == None:
        return -1

    print(str(len(respuesta)) + " usuarios encontrados: ")
    i=0
    for user in respuesta:
        if user["nombre"] == None:
            user["nombre"] = "None"
        if user["email"] == None:
            user["email"] = "None"
        if user["userID"] == None:
            user["userID"] = "None"
            
        print("["+str(i+1)+"] " + user["nombre"]+", " + user["email"] + ", ID: " + user["userID"])
        i+=1

    return 0

def delete_id(id):
    '''
        Nombre: delete_id
        Descripción: Funcion que elimina un usuario.
        Argumentos:
            id: usuario a eliminar.
        Retorno:
            0 si todo es correcto, -1 en otro caso. Imprime por pantalla el resultado.
    '''

    datos = dict()
    datos["userID"] = str(id)

    respuesta = make_post_request("/users/delete", datos)
    if respuesta == None:
        return -1

    print("Usuario con ID: " + respuesta["userID"] + " eliminado con exito.")

def get_public_key(id):
    '''
        Nombre: delete_id
        Descripción: Funcion que devuelve la clave publica de un usuario como cadena.
        Argumentos:
            id: usuario del que obtener la clave publica.
        Retorno:
            cadena con la clave publica, o bien None en caso de error.
    '''
    datos = dict()
    datos["userID"] = str(id)

    respuesta = make_post_request("/users/getPublicKey", datos)
    if respuesta == None:
        return None

    return respuesta["publicKey"].replace('-----BEGIN PUBLIC KEY-----\n','').replace('-----END PUBLIC KEY-----','').replace('\n','')