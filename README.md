# practica2

Segunda práctica de la asignatura REDES II. Creación de un almacenamiento seguro de ficheros.
Autores: Alejandro Bravo de la Serna y Miguel González González.

### Datos de prueba para la corrección.
ID: 377666

Token de Autorización: EA840b1Bd65Cc3f2. **Debe registrarse con una clave (palabra de paso arbitraria) mediante --register_token EA840b1Bd65Cc3f2 _clave_**

ID del fichero "prueba2.txt" subido para "e281430": 0f71Fc34

Comando utilizado para subir el fichero: (python3) securebox_client.py --upload prueba2.txt --dest_id e281430 --password _clave_

Comando que se debe utilizar para descargarlos: (python3) securebox_client.py --download 0f71Fc34 --source_id 377666 --password _clave_


## Utilización del cliente
El cliente permite conectarse a SecureBox para transferir ficheros cifrados y firmados. Para utilizarlo, debe haberse configurado correctamente, según indica la siguiente sección.

## Configuración del cliente
Para configurar el cliente, debe registrarse el token de autenticacion mediante la opción --register_token _token_ _clave_. Esto vinculará una clave de paso elegida por el usuario al token, que será cifrado con ella. Asimismo, cuando el usuario genere claves RSA, la clave privada irá cifrada con el token, razón por la cual conviene que el token requiera una contraseña. Asimismo se puede personalizar la URL y los endpoints en el fichero de configuración, en caso de que sea necesario. Si faltasen campos del fichero de configuración, o el propio fichero, o si se hubiese modificado erróneamente el fichero de tal modo que el cliente reporta advertencias o errores, es posible crear un fichero correcto (a falta de insertar el token del usuario) con la opción --generate_config _nombre_. Si se desease usar otro fichero de configuración que no fuese _config.json_, podría hacerse con --config_file _nombre_.  

En adelante, todas las acciones requerirán de la opción --password _clave_ para identificarse y descifrar así el token y, cuando sea necesario, la clave privada.
## Creación de una identidad
Para llevar a cabo cifrados y firmas, debe crearse una identidad en SecureBox y asociarle la clave pública. Para ello, basta con correr el script con las opción --create_id _nombre_ _email_. Una vez hecho esto, se almacenará en la misma ubicación que el script un fichero _privateKey.pem_, que corresponde a la clave privada, y en el servidor quedará registrada la clave pública. En caso de querer renovarlas, se puede volver a ejecutar la misma opción, pero los ficheros que hayan sido cifrados y subidos en el pasado dejarán de ser válidos (dado que la clave pública se ha actualizado).

## Eliminación de una identidad
Con la opción --delete_id _identificador_ se puede eliminar la identidad de SecureBox. Esto, además de retirar los datos del servidor, invalida el token de autenticación y los ficheros que se hayan subido, por tanto, para volver a utilizar el cliente, debe generarse un nuevo token de autenticación, colocarlo en el fichero indicado anteriormente, y subir de nuevo los ficheros que se deseen.
## Envío de ficheros
Para enviar un fichero a otra persona, basta con ejecutar el script con las opciones --upload _ruta_ y --dest_id _identificador del receptor_. El fichero se cifrará y firmará para ese destinatario, suponiendo que tiene una clave pública correcta en el servidor, y se subirá.

## Descarga de ficheros
Para descargarse un fichero que ha sido enviado para nosotros, se ejecuta el script con las opciones --download _identificador del fichero_ y --source_id _identificador del emisor_. El fichero se descargará con el mismo nombre que se subió, y se descifrará y comprobará su firma automáticamente. Si la firma no es correcta, se reportará un error y no se guardará.

## Cifrados y firmas locales
Con las opciones --encrypt, --sign y --enc_sign, seguidas de la ruta del fichero deseado, y --dest_id _identificador del receptor_, se puede obtener un fichero cifrado/firmado localmente. Aun así es necesario conectarse a SecureBox para recuperar la clave del receptor.

## Otras opciones
Se pueden realizar también las siguientes funcionalidades:

- Buscar un usuario con --search_id _cadena_. Mostrará todos los usuarios registrados cuyo nombre o email tenga coincidencias con la cadena.
- Listar los ficheros propios con --list_files
- Eliminar ficheros propios con --delete_file _identificador_