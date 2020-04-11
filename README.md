# practica2

Segunda práctica de la asignatura REDES II. Creación de un almacenamiento seguro de ficheros.
Autores: Alejandro Bravo de la Serna y Miguel González González.

### Datos de prueba para la corrección.
ID: 377666

Token de Autorización: Se incluye en config.json, es: EA840b1Bd65Cc3f2.

ID del fichero "prueba2.txt" subido para "e281430": 5D7d2bf9

Comando utilizado para subir el fichero: (python3) securebox_client.py --upload prueba2.txt --dest_id e281430

Comando que se debe utilizar para descargarlos: (python3) securebox_client.py --download 5D7d2bf9 --source_id 377666


## Utilización del cliente
El cliente permite conectarse a SecureBox para transferir ficheros cifrados y firmados. Para utilizarlo, debe haber un token de autenticación en el fichero auth_token.dat, que debe encontrarse en la misma ubicación relativa al script. 

## Creación de una identidad
Para llevar a cabo cifrados y firmas, debe crearse una identidad en SecureBox y asociarle la clave pública. Para ello, basta con correr el script con las opción --create_id _nombre_ _email_. Una vez hecho esto, se almacenará en la misma ubicación que el script un fichero _privateKey.pem_, que corresponde a la clave privada, y en el servidor quedará registrada la clave pública. En caso de querer renovarlas, se puede volver a ejecutar la misma opción, pero los ficheros que hayan sido cifrados y subidos en el pasado dejarán de ser válidos (dado que la clave pública se ha actualizado).

## Eliminación de una identidad.
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