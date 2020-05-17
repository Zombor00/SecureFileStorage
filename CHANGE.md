# Cambios respecto de la entrega temprana

1. Se ha añadido un fichero de configuración.
2. Se ha añadido la función _register_token_ que permite registrar un token con una contraseña, encriptando con AES-CBC el token, requiriendo así introducir la contraseña cada vez.
3. Cuando se llama a create_id la clave privada generada se encripta con el token del usuario.
4. Se ha añadido la función _password_ que permite introducir la contraseña del usuario para desencriptar el token y ,por tanto, la clave privada.
5. Actualizada convenientemente la wiki. 