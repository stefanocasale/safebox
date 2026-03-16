# safebox

### Módulo 0 – Base Común 
- Responsabilidad: Establecer las bases del proyecto: entender las definiciones de los headers, acordar convenciones de codificación y crear funciones auxiliares que serán usadas por todos los módulos.

- Lógica y conceptos clave:

    - Revisar safebox.h para conocer:

        - Opcodes (SB_OP_LIST, SB_OP_GET, etc.) y códigos de error (SB_OK, SB_ERR_NOTFOUND, etc.).

        - Estructura sb_auth_msg_t (probablemente contiene un campo hash y quizás un opcode).

        - Función djb2 para calcular hash de la clave.

        - Prototipo de sb_log (debe usarse en todo el daemon).

    - Definir funciones auxiliares send_all y recv_all que envuelvan a send/recv para garantizar que se transmitan todos los bytes (manejo de interrupciones y parciales). Estas funciones serán usadas en el manejo del socket.

    - Acordar el formato de la lista de archivos en la respuesta de LIST. Por simplicidad y para cumplir con el protocolo binario, se puede usar:

        - Primero un uint32_t (en big-endian) con la cantidad de archivos.

        - Luego, para cada archivo, una cadena terminada en \0 (incluyendo el terminador).

    - Decidir si se usarán funciones como htonl/ntohl (de <arpa/inet.h>) para manejar el campo payload_size en la cabecera de archivo.

    - Elegir nombres de variables globales en el daemon: master_key (buffer de unsigned char), master_key_len, master_key_hash, boveda_path, log_fd. Estas serán declaradas como extern en un header interno (ej. daemon.h) o como variables globales en safebox-daemon.c con acceso mediante funciones.

- Interfaz:

    - Las funciones send_all y recv_all serán utilizadas por los módulos que manejan el socket (Módulos 2 y 4).

    - Las constantes y estructuras ya están en los headers provistos, pero es crucial que ambos integrantes las conozcan.

- Peligros:

    - No malinterpretar el orden de bytes: el campo payload_size en disco debe ser big-endian. Usar htonl al escribir y ntohl al leer.

    - Asegurarse de que sb_log funciona correctamente; probablemente necesita que se haya abierto el archivo de log y se haya asignado a una variable global log_fd. Esto lo hará el Módulo 1.


### Módulo 1 – Arranque, Daemonización y Gestión de Señales 

- Archivo: src/safebox-daemon.c (parte inicial)

- Responsabilidad: Implementar el punto de entrada del daemon: lectura segura de la clave maestra, daemonización del proceso, creación del socket de escucha, instalación del manejador de SIGTERM y el bucle principal de aceptación de conexiones.

- Lógica y conceptos clave:

    - Lectura de la clave con termios:

    - Usar tcgetattr para obtener la configuración actual de la terminal.

    - Desactivar el flag ECHO en c_lflag.

    - Llamar a tcsetattr para aplicar los cambios.

    - Leer la línea de stdin con fgets o read.

    - Restaurar inmediatamente la terminal a su estado original (incluso si hay error) usando tcsetattr con los atributos guardados.

    - Calcular el hash de la clave con djb2 (función provista) y almacenar tanto la clave original (para cifrado) como su hash (para autenticación). La clave original debe guardarse en un buffer dinámico o estático; al finalizar el daemon se debe sobrescribir con ceros (memset).

- Daemonización:

    - Hacer fork(). El padre imprime [safebox] pid=<PID_HIJO> listo y termina con exit(0).

    - El hijo: llamar a setsid() para crear una nueva sesión y liberar la terminal.

    - Redirigir stdin, stdout, stderr a /dev/null usando dup2 sobre un descriptor abierto con open("/dev/null", O_RDWR).

    - Cambiar el directorio actual a / (opcional pero recomendado) con chdir.

    - Abrir el archivo de log /tmp/safebox.log con open(..., O_WRONLY|O_CREAT|O_APPEND, 0644). Guardar el descriptor en la variable global log_fd.

    - Escribir el PID del daemon en /tmp/safebox.pid usando fprintf o dprintf.

- Manejo de SIGTERM:

    - Usar sigaction para instalar un manejador que solo establezca una bandera global volatile sig_atomic_t a 1. No llamar a funciones no async-signal-safe (como sb_log) dentro del manejador.

    - En el bucle principal, verificar la bandera; si está activada, realizar la limpieza:

    - Cerrar el socket de escucha.

    - Eliminar /tmp/safebox.sock y /tmp/safebox.pid con unlink.

    - Escribir un mensaje de despedida en el log (usando write directamente sobre log_fd o llamando a sb_log desde el contexto normal, ya que no estamos en el manejador).

    - Sobrescribir la clave maestra con ceros.

    - Cerrar el log y salir con exit(0).

- Socket Unix y bucle de aceptación:

    - Crear un socket con socket(AF_UNIX, SOCK_STREAM, 0).

    - Configurar la estructura sockaddr_un con sun_family = AF_UNIX y sun_path = "/tmp/safebox.sock".

    - Llamar a bind y listen.

    - En un bucle infinito (hasta que llegue la señal), aceptar conexiones con accept.

    - Por cada conexión, obtener las credenciales del cliente mediante getsockopt con SO_PEERCRED para registrar uid y pid en el log.

    - Llamar a una función manejar_cliente(int conn_fd, uid_t uid, pid_t client_pid) que será implementada en otros módulos.

    - Cerrar el descriptor de conexión cuando manejar_cliente retorne.

- Interfaz:

    - Expone las variables globales: master_key, master_key_len, master_key_hash, boveda_path, log_fd.

    - Define la función manejar_cliente (a implementar en Módulo 2) que debe ser llamada desde el bucle.

- Peligros:

    - En la lectura de clave, restaurar el echo incluso si hay error (usar atexit o asegurarse de hacerlo antes de cada salida).

    - Después del fork, el hijo debe cerrar los descriptores heredados que no usará (especialmente si el padre tenía archivos abiertos). En este caso, el padre termina pronto, no hay problema.

    - El manejador de SIGTERM debe ser async-signal-safe; usar solo la bandera. La limpieza real se hace en el flujo principal.

    - El socket debe ser eliminado al iniciar (por si quedó de una ejecución anterior) y al terminar. Usar unlink antes de bind para evitar errores.


### Módulo 2 – Protocolo de Autenticación y Comunicación Básica 
- Archivos: src/safebox_client.c (completo) y parte de src/safebox-daemon.c (la función manejar_cliente que maneja autenticación y el envío/recepción de opcodes).

- Responsabilidad:

    - En el cliente: implementar las seis funciones requeridas (sb_open, sb_close, sb_list, sb_get, sb_put, sb_del) según las firmas de safebox_client.h. Cada función debe construir el mensaje binario correspondiente, enviarlo por el socket y recibir la respuesta.

    - En el daemon: implementar la lógica de autenticación y el despachador de comandos. Para cada comando, llamará a funciones auxiliares (proporcionadas por los Módulos 3 y 4) que realizan la operación concreta.

- Lógica y conceptos clave (cliente):

    - sb_open:

        - Crear socket con socket(AF_UNIX, SOCK_STREAM, 0).

        - Conectar al path /tmp/safebox.sock usando connect.

        - Enviar el mensaje de autenticación: según safebox.h, probablemente es una estructura sb_auth_msg_t que contiene el hash de la clave (calculado con djb2). El hash se pasa como parámetro o se calcula internamente (depende de la firma).

        - Recibir la respuesta (un byte: SB_OK o error). Si es SB_OK, guardar el descriptor del socket para usarlo en las siguientes llamadas; si no, cerrar y retornar error.

    - sb_close: enviar el opcode SB_OP_BYE y cerrar el socket.

    - sb_list: enviar SB_OP_LIST, luego recibir la respuesta:

        - Leer un byte de estado.

        - Si es SB_OK, recibir la lista según el formato acordado (ej. primero un uint32_t count, luego los nombres). Usar recv_all para asegurar la lectura completa.

        - Devolver la lista al shell (el shell espera un formato específico, probablemente un arreglo de strings).

    - sb_get: enviar SB_OP_GET seguido del nombre (incluyendo el \0). Luego leer el byte de estado. Si es SB_OK, recibir un descriptor de archivo mediante recvmsg con SCM_RIGHTS. El descriptor corresponde a un memfd que contiene el archivo descifrado. La función debe devolver ese descriptor (o leerlo y devolver el contenido, según la firma).

    - sb_put: enviar SB_OP_PUT, luego el nombre (con \0), luego el tamaño (uint32_t en big-endian) y finalmente los datos. Esperar el byte de estado.

    - sb_del: enviar SB_OP_DEL + nombre, esperar estado.

    - Todas las funciones deben usar send_all y recv_all para manejo de datos parciales.

- Lógica y conceptos clave (daemon: manejo de autenticación):

    - En manejar_cliente(conn_fd, uid, pid):

        - Leer el mensaje de autenticación (estructura fija). Comparar el hash recibido con master_key_hash.

        - Si no coinciden, registrar con sb_log un mensaje de advertencia ([WARN] autenticacion fallida ...) y cerrar la conexión (sin enviar respuesta).

        - Si coinciden, enviar un byte SB_OK y registrar [OK] autenticacion exitosa ....

        - Luego entrar en un bucle donde:

            - Leer un byte (opcode) con recv.

            - Según el opcode, llamar a la función correspondiente (implementadas en Módulo 3 y 4):

                - handle_list(conn_fd)

                - handle_get(conn_fd, nombre)

                - handle_put(conn_fd, nombre, size, datos)

                - handle_del(conn_fd, nombre)

                - SB_OP_BYE: salir del bucle.

            - Cada función handle_* debe enviar la respuesta (código de estado y posiblemente datos) y registrar el evento en el log (usando sb_log con el nivel adecuado: OK, WARN, ERROR).

        - Al salir, cerrar conn_fd.

- Interfaz:

    - El daemon necesita las funciones handle_* que serán implementadas en Módulo 3 y 4. Se acuerdan prototipos como:

        - int handle_list(int conn_fd); (envía la lista y retorna 0 o -1)

        - int handle_get(int conn_fd, const char *name);

        - int handle_put(int conn_fd, const char *name, uint32_t size, const unsigned char *data);

        - int handle_del(int conn_fd, const char *name);

    - El cliente usa las funciones de socket y el formato de mensajes.

- Peligros:

    - En el cliente, al recibir el fd con SCM_RIGHTS, el buffer de control debe ser suficientemente grande. Usar CMSG_SPACE(sizeof(int)).

    - En el daemon, al leer el nombre, asegurarse de que está terminado en null y no excede un tamaño máximo (para evitar desbordamientos).

    - No confiar en que el cliente envía los datos correctos; validar longitudes.

    - Manejar correctamente los errores de recv/send (desconexión repentina).


### Módulo 3 – Operaciones de Archivos (LIST, PUT, DEL) y Cifrado 
- Archivo: src/safebox-daemon.c (funciones internas)

- Responsabilidad:

    - Implementar las funciones que manipulan el directorio de la bóveda aplicando el cifrado XOR con la clave maestra. Incluye:

    - Listar archivos.

    - Escribir un nuevo archivo (PUT) con el formato especificado.

    - Eliminar un archivo (DEL).

    - (Para GET, se implementará una función que devuelva un memfd con el contenido descifrado; esto será usado por el Módulo 4).

- Lógica y conceptos clave:

    - Cifrado/descifrado XOR:

        - La clave es un string de longitud key_len. Para cifrar un buffer buf de longitud len, se aplica: buf[i] ^= key[i % key_len].

        - La misma operación descifra. Es importante notar que se modifica el buffer original; si se necesita conservar una copia, se debe copiar antes.

    - Formato de archivo en disco (sección 5 del enunciado):

        - Cabecera de 8 bytes en claro:

            - version (1 byte): siempre 0x01.

            - payload_size (4 bytes): tamaño del payload cifrado (incluyendo los 4 bytes mágicos). Almacenar en big-endian (usar htonl).

            - reserved (3 bytes): ceros.

        - A continuación, payload_size bytes de datos cifrados.

        - El payload en claro antes de cifrar es: "SBX!" (4 bytes) seguido del contenido original del archivo.

    - LIST: función list_files(boveda_path, char **out_buffer, size_t *out_len):

        - Abrir el directorio con opendir.

        - Leer entradas con readdir, ignorando "." y "..".

        - Contar los archivos y luego construir un buffer con el formato acordado: uint32_t count (big-endian) seguido de cada nombre terminado en null.

        - Devolver el buffer (asignado con malloc) y su longitud. El llamador (Módulo 2) lo enviará y luego liberará.

        - En caso de error, retornar código de error.

    - PUT: función put_file(boveda_path, name, data, size, master_key, key_len):

        - Validar que name no contenga '/' (para evitar path traversal). Si contiene, retornar SB_ERR_PERM.

        - Construir el buffer plain = "SBX!" (4 bytes) + data (size bytes). Total = size+4.

        - Cifrar plain con XOR usando la clave.

        - Abrir el archivo en la bóveda con open(path, O_WRONLY|O_CREAT|O_TRUNC, 0600).

        - Escribir la cabecera: version = 0x01, payload_size = htonl(size+4), reserved[3] = {0}.

        - Escribir el payload cifrado.

        - Cerrar y retornar SB_OK o error (ej. SB_ERR_PERM si no se puede escribir).

        - Registrar el evento (el Módulo 2 lo hará, pero la función puede retornar el código).

    - DEL: función del_file(boveda_path, name):

        - Validar nombre.

        - Usar unlink para eliminar el archivo. Retornar SB_OK si existe y se pudo eliminar, o SB_ERR_NOTFOUND si no existe.

    GET (función auxiliar para Módulo 4): get_file_as_memfd(boveda_path, name, master_key, key_len, int *out_fd):

        - Abrir el archivo con open (modo lectura).

        - Leer la cabecera (8 bytes). Extraer payload_size (convertir con ntohl).

        - Leer payload_size bytes a un buffer (usar malloc o mmap).

        - Descifrar el buffer con XOR (in-place).

        - Verificar que los primeros 4 bytes sean "SBX!". Si no, retornar SB_ERR_CORRUPT.

        - Crear un memfd con memfd_create("content", MFD_CLOEXEC).

        - Escribir en él el contenido (desde el offset 4, tamaño payload_size-4). Se puede usar write o ftruncate + mmap para copiar.

        - Asignar el descriptor a *out_fd.

        - Cerrar el archivo original y liberar el buffer.

        - Retornar SB_OK o error.

- Interfaz:

    - Estas funciones serán llamadas por los handlers del Módulo 2 (LIST, PUT, DEL) y por el handler de GET del Módulo 4.

    - Necesitan acceso a boveda_path, master_key y key_len (globales).

- Peligros:

    - Al leer archivos, el payload_size podría ser muy grande (archivo corrupto o malicioso). Limitar a un tamaño razonable o usar mmap para evitar agotar memoria.

    - Al escribir, usar O_CREAT|O_TRUNC para sobrescribir. Asegurar permisos (0600).

    - Validar nombres: no permitir rutas absolutas ni ... Usar strchr(name, '/') para detectar.

    - En el cifrado, la clave puede tener cualquier byte, incluyendo ceros; tratar como buffer de bytes, no como string (no usar strlen sobre la clave para la longitud; usar la longitud real).

    - Después de usar la clave, sobrescribir buffers temporales con memset para evitar que queden en memoria.


### Módulo 4 – Transferencia de Descriptores (GET) y Logging Completo 
- Archivo: src/safebox-daemon.c (implementación de handle_get y revisión de logging)

- Responsabilidad:

    - Implementar el handler de GET en el daemon, que utiliza la función get_file_as_memfd del Módulo 3 y envía el descriptor mediante sendmsg con SCM_RIGHTS.

    - Asegurar que todos los eventos del daemon (autenticación, cada operación, inicio y fin) se registren en el log con el formato y niveles especificados.

- Lógica y conceptos clave:

    - Handler de GET:

        - En handle_get(conn_fd, name):

            - Llamar a get_file_as_memfd(...) para obtener un descriptor fd_mem y un código de estado.

            - Si el código no es SB_OK, enviar ese código como respuesta (un byte) y retornar.

            - Si es SB_OK, preparar un mensaje para enviar el descriptor:

                - Construir un struct iovec con un byte de respuesta (SB_OK).

                - Construir un mensaje de control con CMSG_SPACE(sizeof(int)) y usar CMSG_DATA para colocar el descriptor.

                - Llamar a sendmsg para enviar el byte y el fd.

                - Cerrar el descriptor local (el que se envió) para no agotar límites.

            - Registrar en el log con sb_log el evento [OK] GET nombre — entregado a pid=....

            - En caso de error, registrar el nivel correspondiente ([WARN] GET nombre — archivo no encontrado o [ERROR] GET nombre — corrupto).

    - Logging completo:

        - El Módulo 1 ya registra inicio y fin.

        - El Módulo 2 registra autenticaciones.

        - Este módulo debe asegurar que cada operación (LIST, PUT, DEL) también se registre con el nivel adecuado. Para ello, los handlers deben llamar a sb_log después de ejecutar la operación.

        - El formato de fecha debe obtenerse con localtime y strftime. sb_log probablemente ya lo incluye, pero si no, se debe implementar una función auxiliar.

        - Usar O_APPEND garantiza atomicidad en cada escritura.

    - Consideraciones adicionales:

        - En LIST, después de enviar la lista, registrar [OK] LIST — enviados X archivos.

        - En PUT, después de escribir, registrar [OK] PUT nombre — cifrado y guardado.

        - En DEL, registrar [OK] DEL nombre — eliminado.

        - En errores, usar [WARN] o [ERROR] según corresponda.

- Interfaz:

    - Necesita la función get_file_as_memfd del Módulo 3.

    - Depende de las variables globales log_fd, boveda_path, master_key, etc.

    - Los handlers de LIST, PUT y DEL (que llamará el Módulo 2) también deben registrar eventos; por tanto, el Módulo 4 puede coordinarse con el Módulo 2 para incluir las llamadas a sb_log dentro de esos handlers (o el Módulo 2 mismo puede llamar a sb_log). Lo importante es que quede claro quién es responsable de cada mensaje.

- Peligros:

    - Al enviar el fd con SCM_RIGHTS, asegurarse de que el mensaje de control esté correctamente alineado y que se use CMSG_FIRSTHDR y CMSG_NXTHDR correctamente.

    - El descriptor enviado debe ser duplicado en el receptor; el emisor puede cerrar el suyo después de sendmsg.

    - En el log, usar sb_log que ya maneja el timestamp; verificar que esté disponible. Si no, implementar una función que formatee la fecha.

    - No olvidar registrar también cuando el daemon recibe SIGTERM (Módulo 1) y cuando se cierra una sesión (BYE).


### DIVISIÓN DE CHAMBA
- Stefano (Módulos 1 y 3): Se encarga del corazón del daemon: arranque, daemonización, lectura segura de la clave, manejo de señales, y toda la lógica de cifrado/descifrado y operaciones con archivos (LIST, PUT, DEL, y la función auxiliar para GET). Es un rol que trabaja directamente con llamadas al sistema como fork, setsid, termios, opendir, open, mmap (opcional), y el cifrado XOR.

- Alejandro (Módulos 2 y 4): Se enfoca en la comunicación: implementar las funciones del cliente (safebox_client.c) que el shell usará, y en el daemon el manejo de la autenticación, el despachador de comandos, y la transferencia de descriptores con SCM_RIGHTS para GET. También asegura que todo quede registrado en el log. Usa socket, connect, sendmsg/recvmsg, y memfd_create