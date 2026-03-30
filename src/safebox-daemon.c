/*
 * safebox-daemon.c
 *
 * CI3825 - Sistemas de Operacion I
 * Proyecto 3 - SafeBox
 *
 * Daemon de la boveda de archivos cifrados.
 *
 * Syscalls principales:
 *   termios:         lectura segura del password (sin echo)
 *   fork/setsid:     daemonizacion
 *   socket/bind/listen/accept: Unix Domain Socket
 *   getsockopt:      SO_PEERCRED (identidad del cliente)
 *   open/mmap/msync: acceso a archivos cifrados
 *   memfd_create:    fd anonimo en RAM para el contenido descifrado
 *   sendmsg:         SCM_RIGHTS (transferir fd al cliente)
 *   opendir/readdir: listar directorio del safebox
 *   unlink:          eliminar archivos
 *   signal:          SIGTERM handler para cierre limpio
 *
 * Compilacion:
 *   gcc -std=c11 -Wall -Wextra -Werror -Iinclude -o safebox-daemon src/safebox-daemon.c
 *
 * Uso:
 *   ./safebox-daemon ./mi_boveda
 *   safebox password: ****
 *   [safebox] pid=XXXX listo
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <termios.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <dirent.h>
#include <limits.h>
#include <stdint.h>

#include "safebox.h"

#include <arpa/inet.h>

// Variables globales
static unsigned char *master_key = NULL;
static size_t master_key_len = 0;
static unsigned long master_key_hash = 0;
static char *boveda_path = NULL;
static int log_fd = -1;
static int sock_fd = -1;
static volatile sig_atomic_t terminar = 0;

// Funciones que manejarán cada cliente y archivos
static void manejar_cliente(int conn_fd, uid_t uid, pid_t client_pid);

// Manejador de señal SIGTERM
static void sigterm_handler(int sig)
{
    (void)sig;
    terminar = 1;
}

static int send_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = send(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        p += n;
        len -= n;
    }
    return 0;
}

static int recv_all(int fd, void *buf, size_t len) {
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = recv(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        p += n;
        len -= n;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    // Verificamos el argumento
    if (argc != 2)
    {
        fprintf(stderr, "Uso: %s <directorio_boveda>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    boveda_path = argv[1];

    // Lectura de clave
    struct termios orig_termios, new_termios;
    char password[256];

    // Obtenemos atributos actuales de la terminal
    if (tcgetattr(STDIN_FILENO, &orig_termios) == -1)
    {
        perror("tcgetattr");
        exit(EXIT_FAILURE);
    }

    new_termios = orig_termios;
    new_termios.c_lflag &= ~ECHO; // Desactiva eco

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_termios) == -1)
    {
        perror("tcsetattr");
        exit(EXIT_FAILURE);
    }

    // Leemos contraseña
    printf("safebox password: ");
    fflush(stdout);
    if (fgets(password, sizeof(password), stdin) == NULL)
    {
        // Restauramos terminal antes de salir
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
        fprintf(stderr, "Error leyendo password\n");
        exit(EXIT_FAILURE);
    }

    // Restauraramos terminal inmediatamente
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);

    // Eliminamos el salto de línea final
    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n')
    {
        password[len - 1] = '\0';
        len--; // ajustar longitud
    }

    // Validamosr que no esté vacía
    if (len == 0)
    {
        fprintf(stderr, "Password vacío no permitido\n");
        exit(EXIT_FAILURE);
    }

    // Guardamos clave y hash
    master_key_len = len;
    master_key = malloc(master_key_len);
    if (!master_key)
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memcpy(master_key, password, master_key_len);
    master_key_hash = sb_djb2(password);

    // Limpiamos buffer por seguridad
    memset(password, 0, sizeof(password));

    // Daemonización
    pid_t pid = fork();
    if (pid == -1)
    {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (pid > 0)
    { // Padre
        printf("[safebox] pid=%d listo\n", pid);
        exit(EXIT_SUCCESS); // El padre termina correctamente
    }

    // Hijo: continuar como demonio
    setsid(); // Nueva sesión, liberar terminal

    // Redirigir stdin, stdout, stderr a /dev/null
    int fd_null = open("/dev/null", O_RDWR);
    if (fd_null == -1)
    {
        // Sin terminal, no podemos mostrar error, abortamos
        exit(EXIT_FAILURE);
    }
    dup2(fd_null, STDIN_FILENO);
    dup2(fd_null, STDOUT_FILENO);
    dup2(fd_null, STDERR_FILENO);
    if (fd_null > 2)
        close(fd_null);

    // Abrimos archivo de log
    log_fd = open("/tmp/safebox.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (log_fd == -1)
    {
        exit(EXIT_FAILURE);
    }

    // Escribimos PID en archivo
    int pid_fd = open("/tmp/safebox.pid", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (pid_fd != -1)
    {
        dprintf(pid_fd, "%d\n", getpid());
        close(pid_fd);
    }

    sb_log(log_fd, SB_LOG_INFO, "daemon iniciado pid=%d boveda=%s", getpid(), boveda_path);

    // Socket Unix
    // Eliminar socket previo si existe
    unlink("/tmp/safebox.sock");

    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd == -1)
    {
        sb_log(log_fd, SB_LOG_ERROR, "No se pudo crear el socket: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/tmp/safebox.sock", sizeof(addr.sun_path) - 1);

    if (bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        sb_log(log_fd, SB_LOG_ERROR, "bind falló: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (listen(sock_fd, 5) == -1)
    {
        sb_log(log_fd, SB_LOG_ERROR, "listen falló: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    sb_log(log_fd, SB_LOG_INFO, "escuchando en /tmp/safebox.sock");

    // Manejador de SIGTERM
    struct sigaction sa;
    sa.sa_handler = sigterm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGTERM, &sa, NULL) == -1)
    {
        sb_log(log_fd, SB_LOG_ERROR, "sigaction falló: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Bucle principal
    while (!terminar)
    {
        int conn_fd = accept(sock_fd, NULL, NULL);
        if (conn_fd == -1)
        {
            if (errno == EINTR)
                continue; // interrupción por señal
            sb_log(log_fd, SB_LOG_ERROR, "accept falló: %s", strerror(errno));
            break;
        }

        // Obtenemos credenciales del cliente
        struct ucred cred;
        socklen_t cred_len = sizeof(cred);
        if (getsockopt(conn_fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) == 0)
        {
            uid_t uid = cred.uid;
            pid_t client_pid = cred.pid;
            sb_log(log_fd, SB_LOG_INFO, "conexion entrante uid=%d pid=%d", uid, client_pid);
            manejar_cliente(conn_fd, uid, client_pid);
        }
        else
        {
            sb_log(log_fd, SB_LOG_WARN, "No se pudieron obtener credenciales del cliente");
            close(conn_fd);
        }
    }

    // Limpiamos
    if (terminar)
    {
        sb_log(log_fd, SB_LOG_INFO, "SIGTERM recibido — daemon terminado limpiamente");
    }
    else
    {
        sb_log(log_fd, SB_LOG_INFO, "Daemon terminado por error en accept");
    }

    close(sock_fd);
    unlink("/tmp/safebox.sock");
    unlink("/tmp/safebox.pid");

    // Sobreescribimos clave maestra
    if (master_key)
    {
        memset(master_key, 0, master_key_len);
        free(master_key);
    }

    close(log_fd);
    exit(EXIT_SUCCESS);
}



/*
 * list_files - Obtiene la lista de nombres de archivos en la bóveda
 * @lista: puntero a un arreglo de strings donde se guardarán los nombres
 * @count: puntero donde se almacenará el número de archivos
 *
 * Retorna: 0 en éxito, -1 en error
 */
static int list_files(char ***lista, size_t *count)
{
    DIR *dir;
    struct dirent *entry;
    char **names = NULL;
    size_t n = 0;
    size_t capacity = 0;

    // Abrimos el directorio de la bóveda
    dir = opendir(boveda_path);
    if (dir == NULL) {
        return -1;
    }

    // Contamos los archivos y asignamos dinámicamente
    while ((entry = readdir(dir)) != NULL) {
        // Ignoramos "." y ".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        // Agrandamos el arreglo si es necesario
        if (n >= capacity) {
            capacity = capacity == 0 ? 8 : capacity * 2;
            char **new_names = realloc(names, capacity * sizeof(char *));
            if (new_names == NULL) {
                // Error de memoria: liberamos lo que llevamos
                for (size_t i = 0; i < n; i++)
                    free(names[i]);
                free(names);
                closedir(dir);
                return -1;
            }
            names = new_names;
        }

        // Duplicamos el nombre y lo guardamos
        names[n] = strdup(entry->d_name);
        if (names[n] == NULL) {
            for (size_t i = 0; i < n; i++)
                free(names[i]);
            free(names);
            closedir(dir);
            return -1;
        }
        n++;
    }

    closedir(dir);

    // Asignamos los resultados
    *lista = names;
    *count = n;
    return 0;
}

/*
 * del_file - Elimina un archivo de la bóveda
 * @name: nombre del archivo (sin rutas)
 *
 * Retorna: 0 en éxito, -1 en error (archivo no existe, permisos, etc.)
 */
static int del_file(const char *name)
{
    // Validamos que el nombre no contenga '/' 
    if (strchr(name, '/') != NULL) {
        return -1;  
    }

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", boveda_path, name);

    if (unlink(path) == 0) {
        return 0;   // éxito
    } else {
        return -1;  // error 
    }
}

/*
 * put_file - Guarda un archivo cifrado en la bóveda
 * @name: nombre del archivo (sin rutas)
 * @data: contenido del archivo en claro
 * @size: tamaño del contenido en bytes
 *
 * Retorna: 0 en éxito, -1 en error
 */
static int put_file(const char *name, const unsigned char *data, uint32_t size)
{
    // Validamos nombre
    if (strchr(name, '/') != NULL) {
        return -1;
    }

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", boveda_path, name);

    // Abrimos el archivo para escritura
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1) {
        return -1;
    }

    // Construimos el buffer 
    uint32_t payload_size = size + SB_MAGIC_LEN; 
    unsigned char *plain = malloc(payload_size);
    if (!plain) {
        close(fd);
        return -1;
    }
    memcpy(plain, SB_MAGIC, SB_MAGIC_LEN);
    memcpy(plain + SB_MAGIC_LEN, data, size);

    // Ciframos con XOR
    for (uint32_t i = 0; i < payload_size; i++) {
        plain[i] ^= master_key[i % master_key_len];
    }

    // Preparamos la cabecera 
    sb_file_header_t header;
    header.version = SB_VERSION;
    header.payload_size = htonl(payload_size); // big-endian
    memset(header.reserved, 0, 3);

    // Escribimos cabecera
    ssize_t written = write(fd, &header, sizeof(header));
    if (written != sizeof(header)) {
        free(plain);
        close(fd);
        return -1;
    }

    // Escribimos payload cifrado
    written = write(fd, plain, payload_size);
    if (written != (ssize_t)payload_size) {
        free(plain);
        close(fd);
        return -1;
    }

    free(plain);
    close(fd);
    return 0;
}

/*
 * get_file_as_memfd - Lee un archivo, lo descifra y devuelve un memfd con el contenido
 * @name: nombre del archivo (sin rutas)
 * @out_fd: puntero donde se guardará el descriptor del memfd
 *
 * Retorna: 0 en éxito, -1 en error (archivo no existe, corrupto, etc.)
 */
static int get_file_as_memfd(const char *name, int *out_fd)
{
    // Validamos nombre
    if (strchr(name, '/') != NULL) {
        return -1;
    }

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", boveda_path, name);

    int fd_file = open(path, O_RDONLY);
    if (fd_file == -1) {
        return -1; 
    }

    // Leemos la cabecera
    sb_file_header_t header;
    ssize_t n = read(fd_file, &header, sizeof(header));
    if (n != sizeof(header)) {
        close(fd_file);
        return -1;
    }

    // Validamos versión
    if (header.version != SB_VERSION) {
        close(fd_file);
        return -1;
    }

    uint32_t payload_size = ntohl(header.payload_size);

    // Leemos el payload cifrado
    unsigned char *cipher = malloc(payload_size);
    if (!cipher) {
        close(fd_file);
        return -1;
    }
    n = read(fd_file, cipher, payload_size);
    if (n != (ssize_t)payload_size) {
        free(cipher);
        close(fd_file);
        return -1;
    }
    close(fd_file);

    // Desciframos in-place
    for (uint32_t i = 0; i < payload_size; i++) {
        cipher[i] ^= master_key[i % master_key_len];
    }

    // Verificamos el magic number
    if (memcmp(cipher, SB_MAGIC, SB_MAGIC_LEN) != 0) {
        free(cipher);
        return -1; 
    }

    // Creamos un memfd
    int fd_mem = memfd_create("content", MFD_CLOEXEC);
    if (fd_mem == -1) {
        free(cipher);
        return -1;
    }

    // Escribimos el contenido 
    uint32_t content_size = payload_size - SB_MAGIC_LEN;
    n = write(fd_mem, cipher + SB_MAGIC_LEN, content_size);
    if (n != (ssize_t)content_size) {
        close(fd_mem);
        free(cipher);
        return -1;
    }

    // Rebobinamos el fd para que el cliente lea desde el principio
    lseek(fd_mem, 0, SEEK_SET);

    free(cipher);
    *out_fd = fd_mem;
    return 0;
}

// Stub para manejar cliente TEMPORAL
static void manejar_cliente(int conn_fd, uid_t uid, pid_t client_pid)
{
    sb_auth_msg_t auth;

    /* Paso 1: AUTENTICACIÓN */
    if (recv_all(conn_fd, &auth, sizeof(auth)) < 0) {
        sb_log(log_fd, SB_LOG_WARN, "conexion rota antes de autenticacion uid=%d pid=%d", uid, client_pid);
        close(conn_fd);
        return;
    }

    if (auth.password_hash != master_key_hash) {
        sb_log(log_fd, SB_LOG_WARN, "autenticacion fallida uid=%d pid=%d", uid, client_pid);
        close(conn_fd);
        return;
    }

    /* Autenticación exitosa */
    uint8_t ok = SB_OK;
    send_all(conn_fd, &ok, 1);
    sb_log(log_fd, SB_LOG_OK, "autenticacion exitosa uid=%d pid=%d", uid, client_pid);

    /* Paso 2: BUCLE DE COMANDOS */
    while (1) {
        uint8_t op;
        ssize_t n = recv(conn_fd, &op, 1, 0);

        if (n == 0) {
            sb_log(log_fd, SB_LOG_INFO, "cliente pid=%d cerro conexion", client_pid);
            break;
        }
        if (n < 0) {
            sb_log(log_fd, SB_LOG_WARN, "error leyendo opcode pid=%d: %s", client_pid, strerror(errno));
            break;
        }

        /* ---------------- SB_OP_LIST ---------------- */
        if (op == SB_OP_LIST) {
            char **lista = NULL;
            size_t count = 0;

            if (list_files(&lista, &count) < 0) {
                uint8_t err = SB_ERR_IO;
                send_all(conn_fd, &err, 1);
                continue;
            }

            uint8_t resp = SB_OK;
            send_all(conn_fd, &resp, 1);

            uint32_t n_be = htonl(count);
            send_all(conn_fd, &n_be, sizeof(n_be));

            for (size_t i = 0; i < count; i++) {
                send_all(conn_fd, lista[i], strlen(lista[i]) + 1);
                free(lista[i]);
            }
            free(lista);

            sb_log(log_fd, SB_LOG_OK, "LIST — enviados %zu archivos", count);
        }

        /* ---------------- SB_OP_GET ---------------- */
        else if (op == SB_OP_GET) {
            char name[MAX_FNAME_LEN];
            size_t pos = 0;

            /* leer nombre hasta \0 */
            while (pos < sizeof(name)) {
                if (recv(conn_fd, &name[pos], 1, 0) <= 0) {
                    goto cerrar;
                }
                if (name[pos] == '\0') break;
                pos++;
            }

            int fd_mem;
            if (get_file_as_memfd(name, &fd_mem) < 0) {
                uint8_t err = SB_ERR_NOFILE;
                send_all(conn_fd, &err, 1);
                sb_log(log_fd, SB_LOG_WARN, "GET %s — archivo no encontrado/corrupto", name);
                continue;
            }

            /* enviar SB_OK + fd via SCM_RIGHTS */
            uint8_t resp = SB_OK;

            struct msghdr msg = {0};
            struct iovec iov = { .iov_base = &resp, .iov_len = 1 };

            char cmsgbuf[CMSG_SPACE(sizeof(int))];
            memset(cmsgbuf, 0, sizeof(cmsgbuf));

            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsgbuf;
            msg.msg_controllen = sizeof(cmsgbuf);

            struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
            cmsg->cmsg_level = SOL_SOCKET;
            cmsg->cmsg_type = SCM_RIGHTS;
            cmsg->cmsg_len = CMSG_LEN(sizeof(int));

            memcpy(CMSG_DATA(cmsg), &fd_mem, sizeof(int));

            sendmsg(conn_fd, &msg, 0);
            close(fd_mem);

            sb_log(log_fd, SB_LOG_OK, "GET %s — entregado a pid=%d", name, client_pid);
        }

        /* ---------------- SB_OP_PUT ---------------- */
        else if (op == SB_OP_PUT) {
            char name[MAX_FNAME_LEN];
            size_t pos = 0;

            while (pos < sizeof(name)) {
                if (recv(conn_fd, &name[pos], 1, 0) <= 0) goto cerrar;
                if (name[pos] == '\0') break;
                pos++;
            }

            uint32_t size_be;
            if (recv_all(conn_fd, &size_be, sizeof(size_be)) < 0) goto cerrar;
            uint32_t size = ntohl(size_be);

            unsigned char *data = malloc(size);
            if (!data) goto cerrar;

            if (recv_all(conn_fd, data, size) < 0) {
                free(data);
                goto cerrar;
            }

            int r = put_file(name, data, size);
            free(data);

            uint8_t resp = (r == 0 ? SB_OK : SB_ERR_IO);
            send_all(conn_fd, &resp, 1);

            if (r == 0)
                sb_log(log_fd, SB_LOG_OK, "PUT %s — cifrado y guardado (pid=%d)", name, client_pid);
            else
                sb_log(log_fd, SB_LOG_WARN, "PUT %s — error al guardar", name);
        }

        /* ---------------- SB_OP_DEL ---------------- */
        else if (op == SB_OP_DEL) {
            char name[MAX_FNAME_LEN];
            size_t pos = 0;

            while (pos < sizeof(name)) {
                if (recv(conn_fd, &name[pos], 1, 0) <= 0) goto cerrar;
                if (name[pos] == '\0') break;
                pos++;
            }

            int r = del_file(name);
            uint8_t resp;

            if (r == 0) {
                resp = SB_OK;
                sb_log(log_fd, SB_LOG_OK, "DEL %s — eliminado (pid=%d)", name, client_pid);
            } else {
                resp = SB_ERR_NOFILE;
                sb_log(log_fd, SB_LOG_WARN, "DEL %s — no existe", name);
            }

            send_all(conn_fd, &resp, 1);
        }

        /* ---------------- SB_OP_BYE ---------------- */
        else if (op == SB_OP_BYE) {
            sb_log(log_fd, SB_LOG_INFO, "BYE uid=%d pid=%d — sesion cerrada", uid, client_pid);
            break;
        }

        /* ---------------- OPCODE DESCONOCIDO ---------------- */
        else {
            sb_log(log_fd, SB_LOG_WARN, "opcode desconocido %d", op);
            break;
        }
    }

cerrar:
    close(conn_fd);
}
