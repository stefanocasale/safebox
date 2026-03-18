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
#include <signal.h>
#include <errno.h>
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

// Stub para manejar cliente TEMPORAL
static void manejar_cliente(int conn_fd, uid_t uid, pid_t client_pid)
{
    // Por ahora, solo cerrar
    (void)uid;
    close(conn_fd);
    sb_log(log_fd, SB_LOG_INFO, "cliente %d desconectado (stub)", client_pid);
}
