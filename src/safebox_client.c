/*
 * safebox_client.c
 *
 * CI3825 - Sistemas de Operacion I
 * Proyecto 3 - SafeBox
 *
 * ╔══════════════════════════════════════════════════════╗
 * ║  ARCHIVO A IMPLEMENTAR POR LOS ESTUDIANTES           ║
 * ║  Este es el codigo de REFERENCIA del profesor.       ║
 * ║  Los estudiantes entregaran su propia version.       ║
 * ╚══════════════════════════════════════════════════════╝
 *
 * Implementa las funciones declaradas en safebox_client.h.
 * Este archivo es la "biblioteca de enlace" entre el
 * minishell (safebox-shell.c) y el daemon.
 *
 * Syscalls principales usadas:
 *   socket(2), connect(2), send(2), recv(2)
 *   sendmsg(2), recvmsg(2) con SCM_RIGHTS
 *   open(2), read(2), fstat(2)
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>

#include "safebox.h"
#include "safebox_client.h"

#include <arpa/inet.h>

/* helpers internos */

static int send_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf; // puntero de lectura
    while (len > 0) // enviar hasta completar
    {
        ssize_t n = send(fd, p, len, 0); // intento de envío
        if (n < 0)
        {
            if (errno == EINTR) // reintentar si fue interrumpido
                continue;
            return -1; // error permanente
        }
        if (n == 0) // conexión cerrada inesperadamente
            return -1;
        p += n; // avanzar puntero
        len -= (size_t)n; // reducir bytes restantes
    }
    return 0; // éxito
}

static int recv_all(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf; // puntero de escritura
    while (len > 0) // recibir hasta completar
    {
        ssize_t n = recv(fd, p, len, 0); // intento de lectura
        if (n < 0)
        {
            if (errno == EINTR) // reintentar si fue interrumpido
                continue;
            return -1; // error permanente
        }
        if (n == 0) // conexión cerrada
            return -1;
        p += n; // avanzar puntero
        len -= (size_t)n; // reducir bytes restantes
    }
    return 0; // éxito
}

/*
 * sb_connect()
 *
 * Conecta al daemon en socket_path y autentica con password.
 * Internamente:
 *   1. Crea socket AF_UNIX SOCK_STREAM
 *   2. connect() al socket_path
 *   3. Calcula djb2(password)
 *   4. Envia sb_auth_msg_t con el opcode SB_OP_LIST (dummy) y el hash
 *   5. Lee la respuesta del daemon (SB_OK o SB_ERR_AUTH)
 *
 * Retorna: fd del socket autenticado, o -1 si falla.
 * El caller es responsable de cerrar con sb_bye().
 */
int sb_connect(const char *socket_path, const char *password)
{

    if (!socket_path || !password) // validar argumentos
    {
        errno = EINVAL;
        return -1;
    }

    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0); // crear socket UNIX
    if (sockfd < 0)
    {
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr)); // limpiar estructura
    addr.sun_family = AF_UNIX; // familia de socket local
    if (strlen(socket_path) >= sizeof(addr.sun_path)) // validar longitud de ruta
    {
        close(sockfd);
        errno = ENAMETOOLONG;
        return -1;
    }
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1); // copiar ruta del socket

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) // conectar al daemon
    {
        close(sockfd);
        return -1;
    }

    sb_auth_msg_t msg;
    msg.op = SB_OP_LIST; // dummy opcode segun especificacion 
    msg.password_hash = sb_djb2(password); // enviar hash de la clave

    if (send_all(sockfd, &msg, sizeof(msg)) < 0) // enviar mensaje de autenticación
    {
        close(sockfd);
        return -1;
    }

    uint8_t resp;
    if (recv_all(sockfd, &resp, sizeof(resp)) < 0) // recibir respuesta del daemon
    {
        close(sockfd);
        return -1;
    }

    if (resp != SB_OK) // autenticación fallida
    {
        close(sockfd);
        errno = EACCES;
        return -1;
    }

    return sockfd; // conexión autenticada
}

/*
 * sb_bye()
 *
 * Cierra la sesion enviando SB_OP_BYE al daemon y cierra sockfd.
 */
void sb_bye(int sockfd)
{
    if (sockfd < 0) // validar descriptor
        return;
    uint8_t op = SB_OP_BYE; // opcode para cerrar sesión
    (void)send(sockfd, &op, sizeof(op), 0); // enviar BYE al daemon
    close(sockfd); // cerrar socket
}

/*
 * sb_list()
 *
 * Lista los archivos disponibles en el safebox.
 * Escribe los nombres en buf separados por '\n', terminados en '\0'.
 *
 * Retorna: numero de archivos listados, o -1 si hay error.
 */
int sb_list(int sockfd, char *buf, size_t buflen)
{
    if (sockfd < 0 || !buf || buflen == 0)
    {
        errno = EINVAL;
        return -1;
    }

    uint8_t op = SB_OP_LIST;
    if (send_all(sockfd, &op, sizeof(op)) < 0)
    {
        return -1;
    }

    // Leemos respuesta del daemon
    uint8_t resp;
    if (recv_all(sockfd, &resp, 1) < 0)
        return -1;

    if (resp != SB_OK)
    {
        // error del daemon
        buf[0] = '\0';
        return 0;
    }

    // Leemos count (uint32_t big-endian)
    uint32_t count_be;
    if (recv_all(sockfd, &count_be, sizeof(count_be)) < 0)
        return -1;

    uint32_t count = ntohl(count_be);

    if (count == 0)
    {
        buf[0] = '\0';
        return 0;
    }

    // Leemos todos los nombres concatenados en buf
    //    Cada nombre termina en '\0'
    size_t off = 0;

    for (uint32_t i = 0; i < count; i++)
    {
        // Leemos nombre byte a byte
        while (off < buflen - 1)
        {
            if (recv(sockfd, &buf[off], 1, 0) <= 0)
                return -1;

            if (buf[off] == '\0')
            {
                // Si encontramos el fin del nombre, lo reemplazamos por \n
                // (excepto si es el último archivo, donde dejaremos que se sobrescriba luego con \0)
                buf[off] = '\n';
                off++;
                break;
            }
            off++;
        }

        if (off >= buflen - 1)
        {
            // buffer insuficiente
            buf[buflen - 1] = '\0';
            return (int)i; // devolvemos los que sí cupieron
        }
    }

    // Aseguramos terminación correcta.
    if (off > 0)
    {
        buf[off - 1] = '\0';
    }
    else
    {
        buf[0] = '\0';
    }

    // Retornamos cantidad de archivos
    return (int)count;
}

/*
 * sb_get()
 *
 * Solicita un archivo al daemon.
 * El daemon descifra el archivo y envia un fd anonimo (memfd) via SCM_RIGHTS.
 *
 * Retorna: fd del memfd con el contenido descifrado (listo para read()),
 *          o -1 si el archivo no existe o hay error.
 *
 * IMPORTANTE: el caller es responsable de close(fd) cuando termine.
 */
int sb_get(int sockfd, const char *filename)
{
    if (sockfd < 0 || !filename) // validar argumentos
    {
        errno = EINVAL;
        return -1;
    }

    size_t flen = strlen(filename) + 1; // longitud del nombre con '\0'
    if (flen > MAX_FNAME_LEN) // nombre demasiado largo
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    uint8_t op = SB_OP_GET; // opcode GET
    size_t msglen = 1 + flen; // tamaño del mensaje
    uint8_t *msg = malloc(msglen); // buffer para mensaje
    if (!msg)
        return -1;
    msg[0] = op; // escribir opcode
    memcpy(msg + 1, filename, flen); // copiar nombre

    if (send_all(sockfd, msg, msglen) < 0) // enviar solicitud
    {
        free(msg);
        return -1;
    }
    free(msg);

    struct msghdr msgh; // estructura para recvmsg
    struct iovec iov; // buffer para status
    uint8_t status; // byte de estado
    char cmsgbuf[CMSG_SPACE(sizeof(int))]; // espacio para fd recibido

    memset(&msgh, 0, sizeof(msgh)); // limpiar msgh
    memset(cmsgbuf, 0, sizeof(cmsgbuf)); // limpiar buffer de control

    iov.iov_base = &status; // status en iovec
    iov.iov_len = sizeof(status);
    msgh.msg_iov = &iov; // asignar iovec
    msgh.msg_iovlen = 1;
    msgh.msg_control = cmsgbuf; // buffer para fd
    msgh.msg_controllen = sizeof(cmsgbuf);

    ssize_t n = recvmsg(sockfd, &msgh, 0); // recibir status + fd
    if (n < 0) // error de recvmsg
    {
        return -1;
    }
    if (n == 0) // conexión cerrada
    {
        errno = ECONNRESET;
        return -1;
    }

    int received_fd = -1; // fd recibido
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msgh); // primer header de control
    if (cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) // validar fd
    {
        memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(int)); // extraer fd
    }

    if (status != SB_OK || received_fd < 0) // verificar éxito
    {
        if (received_fd >= 0)
            close(received_fd); // cerrar fd inválido
        errno = (status == SB_ERR_NOFILE) ? ENOENT : EIO; // error apropiado
        return -1;
    }

    return received_fd; // devolver memfd listo para leer
}

/*
 * sb_put()
 *
 * Envia un archivo local al daemon para que lo cifre y almacene.
 * Lee el contenido desde filepath en el filesystem local.
 *
 * Protocolo enviado:
 *   [SB_OP_PUT][nombre\0][uint32_t tamano][bytes del contenido]
 *
 * Retorna: 0 si exito, -1 si error.
 */
int sb_put(int sockfd, const char *filename, const char *filepath)
{
    if (sockfd < 0 || !filename || !filepath) // validar argumentos
    {
        errno = EINVAL;
        return -1;
    }

    size_t flen = strlen(filename) + 1; // longitud del nombre con '\0'
    if (flen > MAX_FNAME_LEN) // nombre demasiado largo
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    int fd = open(filepath, O_RDONLY); // abrir archivo local
    if (fd < 0)
        return -1;

    struct stat st;
    if (fstat(fd, &st) < 0) // obtener tamaño del archivo
    {
        close(fd);
        return -1;
    }

    if (st.st_size < 0) // tamaño inválido
    {
        close(fd);
        errno = EINVAL;
        return -1;
    }

    uint32_t size = (uint32_t)st.st_size; // tamaño en uint32_t
    uint8_t *buf = malloc(size); // buffer para contenido
    if (!buf && size > 0)
    {
        close(fd);
        return -1;
    }

    ssize_t rtotal = 0; // bytes leídos acumulados
    while (rtotal < (ssize_t)size) // leer archivo completo
    {
        ssize_t n = read(fd, buf + rtotal, size - (size_t)rtotal);
        if (n < 0)
        {
            if (errno == EINTR) // reintentar si fue interrumpido
                continue;
            free(buf);
            close(fd);
            return -1;
        }
        if (n == 0) // EOF inesperado
            break;
        rtotal += n;
    }
    close(fd);

    if ((uint32_t)rtotal != size) // verificar lectura completa
    {
        free(buf);
        errno = EIO;
        return -1;
    }

    uint8_t op = SB_OP_PUT; // opcode PUT
    uint32_t payload_size = htonl(size); // tamaño en big-endian

    size_t header_len = 1 + flen + sizeof(uint32_t); // tamaño del header
    uint8_t *header = malloc(header_len); // buffer del header
    if (!header)
    {
        free(buf);
        return -1;
    }

    size_t off = 0;
    header[off++] = op; // escribir opcode
    memcpy(header + off, filename, flen); // escribir nombre
    off += flen;
    memcpy(header + off, &payload_size, sizeof(uint32_t)); // escribir tamaño

    if (send_all(sockfd, header, header_len) < 0) // enviar header
    {
        free(header);
        free(buf);
        return -1;
    }
    free(header);

    if (size > 0 && send_all(sockfd, buf, size) < 0) // enviar contenido
    {
        free(buf);
        return -1;
    }
    free(buf);

    uint8_t resp;
    if (recv_all(sockfd, &resp, sizeof(resp)) < 0) // leer respuesta
    {
        return -1;
    }

    if (resp != SB_OK) // verificar éxito
    {
        errno = EIO;
        return -1;
    }

    return 0; // éxito
}


/*
 * sb_del()
 *
 * Elimina un archivo del safebox.
 *
 * Retorna: 0 si exito, -1 si el archivo no existe o hay error.
 */
int sb_del(int sockfd, const char *filename)
{
    if (sockfd < 0 || !filename) // validar argumentos
    {
        errno = EINVAL;
        return -1;
    }

    size_t flen = strlen(filename) + 1; // longitud del nombre incluyendo '\0'
    if (flen > MAX_FNAME_LEN) // nombre demasiado largo
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    uint8_t op = SB_OP_DEL; // opcode para eliminar archivo
    size_t msglen = 1 + flen; // tamaño del mensaje a enviar
    uint8_t *msg = malloc(msglen); // buffer para mensaje
    if (!msg)
        return -1;

    msg[0] = op; // primer byte: opcode
    memcpy(msg + 1, filename, flen); // copiar nombre del archivo

    if (send_all(sockfd, msg, msglen) < 0) // enviar solicitud al daemon
    {
        free(msg);
        return -1;
    }
    free(msg);

    uint8_t resp;
    if (recv_all(sockfd, &resp, sizeof(resp)) < 0) // leer respuesta del daemon
    {
        return -1;
    }

    if (resp != SB_OK) // verificar si hubo error
    {
        errno = (resp == SB_ERR_NOFILE) ? ENOENT : EIO; // archivo no existe o error general
        return -1;
    }

    return 0; // éxito
}
