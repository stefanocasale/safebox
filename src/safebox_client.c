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

/* helpers internos */

static int send_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    while (len > 0) {
        ssize_t n = send(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int recv_all(int fd, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    while (len > 0) {
        ssize_t n = recv(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
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
int sb_connect(const char *socket_path, const char *password) {
    
    if (!socket_path || !password) {
        errno = EINVAL;
        return -1;
    }

    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(addr.sun_path)) {
        close(sockfd);
        errno = ENAMETOOLONG;
        return -1;
    }
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sockfd);
        return -1;
    }

    sb_auth_msg_t msg;
    msg.op = SB_OP_LIST; /* dummy opcode segun especificacion */
    msg.password_hash = sb_djb2(password);

    if (send_all(sockfd, &msg, sizeof(msg)) < 0) {
        close(sockfd);
        return -1;
    }

    uint8_t resp;
    if (recv_all(sockfd, &resp, sizeof(resp)) < 0) {
        close(sockfd);
        return -1;
    }

    if (resp != SB_OK) {
        close(sockfd);
        errno = EACCES;
        return -1;
    }

    return sockfd;
}

/*
 * sb_bye()
 *
 * Cierra la sesion enviando SB_OP_BYE al daemon y cierra sockfd.
 */
void sb_bye(int sockfd) {
    if (sockfd < 0) return;
    uint8_t op = SB_OP_BYE;
    (void)send(sockfd, &op, sizeof(op), 0);
    close(sockfd);
}

/*
 * sb_list()
 *
 * Lista los archivos disponibles en el safebox.
 * Escribe los nombres en buf separados por '\n', terminados en '\0'.
 *
 * Retorna: numero de archivos listados, o -1 si hay error.
 */
int sb_list(int sockfd, char *buf, size_t buflen) {
    if (sockfd < 0 || !buf || buflen == 0) {
        errno = EINVAL;
        return -1;
    }

    uint8_t op = SB_OP_LIST;
    if (send_all(sockfd, &op, sizeof(op)) < 0) {
        return -1;
    }

    size_t off = 0;
    while (off < buflen - 1) {
        ssize_t n = recv(sockfd, buf + off, buflen - 1 - off, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) break;
        off += (size_t)n;
        if (buf[off - 1] == '\0') break;
    }

    if (off == 0) {
        if (buflen > 0) buf[0] = '\0';
        return 0;
    }

    buf[buflen - 1] = '\0';

    int count = 0;
    for (size_t i = 0; i < off && buf[i] != '\0'; ++i) {
        if (buf[i] == '\n') count++;
    }

    return count;
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
int sb_get(int sockfd, const char *filename) {
    if (sockfd < 0 || !filename) {
        errno = EINVAL;
        return -1;
    }

    size_t flen = strlen(filename) + 1;
    if (flen > MAX_FNAME_LEN) {
        errno = ENAMETOOLONG;
        return -1;
    }

    uint8_t op = SB_OP_GET;
    size_t msglen = 1 + flen;
    uint8_t *msg = malloc(msglen);
    if (!msg) return -1;
    msg[0] = op;
    memcpy(msg + 1, filename, flen);

    if (send_all(sockfd, msg, msglen) < 0) {
        free(msg);
        return -1;
    }
    free(msg);

    struct msghdr msgh;
    struct iovec iov;
    uint8_t status;
    char cmsgbuf[CMSG_SPACE(sizeof(int))];

    memset(&msgh, 0, sizeof(msgh));
    memset(cmsgbuf, 0, sizeof(cmsgbuf));

    iov.iov_base = &status;
    iov.iov_len = sizeof(status);
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    msgh.msg_control = cmsgbuf;
    msgh.msg_controllen = sizeof(cmsgbuf);

    ssize_t n = recvmsg(sockfd, &msgh, 0);
    if (n < 0) {
        return -1;
    }
    if (n == 0) {
        errno = ECONNRESET;
        return -1;
    }

    int received_fd = -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msgh);
    if (cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
        memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(int));
    }

    if (status != SB_OK || received_fd < 0) {
        if (received_fd >= 0) close(received_fd);
        errno = (status == SB_ERR_NOFILE) ? ENOENT : EIO;
        return -1;
    }

    return received_fd;
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
int sb_put(int sockfd, const char *filename, const char *filepath) {
    if (sockfd < 0 || !filename || !filepath) {
        errno = EINVAL;
        return -1;
    }

    size_t flen = strlen(filename) + 1;
    if (flen > MAX_FNAME_LEN) {
        errno = ENAMETOOLONG;
        return -1;
    }

    int fd = open(filepath, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }

    if (st.st_size < 0) {
        close(fd);
        errno = EINVAL;
        return -1;
    }

    uint32_t size = (uint32_t)st.st_size;
    uint8_t *buf = malloc(size);
    if (!buf && size > 0) {
        close(fd);
        return -1;
    }

    ssize_t rtotal = 0;
    while (rtotal < (ssize_t)size) {
        ssize_t n = read(fd, buf + rtotal, size - (size_t)rtotal);
        if (n < 0) {
            if (errno == EINTR) continue;
            free(buf);
            close(fd);
            return -1;
        }
        if (n == 0) break;
        rtotal += n;
    }
    close(fd);

    if ((uint32_t)rtotal != size) {
        free(buf);
        errno = EIO;
        return -1;
    }

    uint8_t op = SB_OP_PUT;
    uint32_t payload_size = size;

    /* mensaje: [op][nombre\0][uint32_t tamano][bytes] */
    size_t header_len = 1 + flen + sizeof(uint32_t);
    uint8_t *header = malloc(header_len);
    if (!header) {
        free(buf);
        return -1;
    }

    size_t off = 0;
    header[off++] = op;
    memcpy(header + off, filename, flen);
    off += flen;
    memcpy(header + off, &payload_size, sizeof(uint32_t));

    if (send_all(sockfd, header, header_len) < 0) {
        free(header);
        free(buf);
        return -1;
    }
    free(header);

    if (size > 0 && send_all(sockfd, buf, size) < 0) {
        free(buf);
        return -1;
    }
    free(buf);

    uint8_t resp;
    if (recv_all(sockfd, &resp, sizeof(resp)) < 0) {
        return -1;
    }

    if (resp != SB_OK) {
        errno = EIO;
        return -1;
    }

    return 0;
}

/*
 * sb_del()
 *
 * Elimina un archivo del safebox.
 *
 * Retorna: 0 si exito, -1 si el archivo no existe o hay error.
 */
int sb_del(int sockfd, const char *filename) {
    if (sockfd < 0 || !filename) {
        errno = EINVAL;
        return -1;
    }

    size_t flen = strlen(filename) + 1;
    if (flen > MAX_FNAME_LEN) {
        errno = ENAMETOOLONG;
        return -1;
    }

    uint8_t op = SB_OP_DEL;
    size_t msglen = 1 + flen;
    uint8_t *msg = malloc(msglen);
    if (!msg) return -1;

    msg[0] = op;
    memcpy(msg + 1, filename, flen);

    if (send_all(sockfd, msg, msglen) < 0) {
        free(msg);
        return -1;
    }
    free(msg);

    uint8_t resp;
    if (recv_all(sockfd, &resp, sizeof(resp)) < 0) {
        return -1;
    }

    if (resp != SB_OK) {
        errno = (resp == SB_ERR_NOFILE) ? ENOENT : EIO;
        return -1;
    }

    return 0;

}
