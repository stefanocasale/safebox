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
    
}

/*
 * sb_bye()
 *
 * Cierra la sesion enviando SB_OP_BYE al daemon y cierra sockfd.
 */
void sb_bye(int sockfd) {

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

}

/*
 * sb_del()
 *
 * Elimina un archivo del safebox.
 *
 * Retorna: 0 si exito, -1 si el archivo no existe o hay error.
 */
int sb_del(int sockfd, const char *filename) {


}
