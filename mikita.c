#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <ev.h>

#include "server_eh.h"
#include "sha256.h"

#define PORT 8080

void rand_str(char *dest, size_t length) {
    char charset[] = "0123456789!@#$%^&*()_\\[]{}:\"+<>?/`~"
                     "abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    while (length-- > 0) {
        size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
        *dest++ = charset[index];
    }
    *dest = '\0';
}

void headers(int resp_code, int fd) {
    SHA256_CTX ctx;
    unsigned char hash[32];
    char sessstr[16];

    switch (resp_code) {
      case 200:
          write(fd, "HTTP/1.1 200 OK\r\n", 17);
          break;

      case 404:
          write(fd, "HTTP/1.1 404 Not Found\r\n", 24);
          break;
    }
    write(fd, "Server: Mikita/0.1 (Federation)\r\n", 33);
    write(fd, "X-Session: ", 11);

    rand_str(sessstr, 16);

    sha256_init(&ctx);
    sha256_update(&ctx, (unsigned char *)sessstr, 16);
    sha256_final(&ctx, hash);

    int idx;
    char hash2[64];
    for (idx=0; idx<32; ++idx)
        sprintf(&hash2[idx*2], "%02x", (unsigned int)hash[idx]);

    write(fd, hash2, 64);
    write(fd, "\r\n", 2);
    write(fd, "Content-Type: application/json; charset=utf-8\r\n\r\n", 49);
}

void handle_request(struct http_request *request, int fd) {
    if (!request->url)
        goto disconn;

    if (!strcmp("/", request->url)) {
	puts("ROOT");
        headers(200, fd);
        write(fd, "{\n\t\"status\":\"online\"\n}", 22);
        write(fd, "\r\n\r\n", 4);

    } else if (!strcmp("/authorize", request->url)) {
	puts("AUTH");
        headers(200, fd);
        write(fd, "{\n\t\"status\":\"expecting parameters\"\n}", 36);
        write(fd, "\r\n\r\n", 4);

    } else {
        puts("404");
        headers(404, fd);
        write(fd, "{\n\t\"status\":\"not found\"\n}", 25);
        write(fd, "\r\n\r\n", 4);
    }

    struct http_header *header = request->headers;
    //write(fd, "<pre>Headers:\n", 14);
    while (header != NULL) {
        /*write(fd, header->name, strlen(header->name));
        write(fd, ": ", 2);
        write(fd, header->value, strlen(header->value));
        write(fd, "\n", 1);*/
	printf("%s: %s\n", header->name, header->value);
        header = header->next;
    }
    if (request->flags & F_HREQ_KEEPALIVE) {
         //write(fd, "\nis keepalive.\n", 16);
	puts("KEEP ALIVE");
    }
    /*char *my_data = (char*) request->data;
    write(fd, "my string is ", 13);
    write(fd, my_data, strlen(my_data));*/
    //write(fd, "{\n\t\"status\":\"online\"\n}", 22);
    //write(fd, "\r\n\r\n", 4);

disconn:
    close(fd);
}

static struct http_server server;

void sigint_handler(int s) {
    struct ev_loop *loop = server.loop;
    ev_io_stop(EV_A_ server.ev_accept);
    exit(0);
}

int main(int argc, char *argv[]) {
    // configure server structures and desired listen address
    struct sockaddr_in listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));

    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(PORT);

    server.listen_addr = &listen_addr;
    server.handle_request = &handle_request;
    //server.data = "this is my string";

    // ignore SIGPIPE
    struct sigaction on_sigpipe;
    memset(&on_sigpipe, 0, sizeof(struct sigaction));
    on_sigpipe.sa_handler = SIG_IGN;
    sigemptyset(&on_sigpipe.sa_mask);
    sigaction(SIGPIPE, &on_sigpipe, NULL);

    // handle SIGINT
    struct sigaction on_sigint;
    memset(&on_sigint, 0, sizeof(struct sigaction));
    on_sigint.sa_handler = &sigint_handler;
    sigemptyset(&on_sigint.sa_mask);
    on_sigint.sa_flags = 0;
    sigaction(SIGINT, &on_sigint, NULL);

    // start the server
    return http_server_loop(&server);
}
