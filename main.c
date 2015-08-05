#include "server_eh.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <ev.h>

// see http_parser.h
// char DELETE = 0;
// char GET = 1;
// char HEAD = 2;
// char POST = 3;
// char PUT = 4;

void handle_request(struct http_request *request, int fd) {
    if (!strcmp("/", request->url))
	puts("ROOT");
    else if (!strcmp("/auth", request->url))
	puts("AUTH");
    write(fd, "HTTP/1.1 200 OK\r\n", 17);
    write(fd, "Server: Mikita\\Federation/0.1\r\n", 31);
    write(fd, "Connection: Close\r\n", 19);
    write(fd, "Content-Type: text/html; charset=iso-8859-1\r\n\r\n", 47);
    struct http_header *header = request->headers;
    write(fd, "<pre>Headers:\n", 14);
    while (header != NULL) {
        write(fd, header->name, strlen(header->name));
        write(fd, ": ", 2);
        write(fd, header->value, strlen(header->value));
        write(fd, "\n", 1);
        header = header->next;
    }
    if (request->flags & F_HREQ_KEEPALIVE) {
         write(fd, "\nis keepalive.\n", 16);
    }
    char *my_data = (char*) request->data;
    write(fd, "my string is ", 13);
    write(fd, my_data, strlen(my_data));
    write(fd, "\r\n\r\n", 4);
    close(fd);
}

static struct http_server server;

void sigint_handler(int s) {
    struct ev_loop *loop = server.loop;
    ev_io_stop(EV_A_ server.ev_accept);
    exit(0);
}

int main(int argc, char **argv) {
    // configure server structures and desired listen address
    struct sockaddr_in listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(8080);
    server.listen_addr = &listen_addr;
    server.handle_request = handle_request;
    server.data = "this is my string";

    // ignore SIGPIPE
    struct sigaction on_sigpipe;
    memset(&on_sigpipe, 0, sizeof(struct sigaction));
    on_sigpipe.sa_handler = SIG_IGN;
    sigemptyset(&on_sigpipe.sa_mask);
    sigaction(SIGPIPE, &on_sigpipe, NULL);

    // handle C-c
    struct sigaction on_sigint;
    memset(&on_sigint, 0, sizeof(struct sigaction));
    on_sigint.sa_handler = sigint_handler;
    sigemptyset(&on_sigint.sa_mask);
    on_sigint.sa_flags = 0;
    sigaction(SIGINT, &on_sigint, NULL);

    // start the server
    return http_server_loop(&server);
}
