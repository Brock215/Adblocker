#ifndef ADBLOCKER_H
#define ADBLOCKER_H

#include <winsock2.h>

SOCKET create_listener_socket(const char *port);

void receive(SOCKET listener_socket, char *buffer, int buffer_size);
//Parse a DNS question from a packet. Returns 0 on success, -1 on failure.
int parse_question(const unsigned char *pkt, int len, char *name, size_t name_cap,
                   unsigned short *qtype, int *qend);

int build_reply(const unsigned char *query, int qend, unsigned short qtype, unsigned char *reply);

#endif