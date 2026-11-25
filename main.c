#include "adblocker.h"
#include <stdio.h>
#include <string.h>


int main(void){
    //Needed for Windows
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    int count = 0;
    int r = read_blocklist("blocklist.txt");
    if (r < 0) printf("No blocklist.txt, skipping\n"); else count = r;
    r = read_blocklist("hosts.txt");
    if (r < 0) printf("No hosts.txt, skipping\n"); else count = r;
    printf("Loaded %d blocked domains\n", count);

    //Socket that listens for DNS queries on localhost.
    SOCKET s = create_listener_socket("53");
    printf("Listening for DNS queries on 127.0.0.1:53\n");

    //Socket used to forward allowed queries to the real DNS server.
    SOCKET up = create_upstream_socket();
    if (up == INVALID_SOCKET) {
        printf("Could not create upstream socket\n");
        return 1;
    }

    char buf[4096];
    receive(s, up, buf, sizeof(buf)); //Loops forever

    return 0;
}