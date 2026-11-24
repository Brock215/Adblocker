#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

int main(void){
    // Needed for Windows sockets
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);

    // setup for binding 
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);         
    addr.sin_family = AF_INET;
    addr.sin_port = htons(15353);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (bind(s, (struct sockaddr *)&addr, sizeof addr) == SOCKET_ERROR) {    
        printf("bind failed: %d\n", WSAGetLastError());
        return 1;
    }

    
    char buf[4096];
    char ipstr[INET_ADDRSTRLEN];
    struct sockaddr_in client;

    while (1)
    {
        int client_len = sizeof client;
        int n = recvfrom(s, buf, sizeof buf, 0, (struct sockaddr *)&client, &client_len);
        if (n == SOCKET_ERROR) {
            printf("recvfrom failed: %d\n", WSAGetLastError());
            continue;
        }
        inet_ntop(AF_INET, &client.sin_addr, ipstr, sizeof ipstr);
        printf("received %d bytes from %s:%d\n", n, ipstr, ntohs(client.sin_port));
    }

    return 0;
}