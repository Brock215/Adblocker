#include "adblocker.h"
#include <stdio.h>
#include <string.h>


int main(void){
    int count = read_blocklist("blocklist.txt");
    if (count < 0) {
        printf("Could not open blocklist.txt\n");
        return 1;
    }
    printf("Loaded %d blocked domains\n", count);
    


    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    SOCKET s = create_listener_socket("15353");

    char buf[4096];
    receive(s, buf, sizeof(buf));  

    return 0;
}