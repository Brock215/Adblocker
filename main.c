#include "adblocker.h"
#include <stdio.h>
#include <string.h>


int main(void){
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    SOCKET s = create_listener_socket("15353");

    char buf[4096];
    receive(s, buf, sizeof(buf));  

    return 0;
}