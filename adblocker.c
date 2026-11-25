#include <winsock2.h>
#include "adblocker.h"
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

SOCKET create_listener_socket(const char *port){
    struct addrinfo socket_settings; //settings for the socket we want
    struct addrinfo *results, *curr_addr; //result list and current item in loop request
    SOCKET listener_socket; //Holds the listener socket handle 
    int enable = 1; //Used for setting socket options

    //Initialize the socket_settings to 0.
    memset(&socket_settings, 0, sizeof socket_settings);
    socket_settings.ai_family = AF_INET; //IPv4 only
    socket_settings.ai_socktype = SOCK_DGRAM; //Request a UDP socket

    //Get a UDP socket address on localhost only, so other machines on the network can't reach it.
    int address_result = getaddrinfo("127.0.0.1", port, &socket_settings, &results);
    //If there is an error exit the code and return a message.
    if(address_result != 0) {
        fprintf(stderr, "getaddrinfo failed: %d\n", address_result);
        exit(1);
    }

    //Try every addresss returned by getaddrinfo() and attempt to create a socket,
    //set socket options and bind it to th local IP and port.
    for(curr_addr = results; curr_addr != NULL; curr_addr = curr_addr->ai_next){
        //Create the new socket using the setting from addrinfo struct, IPv4, UDP and protocol=0. 
        listener_socket = socket(curr_addr->ai_family, curr_addr->ai_socktype, curr_addr->ai_protocol);

        if(listener_socket == INVALID_SOCKET) {  //If creation fails move to the next address.
            continue; //failed to create a socket, try the next one.
        }

        //Windows version of the port option: stops another program from binding the same port as us.
        if(setsockopt(listener_socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&enable, sizeof(int)) == SOCKET_ERROR) {
            fprintf(stderr, "setsockopt failed: %d\n", WSAGetLastError());
            closesocket(listener_socket);
            continue;
        }

        //binding the socket to a specific local IP and port and making sure it succesful.
        if(bind(listener_socket, curr_addr->ai_addr, (int)curr_addr->ai_addrlen) == 0){
            break; 
        }
        //If binding fails close the socket and try next address option.
        closesocket(listener_socket);
    }

    //free up the address info memory.
    freeaddrinfo(results);

    //If all options have been tried and didnt bind exit with an error.
    if(curr_addr == NULL){
        fprintf(stderr, "Failed to bind to port %s: %d\n", port, WSAGetLastError());
        exit(1);
    }

    //Successfully created and bound 
    return listener_socket;
}