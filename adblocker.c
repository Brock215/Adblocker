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

void receive(SOCKET listener_socket, char *buffer, int buffer_size){
    struct sockaddr_in client_addr; //Holds the address of the client that sent the data
    char ipstr[INET_ADDRSTRLEN];    //Holds the client's IP as text
    unsigned char reply[4096 + 16]; //Room for a full-size query plus the 16 byte answer

    while (1)
    {
        int addr_len = sizeof(client_addr); //Reset every time, recvfrom overwrites it.
        int n = recvfrom(listener_socket, buffer, buffer_size, 0, (struct sockaddr *)&client_addr, &addr_len);
        if (n == SOCKET_ERROR) {
            printf("recvfrom failed: %d\n", WSAGetLastError());
            continue;
        }
        inet_ntop(AF_INET, &client_addr.sin_addr, ipstr, sizeof ipstr);
        printf("received %d bytes from %s:%d\n", n, ipstr, ntohs(client_addr.sin_port));
        
        // no point allocating these if function fails early 
        char name[256];
        unsigned short qtype;
        int qend;
        if (parse_question((const unsigned char *)buffer, n, name, sizeof name, &qtype, &qend) < 0) {
            printf("malformed packet\n");
            continue;
        }
        printf("question: %s type=%u qend=%d\n", name, qtype, qend);
        int reply_len = build_reply((const unsigned char *)buffer, qend, qtype, reply);
        if (sendto(listener_socket, (const char *)reply, reply_len, 0,
            (struct sockaddr *)&client_addr, addr_len) == SOCKET_ERROR) {
                printf("sendto failed: %d\n", WSAGetLastError());
        }
    }
}

int parse_question(const unsigned char *pkt, int len, char *name, size_t name_cap,
                   unsigned short *qtype, int *qend){
    if (name_cap == 0) return -1; //No room to write anything
    if (len < 12) return -1; //Too short to even hold a header
    if (((pkt[4] << 8) | pkt[5]) != 1) return -1; //Expect exactly one question

    int pos = 12; //The question starts right after the 12 byte header.
    size_t out = 0; //How many characters we have written to name so far.

    while (1) {
        if (pos >= len) return -1; //Ran off the end before finding the zero byte

        int label_len = pkt[pos++]; //First byte of each label is its length
        if (label_len == 0) break; //A zero length means the name is finished
        if (label_len & 0xC0) return -1; //Compression pointer or reserved bits, treat as malformed
        if (pos + label_len > len) return -1; //Label claims more bytes than the packet has
        if (out + label_len + 2 > name_cap) return -1; //Label, a possible '.', and the '\0' must fit

        if (out > 0) name[out++] = '.'; //Separate labels with a dot
        memcpy(name + out, pkt + pos, label_len); //Copy the label's characters
        out += label_len;
        pos += label_len;
    }

    name[out] = '\0'; //Terminate the string.

    if (pos + 4 > len) return -1; //Still need 2 bytes of type and 2 bytes of class

    *qtype = (pkt[pos] << 8) | pkt[pos + 1]; //Query type, big-endian 
    *qend = pos + 4; //Offset just past the question (skips type and class)

    return 0;
}

int build_reply(const unsigned char *query, int qend, unsigned short qtype, unsigned char *reply){
    //The answer record for a blocked domain, always 16 bytes
    static const unsigned char answer[16] = {
        0xC0, 0x0C,             //name: pointer back to offset 12, where the question's name starts
        0x00, 0x01,             //type A.
        0x00, 0x01,             //class IN.
        0x00, 0x00, 0x00, 0x3C, //TTL of 60 seconds.
        0x00, 0x04,             //data length, 4 bytes.
        0x00, 0x00, 0x00, 0x00  //the address, 0.0.0.0.
    };

    memcpy(reply, query, qend); //Copy the header and question, this keeps the transaction ID
    reply[2] = 0x80 | (query[2] & 0x79); // keep the opcode and RD bits from the query
    reply[3] = 0x80; //RA=1 recursion, RCODE=0 .
    memset(reply + 6, 0, 6); //Zero ANCOUNT, NSCOUNT and ARCOUNT, so we don't claim records that aren't there

    int len = qend; //Reply length so far.

    if (qtype == 1) { //Only A queries get an answer, anything else gets a valid empty reply
        reply[7] = 1; //ANCOUNT = 1.
        memcpy(reply + len, answer, sizeof answer);
        len += sizeof answer;
    }

    return len; //Total bytes to send.
}