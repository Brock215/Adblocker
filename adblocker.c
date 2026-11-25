#include <winsock2.h>
#include "adblocker.h"
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DOMAIN 256 //Longest domain to store
#define TABLE_SIZE 262144 //Number of buckets, a power of two so we can use & instead of %.

typedef struct entry { //One blocked domain in a bucket's linked list.
    char *domain;
    struct entry *next;
} entry_t;

static struct sockaddr_in upstream_addr; //Address of the real DNS server we forward to
static entry_t *table[TABLE_SIZE]; //Each slot starts a list of the domains that hashed to it.
static int blocklist_count = 0; //How many are loaded so far



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

void receive(SOCKET listener_socket, SOCKET upstream_socket, char *buffer, int buffer_size){
    struct sockaddr_in client_addr; //Holds the address of the client that sent the data
    char ipstr[INET_ADDRSTRLEN];    //Holds the client's IP as text
    unsigned char reply[4096 + 16]; //Room for a full-size query plus the 16 byte answer
    char response[4096]; //Holds the upstream server's answer.

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
        if (is_blocked(name)) {
            printf("BLOCKED\n");
            int reply_len = build_reply((const unsigned char *)buffer, qend, qtype, reply);
            if (sendto(listener_socket, (const char *)reply, reply_len, 0,
                    (struct sockaddr *)&client_addr, addr_len) == SOCKET_ERROR) {
                printf("sendto failed: %d\n", WSAGetLastError());
            }
        } else {
            int rn = forward_query(upstream_socket, buffer, n, response, sizeof response);
            if (rn < 0) {
                printf("allowed, but upstream failed\n");
                continue;
            }
            printf("allowed (forwarded, %d byte reply)\n", rn);
            if (sendto(listener_socket, response, rn, 0,
                    (struct sockaddr *)&client_addr, addr_len) == SOCKET_ERROR) {
                printf("sendto failed: %d\n", WSAGetLastError());
            }
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

    memcpy(reply, query, qend); 
    reply[2] = 0x80 | (query[2] & 0x79); 
    reply[3] = 0x80; 
    memset(reply + 6, 0, 6); //Zero ANCOUNT, NSCOUNT and ARCOUNT, so we don't claim records that aren't there

    int len = qend; //Reply length so far.

    if (qtype == 1) { //Only A queries get an answer, anything else gets a valid empty reply
        reply[7] = 1; //ANCOUNT = 1.
        memcpy(reply + len, answer, sizeof answer);
        len += sizeof answer;
    }

    return len; //Total bytes to send
}

int read_blocklist(const char *path){
    FILE *f = fopen(path, "r");
    if (f == NULL) return -1; //Couldn't open the file.

    char line[512];
    while (fgets(line, sizeof line, f) != NULL) {
        //No newline and not at the end of the file means the line was too long for the buffer, so skip the rest of it.
        if (strchr(line, '\n') == NULL && !feof(f)) {
            int c;
            while ((c = fgetc(f)) != '\n' && c != EOF) {}
            continue;
        }

        char *hash = strchr(line, '#'); //Cut off any comment.
        if (hash != NULL) *hash = '\0';

        size_t len = strlen(line);
        while (len > 0 && isspace((unsigned char)line[len - 1])) { //Strip trailing spaces, '\n' and '\r'.
            line[--len] = '\0';
        }
        if (len > 0 && line[len - 1] == '.') line[--len] = '\0'; //Strip a trailing dot, "example.com." is the same name.

        char *start = line + len; //Hosts lines look like "0.0.0.0 domain", so take the last word on the line.
        while (start > line && !isspace((unsigned char)start[-1])) start--;

        if (*start == '\0') continue; //Empty line or comment only.
        if (strchr(start, '.') == NULL) continue; //No dot means "localhost", "broadcasthost" and so on.
        if (strcmp(start, "0.0.0.0") == 0) continue; //The list has a "0.0.0.0 0.0.0.0" line.
        if (strlen(start) >= MAX_DOMAIN) continue; //Too long to be a real domain.

        for (char *p = start; *p != '\0'; p++) { //DNS names are case-insensitive, store lowercase.
            *p = (char)tolower((unsigned char)*p);
        }

        table_add(start); //Adds it to the hash table, duplicates are ignored.
    }

    fclose(f);
    return blocklist_count; //Running total across every file loaded so far.
}


int is_blocked(const char *name){
    char lower[MAX_DOMAIN]; //A lowercase copy, so we don't change the caller's string.
    size_t len = strlen(name);
    if (len >= sizeof lower) return 0; //Too long to be in our list anyway.

    for (size_t i = 0; i < len; i++) { //DNS names are case-insensitive, compare in lowercase.
        lower[i] = (char)tolower((unsigned char)name[i]);
    }
    lower[len] = '\0';

    const char *p = lower; //Start with the full name, "ads.doubleclick.net".
    while (p != NULL) {
        if (table_contains(p)) return 1; //Exact match on this part of the name.
        p = strchr(p, '.'); //Jump to the next dot...
        if (p != NULL) p++; //...and step past it, giving "doubleclick.net", then "net".
    }
    return 0; //No part of the name was on the list.
}

unsigned int hash_str(const char *s){ //djb2, a simple string hash.
    unsigned int h = 5381;
    while (*s) h = h * 33 + (unsigned char)*s++;
    return h & (TABLE_SIZE - 1); //Keep the result inside the table.
}

int table_contains(const char *domain){
    for (entry_t *e = table[hash_str(domain)]; e != NULL; e = e->next) {
        if (strcmp(e->domain, domain) == 0) return 1;
    }
    return 0;
}

void table_add(const char *domain){
    if (table_contains(domain)) return; //Lists often repeat domains.
    entry_t *e = malloc(sizeof *e);
    char *copy = strdup(domain);
    if (e == NULL || copy == NULL) { printf("out of memory\n"); exit(1); }
    unsigned int h = hash_str(domain);
    e->domain = copy;
    e->next = table[h]; //Insert at the front of this bucket's list.
    table[h] = e;
    blocklist_count++;
}

SOCKET create_upstream_socket(void){
    SOCKET up = socket(AF_INET, SOCK_DGRAM, 0);
    if (up == INVALID_SOCKET) {
        printf("socket failed: %d\n", WSAGetLastError());

        return INVALID_SOCKET;
    }

    memset(&upstream_addr, 0, sizeof upstream_addr);
    upstream_addr.sin_family = AF_INET;
    upstream_addr.sin_port = htons(53);
    inet_pton(AF_INET, "1.1.1.1", &upstream_addr.sin_addr);

    DWORD timeout = 3000; //On Windows this option takes milliseconds as a DWORD, not a timeval.
    if (setsockopt(up, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof timeout) == SOCKET_ERROR) {
        printf("setsockopt failed: %d\n", WSAGetLastError());
        closesocket(up);
        return INVALID_SOCKET;
    }
    return up;
}

int forward_query(SOCKET up, const char *query, int qlen, char *response, int response_cap){
    if (sendto(up, query, qlen, 0, (struct sockaddr *)&upstream_addr, sizeof upstream_addr) == SOCKET_ERROR) {
        return -1; //Couldn't send.
    }

    while (1) {
        int n = recvfrom(up, response, response_cap, 0, NULL, NULL);
        if (n == SOCKET_ERROR) return -1; //Timed out or failed.

        //Only accept a reply whose transaction ID matches our query.
        if (n >= 2 && response[0] == query[0] && response[1] == query[1]) return n;
        //Otherwise it's a late reply to an older query, ignore it and keep waiting.
    }
}