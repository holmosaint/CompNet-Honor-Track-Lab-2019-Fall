#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <algorithm>
#include "socket.hpp"
#include "ip.hpp"
#include "tools.hpp"

pthread_mutex_t socket_dc_pool_mutex;
socket_dc socket_dc_pool[SOCKETDCSTART + MAXSOCKETNUM + 1];

int lookupSocketDc() {
    int ret = -1;
    pthread_mutex_lock(&socket_dc_pool_mutex);

    for(int i = SOCKETDCSTART; i < SOCKETDCSTART + MAXSOCKETNUM; ++i) {
        if(!socket_dc_pool[i].busy) {
            socket_dc_pool[i].busy = true;
            ret = i;
            break;
        }
    }

    pthread_mutex_unlock(&socket_dc_pool_mutex);
    return ret;
}

/*
* Initialization of sockets
*/
void initSocketPool() {
    memset(socket_dc_pool, 0, sizeof(socket_dc_pool));
    pthread_mutex_init(&socket_dc_pool_mutex, 0);
      
    for(int i = 0; i < SOCKETDCSTART + MAXSOCKETNUM; ++i) {
        pthread_mutex_init(&socket_dc_pool[i].msg_mutex, 0);
        pthread_mutex_init(&socket_dc_pool[i].pkt_mutex, 0);
    }
}

/*
* Release of sockets
*/
void releaseSocket() {
    pthread_mutex_destroy(&socket_dc_pool_mutex);
      
    for(int i = 0; i < SOCKETDCSTART + MAXSOCKETNUM; ++i) {
        pthread_mutex_destroy(&socket_dc_pool[i].msg_mutex);
        pthread_mutex_destroy(&socket_dc_pool[i].pkt_mutex);
    }
}


/**
* @see [POSIX.1-2017:socket](http://pubs.opengroup.org/onlinepubs/
* 9699919799/functions/socket.html)
* @domain
*     The address domain requested, either AF_INET, AF_INET6, AF_UNIX, or AF_RAW.
* @type
*     The type of socket created, either SOCK_STREAM, SOCK_DGRAM, or SOCK_RAW.
* @protocol
*     The protocol requested. Some possible values are 0, IPPROTO_UDP, or IPPROTO_TCP.
* @Return
      The socket descriptor
*/
int __wrap_socket(int domain, int type, int protocol) {
    if((protocol != 0) && (protocol != IPPROTO_TCP)) {
        printf("The protocol should be in [0, IPPROTO_TCP]\n");
        return -1;
    }

    // Default protocol
    if(protocol == 0) {
        protocol = IPPROTO_TCP;
    }

    if(domain != AF_INET) {
        printf("Current socket API only supports IPv4!\n");
        return -1;
    }

    if(type != SOCK_STREAM) {
        printf("Current socket API only supports stream transmission!\n");
        return -1;
    }

    int socket_id;
    socket_id = lookupSocketDc();
    if(socket_id < 0) {
        printf("The number of socket descriptor has reach the upper limitation!\n");
        return -1;
    }

    socket_dc_pool[socket_id].domain = domain;
    socket_dc_pool[socket_id].type = type;
    socket_dc_pool[socket_id].protocol = protocol;
    socket_dc_pool[socket_id].src_ip.s_addr = 0;
    socket_dc_pool[socket_id].src_port = -1;
    memset(socket_dc_pool[socket_id].msg_buf, 0, sizeof(socket_dc_pool[socket_id].msg_buf));
    socket_dc_pool[socket_id].msg_start = 0;
    socket_dc_pool[socket_id].msg_end = 0;
    socket_dc_pool[socket_id].msg_full = false;
    memset(socket_dc_pool[socket_id].pkt_buf, 0, sizeof(socket_dc_pool[socket_id].pkt_buf));
    socket_dc_pool[socket_id].pkt_start = 0;
    socket_dc_pool[socket_id].pkt_end = 0;
    socket_dc_pool[socket_id].pkt_full = false;

    return socket_id;
}

// get sockaddr, IPv4 or IPv6:
in_addr get_in_addr(const struct sockaddr *sa) {
    return ((const struct sockaddr_in*)sa)->sin_addr;
}

// get port number
in_port_t get_port_addr(const struct sockaddr *sa) {
    return ((const struct sockaddr_in *)sa)->sin_port;
}

/**
* @see [POSIX.1-2017:bind](http://pubs.opengroup.org/onlinepubs/
* 9699919799/functions/bind.html)
* @socket
*     The socket descriptor returned by a previous socket() call.
* @address
*     The pointer to a sockaddr structure containing the name that is to be bound to socket. 
* @address_len
*     The size of address in bytes.
* @Return
*     0 if successful; -1 if not
*/
int __wrap_bind(int socket, const struct sockaddr *address, socklen_t address_len) {
    socket_dc_pool[socket].src_port = get_port_addr(address);
    socket_dc_pool[socket].src_ip = get_in_addr(address);

    return 0;
}

/*
* @Return
*       0 if successful; -1 if not
*/
int sendTCPPacket(int socket, int data_offset, int packet_type, int window, const void *buf, int len) {
    in_port_t src_port, dest_port;
    in_addr src_ip, dest_ip;
    tcphdr tcp_header;

    src_port = socket_dc_pool[socket].src_port;
    src_ip = socket_dc_pool[socket].src_ip;
    dest_port = socket_dc_pool[socket].dest_port;
    dest_ip = socket_dc_pool[socket].dest_ip;

    tcp_header.th_sport = src_port;
    tcp_header.th_dport = dest_port;
    tcp_header.th_seq = socket_dc_pool[socket].th_seq;
    tcp_header.th_ack = socket_dc_pool[socket].th_ack;
    tcp_header.th_flags = (uint8_t)packet_type;
    tcp_header.th_win = window;
    tcp_header.th_off = data_offset;
    // tcp_header.th_sum
    // tcp_header.th_urp

    char data[MAXMSGLENGTH];
    ((uint32_t *)data)[0] = NORMAL;
    memcpy((char *)data + 4, (char *)&tcp_header, sizeof(tcphdr));
    memcpy((char *)data + 4 + sizeof(tcphdr), (char *)buf, len);

    return sendIPPacket(src_ip, dest_ip, 6, (const void *)data, len + sizeof(tcphdr) + 4);
}

/**
* @brief Process an TCP packet upon receiving it.
*
* @param buf Pointer to the packet.
* @param len Length of the packet.
* @return 0 on success, -1 on error.
* @see addDevice
*/
int TCPReceiveHandler(const void* buf, int len, in_addr src_ip) {
    tcphdr tcp_header;
    memcpy(&tcp_header, buf, sizeof(tcphdr));

    // printf("[DEBUG]\n");
    /* printTCPHeader(&tcp_header);
    printf("\n"); */
    // printf("Payload in receive: %s\n", (char *)buf + sizeof(tcphdr));

    // Check the dest port number, and put the message into the right packet buffer
    int socket = -1;
    in_port_t src_port, dest_port;
    src_port = tcp_header.th_sport;
    dest_port = tcp_header.th_dport;

    pthread_mutex_lock(&socket_dc_pool_mutex);
    for(int i = SOCKETDCSTART; i < SOCKETDCSTART + MAXSOCKETNUM; ++i) {
        if(!socket_dc_pool[i].busy) {
            continue;
        }
        if(socket_dc_pool[i].setup && (socket_dc_pool[i].src_port == dest_port) && (socket_dc_pool[i].dest_port == src_port)) {
            socket = i;
            break;
        }
        else if((!socket_dc_pool[i].setup) && (socket_dc_pool[i].src_port == dest_port)) {
            socket = i;
            // No break here!
        }
    }
    pthread_mutex_unlock(&socket_dc_pool_mutex);

    if(socket < 0) {
        printf("Not found socket open at port %d\n", dest_port);
        return -1;
    }

    // copy packet
    pthread_mutex_lock(&socket_dc_pool[socket].pkt_mutex);
    // printf("[DEBUG] pkt start: %d, pkt end: %d\n", socket_dc_pool[socket].pkt_start, socket_dc_pool[socket].pkt_end);
    
    if(socket_dc_pool[socket].pkt_full) {
        printf("Packet buffer is full at port %d, discard the packet automatically!\n", dest_port);
        pthread_mutex_unlock(&socket_dc_pool[socket].pkt_mutex);
        return -1;
    }

    memcpy(socket_dc_pool[socket].pkt_buf[socket_dc_pool[socket].pkt_end], buf, len);
    socket_dc_pool[socket].pkt_ip_buf[socket_dc_pool[socket].pkt_end] = src_ip;

    // update pointer
    socket_dc_pool[socket].pkt_end = (socket_dc_pool[socket].pkt_end + 1) % MAXPACKETNUM;
    if(socket_dc_pool[socket].pkt_end == socket_dc_pool[socket].pkt_start) {
        socket_dc_pool[socket].pkt_full = true;
    }
    
    pthread_mutex_unlock(&socket_dc_pool[socket].pkt_mutex);

    return 0;
}

/*
* Verify whether ACK has been received
* 
*/
int waitPacket(int socket, int type) {
    int packet_start, packet_end;
    tcphdr tcp_header;
    bool is_break = false;

    // Waiting for SYN packet
    while(!is_break) {
        pthread_mutex_lock(&socket_dc_pool[socket].pkt_mutex);

        packet_start = socket_dc_pool[socket].pkt_start;
        packet_end = socket_dc_pool[socket].pkt_end;

        while((packet_start != packet_end) || (socket_dc_pool[socket].pkt_full)) {
            memcpy(&tcp_header, socket_dc_pool[socket].pkt_buf[packet_start], sizeof(tcphdr));

            if((tcp_header.th_flags & type) == type) {
                is_break = true;

                // set up connection
                if(type == TH_SYN) {
                    socket_dc_pool[socket].dest_port = tcp_header.th_sport;
                    socket_dc_pool[socket].dest_ip = socket_dc_pool[socket].pkt_ip_buf[packet_start];
                }

            }

            // Update pointer
            socket_dc_pool[socket].pkt_start = (socket_dc_pool[socket].pkt_start + 1) % MAXPACKETNUM;
            packet_start = socket_dc_pool[socket].pkt_start;
            socket_dc_pool[socket].pkt_full = false;

            if(is_break)
                break;
        }

        pthread_mutex_unlock(&socket_dc_pool[socket].pkt_mutex);
        
        if(is_break)
            break;

        sleep(1);        
    }

    return 0;
}

/**
* @see [POSIX.1-2017:listen](http://pubs.opengroup.org/onlinepubs/
* 9699919799/functions/listen.html)
* @socket
*     The socket descriptor.
* @backlog
*     Defines the maximum length for the queue of pending connections.
* @Return
      0 if successful, otherwise negative
*/
int __wrap_listen(int socket, int backlog) {
    return waitPacket(socket, TH_SYN);
}


/**
* @see [POSIX.1-2017:accept](http://pubs.opengroup.org/onlinepubs/
* 9699919799/functions/accept.html)
* @socket
*     The socket descriptor.
* @address
*     The socket address of the connecting client that is filled in by accept() before it returns. 
*     The format of address is determined by the domain that the client resides in. 
*     This parameter can be NULL if the caller is not interested in the client address.
* @address_len
*     Must initially point to an integer that contains the size in bytes of the storage 
* pointed to by address. On return, that integer contains the size required to represent 
* the address of the connecting socket. If this value is larger than the size supplied on input, 
* then the information contained in sockaddr is truncated to the length supplied on input. 
* If address is NULL, address_len is ignored.
*/
int __wrap_accept(int socket, struct sockaddr *address, socklen_t *address_len) {
    in_addr src_ip, dest_ip;
    in_port_t src_port, dest_port;
    src_ip = socket_dc_pool[socket].src_ip;
    dest_ip = socket_dc_pool[socket].dest_ip;
    src_port = socket_dc_pool[socket].src_port;
    dest_port = socket_dc_pool[socket].dest_port;

    // Send ACK packet
    // TODO: verify how SYN/ACK are calculated

    char buf[10];
    memset(buf, 0, sizeof(buf));
    if(sendTCPPacket(socket, 0, TH_ACK, 1, buf, 0) < 0) {
        printf("Error in sending the TCP packet!\n");
        return -1;
    }

    // Waiting for ACK back
    if(waitPacket(socket, TH_ACK) < 0) {
        printf("Error waiting for ACK package back!\n");
        return -1;
    }

    // Writing to the address field
    sockaddr_in name;
    name.sin_family = AF_INET;
    name.sin_addr = dest_ip;
    name.sin_port = dest_port;

    if(address != NULL) {
        *address = *(sockaddr *)&name;
    }

    if (address_len != NULL) {
        *address_len = sizeof(name);
    }

    return 0;
}

/**
* @see [POSIX.1-2017:connect](http://pubs.opengroup.org/onlinepubs/
* 9699919799/functions/connect.html)
* @socket
*     The socket descriptor.
* @address
*     The pointer to a socket address structure containing the address of the socket to which a connection will be attempted.
* @address_len
*     The size of the socket address pointed to by address in bytes.
* @Return 
*     0 if successful, negative otherwise
*/
int __wrap_connect(int socket, const struct sockaddr *address, socklen_t address_len) {
    char buf[10];
    memset(buf, 0, sizeof(buf));

    sockaddr_in addr_in;
    addr_in = *(sockaddr_in *)address;

    in_port_t dest_port;
    in_addr dest_ip;
    dest_ip = addr_in.sin_addr;
    dest_port = addr_in.sin_port;

    // Set up connection
    socket_dc_pool[socket].dest_ip = dest_ip;
    socket_dc_pool[socket].dest_port = dest_port; 

    if(sendTCPPacket(socket, 0, TH_SYN, 1, buf, 0) < 0) {
        printf("Error in connection sending SYN packet!\n");
        return -1;
    }

    if(waitPacket(socket, TH_ACK)) {
        printf("Error in connection waiting ACK packet!\n");
        return -1;
    }

    if(sendTCPPacket(socket, 0, TH_ACK, 1, buf, 0) < 0) {
        printf("Error in connection sending ACK packet!\n");
        return -1;
    }

    return 0;
}

/**
* @see [POSIX.1-2017:read](http://pubs.opengroup.org/onlinepubs/
* 9699919799/functions/read.html)
* @fs
*     The file or socket descriptor.
* @buf
*     The pointer to the buffer that receives the data.
* @N
*     The length in bytes of the buffer pointed to by the buf parameter.
*/
ssize_t __wrap_read(int fildes, void *buf, size_t nbyte) {
    // Fallback to linux library function
    if(fildes < SOCKETDCSTART) {
        return read(fildes, buf, nbyte);
    }

    // Each time calling this function, move the data in the packet buffer to message buffer
    int packet_start, packet_end;
    int msg_start, msg_end;
    int empty_size;
    tcphdr tcp_header;
    bool is_break = false;
    int cnt = 0;
    char tmp_buf[MAXMSGSIZE];

    // Get the current msg buffer size
    pthread_mutex_lock(&socket_dc_pool[fildes].msg_mutex);

    msg_start = socket_dc_pool[fildes].msg_start;
    msg_end = socket_dc_pool[fildes].msg_end;
    empty_size = MAXMSGSIZE - ((msg_end - msg_start + MAXMSGSIZE) % MAXMSGSIZE);
    if((empty_size == MAXMSGSIZE) && socket_dc_pool[fildes].msg_full)
        empty_size = 0;

    pthread_mutex_unlock(&socket_dc_pool[fildes].msg_mutex);

    // printf("[DEBUG] empty size: %d\n", empty_size);

    // Copy packet to tmp msg buffer
    pthread_mutex_lock(&socket_dc_pool[fildes].pkt_mutex);

    packet_start = socket_dc_pool[fildes].pkt_start;
    packet_end = socket_dc_pool[fildes].pkt_end;
    // printf("[DEBUG] Pakcet start: %d, packet end: %d\n", packet_start, packet_end);

    while((packet_start != packet_end) || (socket_dc_pool[fildes].pkt_full)) {
        if(cnt + MAXMSGLENGTH >= empty_size)
            break;

        // Copy data
        int payload_size = strlen(socket_dc_pool[fildes].pkt_buf[packet_start] + sizeof(tcphdr));
        memcpy(&tcp_header, socket_dc_pool[fildes].pkt_buf[packet_start], sizeof(tcphdr));
        memcpy(tmp_buf + cnt, socket_dc_pool[fildes].pkt_buf[packet_start] + sizeof(tcphdr), payload_size);
        // printf("[DEBUG] payload size in read: %d\n", payload_size);
        cnt += payload_size;
        
        // Update pointer
        socket_dc_pool[fildes].pkt_start = (socket_dc_pool[fildes].pkt_start + 1) % MAXPACKETNUM;
        packet_start = socket_dc_pool[fildes].pkt_start;
        if(packet_start == packet_end) {
            socket_dc_pool[fildes].pkt_full = false;
        }
    }

    pthread_mutex_unlock(&socket_dc_pool[fildes].pkt_mutex);

    // Copy tmp buffer to msg buffer
    pthread_mutex_lock(&socket_dc_pool[fildes].msg_mutex);

    msg_start = socket_dc_pool[fildes].msg_start;
    msg_end = socket_dc_pool[fildes].msg_end;

    if(socket_dc_pool[fildes].msg_end < socket_dc_pool[fildes].msg_start) {
        memcpy(socket_dc_pool[fildes].msg_buf + msg_end, tmp_buf, cnt);
        socket_dc_pool[fildes].msg_end += cnt;
    }
    else {
        int payload_size = std::min(cnt, MAXMSGSIZE - msg_end);
        memcpy(socket_dc_pool[fildes].msg_buf + msg_end, tmp_buf, std::min(cnt, MAXMSGSIZE - msg_end));
        memcpy(socket_dc_pool[fildes].msg_buf, tmp_buf + payload_size, std::max(0, cnt - payload_size));
        socket_dc_pool[fildes].msg_end = (socket_dc_pool[fildes].msg_end + cnt) % MAXMSGSIZE;
    }

    if((cnt > 0) && (socket_dc_pool[fildes].msg_end == socket_dc_pool[fildes].msg_start))
        socket_dc_pool[fildes].msg_full = true;

    // Read msg from buffer
    size_t available_payload = (socket_dc_pool[fildes].msg_end - socket_dc_pool[fildes].msg_start + MAXMSGSIZE) % MAXMSGSIZE;
    if(socket_dc_pool[fildes].msg_full)
        available_payload = MAXMSGSIZE;
    nbyte = std::min(nbyte, available_payload);

    msg_start = socket_dc_pool[fildes].msg_start;
    msg_end = socket_dc_pool[fildes].msg_end;

    if(msg_end <= msg_start) {
        size_t left = nbyte - std::min((size_t)(MAXMSGSIZE - msg_start), nbyte);
        memcpy(buf, socket_dc_pool[fildes].msg_buf + msg_start, std::min((size_t)(MAXMSGSIZE - msg_start), nbyte));        
        memcpy(buf + nbyte - left, socket_dc_pool[fildes].msg_buf, left);

        // Update pointer
        socket_dc_pool[fildes].msg_start += std::min((size_t)(MAXMSGSIZE - msg_start), nbyte);
        socket_dc_pool[fildes].msg_start += left;
        socket_dc_pool[fildes].msg_start %= MAXMSGLENGTH;
    }
    else {
        memcpy(buf, socket_dc_pool[fildes].msg_buf + msg_start, nbyte);

        // Update pointer
        socket_dc_pool[fildes].msg_start += nbyte;
        socket_dc_pool[fildes].msg_start %= MAXMSGLENGTH;
    }

    pthread_mutex_unlock(&socket_dc_pool[fildes].msg_mutex);

    return nbyte;
}

/**
* @see [POSIX.1-2017:write](http://pubs.opengroup.org/onlinepubs/
* 9699919799/functions/write.html)
* @fs
*     The file or socket descriptor.
* @buf
*     The pointer to the buffer holding the data to be written.
* @N
*     The length in bytes of the buffer pointed to by the buf parameter.
*/
ssize_t __wrap_write(int fildes, const void *buf, size_t nbyte) {
    // Fallback to linux library function
    if(fildes < SOCKETDCSTART) {
        return write(fildes, buf, nbyte);
    }

    int ret = sendTCPPacket(fildes, 0, 0, 1, buf, nbyte);

    if(ret < 0) {
        printf("Error in write, can not send TCP packet!\n");
        return -1;
    }

    return nbyte;
}

/**
* @see [POSIX.1-2017:close](http://pubs.opengroup.org/onlinepubs/
* 9699919799/functions/close.html)
*/
ssize_t __wrap_close(int fildes) {
    if(fildes < SOCKETDCSTART) {
        return close(fildes);
    }

    char buf[10];
    memset(buf, 0, sizeof(buf));

    if(sendTCPPacket(fildes, 0, TH_FIN, 1, buf, 0) < 0) {
        printf("Error in close, can not send FIN packet!\n");
        return -1;
    }

    if(waitPacket(fildes, TH_ACK) < 0) {
        printf("Error in close, can not receive ACK packet!\n");
        return -1;
    }

    if(waitPacket(fildes, TH_FIN) < 0) {
        printf("Error in close, can not receive SYN packet!\n");
        return -1;
    }

    if(sendTCPPacket(fildes, 0, TH_ACK, 1, buf, 0) < 0) {
        printf("Error in close, can not send ACK packet!\n");
        return -1;
    }

    pthread_mutex_lock(&socket_dc_pool_mutex);
    memset(&socket_dc_pool[fildes], 0, sizeof(socket_dc_pool[fildes]));
    socket_dc_pool[fildes].busy = false;
    pthread_mutex_unlock(&socket_dc_pool_mutex);

    return 0; 
}

/**
* @see [POSIX.1-2017:getaddrinfo](http://pubs.opengroup.org/onlinepubs/
* 9699919799/functions/getaddrinfo.html)
*/
int __wrap_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    
}