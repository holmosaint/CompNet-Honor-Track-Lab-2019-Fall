/**
* @file socket.h
* @brief POSIX-compatible socket library supporting TCP protocol on
IPv4.
*/
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#ifndef SOCKET_HPP__
#define SOCKET_HPP__

#define SOCKETDCSTART 500     // the socket descriptor starts from 500
#define MAXSOCKETNUM 1000     // the max socket number is 1000
#define MAXMSGLENGTH 1000     // the max message length is 1000
#define MAXPACKETNUM 10       // the max packet buffer size
#define MAXMSGSIZE 10000

struct socket_dc {
      bool busy;
      bool setup;
      int id;
      int domain;
      int type;
      int protocol;
      in_port_t src_port;
      in_port_t dest_port;
      in_addr src_ip;
      in_addr dest_ip;

      // sockaddr *address;
      // socklen_t address_len;

      // msg buffer when connection has been set up
      pthread_mutex_t msg_mutex;
      char msg_buf[MAXMSGSIZE];
      int msg_start;
      int msg_end;
      bool msg_full;

      // pkt buffer when connection hasn't been set up
      pthread_mutex_t pkt_mutex;
      char pkt_buf[MAXPACKETNUM][MAXMSGLENGTH];
      in_addr pkt_ip_buf[MAXPACKETNUM];
      int pkt_start;
      int pkt_end;
      bool pkt_full;

      // seq and ack number
      tcp_seq th_seq;
      tcp_seq th_ack;
};

extern pthread_mutex_t socket_dc_pool_mutex;
extern socket_dc socket_dc_pool[SOCKETDCSTART + MAXSOCKETNUM + 1];

/*
* Initialization of sockets
*/
void initSocketPool();

/*
* Release of sockets
*/
void releaseSocket();

/**
* @brief Process an TCP packet upon receiving it.
*
* @param buf Pointer to the packet.
* @param len Length of the packet.
* @return 0 on success, -1 on error.
* @see addDevice
*/
int TCPReceiveHandler(const void* buf, int len, in_addr src_ip);

/**
* @see [POSIX.1-2017:socket](http://pubs.opengroup.org/onlinepubs/
* 9699919799/functions/socket.html)
* @domain
*     The address domain requested, either AF_INET, AF_INET6, AF_UNIX, or AF_RAW.
* @type
*     The type of socket created, either SOCK_STREAM, SOCK_DGRAM, or SOCK_RAW.
* @protocol
*     The protocol requested. Some possible values are 0, IPPROTO_UDP, or IPPROTO_TCP.
* @Retur
      The socket descriptor
*/
int __wrap_socket(int domain, int type, int protocol);

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
int __wrap_bind(int socket, const struct sockaddr *address, socklen_t address_len);

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
int __wrap_listen(int socket, int backlog);

/**
* @see [POSIX.1-2017:connect](http://pubs.opengroup.org/onlinepubs/
* 9699919799/functions/connect.html)
*/
int __wrap_connect(int socket, const struct sockaddr *address, socklen_t address_len);

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
int __wrap_accept(int socket, struct sockaddr *address, socklen_t *address_len);

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
ssize_t __wrap_read(int fildes, void *buf, size_t nbyte);

/**
* @see [POSIX.1-2017:write](http://pubs.opengroup.org/onlinepubs/
* 9699919799/functions/write.html)
*/
ssize_t __wrap_write(int fildes, const void *buf, size_t nbyte);

/**
* @see [POSIX.1-2017:close](http://pubs.opengroup.org/onlinepubs/
* 9699919799/functions/close.html)
*/
ssize_t __wrap_close(int fildes);

/**
* @see [POSIX.1-2017:getaddrinfo](http://pubs.opengroup.org/onlinepubs/
* 9699919799/functions/getaddrinfo.html)
*/
int __wrap_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);

#endif