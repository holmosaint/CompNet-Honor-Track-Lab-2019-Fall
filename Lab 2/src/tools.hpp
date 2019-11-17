/* Util Functions */
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <netdb.h> 
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <signal.h>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include "ip.hpp"

#ifndef TOOLS_HPP__
#define TOOLS_HPP__

/* General Tool Funtions */
/* convert integer to hex representations */
template <class T>
std::string int2hex(T t, std::ios_base & (*f)(std::ios_base&));

/*
* convert string MAC address to integre array
* return the string representation of the integer array
*/
std::string MACstring2arr(const char *mac);

/* Link Layer Functions */
int lookupdevice(std::string device);

int lookupdevice(in_addr ip_addr);

void printDeviceInfo(Device device);

/* IP Layer Functions */
char *IPPacketType2String(uint32_t type_id);

void IP2IPString(in_addr_t ip_addr, char *addr);

void printIPHeader(myIPHeader * ip_header);

connection_entry *lookupConnectionNode(uint32_t ns_id);

void printRoutingEntry(routing_entry *entry, int entry_id);

void printLogicalNode(logical_node *node);

void printEdge(edge *e);

void printTCPHeader(tcphdr *tcp_header);

#endif