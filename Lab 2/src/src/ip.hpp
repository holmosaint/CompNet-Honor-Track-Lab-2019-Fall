/**
* @file ip.h
* @brief Library supporting sending/receiving IP packets encapsulated in an Ethernet II frame.
*/
#include <deque>
#include <netinet/ip.h>
#include "device.hpp"

#ifndef IP_HPP__
#define IP_HPP__

enum IPPacketType {
    ADVERTISE,      // for router, broadcast its existence
    EDGE,           // for router, send topology
    NORMAL,           // for router and client, normal ip packets
};

struct myIPHeader {
    iphdr ipHeader;
    uint32_t packet_type;   // for router, what type
};

struct routing_entry {
    int dis;
    int mask_length;    // Record the length of the prefix
    int next_hop_id;    // Record the device id of the next hop
    in_addr network_destination;
    in_addr netmask;
    char *nextMAC;
    char *nextDeviceName;
};

extern pthread_mutex_t routing_mutex;
extern std::deque<routing_entry *> routing_table;

struct connection_entry {
    uint32_t conn_ns_id;  // network namespace id
    Device *NIC_device;
};

extern pthread_mutex_t connection_mutex;
extern std::deque<connection_entry *> connection_table;

/* Edge send by EDGE type IP packet */
struct edge {
    logical_node nodeA;
    logical_node nodeB;
    in_addr ip_link;
};

struct dij_node {
    logical_node node;
    int dis;
    int path;
    dij_node(logical_node n, int di, int p):node(n), dis(di), path(p) {}
    dij_node() {}
};

bool operator>(const dij_node &n1, const dij_node &n2);

extern pthread_mutex_t edge_mutex;
extern std::deque<edge *> edge_table;

/**
* @brief Send an IP packet to specified host.
*
* @param src Source IP address.
* @param dest Destination IP address.
* @param proto Value of `protocol` field in IP header.
* @param buf pointer to IP payload
* @param len Length of IP payload
* @return 0 on success, -1 on error.
*/
int sendIPPacket(const struct in_addr src, const struct in_addr dest, int proto, const void *buf, int len);

/**
* @brief Process an IP packet upon receiving it.
*
* @param buf Pointer to the packet.
* @param len Length of the packet.
* @return 0 on success, -1 on error.
* @see addDevice
*/
typedef int (*IPPacketReceiveCallback)(const void* buf, int len);

extern IPPacketReceiveCallback ip_callback_function_ptr;

/**
* @brief Register a callback function to be called each time an IP packet was received.
*
* @param callback The callback function.
* @return 0 on success, -1 on error.
* @see IPPacketReceiveCallback
*/
int setIPPacketReceiveCallback(IPPacketReceiveCallback callback);

/**
* @brief Process an IP packet upon receiving it.
*
* @param buf Pointer to the packet.
* @param len Length of the packet.
* @return 0 on success, -1 on error.
* @see addDevice
*/
int IPReceiveHandler(const void* buf, int len);

int calRoutingTable();

/**
* @brief Manully add an item to routing table. Useful when talking with real Linux machines.
*
* @param dest The destination IP prefix.
* @param mask The subnet mask of the destination IP prefix.
* @param nextHopMAC MAC address of the next hop.
* @param device Name of device to send packets on.
* @return 0 on success, -1 on error
*/
int setRoutingTable(const struct in_addr dest, const struct in_addr mask, const void* nextHopMAC, const char *device);

/* Broadcast Information */
void broadCast(void *payload, int len);

/* Advertising Thread Task Function */
void *advertisingTask(void *args);

void broadcastEdge(edge *e);

#endif