#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <netdb.h> 
#include <pthread.h>
#include <unistd.h>
#include <string>
#include <cstring>
#include <deque>
#include <queue>
#include "ip.hpp"
#include "device.hpp"
#include "tools.hpp"
#include "packetio.hpp"
#include "ip.hpp"
#include "socket.hpp"

/* Global Variables */
IPPacketReceiveCallback ip_callback_function_ptr;

/* Routing Table */
pthread_mutex_t routing_mutex;
std::deque<routing_entry *> routing_table;

/* Connection Table */
pthread_mutex_t connection_mutex;
std::deque<connection_entry *> connection_table;

/* Edge table */
pthread_mutex_t edge_mutex;
std::deque<edge *> edge_table;


bool operator>(const dij_node &n1, const dij_node &n2) {
    return n1.dis > n2.dis;
}

/* Searching Routing Table */
routing_entry *routing(in_addr daddr) {
    routing_entry entry, *match_entry = NULL;

    pthread_mutex_lock(&routing_mutex);
    //printf("Get routing lock!\n");
    std::deque<routing_entry *>::iterator it = routing_table.begin();       
    while(it != routing_table.end()) {
        entry = **it;
        // If the prefix matches, choose the longest one
        if(entry.netmask.s_addr & daddr.s_addr == entry.network_destination.s_addr) {
            if(match_entry && (match_entry->mask_length < entry.mask_length)) {
                match_entry = *it;
            }
            else if(!match_entry) {
                match_entry = *it;
            }
        }
        ++it;
    }

    pthread_mutex_unlock(&routing_mutex);
    // printf("Release routing lock!\n");
    return match_entry;
}

/* Broadcast Information */
void broadCast(void *payload, int len) {
    pthread_mutex_lock(&device_mutex);
    // printf("Get device lock!\n");
    for(int i = 0;i < device_list.size(); ++i) {
        /* in_addr dest;
        dest.s_addr = 0; */
        sendIPPacket(device_list[i].ip_addr, device_list[i].ip_addr, 6, payload, len);
    }
    pthread_mutex_unlock(&device_mutex);
    // printf("Release device lock!\n");
}

void broadcastEdge(edge *e) {
    char buf[sizeof(edge) + 5];
    ((uint32_t *)buf)[0] = (uint32_t)EDGE;
    memcpy(buf + 4, e, sizeof(edge));
    broadCast((void *) buf, sizeof(edge) + 4);
}

void broadcastAllEdge() {
    for(int i = 0;i < edge_table.size(); ++i) {
        broadcastEdge(edge_table[i]);
    }
}

/**
* @brief Send an IP packet to specified host.
*
* @param src Source IP address.
* @param dest Destination IP address.
* @param proto Value of `protocol` field in IP header.
* @param buf pointer to IP payload: the first 2 bytes contain the information about the packet type
* @param len Length of IP payload
* @return 0 on success, -1 on error.
*/
int sendIPPacket(const struct in_addr src, const struct in_addr dest, int proto, const void *buf, int len) {
    /* Construct IP header */
    iphdr ip_header;
    // Default values
    ip_header.version = 4;
    ip_header.ihl = 6;
    ip_header.id = 0;
    ip_header.frag_off = (1 << 14); // turn on the DF bit
    ip_header.ttl = 255;
    ip_header.protocol = proto; // TCP: 6
    ip_header.tos = 0;
    
    // IP addresses
    ip_header.saddr = src.s_addr;
    ip_header.daddr = dest.s_addr;

    // Datagram size
    ip_header.tot_len = sizeof(iphdr) + len;

    // Header checksum
    uint16_t check = 0;
    ip_header.check = 0;
    for(int i = 0;i < 10; ++i) {
        check += *((uint16_t *)(&ip_header) + i);
    }
    ip_header.check = (uint16_t)(-1) - check;
    ip_header.check += 1;

    uint32_t packet_type = *((uint32_t *)(buf));
    myIPHeader my_ip_header;
    my_ip_header.ipHeader = ip_header;
    my_ip_header.packet_type = packet_type;

    /* printf("[DEBUG]\n");
    printIPHeader(&my_ip_header); */

    /* Copy data */
    char datagram[sizeof(iphdr) + len];
    memcpy(datagram, &my_ip_header, sizeof(myIPHeader));
    memcpy(datagram + sizeof(myIPHeader), (char *)buf + 4, len - 4);

    /* Send packet down to link layer */
    char nextMAC[20];
    int id;

    // Search routing table to get the MAC address and device id
    // Client: send to the router (client should only connect to a single router)
    if(device_type == CLIENT) {
        id = 0;
    }
    // Router: search for the next hop in the routing table
    else if(device_type == ROUTER) {
        std::deque<routing_entry *>::iterator it = routing_table.begin();
        routing_entry entry = **it;
        routing_entry *cur_match = NULL;

        cur_match = routing(dest);

        if(!cur_match) {
            printf("Can not find a path to the host.\n");
            printIPHeader(&my_ip_header);
            return -1;
        }

        id = cur_match->next_hop_id;

    }
    memcpy(nextMAC, device_list[id].dMAC_addr, 12);
    nextMAC[12] = '\0';

    /* Pass down to link layer */
    if(sendFrame(datagram, sizeof(iphdr) + len, 0x0800, nextMAC, id) < 0) {
        printf("Error in sending the IP packet! The IP header is below: \n");
        printIPHeader(&my_ip_header);
        return -1;
    }

    return 0;
}

edge *lookupEdge(logical_node nodeA, logical_node nodeB) {
    std::deque<edge *>::iterator it = edge_table.begin();
    while(it != edge_table.end()) {
        edge e = **it;
        if((nodeA.ns_id == e.nodeA.ns_id) && (nodeB.ns_id == e.nodeB.ns_id)) 
            return *it;
        if((nodeA.ns_id == e.nodeB.ns_id) && (nodeB.ns_id == e.nodeA.ns_id))
            return *it;
        ++it;
    }
    return NULL;
}

void addEdge(logical_node *nodeA, logical_node *nodeB, in_addr ip_link) {
    pthread_mutex_lock(&edge_mutex);
    // printf("Get edge lock!\n");

    edge *e = lookupEdge(*nodeA, *nodeB);

    bool needBroadcast = false;

    // Create a new one
    if(!e) {
        edge_table.push_back(new edge());
        int edge_id = edge_table.size() - 1;
        edge_table[edge_id]->nodeA = *nodeA;
        edge_table[edge_id]->nodeB = *nodeB;
        edge_table[edge_id]->ip_link = ip_link;
        needBroadcast = true;
        e = edge_table[edge_id];
    }
    // Update
    else if((!((e->nodeA == *nodeA) && (e->nodeB == *nodeB) && (e->ip_link.s_addr == ip_link.s_addr)))
        && (!((e->nodeA == *nodeB) && (e->nodeB == *nodeA) && (e->ip_link.s_addr == ip_link.s_addr)))) {
        e->nodeA = *nodeA;
        e->nodeB = *nodeB;
        e->ip_link = ip_link;
        needBroadcast = true;
    }

    pthread_mutex_unlock(&edge_mutex);

    // printEdge(e);
    
    // printf("Release edge lock!\n");
    if(needBroadcast) {
        // broadcastEdge(e);
        broadcastAllEdge();
    }
}

/**
* @brief Process an IP packet upon receiving it.
*
* @param buf Pointer to the packet.
* @param len Length of the packet.
* @return 0 on success, -1 on error.
* @see addDevice
*/
int IPReceiveHandler(const void* buf, int len) {
    /* Extract IP header */
    // iphdr ip_header;
    // memcpy(&ip_header, buf, sizeof(ip_header));
    myIPHeader ip_header;
    memcpy(&ip_header, buf, sizeof(myIPHeader));

    /* Get ip addr and dest addr */
    in_addr src, dest;
    src.s_addr = ip_header.ipHeader.saddr;
    dest.s_addr = ip_header.ipHeader.daddr;

    /* Get packet size */
    uint32_t payload_size;
    payload_size = len - ip_header.ipHeader.ihl * 4;

    // Check the correctness of the datagram
    uint16_t checksum = 0;
    for(int i = 0;i < 10; ++i) {
        checksum += *((uint16_t *)(&ip_header) + i);
    }

    // Endian Resolve
    if(checksum  != (uint16_t)0) {
        printf("Wrong checksum in the ip packet! Got checksum: %x\n", ip_header.ipHeader.check);
        // printIPHeader(&ip_header);
        return -1;
    }

    // Print payload
    char payload[payload_size + 5];
    memcpy(payload, (char *)buf + sizeof(myIPHeader), payload_size);

    char saddr [INET_ADDRSTRLEN], daddr [INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header.ipHeader.saddr), saddr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header.ipHeader.daddr), daddr, INET_ADDRSTRLEN);
    
    /* 3 types of process:
     *      - modify routing table
     *      - continue sending the packet according to the routing table
     *      - arrives at destination, extract payload and pass to TCP layer
     */
    if(device_type == CLIENT) {
        // printf("Receive [%s] packet from [%s] with content: %s\n", IPPacketType2String(ip_header.packet_type), saddr, payload);

        // in part-3, pass the packet to TCP layer
        if(TCPReceiveHandler(payload, payload_size, src) < 0) {
            // printf("Error in sending packet from IP layer to TCP layer!\n");
            // return -1;
            return 0;
        }
    }
    else if(device_type == ROUTER) {
        bool needConnection = false, needEdge = false;
        printf("Receive [%s] packet from [%s] with content: %s\n", IPPacketType2String(ip_header.packet_type), saddr, payload);
        
        /* If the packet type is ADVERTISE, need to add the node to direct link table */
        if(ip_header.packet_type == ADVERTISE) {
            // Add a new connection if needed

            // Create a connection entry
            logical_node *connection_node;
            uint32_t ns_id;
            // The payload should contain the [IP Prefix, Mask, NS ID]
            connection_node = (logical_node *)payload;
            /* printf("Payload size: %d\n", payload_size);
            printIPHeader(&ip_header);
            printf("---Receiving node information---\n");
            printLogicalNode(connection_node); */

            pthread_mutex_lock(&device_mutex);
            char buf[50];
            IP2IPString(src.s_addr, buf);
            int device_id = lookupdevice(src);
            // look up device
            if(device_id < 0) {
                printf("Cannot find target device on this network space!\n");
                printIPHeader(&ip_header);
                pthread_mutex_unlock(&device_mutex);
                return -1;
            }

            if(device_list[device_id].conn_node == *connection_node) {
                pthread_mutex_unlock(&device_mutex);
            }
            else {
                device_list[device_id].conn_node = *connection_node;
                pthread_mutex_unlock(&device_mutex);
                logical_node *node = new logical_node(device_list[device_id].ip_addr, device_list[device_id].subnet_mask, global_ns_id);
                printLogicalNode(node);
                addEdge(node, connection_node, device_list[device_id].ip_addr);
            }
        }
        /* If the packet type is EDGE, need to add the node to edge tables */
        else if(ip_header.packet_type == EDGE) {
            // Add a new edge if needed
            // The content should be: [IP_prefix, Mask, network namespace ID] for each node
            logical_node nodeA, nodeB;
            in_addr ip_link;
            memcpy(&nodeA, (char *)buf + ip_header.ipHeader.ihl * 4, sizeof(logical_node));
            memcpy(&nodeB, (char *)buf + ip_header.ipHeader.ihl * 4 + sizeof(logical_node), sizeof(logical_node));
            memcpy(&ip_link, (char *)buf + ip_header.ipHeader.ihl * 4 + sizeof(logical_node) * 2, sizeof(in_addr));
            addEdge(&nodeA, &nodeB, ip_link);
        }
        /* If the packet type is NORMAL, transfer the data to another router/client according to the routing table */
        else if(ip_header.packet_type == NORMAL) {
            sendIPPacket(src, dest, 6, (char *)buf + sizeof(iphdr), len - sizeof(iphdr));
        }
    }

    return 0;
}

/**
* @brief Register a callback function to be called each time an IP packet was received.
*
* @param callback The callback function.
* @return 0 on success, -1 on error.
* @see IPPacketReceiveCallback
*/
int setIPPacketReceiveCallback(IPPacketReceiveCallback callback) {
    ip_callback_function_ptr = callback;
    return 0;
}

/* Calculate Routing Table */
int calRoutingTable() {
    pthread_mutex_lock(&routing_mutex);
    pthread_mutex_lock(&edge_mutex);

    /* Build Graph */
    int node_num = 1;
    int root_id = global_ns_id;
    std::priority_queue<dij_node, std::vector<dij_node>, std::greater<dij_node>> que;
    int mark_arr[10000];
    memset(mark_arr, 0, sizeof(mark_arr));
    mark_arr[global_ns_id] = -1;

    /* int root_path = lookupdevice(host_node.ip_prefix);
    if(root_path < 0) {
        printf("Cannot find root path!\n");
        pthread_mutex_unlock(&edge_mutex);
        pthread_mutex_unlock(&routing_mutex);
        return -1;
    }
    que.push(dij_node(host_node, 0, root_path)); */

    for(int i = 0;i < edge_table.size(); ++i) {
        logical_node nA = edge_table[i]->nodeA, nB = edge_table[i]->nodeB;
        if(nA.ns_id == global_ns_id) {
            int path = lookupdevice(edge_table[i]->ip_link);
            que.push(dij_node(nB, 1, path));
        }
        else if(nB.ns_id == global_ns_id) {
            int path = lookupdevice(edge_table[i]->ip_link);
            que.push(dij_node(nA, 1, path));            
        }
        
    }

    int res[10000];

    while(!que.empty()) {
        dij_node top_node;
        top_node = que.top();

        /* Delete Node Calculated Already */
        while(mark_arr[top_node.node.ns_id] == -1) {
            que.pop();
            if(que.empty())
                break;
            top_node = que.top();
        }
        if(que.empty())
            break;
        mark_arr[top_node.node.ns_id] = -1;
        res[top_node.node.ns_id] = top_node.path;

        // Set Routing Table w/o Itself
        if(top_node.dis > 0) {

            /* printLogicalNode(&(top_node.node));
            printf("Path: %d, Dis: %d\n", top_node.path, top_node.dis); */

            int ret_id = setRoutingTable(top_node.node.ip_prefix, top_node.node.mask, device_list[top_node.path].dMAC_addr, device_list[top_node.path].device_name.c_str());
            if(ret_id < 0) {
                printf("Error in setting the routing table!\n");
                pthread_mutex_unlock(&edge_mutex);
                pthread_mutex_unlock(&routing_mutex);
                return -1;
            }

        }

        for(int i = 0;i < edge_table.size(); ++i) {
            logical_node nA = edge_table[i]->nodeA, nB = edge_table[i]->nodeB;

            if((nA.ns_id == top_node.node.ns_id) && (mark_arr[nB.ns_id] != -1)) {
                int path = top_node.path;
                que.push(dij_node(nB, 1 + top_node.dis, path));
            }
            else if((nB.ns_id == top_node.node.ns_id) && (mark_arr[nA.ns_id] != -1)) {
                int path = top_node.path;
                que.push(dij_node(nA, 1 + top_node.dis, path));
            }
        }
    }

    pthread_mutex_unlock(&edge_mutex);

    printf("-----------Routing Table-----------\n");
    for(int i = 0;i < routing_table.size(); ++i) {
        printRoutingEntry(routing_table[i], i);
    }
    printf("------------------------------------\n");
    pthread_mutex_unlock(&routing_mutex);
}

/**
* @brief Manully add an item to routing table. Useful when talking with real Linux machines.
*
* @param dest The destination IP prefix.
* @param mask The subnet mask of the destination IP prefix.
* @param nextHopMAC MAC address of the next hop.
* @param device Name of device to send packets on.
* @return 0 on success, -1 on error
*/
int setRoutingTable(const struct in_addr dest, const struct in_addr mask, const void* nextHopMAC, const char *device) {
    /* Get the Next Device ID */
    int dev_id;
    dev_id = lookupdevice(device);
    if(dev_id < 0) {
        printf("Can not find device: [%s]\n", device);
        return -1;
    }

    bool isNew = true;
    routing_entry *entry;

    /* Check if there exists an entry containing the same dest addr and modify if needed */
    std::deque<routing_entry *>::iterator it = routing_table.begin();
    while((it != routing_table.end()) && isNew) {
        if((dest.s_addr == (*it)->network_destination.s_addr) && (mask.s_addr == (*it)->netmask.s_addr)) {
            isNew = false;
            entry = (*it);
        }
        /* else if(dest.s_addr == (*it)->network_destination.s_addr) {
            (*it)->netmask.s_addr = mask.s_addr;
            isNew = false;
            entry = (*it);
        }
        else if(mask.s_addr == (*it)->netmask.s_addr) {
            (*it)->network_destination.s_addr = dest.s_addr;
            isNew = false;
            entry = (*it);
        } */
        ++it;
    }

    /* Set a New Entry */
    if(isNew) {
        int entry_id;
        entry = new routing_entry();
        entry_id = routing_table.size() - 1;
        routing_table.push_back(entry);
        entry->network_destination = dest;
        entry->next_hop_id = dev_id;
        entry->netmask = mask;
        // memcpy(routing_table[entry_id]->nextMAC, nextHopMAC, 12);
        entry->nextMAC = device_list[dev_id].dMAC_addr;
        // memcpy(routing_table[entry_id]->nextDeviceName, device, strlen(device));
        // routing_table[entry_id]->nextDeviceName[strlen(device)] = '\0';
        // entry = routing_table[entry_id];
    }

    return 0;
}

/* Advertising Thread Task Function */
void *advertisingTask(void *args) {
    int re_routing_cnt = 0;
    while(1) {
        char buf[50];
        ((uint32_t *)buf)[0] = (uint32_t)ADVERTISE;
        /* memcpy(buf + 4, &host_node, sizeof(logical_node));
        broadCast((void *)buf, sizeof(logical_node) + 4); */

        for(int i = 0;i < device_list.size(); ++i) {
            logical_node node;
            node.ip_prefix = device_list[i].ip_addr;
            node.mask = device_list[i].subnet_mask;
            node.ns_id = global_ns_id;
            memcpy(buf + 4, &node, sizeof(logical_node));
            sendIPPacket(node.ip_prefix, node.ip_prefix, 6, buf, sizeof(logical_node) + 4);
        }

        // Sleep for 10s
        sleep(10);
        if(device_type == ROUTER) {
            re_routing_cnt = (re_routing_cnt + 1) / 3;
            calRoutingTable();
        }
    }
}
