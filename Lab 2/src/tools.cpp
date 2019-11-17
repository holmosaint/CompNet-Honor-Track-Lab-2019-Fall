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
#include <string.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <deque>
#include "device.hpp"
#include "ip.hpp"
#include "tools.hpp"

/* General Tool Funtions */
/* convert integer to hex representations */
template <class T>
std::string int2hex(T t, std::ios_base & (*f)(std::ios_base&)) {
    std::ostringstream oss;
    oss.width(sizeof(T));
    oss.fill('0');
    oss << f << t;
    return oss.str();
}

/*
* convert string MAC address to integre array
* return the string representation of the integer array
*/
std::string MACstring2arr(const char *mac) {
    int values[6];
    int i;
    std::string tmp_res = "";
    std::string res = "abcdef";

    // cout << mac << endl;
    if(6 == sscanf(mac, "%x:%x:%x:%x:%x:%x%*c",
        &values[0], &values[1], &values[2],
        &values[3], &values[4], &values[5])) {
        /* convert to uint8_t */
        for( i = 0; i < 6; ++i ) {
            // tmp_res = int2hex<uint16_t>(values[i], hex);
            res[i] = (char)values[i];
        }
        // printf("%s\n", res.c_str());
    }
    return res;
}

/* Link Layer Functions */
int lookupdevice(std::string device) {
    for(int i = 0;i < device_list.size(); ++i) {
        if(device_list[i].device_name.compare(device) == 0)
            return i;
    }
    return -1;
}

int lookupdevice(in_addr ip_addr) {
    for(int i = 0;i < device_list.size(); ++i) {
        if((device_list[i].ip_addr.s_addr & device_list[i].subnet_mask.s_addr) == (ip_addr.s_addr & device_list[i].subnet_mask.s_addr)) {
            return i;
        }
    }
    return -1;
}

void printDeviceInfo(Device device) {
    printf("%s:\n", device.device_name.c_str());
    printf("\tMAC address: %s\n", device.MAC_addr);
    printf("\tIP address: %s\n", device.ip_addr_str);
    printf("\tSubnet mask: %s\n", device.subnet_mask_str);
}


/* IP Layer Functions */
char *IPPacketType2String(uint32_t type_id) {
    switch (type_id)
    {
    case ADVERTISE:
        return "ADVERTISE";
        break;
    case EDGE:
        return "EDGE";
        break;
    case NORMAL:
        return "Normal Packets";
        break;
    default:
        break;
    }
    printf("Error IP packet type: %ud\n", type_id);
    return "Error in interpreting IP packet type\n";
}

void IP2IPString(in_addr_t ip_addr, char *addr) {
    inet_ntop(AF_INET, &ip_addr, addr, INET_ADDRSTRLEN);
}

void printIPHeader(myIPHeader * ip_header) {
    iphdr *ip = &(ip_header->ipHeader);
    char saddr [INET_ADDRSTRLEN], daddr [INET_ADDRSTRLEN];
    IP2IPString(ip->saddr, saddr);
    IP2IPString(ip->daddr, daddr);

    printf("*** Internet Protocol Version 4 ***\n");
    printf("Version: %d\n", ip->version);
    printf("Header Length: %d bytes\n", ip->ihl * 4);
    printf("Differentiated Services Field: %#02x\n", ip->tos);
    printf("Total Length: %d\n", be16toh(ip->tot_len));
    printf("Identification: %#04x\n", be16toh(ip->id));
    printf("Flags: %#02x\n", ip->frag_off);
    printf("Fragment Offset: %d\n", ip->frag_off);
    printf("Time to live: %d\n", ip->ttl);
    printf("Protocol: %s (%d)\n", getprotobynumber(ip->protocol)->p_aliases[0], ip->protocol);
    printf("Header checksum: %#04x\n", be16toh(ip->check));
    printf("Source: %s\n", saddr);
    printf("Destination: %s\n", daddr);

    printf("IP Packet Type: %s\n", IPPacketType2String(ip_header->packet_type));
}

connection_entry *lookupConnectionNode(uint32_t ns_id) {
    std::deque<connection_entry *>::iterator it = connection_table.begin();
    while(it != connection_table.end()) {
        if((**it).conn_ns_id == ns_id)
            return *it;
        ++it;
    }
    return NULL;
}

void printRoutingEntry(routing_entry *entry, int entry_id) {
    char ip_buf[30], mask_buf[30];
    IP2IPString(entry->network_destination.s_addr, ip_buf);
    IP2IPString(entry->netmask.s_addr, mask_buf);

    printf("Routing Entry %d: Dest IP: %s, Dest Mask: %s, Next HOP ID: %d, Next MAC Addr: %s\n", 
            entry_id, ip_buf, mask_buf, entry->next_hop_id, entry->nextMAC);
}

void printLogicalNode(logical_node *node) {
    char buf[50], mask_buf[50];
    IP2IPString(node->ip_prefix.s_addr, buf);
    IP2IPString(node->mask.s_addr, mask_buf);
    printf("NS ID: %d; IP Prefix: %s; Mask: %s\n", node->ns_id, buf, mask_buf);
}

void printEdge(edge *e) {
    printf("{\n");
    printf("\t"), printLogicalNode(&(e->nodeA));
    printf("\t"), printLogicalNode(&(e->nodeB));
    char buf[50];
    IP2IPString(e->ip_link.s_addr, buf);
    printf("\tIP Link: %s\n" ,buf);
    printf("}\n");
}

void printTCPHeader(tcphdr *tcp_header) {
    printf("-------TCP Header-------\n");
    printf("Src port: %d. Dest port: %d\n", tcp_header->th_sport, tcp_header->th_dport);
    printf("Seq number: %d, Ack number: %d\n", tcp_header->th_seq, tcp_header->th_ack);
    printf("Data offset: %d\n", tcp_header->th_off);
    printf("Flags: %x\n", tcp_header->th_flags);
    printf("Window: %d\n", tcp_header->th_win);
    printf("Checksum: %d\n", tcp_header->th_sum);
    printf("------------------------\n");
}