#include <pcap.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <cstring>
#include <string>
#include <stdlib.h>
#include <sys/socket.h>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include "device.hpp"
#include "tools.hpp"
#include "packetio.hpp"

std::vector<Device> device_list;
DeviceType device_type;
logical_node host_node;
pthread_mutex_t device_mutex;
uint32_t global_ns_id;

bool operator==(const logical_node &n1, const logical_node &n2) {
    return (n1.ip_prefix.s_addr == n2.ip_prefix.s_addr) 
        && (n1.mask.s_addr == n2.mask.s_addr) 
        && (n1.ns_id == n2.ns_id);
}

/**
* Add a device to the library for sending/receiving packets.
*
* @param device Name of network device to send/receive packet on.
* @return A non-negative _device-ID_ on success, -1 on error.
*/
int addDevice(const char* device) {
    Device dev;
    dev.device_name = std::string(device);
    
    dev.id = device_list.size();
    device_list.push_back(dev);

    if(findDevice(device) < 0) {
        printf("Error in finding the device (%s)\n", device);
        device_list.pop_back(); // Delete the device
        return -1;
    }


    if(device_type == ROUTER) {
        routing_entry *entry = new routing_entry();

        pthread_mutex_lock(&routing_mutex);
        routing_table.push_back(entry);
        entry->dis = 1;
        entry->mask_length = 24;
        entry->netmask = device_list[dev.id].subnet_mask;
        entry->next_hop_id = dev.id;
        entry->nextMAC = device_list[dev.id].dMAC_addr;
        entry->network_destination = device_list[dev.id].ip_addr;
        pthread_mutex_unlock(&routing_mutex);
    }
    return dev.id;
}

/**
* Find a device added by `addDevice`.
*
* @param device Name of the network device.
* @return A non-negative _device-ID_ on success, -1 if no such device
* was found.
*/
int findDevice(const char *device) {
    char ip[20];
    char subnet_mask[20];
    bpf_u_int32 ip_raw; /* IP address as integer */
    bpf_u_int32 subnet_mask_raw; /* Subnet mask as integer */
    int lookup_return_code;
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
    in_addr address; /* Used for both ip & subnet */
    
    /* Get device info */
    lookup_return_code = pcap_lookupnet(
        device,
        &ip_raw,
        &subnet_mask_raw,
        error_buffer
    );

    if (lookup_return_code == -1)
        printf("%s\n", error_buffer);
    else {
        int device_id = device_list[device_list.size() - 1].id;

        /* Get ip in human readable form */
        address.s_addr = ip_raw;
        device_list[device_id].ip_addr.s_addr = ip_raw;
        strcpy(ip, inet_ntoa(address));
        if (ip == NULL) {
            perror("inet_ntoa"); /* print error */
            return -1;
        }
        
        /* Get subnet mask in human readable form */
        address.s_addr = subnet_mask_raw;
        device_list[device_id].subnet_mask.s_addr = subnet_mask_raw;
        strcpy(subnet_mask, inet_ntoa(address));
        if (subnet_mask == NULL) {
            perror("inet_ntoa");
            return -1;
        }

        /* Get MAC address */
        // Read file from /sys/class/net/LABveth1-2/address
        std::string filename = "/sys/class/net/" + std::string(device) + "/address";
        std::ifstream in(filename, std::ios::in);
        std::string mac;
        if (!in.is_open()) {
            std::cerr << "Error: Unable to get the MAC address of device (" << device << ")" << std::endl;
            return -1;
        }
        getline(in, mac);
        in.close();

        strcpy(device_list[device_id].ip_addr_str, ip);
        strcpy(device_list[device_id].subnet_mask_str, subnet_mask);
        strcpy(device_list[device_id].MAC_addr, mac.c_str());
        
        printf("Find device (%s) successfully!\n", device);
        printDeviceInfo(device_list[device_id]);
    }
    
    return lookup_return_code;
}

/*
* Thread task to listen on incoming messages
*/
void *frameListeningTask(void *device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    Device *device_info = (Device *)device;

    // Open the device
    pcap_t *device_pcap = pcap_open_live(device_info->device_name.c_str(), MAXBYTES2CAPTURE, 1, 512, errbuf);
    if(device_pcap == NULL) {
        printf("Error open the device: %s\n", errbuf);
        return NULL;
    }

    std::string id = std::to_string(device_info->id);
    while(1) {
        pcap_loop(device_pcap, 1, frame_callback, (u_char *)(id.c_str()));
    }
}