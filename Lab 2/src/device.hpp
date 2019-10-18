#include <vector>
#include <string>

#define MAXDEVICE 10

#ifndef DEVICE_HPP__
#define DEVICE_HPP__

enum DeviceType {
    ROUTER,
    CLIENT,
    ERROR_TYPE,
};

/* View each virtual NIC as a logical node 
 * Virtual NIC in the same network namespace share the same ns id
 * */
struct logical_node {
    in_addr ip_prefix;
    in_addr mask;
    uint32_t ns_id;
    logical_node() {}
    logical_node(in_addr ip, in_addr m, uint32_t id):ip_prefix(ip), mask(m), ns_id(id) {}
};

bool operator==(const logical_node &n1, const logical_node &n2);

struct Device {
    std::string device_name;
    std::string device_type;

    int id;

    logical_node conn_node;

    in_addr ip_addr;
    char ip_addr_str[20];

    in_addr subnet_mask;
    char subnet_mask_str[20];

    char MAC_addr[20];
    char dMAC_addr[20];
};

extern logical_node host_node;
extern pthread_mutex_t device_mutex;
extern std::vector<Device> device_list;
extern DeviceType device_type;
extern uint32_t global_ns_id;

/**
* @file device.h
* @brief Library supporting network device management.
*/
/**
* Add a device to the library for sending/receiving packets.
*
* @param device Name of network device to send/receive packet on.
* @return A non-negative _device-ID_ on success, -1 on error.
*/
int addDevice(const char* device);

/**
* Find a device added by `addDevice`.
*
* @param device Name of the network device.
* @return A non-negative _device-ID_ on success, -1 if no such device
* was found.
*/
int findDevice(const char* device);

/*
* Thread task to listen on incoming messages
*/
void *frameListeningTask(void *device);

#endif