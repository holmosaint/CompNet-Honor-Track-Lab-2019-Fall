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
using namespace std;

#define MAXBYTES2CAPTURE 1518
#define MAXDEVICE 10

typedef int (*frameReceiveCallback)(const void*, int, int);
static frameReceiveCallback frame_callback_function_ptr;

struct Device {
    string device_name;
    int id;
    char ip_addr[20];
    char subnet_mask[20];
    char MAC_addr[20];
};

static vector<Device> device_list;

// Record the current network namespace
static char* network_name;

void printDeviceInfo(Device device);
int findDevice(const char *device);

/**
* Add a device to the library for sending/receiving packets.
*
* @param device Name of network device to send/receive packet on.
* @return A non-negative _device-ID_ on success, -1 on error.
*/
int addDevice(const char* device) {
    Device dev;
    dev.device_name = string(device);
    dev.id = device_list.size();
    device_list.push_back(dev);
    if(findDevice(device) < 0) {
        printf("Error in finding the device (%s)\n", device);
        device_list.pop_back(); // Delete the device
        return -1;
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
        strcpy(ip, inet_ntoa(address));
        if (ip == NULL) {
            perror("inet_ntoa"); /* print error */
            return -1;
        }
        
        /* Get subnet mask in human readable form */
        address.s_addr = subnet_mask_raw;
        strcpy(subnet_mask, inet_ntoa(address));
        if (subnet_mask == NULL) {
            perror("inet_ntoa");
            return -1;
        }

        /* Get MAC address */
        // Read file from /sys/class/net/LABveth1-2/address
        string filename = "/sys/class/net/" + string(device) + "/address";
        ifstream in(filename, std::ios::in);
        string mac;
        if (!in.is_open()) {
            cerr << "Error: Unable to get the MAC address of device (" << device << ")" << endl;
            return -1;
        }
        getline(in, mac);
        in.close();

        strcpy(device_list[device_id].ip_addr, ip);
        strcpy(device_list[device_id].subnet_mask, subnet_mask);
        strcpy(device_list[device_id].MAC_addr, mac.c_str());
        
        printf("Find device (%s) successfully!\n", device);
        printDeviceInfo(device_list[device_id]);
    }
    
    return lookup_return_code;
}

/*
* convert integer to hex representations
*/
template <class T>
string int2hex(T t, ios_base & (*f)(ios_base&)) {
    ostringstream oss;
    oss.width(sizeof(T));
    oss.fill('0');
    oss << f << t;
    return oss.str();
}

/*
* convert string MAC address to integre array
* 
* @return the string representation of the integer array
*/
string MACstring2arr(const char *mac) {
    int values[6];
    int i;
    string tmp_res = "";
    string res = "";

    cout << mac << endl;
    if(6 == sscanf(mac, "%x:%x:%x:%x:%x:%x%*c",
        &values[0], &values[1], &values[2],
        &values[3], &values[4], &values[5])) {
        /* convert to uint8_t */
        for( i = 0; i < 6; ++i ) {
            // tmp_res = int2hex<uint16_t>(values[i], hex);
            res += (char)values[i];
        }
        printf("%s\n", res.c_str());
    }
    return res;
}

/**
* @brief Encapsulate some data into an Ethernet II frame and send it.
*
* @param buf Pointer to the payload.
* @param len Length of the payload.
* @param ethtype EtherType field value of this frame.
* @param destmac MAC address of the destination.
* @param id ID of the device(returned by `addDevice`) to send on.
* @return 0 on success, -1 on error.
* @see addDevice
*/
int sendFrame(const void* buf, int len, int ethtype, const void* destmac, int id) {
    string frame;
    char errbuf[PCAP_ERRBUF_SIZE];
    int num_sent;

    // dest MAC address
    frame = MACstring2arr((const char *)destmac);

    // source MAC address
    frame += MACstring2arr(device_list[id].MAC_addr);

    // ether type
    if(ethtype == 0x0800) {
        frame += (char)0x08;
        frame += (char)0x00;
    }
    else if(ethtype == 0x0806) {
        frame += (char)0x08;
        frame += (char)0x06;
    }
    else {
        printf("Only support Ethernet II frame type, which EtherType ID is 0x0800 or 0x0806\n");
        return -1;
    }

    // payload
    frame += string((const char *)buf);

    // TODO: checksum
    // frame += int2hex<int>(0x0020203A, hex);
    frame += (char)0x00;
    frame += (char)0x20;
    frame += (char)0x20;
    frame += (char)0x3A;

    // Open the device
    pcap_t *device_pcap = pcap_open_live(device_list[id].device_name.c_str(), MAXBYTES2CAPTURE, 1, 512, errbuf);
    if(device_pcap == NULL) {
        printf("Error open the device: %s\n", errbuf);
        return -1;
    }

    // send the frame
    num_sent = pcap_inject(device_pcap, (const void *)frame.c_str(), frame.size());
    if(num_sent < 0) {
        printf("Error: sending the frame\n");
        pcap_geterr(device_pcap);
        return -1;
    }

    printf("Successfully sent %d bytes to destination: %s\n", num_sent, (const char *)destmac);
    return 0;
}

/**
* @brief Process a frame upon receiving it.
*
* @param buf Pointer to the frame.
* @param len Length of the frame.
* @param id ID of the device (returned by `addDevice`) receiving current frame.
* @return 0 on success, -1 on error.
* @see addDevice
*/
int frameHandler(const void *buf, int len, int id) {
    const char *frame = (const char *)(buf);
    
    // extract MAC addr
    uint8_t destMAC[7];
    strncpy((char *)destMAC, frame, 6);
    destMAC[6] = '\0';

    // extract source MAC addr
    uint8_t srcMAC[7];
    strncpy((char *)srcMAC, frame + 6, 6);
    srcMAC[6] = '\0';

    // extract Ethernet type
    uint8_t etherType[3];
    strncpy((char *)etherType, frame + 14, 2);
    etherType[2] = '\0';

    // extract payload
    char payload[1505];
    strncpy(payload, frame + 16, len - 20);
    payload[len - 20 + 1] = '\0';

    //extract checksum
    uint8_t checksum[5];
    strncpy((char *)checksum, frame + len - 4, 4);
    checksum[4] = '\0';

    printf("Get packet from MAC address: %x:%x:%x:%x:%x:%x, the destination address is %x:%x:%x:%x:%x:%x\
            Ethernet type: %x, Payload: %s, with checksum: %x %x %x %x\n", 
        srcMAC[0], srcMAC[1], srcMAC[2], srcMAC[3], srcMAC[4], srcMAC[5],
        destMAC[0], destMAC[1], destMAC[2], destMAC[3], destMAC[4], destMAC[5],
        etherType[0] * 16 * 16 + etherType[1], payload, checksum[0], checksum[1], checksum[2], checksum[3]);

    // send ACK back to the source MAC addr
    /* char str[20];
    sprintf(str, "%x:%x:%x:%x:%x:%x", srcMAC[0], srcMAC[1], srcMAC[2], srcMAC[3], srcMAC[4], srcMAC[5]);
    if(sendFrame((const void *)"ACK", 3, 0x0800, str, id)) {
        printf("Error in sending ACK frame!\n");
        return -1;
    } */

    return 0;
}

/*
* Callback funtion for the pcap_loop
*/
void frame_callback(u_char *id, const pcap_pkthdr* pkthdr, const u_char* packet)
{
    printf("Timestamp: %lds%ldms, capture length: %d B, expected length: %d B\n", 
        pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, pkthdr->caplen, pkthdr->len);
    if(frame_callback_function_ptr((const void *)packet, pkthdr->caplen, atoi((const char *)id))) {
        printf("Error: processing incoming frame!\n");
    }
}

/**
* @brief Register a callback function to be called each time an Ethernet II
* frame was received.
*
* @param callback the callback function.
* @return 0 on success, -1 on error.
* @see frameReceiveCallback
*/
int setFrameReceiveCallback(frameReceiveCallback callback) {
    frame_callback_function_ptr = callback;
    return 0;
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

    string id = to_string(device_info->id);
    while(1) {
        pcap_loop(device_pcap, 1, frame_callback, (u_char *)(id.c_str()));
    }
}

int lookupdevice(string device) {
    for(int i = 0;i < device_list.size(); ++i) {
        if(device_list[i].device_name.compare(device) == 0)
            return i;
    }
    return -1;
}

void printDeviceInfo(Device device) {
    printf("%s:\n", device.device_name.c_str());
    printf("\tMAC address: %s\n", device.MAC_addr);
    printf("\tIP address: %s\n", device.ip_addr);
    printf("\tSubnet mask: %s\n", device.subnet_mask);
}

int main(int argc, char **argv) {
    if(argc != 2) {
        printf("Usage: ./device [network namespace]\n");
        return -1;
    }

    network_name = (char *)malloc(strlen(argv[1]));
    strcpy(network_name, argv[1]);
    printf("Process on network namespace: %s\n", network_name);
    
    setFrameReceiveCallback(frameHandler);

    pthread_t thread_pool[MAXDEVICE];

    // Command from stdin to manipulate the link layer
    // 1. addDevice [device name] -> automatically create a thread to listen messages sent to the NIC
    // 2. send [device name] [message payload] -> sends a message through the NIC
    // 3. exit -> kill the current process
    string command;
    while(cin >> command) {
        string deviceName, msg, destmac;
        int return_id;

        if(command.compare("addDevice") == 0) {
            cin >> deviceName;

            int device_id = lookupdevice(deviceName);

            // device duplication
            if(device_id >= 0) {
                printf("Device (%s) already in the library!\n", deviceName.c_str());
                continue;
            }

            if(addDevice(deviceName.c_str())) {
                printf("Can not add device (%s)\n", deviceName.c_str());
            }    

            // Open a thread to listen on the incoming messages
            pthread_create(thread_pool + device_id, NULL, frameListeningTask, (void *)(&device_list[device_id]));
        }

        else if(command.compare("send") == 0) {
            cin >> deviceName >> destmac >> msg;

            int device_id = lookupdevice(deviceName);

            // device not found
            if(device_id < 0) {
                printf("Device (%s) not found in the library!\n", deviceName.c_str());
                continue;
            }

            // send message across the link
            return_id = sendFrame((const void *)msg.c_str(), msg.size(), 0x0800, (const void *)destmac.c_str(), device_id);
            if(return_id < 0) {
                printf("Sending frame failed\n");
            }
        }

        else if(command.compare("exit") == 0) {
            // TODO: recollect all the alive threads
            for(unsigned int i = 0;i < device_list.size(); ++i) {
                pthread_kill(thread_pool[i], SIGKILL);
            }
            break;
        }

        else {
            printf("Wrong command code, should be in [\"addDevice\", \"send\", \"exit\"]\n");
        }
    }

    return 0;
}