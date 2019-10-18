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
#include "packetio.hpp"
#include "ip.hpp"
#include "tools.hpp"
using namespace std;

int main(int argc, char **argv) {
    if(argc != 3) {
        printf("Usage: ./device [device type: router, client] [NS ID]\n");
        return -1;
    }

    if(!strcmp(argv[1], "router"))
        device_type = ROUTER;
    else if(!strcmp(argv[1], "client")) 
        device_type = CLIENT;
    else {
        printf("Device type should be in [router, client], but got %s\n", argv[1]);
        return -1;
    }

    global_ns_id = atoi(argv[2]);
    printf("%s, NS %u\n", argv[1], global_ns_id);

    /* if(device_type == ROUTER) {
        host_node.ns_id = ns_id;
        int tmp_ip[4];
        char buf[50];
        std::cout << "Enter the IP domain of the router: ";
        std::cin >> buf;
        std::cout << std::endl << buf << std::endl;
        sscanf(buf, "%d.%d.%d.%d", &tmp_ip[3], &tmp_ip[2], &tmp_ip[1], &tmp_ip[0]);
        host_node.ip_prefix.s_addr = 0;
        for(int i = 0;i < 4; ++i) {
            host_node.ip_prefix.s_addr <<= 8;
            host_node.ip_prefix.s_addr += tmp_ip[i];
        }
        host_node.mask.s_addr = 0x00ffffff;

        printLogicalNode(&host_node);
    } */
    
    /* Initialization */
    setFrameReceiveCallback(frameHandler);
    setIPPacketReceiveCallback(IPReceiveHandler);
    pthread_mutex_init(&device_mutex, 0);
    pthread_mutex_init(&edge_mutex, 0);

    pthread_t listening_thread_pool[MAXDEVICE];
    pthread_t advertising_thread;

    /* Set up the Advertising Thread for Routers */
    // if(device_type == ROUTER)
    pthread_create(&advertising_thread, NULL, advertisingTask, NULL);

    // Command from stdin to manipulate the link layer
    // 1. addDevice [device name] -> automatically create a thread to listen messages sent to the NIC
    // 2. send [device name] [message payload] -> sends a message through the NIC
    // 3. exit -> kill the current process
    string command;
    while(cin >> command) {
        string deviceName, msg, destmac, destIP;
        int return_id;

        if(command.compare("addDevice") == 0) {
            cin >> deviceName;

            int device_id = lookupdevice(deviceName);

            // device duplication
            if(device_id >= 0) {
                printf("Device (%s) already in the library!\n", deviceName.c_str());
                continue;
            }

            if((device_id = addDevice(deviceName.c_str())) < 0) {
                printf("Can not add device (%s)\n", deviceName.c_str());
                continue;
            }    

            // Open a thread to listen on the incoming messages
            pthread_create(listening_thread_pool + device_id, NULL, frameListeningTask, (void *)(&device_list[device_id]));
        }

        else if(command.compare("send") == 0) {
            if(device_type == ROUTER) {
                printf("Router does not support send message manually!\n");
                continue;
            }
            /* cin >> deviceName >> destmac >> msg;

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
            } */

            cin >> deviceName >> destIP >> msg;

            int device_id = lookupdevice(deviceName);
            in_addr daddr;

            // device not found
            if(device_id < 0) {
                printf("Device (%s) not found in the library!\n", deviceName.c_str());
                continue;
            }

            // send message across the link
            inet_pton(AF_INET, destIP.c_str(), &(daddr.s_addr));
            char buf[100000];
            ((uint32_t *)buf)[0] = NORMAL;
            memcpy(buf + 4, msg.c_str(), msg.size());
            return_id = sendIPPacket(device_list[device_id].ip_addr, daddr, 6, buf, 4 + msg.size());
            if(return_id < 0) {
                printf("Sending IP packet failed\n");
            } 
            
        }

        else if(command.compare("exit") == 0) {
            // TODO: recollect all the alive threads
            for(unsigned int i = 0;i < device_list.size(); ++i) {
                pthread_kill(listening_thread_pool[i], SIGKILL);
            }
            pthread_mutex_destroy(&connection_mutex);
            pthread_mutex_destroy(&edge_mutex);
            break;
        }

        else {
            printf("Wrong command code, should be in [\"addDevice\", \"send\", \"exit\"]\n");
        }
    }

    return 0;
}