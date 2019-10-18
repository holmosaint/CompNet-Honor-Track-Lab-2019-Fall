#include <pcap.h>
#include <string>
#include <vector>
#include <cstring>
#include "packetio.hpp"
#include "tools.hpp"
#include "device.hpp"

frameReceiveCallback frame_callback_function_ptr;

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
    std::string frame;
    char link_frame[1520];
    char errbuf[PCAP_ERRBUF_SIZE];
    int num_sent;

    // dest MAC address
    frame = MACstring2arr((const char *)destmac);
    memcpy(link_frame, destmac, 6);

    // source MAC address
    frame = MACstring2arr(device_list[id].MAC_addr);
    memcpy(link_frame + 6, frame.c_str(), 6);

    // ether type
    if(ethtype == 0x0800) {
        frame += (char)0x08;
        frame += (char)0x00;
        link_frame[12] = (char)0x08;
        link_frame[13] = (char)0x00;
    }
    else if(ethtype == 0x0806) {
        frame += (char)0x08;
        frame += (char)0x06;
        link_frame[7] = (char)0x08;
        link_frame[8] = (char)0x06;
    }
    else {
        printf("Only support Ethernet II frame type, which EtherType ID is 0x0800 or 0x0806\n");
        return -1;
    }

    // payload
    // frame += std::string((const char *)buf);
    memcpy(link_frame + 14, buf, len);

    // TODO: checksum
    // frame += int2hex<int>(0x0020203A, hex);
    /* frame += (char)0x00;
    frame += (char)0x20;
    frame += (char)0x20;
    frame += (char)0x3A; */
    *(int *)(link_frame + 14 + len) = 0x3a202000;

    // Open the device
    pcap_t *device_pcap = pcap_open_live(device_list[id].device_name.c_str(), MAXBYTES2CAPTURE, 1, 512, errbuf);
    if(device_pcap == NULL) {
        printf("Error open the device: %s\n", errbuf);
        return -1;
    }

    // send the frame
    num_sent = pcap_inject(device_pcap, (const void *)link_frame, len + 18);
    if(num_sent < 0) {
        printf("Error: sending the frame\n");
        printf("%s\n", pcap_geterr(device_pcap));
        pcap_close(device_pcap);
        return -1;
    }
    
    pcap_close(device_pcap);

    /* char MAC_buf[20];
    sprintf(MAC_buf, "%02x:%02x:%02x:%02x:%02x:%02x", ((char *)destmac)[0], ((char *)destmac)[1], ((char *)destmac)[2], 
                                                      ((char *)destmac)[3], ((char *)destmac)[4], ((char *)destmac)[5]);
    printf("Successfully sent %d bytes to destination: %s\n", num_sent, MAC_buf); */
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
    // strncpy((char *)destMAC, frame, 6);
    for(int i = 0;i < 6; ++i) {
        destMAC[i] = (uint8_t)*(frame + i);
    }
    destMAC[6] = '\0';

    // extract source MAC addr
    uint8_t srcMAC[7];
    // strncpy((char *)srcMAC, frame + 6, 6);
    for(int i = 0;i < 6; ++i) {
        srcMAC[i] = (uint8_t)*(frame + i + 6);
    }
    srcMAC[6] = '\0';

    // if it is the same device, ignore the package
    std::string curSrcMAC;
    bool sameMAC = true;
    curSrcMAC = MACstring2arr(device_list[id].MAC_addr);
    for(int i = 0;i < 6; ++i)
        sameMAC &= ((uint8_t)curSrcMAC[i] == srcMAC[i]);
    if(sameMAC)
        return -2;

    // extract Ethernet type
    uint8_t etherType[3];
    // strncpy((char *)etherType, frame + 12, 2);
    for(int i = 0;i < 2; ++i) {
        etherType[i] = (uint8_t)*(frame + 12 + i);
    }
    etherType[2] = '\0';

    // extract payload
    char payload[1505];
    // strncpy(payload, frame + 14, len - 18);
    for(int i = 0;i < len - 18; ++i) {
        payload[i] = (uint8_t)*(frame + 14 + i);
    }
    payload[len - 18] = '\0';

    //extract checksum
    uint8_t checksum[5];
    // strncpy((char *)checksum, frame + len - 4, 4);
    for(int i = 0;i < 4; ++i) {
        checksum[i] = (uint8_t)*(frame + len - 4 + i);
    }
    checksum[4] = '\0';

    /* printf("Get link frame from MAC address: %x:%x:%x:%x:%x:%x, the destination address is %x:%x:%x:%x:%x:%x\
            Ethernet type: %x, Payload: %s, with checksum: %x %x %x %x\n", 
        srcMAC[0], srcMAC[1], srcMAC[2], srcMAC[3], srcMAC[4], srcMAC[5],
        destMAC[0], destMAC[1], destMAC[2], destMAC[3], destMAC[4], destMAC[5],
        etherType[0] * 16 * 16 + etherType[1], payload, checksum[0], checksum[1], checksum[2], checksum[3]); */

    pthread_mutex_lock(&device_mutex);

    sprintf(device_list[id].dMAC_addr, "%02x:%02x:%02x:%02x:%02x:%02x", srcMAC[0], srcMAC[1], srcMAC[2], srcMAC[3], srcMAC[4], srcMAC[5]);
    // printf("Dest MAC: %s\n", device_list[id].dMAC_addr);

    pthread_mutex_unlock(&device_mutex);

    /* Pass to IP layer */
    if(IPReceiveHandler(payload, len - 18) < 0) {
        printf("Error in processing IP packet!\n");
        return -1;
    }

    return 0;
}

/*
* Callback funtion for the pcap_loop
*/
void frame_callback(u_char *id, const pcap_pkthdr* pkthdr, const u_char* packet) {
    int ret_id = frame_callback_function_ptr((const void *)packet, pkthdr->caplen, atoi((const char *)id));
    if(ret_id == -1) {
        printf("Error: processing incoming frame!\n");
    }
    else if(ret_id >= 0){
        /* printf("Timestamp: %lds%ldms, capture length: %d B, expected length: %d B\n", 
            pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, pkthdr->caplen, pkthdr->len); */
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