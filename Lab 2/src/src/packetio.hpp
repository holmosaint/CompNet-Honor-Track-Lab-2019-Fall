/**
* @file packetio.h
* @brief Library supporting sending/receiving Ethernet II frames.
*/
#include <netinet/ether.h>
#include <pcap.h>
#include <string>

#ifndef PACKETIO_HPP__
#define PACKETIO_HPP__

#define MAXBYTES2CAPTURE 1518

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
int sendFrame(const void* buf, int len, int ethtype, const void* destmac, int id);

/**
* @brief Process a frame upon receiving it.
*
* @param buf Pointer to the frame.
* @param len Length of the frame.* @param id ID of the device (returned by `addDevice`) receiving current frame.
* @return 0 on success, -1 on error.
* @see addDevice
*/
typedef int (*frameReceiveCallback)(const void*, int, int);

/**
* @brief Register a callback function to be called each time an Ethernet II frame was received.
*
* @param callback the callback function.
* @return 0 on success, -1 on error.
* @see frameReceiveCallback
*/
int setFrameReceiveCallback(frameReceiveCallback callback);

extern frameReceiveCallback frame_callback_function_ptr;

/*
* Callback funtion for the pcap_loop
*/
void frame_callback(u_char *id, const pcap_pkthdr* pkthdr, const u_char* packet);

/**
* @brief Process a frame upon receiving it.
*
* @param buf Pointer to the frame.
* @param len Length of the frame.
* @param id ID of the device (returned by `addDevice`) receiving current frame.
* @return 0 on success, -1 on error.
* @see addDevice
*/
int frameHandler(const void *buf, int len, int id);

#endif