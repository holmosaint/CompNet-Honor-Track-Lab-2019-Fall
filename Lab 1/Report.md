# Report for Lab 1

<p align="right">
    1600012947 Kaiwen Sheng
</p>

## 802.11 wireless network protocol

### Beacon Frame

> 1. What are the SSIDs  of the 2 access points that are issuing most of the beacon frames in this trace?

```
---------Cisco---------
Tagged parameters (119 bytes)
Tag: SSID parameter set: 30 Munroe St
Tag Number: SSID parameter set (0)
Tag length: 12
SSID: 30 Munroe St
---------LinksysG---------
Tag: SSID parameter set: li\357\277\275\001\004\357\277
Tag Number: SSID parameter set (0)
Tag length: 9
SSID: li\357\277\275\001\004\357\277\275':2
```

Answer:

We can see from the data that the SSID is `30 Munroe St` for Cisco and `li\357\277\275\001\004\357\277\275':2` for LinksysG.



> 2. What are the intervals of time between the transmissions of the beacon frames the inksys_ses_24086 access point? From the 30 Munroe St. access point? (Hint: this interval of time is contained in the beacon frame itself).

```
Fixed parameters (12 bytes)
Timestamp: 11529295568209666840
Beacon Interval: 0.063488 [Seconds]
```

Answer:

From the data above, we can see the interval is **0.063488s.**



> 3. What (in hexadecimal notation) is the source MAC address on the beacon frame from 30 Munroe St.? Recall that the source, destination, and BSS are three addresses used in an 802.11 frame. For a detailed discussion of the 802.11 frame structure, see the IEEE 802.11 standards document.

Answer:

The addresses can be seen from the following:

```
Transmitter address: Cisco-Li_f7:1d:51 (00:16:b6:f7:1d:51)
Source address: Cisco-Li_f7:1d:51 (00:16:b6:f7:1d:51) -- this is the answer
BSS Id: Cisco-Li_f7:1d:51 (00:16:b6:f7:1d:51)
```



> 4. What (in hexadecimal notation) is the destination MAC address on the beacon frame from 30 Munroe St.?

Answer:

```
Destination address: Broadcast (ff:ff:ff:ff:ff:ff)
```



> 5. What (in hexadecimal notation) is the MAC BSS id on the beacon frame from 30 Munroe St.?

Answer:

```
BSS Id: Cisco-Li_f7:1d:51 (00:16:b6:f7:1d:51)
```



> 6. The beacon frames from the 30 Munroe St. access point advertise that the access point can support four data rates and eight additional “extended supported rates.” What are these rates?

Answer:

The support rates are 1.0, 2.0, 5.5, 11.0 Mbps. The extended rates are 6.0, 9.0, 12.0, 18.0, 24.0, 36.0, 48.0 and 54.0 Mbps. Several data rates have been standardized for wireless LANs. The Supported Rates information element allows an 802.11 network to specify the data rates it supports. When mobile stations attempt to join the network, they check the data rates used in the network. Some rates are mandatory and must be supported by the mobile station, while others are optional. It consists of a string of bytes. Each byte uses the seven low-order bits for the data rate; the most significant bit indicates whether the data rate is mandatory. Mandatory rates are encoded with the most significant bit set to 1 and optional rates have a 0. Up to eight rates may be encoded in the information element. As the number of data rates has proliferated, the Extended Supported Rates element was standardized to handle more than eight data rates.



### Data Transfer

> 7. Find the 802.11 frame containing the SYN TCP segment for this first TCP session (that downloads alice.txt). What are three MAC address fields in the 802.11 frame? Which MAC address in this frame corresponds to the wireless host (give the hexadecimal representation of the MAC address for the host)? To the access point? To the first-hop router? What is the IP address of the wireless host sending this TCP segment? What is the destination IP address? Does this destination IP address correspond to the host, access point, first-hop router, or some other network-attached device? Explain.

Answer:

Three MAC address fields:

```
Receiver address: Cisco-Li_f7:1d:51 (00:16:b6:f7:1d:51) -- access point
Destination address: Cisco-Li_f4:eb:a8 (00:16:b6:f4:eb:a8) -- first-hop router
Source address: IntelCor_d1:b6:4f (00:13:02:d1:b6:4f) -- wirelss host
```

IP address:

```
Source: 192.168.1.109 -- wireless host
Destination: 128.119.245.12 -- destination
```

The destination IP address corresponds to the host. 



> 8. Find the 802.11 frame containing the SYNACK segment for this TCP session. What are three MAC address fields in the 802.11 frame? Which MAC address in this frame corresponds to the host? To the access point?To the first-hop router? Does the sender MAC address in the frame correspond to the IP address of the device that sent the TCP segment encapsulated within this datagram?

Answer:

Three MAC address fields:

```
Receiver address: 91:2a:b0:49:b6:4f (91:2a:b0:49:b6:4f) -- first-hop router
Transmitter address: Cisco-Li_f7:1d:51 (00:16:b6:f7:1d:51) -- access point
Source address: Cisco-Li_f4:eb:a8 (00:16:b6:f4:eb:a8) -- host
```

The sender MAC address in the frame doesn't correspond to the IP address of the device that sent the TCP segment encapsulated within this datagram. 



### Association/Disassociation

> 9. What two actions are taken (i.e., frames are sent) by the host in the trace just after t = 49, to end the association with the 30 Munroe St AP that was initially in place when trace collection began? (Hint: one is an IP-layer action, and one is an 802.11-layer action). Looking at the 802.11 specification, is there another frame that you might have expected to see, but don’t see here?

Answer:

First the host sent a DHCP frame to the AP to release DHCP, and it is at time 49.583615s at IP level. Then the AP sent a DEAUTHENTICATION frame to the host at link layer at time 49.609617s. But the expected DISASSOCIATION request was not seen in the trace file.



> 10.	Examine the trace file and look for AUTHENICATION frames sent from the host to an AP and vice versa. How many AUTHENTICATION messages are sent from the wireless host to the linksys_ses_24086 AP (which has a MAC address of Cisco_Li_f5:ba:bb) starting at around t = 49 ?

Answer:

I used the filter:

```
(wlan.fc.type_subtype=="Authentication") && (wlan.da == 00:18:39:f5:ba:bb)
```

to check the result. And the number is 15.

<img src="./workout/pics/num_authentication.png">



> 11. Does the host want the authentication to require a key or be open?

Answer:

The authentication needs to be open according to the information below:

<img src="Lab1-Part1/workout/pics/open_authentication.png">



> 12. Do you see a reply AUTHENTICATION from the linksys_ses_24086 AP in the trace?

Answer:

No such frame can be seen from the trace file by using the filter:

```
(wlan.fc.type_subtype=="Authentication") && (wlan.sa == 00:18:39:f5:ba:bb)
```



> 13. Now let’s consider what happens as the host gives up trying to associate with the linksys_ses_24086 AP and now tries to associate with the 30 Munroe St AP. Look for AUTHENICATION frames sent from the host to and AP and vice versa. At what times are there an AUTHENTICATION frame from the host to the 30 Munroe St. AP, and when is there a reply AUTHENTICATION sent from that AP to the host in reply? (Note that you can use the filter expression “wlan.fc.subtype == 11 and wlan.fc.type == 0 and wlan.addr == IntelCor_d1:b6:4f” to display only the AUTHENTICATION frames in this trace for this wireless host.)

Answer:

By using the filter:

```
(wlan.fc.type_subtype=="Authentication") && (wlan.addr == 00:13:02:d1:b6:4f)
```

I can see the AUTHENTICATION frame sent at time 63.168087s and reply at time 63.169071s.

<img src="./workout/pics/pair_authentication.png">



> 14. An ASSOCIATE REQUEST from host to AP, and a corresponding ASSOCIATE RESPONSE frame from AP to host are used for the host to associated with an AP. At what time is there an ASSOCIATE REQUEST from host to the 30 Munroe St AP? When is the corresponding ASSOCIATE REPLY sent? (Note that you can use the filter expression “wlan.fc.subtype < 2 and wlan.fc.type == 0 and wlan.addr == IntelCor_d1:b6:4f” to display only the ASSOCIATE REQUEST and ASSOCIATE RESPONSE frames for this trace.)

Answer:

By using the filter:

```
wlan.fc.subtype < 2 and wlan.fc.type == 0 and wlan.addr == 00:13:02:d1:b6:4f
```

I can see the ASSOCIATION REQUEST was sent at time 63.169910s, and REPLY was sent at time 63.192101s.

<img src="./workout/pics/pair_association.png">



> 15. What transmission rates is the host willing to use? The AP? To answer this question, you will need to look into the parameters fields of the 802.11 wireless LAN management frame.

Answer:

In the ASSOCIATION Reply frame, the supported data rates are: 1, 2, 5.5, 11, 6, 9, 12, 18, 24, 36, 48, 54 Mbit/sec. In the ASSOCIATION REQUEST frame, the supported data rates are the same. 

<img src="./workout/pics/datarates_supported.png">



### Other types

> 16. What are the sender, receiver and BSS ID MAC addresses in these frames? What is the purpose of these two types of frames? (To answer this last question, you’ll need to dig into the online references cited earlier in this lab).

Answer:

At time 2.297613s, there is a PROBE REQUEST.

```
Source: 00:12:f0:1f:57:13
Destination: ff:ff:ff:ff:ff:ff
BSSID : ff:ff:ff:ff:ff:ff
```

At time 2.300697, there is a  PROBE RESPONSE.

```
Source: 00:16:b6:f7:1d:51
Destination: 00:12:f0:1f:57:13
BSSID : 00:16:b6:f7:1d:51
```

PROBE REQUEST is used by a host in active scanning to find an Access Point. 
PROBE RESPONSE is sent by the access point to the host sending the request.



## Cross layer analysis

> 1. Calculate the 3 way TCP handshake duration on both devices. Are they the same? Explain the reason.

Answer:

The durations for the 2 devices (server and client) are different due to the processing cycles are different.

```
On the client side, the sequence is
- SYN sent
- longer delay (RTT + remote stack overhead) - 0.020003
- SYN/ACK received
- very small delay (local stack overhead) - 0.000077
- final ACK is sent, socket is open- very small delay (local stack & application overhead) - 0.000223
- GET sent

On the listener (server) side, this would look like
- SYN received
- very small delay (local stack overhead)
- SYN/ACK sent
- longer delay (RTT + remote stack overhead)
- final ACK is received, socket is open
- very small delay (remote stack & application overhead)
- GET is received
```

However, the [SYN, ACK] packages are lost in the trace file, so we can only calculate the durations according to other packages. 

We can use the [FIN, ACK] packages to calculate the 3 way handshake durations. 

On the client side, the duration is $0.003679 + 0.003796 - 0.003753 = 0.003722$.

On the server side, the duration is $0.003796 - 0.003679 = 0.000117$

<img src="./workout/pics/FIN_ACK.png">



> 2. Calculate the mean and standard deviation of the time to retransmit bad packets in iperf_wlan.pcap. Does the retransmission affect the TCP? Why? (Hint: check FCS status to find bad packets)

Answer:





> 3. Calculate the mean and standard deviation values of the TCP out-of-order delay, retransmission rate and RTT observed from the two devices. Describe the difference and explain the reason in detail.

Answer:

**Out-of-order delay**

**Retransmission rate**

On the server end, the total number of TCP packets sent/received is 62412, the number of retransmissions is 27909, so the mean retransmission rate is $27909 \div 62412 = 44.7\%$.

On the client end, the total number of TCP packets sent/received is 49727, the number of retransmissions is 45, so the mean retransmission rate is $45 \div 49727 = 9.05\%$.

The retransmission rate is hugely different between the 2 devices, and the retransmission rate on the client is largely lower then that on the server due to the high congestion traffic on the server end. 

**RTT**



> 4. Plot the time series of throughput, RTT, and retransmission rate observed on both devices. Analyze how the path loss in L1/L2 affects TCP performance (e.g. throughput and RTT).



> 5. Other insights you get from the traces.



## Web latency breakdown

> 1. Implement a processing program to calculate the latency of DNS Lookup, Initial TCP Connection Establishment (i.e. TCP Handshake Time), Request Sending, TTFB (Time to First Byte), Content Downloading Time. Show the results for each website (by charts or figures).

> 2. Choose 3+ page loading procedures (from different websites) and draw visual waterfall graphs to show the breakdown of web latency.

All the answers and data can be seen in the folder: `lantency_pics`. 



## LTE/TCP cross layer analysis 

Please retrieve the statistical results per message type: (a) Get the number of unique messages and the numbers of each message type and put this result in the report in descending order. (b) Group message by PHY, MAC, RLC, PDCP, RRC, and NAS. Get the numbers of messages per each group and add this result (in a table or plain text) in the report. Learn which group is most popular and answer why. (c) Select any 1-min window that contains the TCP flow and plot the arrival patterns of all the messages in this selected time window, where the X-axis is timestamp and Y is the message ID (you can define a unique ID for each unique message type). Include this result in your report with the start and end time for the selected time window.

Timestamp alignment. Calculate the delay between the on-chip time and the system time for this Android phone. (Hints: you can find the pdu size in LTE_PDCP_DL_Cipher_Data_PDU messages for downlink packets and LTE_PDCP_UL_Cipher_Data_PDU messages for uplink packets).

Calculate the two 3-way TCP handshake durations in this trace and put the results into your report. Briefly describe the difference and explain why.

Locate the RRC connection setup procedure happened during the first TCP connection establishment. In principle, the RRC connection setup starts with “RRC Connection Setup Request”, followed by “RRC Connection Setup” and “RRC Connection Setup Complete”. Note that their message type id observed via MobileInsight is the same as LTE_RRC_OTA_Packet and these messages can be distinguished by their field names. For example,
<field name="lte-rrc.rrcConnectionRequest*"> ··· (where * is a wild character)
<field name="lte-rrc.rrcConnectionSetup*"> ··· (where * is a wild character)
<field name="lte-rrc.rrcConnectionSetupComplete*"> ··· (where * is a wild character)

Please extract these messages and calculate the T𝑟𝑎𝑑𝑖𝑜 and T𝑐𝑡𝑟𝑙 showed in Fig.1. Please put these results into your report. 



## Web latency breakdown 

Calculate the overall packet retransmission rate at MAC layer and RLC layer, and put the results of 3 different carriers into your report. Choose one web page loading procedure, plot the time series graph. Note that a packet is considered as a packet loss at MAC layer when it fails the CRC check. You can find the CRC results for downlink packets in LTE_PHY_PDSCH_Stat_Indication messages and the RLC NACK for downlink packets in LTE_RLC_UL_AM_All_PDU messages.

Analyze the uplink latency for uplink IP packets. Calculate the mean and standard deviation values of the uplink grant waiting time and the total uplink latency for each packet. Hints:
a)	Each LTE_MAC_UL_Buffer_Status_Internal message contains the uplink data buffer status for the last 40 ms, with each ‘UL Buffer Status SubPacket’ indicating one millisecond.
b)	LTE_MAC_UL_Transport_Block messages contain the grant information.

Based on the processing program you implemented in Lab1-part I, choose 3 page loading procedures (from different websites) and draw visual waterfall graphs for different carriers to show a more detailed breakdown of web latency. Fig. 2 is an example. (Hints: LTE adds a fixed-sized frame header to each IP packet)



## Web latency breakdown on HSR 

Calculate the overall packet retransmission rate at MAC layer and RLC layer regarding 3 different carriers. Choose a web page loading process and plot the time series graph. Describe the difference between the indoor environment and high-speed rail scenario.

Find handover that happened when a page was loading. For a handover event, analyze the handover duration, data disruption time (i.e. the duration when no data was received), duplicate data transfer time (duplicate data may be detected at PDCP layer). Show the latency breakdown for the handover event you choose. Calculate the overall percentage of page loading that encountered at least one handover.

Choose a website and draw visual waterfall graphs for the 4 phones. Compare them with the static ones. What other observations or insights do you have?

You are encouraged to collect extra dataset considering different mobility (e.g. walking, taking a taxi, taking a subway, taking a train), or choosing other applications (e.g. videos, instant messages). Note that you need to root your phone and install MobileInsight. Some LTE chips may not be supported by MobileInsight.