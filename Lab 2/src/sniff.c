#include <pcap.h>
#include <string.h>
#include <stdlib.h>

#define MAXBYTES2CAPTURE 2048

void processPacket(__u_char *arg, const struct pcap_pkthdr* pkthdr, const __u_char *packet) {
    int i = 0, *counter = (int *)arg;

    printf("Packet Count: %d\n", ++(*counter));
    printf("Received Packet Size: %d\n", pkthdr->len);
    printf("Payload:\n");
    for(int i = 0; i < pkthdr->len; ++i) {
        if (isprint(packet))
            printf("%c ", packet[i]);
        else printf(". ");

        if ((i % 16 == 0 && i != 0) || i == pkthdr->len - 1)
            printf("\n");
    }
    return;
}

int main() {
    int i = 0, count = 0;
    pcap_t *descr = NULL;
    char errbuf[PCAP_ERRBUF_SIZE], *device = NULL;
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    device = pcap_lookupdev(errbuf);
    printf("Opening device %s\n", device);

    descr = pcap_open_live(device, MAXBYTES2CAPTURE, 1, 512, errbuf);

    printf("%x\n", descr);
    pcap_loop(descr, -1, processPacket, (__u_char *)&count);

    return 0;
}