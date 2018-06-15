#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
	char errBuf[PCAP_ERRBUF_SIZE],*deviceStr;
	deviceStr = pcap_lookupdev(errBuf);
	if (deviceStr){
		printf("success: device: %s.\n",deviceStr);
	} else {
		printf("error: %s.\n",errBuf);
		exit(1);
	}

	pcap_t *device = pcap_open_live(deviceStr, 65535, 1, 0, errBuf);
	if (!device) {
		printf("error: pcap_open_live(): %s.\n",errBuf);
		exit(1);
	}

	struct pcap_pkthdr packet;
	const u_char *pktStr = pcap_next(device, &packet);
	if (!pktStr) {
		printf("Did not capture a packet!\n");
		exit(1);
	}

	printf("Packet length: %d.\n", packet.len);
	printf("Number of bytes: %d.\n", packet.caplen);
	printf("Received time: %s.\n", ctime((const time_t *)&packet.ts.tv_sec));

	pcap_close(device);
	return 0;
}
