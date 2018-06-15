#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void getPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main() {
	char errBuf[PCAP_ERRBUF_SIZE],*deviceStr;
	deviceStr = pcap_lookupdev(errBuf);
	if (deviceStr){
		printf("success: device: %s.\n",deviceStr);
	} else {
		printf("error: %s.\n",errBuf);
		exit(1);
	}

	pcap_t *device = pcap_open_live("lo", 65535, 1, 0, errBuf);
	if (!device) {
		printf("error: pcap_open_live(): %s.\n",errBuf);
		exit(1);
	}

	/* filter */
	struct bpf_program filter;
	pcap_compile(device, &filter, "tcp and port 6388", 1, 0);
	pcap_setfilter(device, &filter);

	int id = 0;
	pcap_loop(device, -1, getPacket, (u_char *)&id);

	pcap_close(device);
	return 0;
}

void getPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	int *id = (int *)arg;
	printf("id: %d\n",++(*id));
	printf("Packet length: %d\n", pkthdr->len);
	printf("Number of bytes: %d.\n", pkthdr->caplen);
	printf("Received time: %s.\n", ctime((const time_t *)&pkthdr->ts.tv_sec));

	/*
	int i;
	for (i = 0; i < pkthdr->len; i ++) {
		printf(" %02x",packet[i]);
		if ( (i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	*/
	printf("packet : %s.\n",packet);
	printf("\n\n");
}
