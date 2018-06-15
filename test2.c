#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;
	char filter_app[] = "port";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;
	const u_char *packet;

	dev = pcap_lookupdev(errbuf);

	pcap_lookupnet(dev, &net, &mask, errbuf);

	handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);

	pcap_compile(handle, &filter, filter_app, 0, net);
	pcap_setfilter(handle, &filter);

	packet = pcap_next(handle, &header);

	printf("Jacked a packet with length of %d",header.len);
	return 0;
}
