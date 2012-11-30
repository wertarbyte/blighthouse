#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

static uint8_t ap_mac[6]    = {0x02, 0xDE, 0xAD, 0xBE, 0xEF, 0x42};
static uint8_t timestamp[8] = {0xFF};

static char *append_to_buf(char *buf, char *data, int size) {
	memcpy(buf, data, size);
	return buf+size;
}

static char *append_str(char *buf, char *data) {
	int size = strlen(data);
	return append_to_buf(buf, data, size);
}

int build_beacon(char *buf, char *essid) {
	char *b = buf;
	/* prepend a minimal radiotap header */
	memset(b, 0x00, 8);
	b[2] = 8;
	b += 8;
	b = append_to_buf(b, "\x80\x00\x00\x00", 4); /* IEEE802.11 beacon frame */
	b = append_to_buf(b, "\xff\xff\xff\xff\xff\xff", 6); /* destination */
	b = append_to_buf(b, ap_mac, sizeof(ap_mac)); /* source */
	b = append_to_buf(b, ap_mac, sizeof(ap_mac)); /* BSSID */
	b = append_to_buf(b, "\x00\x00", 2); /* sequence number */
	b = append_to_buf(b, timestamp, sizeof(timestamp)); /* time stamp */
	b = append_to_buf(b, "\x64\x00", 2); /* beacon interval */
	b = append_to_buf(b, "\x01\x04", 2); /* capabilities */

	*(b++) = 0; /* tag essid */
	*(b++) = strlen(essid);
	b = append_str(b, essid);

	b = append_to_buf(b, "\x01\x01\x82", 3); /* We only support 1 MBit */
	b = append_to_buf(b, "\x03\x01\x01", 3); /* we are on channel 1 */
	return (b-buf);
}

int main(int argc, char *argv[]) {
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_errbuf[0] = '\0';
	if (argc < 3) {
		printf("Please specify interface and network names\n");
		exit(1);
	}
	char *if_name = argv[1];
	pcap_t *pcap = pcap_open_live(if_name, 96, 0, 0, pcap_errbuf);
	if (!pcap) {
		printf("%s\n", pcap_errbuf);
		exit(1);
	}
	int netc = argc-2;
	char **netp = argv+2;
	char beacon[1024];
	int count = 0;
	while (1) {
		char *network = netp[count++];
		if (strlen(network) > 32) {
			network[32] = '\0';
		}
		int buffersize = build_beacon(beacon, network);
		int s = pcap_inject(pcap, beacon, buffersize);
		printf("transmitted %d bytes of beacon data on %s for network '%s'\n", s, if_name, network);
		usleep(100000/netc);
		if (count >= netc) count = 0;
	}
	pcap_close(pcap);
	return 0;
}
