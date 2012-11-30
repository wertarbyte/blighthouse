#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

char beacon_pre_ssid[] = 
/* radiotap header */
"\x00\x00\x12\x00\x2e\x48\x00\x00\x00\x02\x6c\x09\xa0\x00\xe6\x07\x00\x00"
/* IEEE802.11 */
"\x80\x00\x00\x00"
/* destination */
"\xff\xff\xff\xff\xff\xff"
/* source */
"\x00\x16\x3e\x1c\x4a\x3f"
"\x00\x16\x3e\x1c\x4a\x3f\x70\x3e"
/* timestamp */
"\x80\x61\x17\x06\x00\x00\x00\x00"
/* beacon interval */
"\x64\x00"
/* capabilities */
"\x01\x04"
;

/* tagged params */
/* tag 0: SSID */
//"\x00"
/* tag length */
//"\x08"
/* ESSID */
//"\x6d\x65\x69\x6e\x6e\x65\x74\x7a"

char beacon_post_ssid[] =
/* supported rates */
"\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24"
/* current channel */
"\x03\x01\x01"
/* traffic indication map */
"\x05\x04\x01\x02\x00\x00"
/* ERP information */
"\x2a\x01\x04"
/* Extended supported rates */
"\x32\x04\x30\x48\x60\x6c"
;

int build_beacon(char *buf, char *essid) {
	char *b = buf;
	memcpy(b, beacon_pre_ssid, sizeof(beacon_pre_ssid)-1);
	b += sizeof(beacon_pre_ssid)-1;
	*(b++) = 0; // tag essid
	*(b++) = strlen(essid);
	memcpy(b, essid, strlen(essid));
	b += strlen(essid);
	memcpy(b, beacon_post_ssid, sizeof(beacon_post_ssid)-1);
	b += sizeof(beacon_post_ssid)-1;
	return (b-buf);
}

int main(int argc, char *argv[]) {
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_errbuf[0] = '\0';
	if (argc < 2) {
		printf("No interface specified\n");
		exit(1);
	}
	char *if_name = argv[1];
	pcap_t *pcap = pcap_open_live(if_name, 96, 0, 0, pcap_errbuf);
	if (!pcap) {
		printf("%s\n", pcap_errbuf);
		exit(1);
	}
	char beacon[1024];
	char *network = "meinnetz";
	while (1) {
		int buffersize = build_beacon(beacon, network);
		int s = pcap_inject(pcap, beacon, buffersize);
		printf("transmitted %d bytes of beacon data on %s for network '%s'\n", s, if_name, network);
		usleep(1000);
	}
	pcap_close(pcap);
	return 0;
}
