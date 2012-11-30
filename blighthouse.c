#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

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

	char *if_name = NULL;
	uint8_t time_ssid = 0;

	int c;
	opterr = 0;
	while ((c = getopt(argc, argv, "i:t")) != -1) {
		switch(c) {
			case 'i':
				if_name = optarg;
				break;
			case 't':
				time_ssid = 1;
				break;
			case '?':
				if (optopt == 'c')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
				return 1;
			default:
				abort();
		}
	}
	/* non-option arguments: network names */
	int netc = argc-optind;
	char **netp = argv+optind;
	int ssids = netc+time_ssid;
	if (!if_name || ssids < 1) {
		fprintf(stderr, "Please specify interface and network names\n");
		exit(1);
	}
	pcap_t *pcap = pcap_open_live(if_name, 96, 0, 0, pcap_errbuf);
	if (!pcap) {
		printf("%s\n", pcap_errbuf);
		exit(1);
	}
	char beacon[1024];
	time_t t;
	struct tm *tmp;
	int count = 0;
	printf("transmitting beacons for %d network%s via '%s'\n", ssids, (ssids == 1 ? "" : "s"), if_name);
	while (1) {
		char network[33];
		if (time_ssid && count == netc+time_ssid-1) {
			t = time(NULL);
			tmp = localtime(&t);
			strftime(network, 32, "%Y-%m-%d %H:%M", tmp);
		} else {
			strncpy(network, netp[count], 32);
		}
		int buffersize = build_beacon(beacon, network);
		int s = pcap_inject(pcap, beacon, buffersize);

		usleep(100000/ssids);
		count++;
		if (count >= ssids) count = 0;
	}
	pcap_close(pcap);
	return 0;
}
