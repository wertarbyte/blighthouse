#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

typedef uint8_t mac_t[6];

static uint8_t timestamp[8] = {0xFF};

static mac_t ap_base_mac = {0x02, 0xDE, 0xAD, 0xBE, 0xEF, 0x42};
static mac_t dest_mac    = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static uint8_t use_wpa = 0;

static char *append_to_buf(char *buf, char *data, int size) {
	memcpy(buf, data, size);
	return buf+size;
}

static char *append_str(char *buf, char *data) {
	int size = strlen(data);
	return append_to_buf(buf, data, size);
}

int build_beacon(char *buf, char *essid, mac_t *mac, uint8_t add_wpa) {
	char *b = buf;
	/* prepend a minimal radiotap header */
	memset(b, 0x00, 8);
	b[2] = 8;
	b += 8;
	b = append_to_buf(b, "\x80\x00\x00\x00", 4); /* IEEE802.11 beacon frame */
	b = append_to_buf(b, dest_mac, sizeof(dest_mac)); /* destination */
	b = append_to_buf(b, *mac, sizeof(*mac)); /* source */
	b = append_to_buf(b, *mac, sizeof(*mac)); /* BSSID */
	b = append_to_buf(b, "\x00\x00", 2); /* sequence number */
	b = append_to_buf(b, timestamp, sizeof(timestamp)); /* time stamp */
	b = append_to_buf(b, "\x64\x00", 2); /* beacon interval */
	b = append_to_buf(b, "\x01\x04", 2); /* capabilities */

	*(b++) = 0; /* tag essid */
	*(b++) = strlen(essid);
	b = append_str(b, essid);

	b = append_to_buf(b, "\x01\x01\x82", 3); /* We only support 1 MBit */
	b = append_to_buf(b, "\x03\x01\x01", 3); /* we are on channel 1 */
	
	/* WPA tags */
	if (use_wpa) {
		b = append_to_buf(b, "\x30", 1);
		b = append_to_buf(b, "\x14", 1); /* tag length */
		b = append_to_buf(b, "\x01\x00", 2); /* version */
		b = append_to_buf(b, "\x00\x0f\xac", 3); /* cipher suite OUI */
		b = append_to_buf(b, "\x02", 1); /* TKIP */
		b = append_to_buf(b, "\x01\x00", 2); /* cipher suite count */
		b = append_to_buf(b, "\x00\x0f\xac\x02", 4); /* pairwire cipher suite list */
		b = append_to_buf(b, "\x01\x00", 2); /* auth key management suite count */
		b = append_to_buf(b, "\x00\x0f\xac\x02", 4); /* auth key management list */
		b = append_to_buf(b, "\x00\x00", 2); /* RSN capabilities */
	}
	return (b-buf);
}

void print_mac(const mac_t m) {
	printf("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", m[0], m[1], m[2], m[3], m[4], m[5]);
}

int read_mac(char *arg) {
	int r = sscanf(arg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", dest_mac, dest_mac+1, dest_mac+2, dest_mac+3, dest_mac+4, dest_mac+5);
	return (r != sizeof(dest_mac));
}

void process_probe(u_char *user, const struct pcap_pkthdr *h, const uint8_t *b) {
	printf("Incoming request\n");
	/* where does the wifi header start? */
	uint16_t rt_length = (b[2] | (uint16_t)b[3]>>8);
	printf("rt_length %d\n", rt_length);
	printf("rt_length %hhx\n", b[rt_length+4]);
	printf("DST: "); print_mac(&b[rt_length+4]); printf("\n");
	printf("SRC: "); print_mac(&b[rt_length+4+6]); printf("\n");
	printf("BSS: "); print_mac(&b[rt_length+4+6+6]); printf("\n");
}

int main(int argc, char *argv[]) {
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_errbuf[0] = '\0';

	char *if_name = NULL;
	uint8_t time_ssid = 0;
	uint8_t verbose = 0;

	int c;
	opterr = 0;
	while ((c = getopt(argc, argv, "i:d:twv")) != -1) {
		switch(c) {
			case 'i':
				if_name = optarg;
				break;
			case 't':
				time_ssid = 1;
				break;
			case 'v':
				verbose = 1;
				break;
			case 'd':
				if (read_mac(optarg)) {
					fprintf (stderr, "Unable to parse mac address.\n", optopt);
					return 1;
				}
				break;
			case 'w':
				use_wpa = 1;
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
	pcap_t *pcap = pcap_open_live(if_name, 1024, 0, 1, pcap_errbuf);
	if (!pcap) {
		printf("%s\n", pcap_errbuf);
		exit(1);
	}
	struct bpf_program filter_probe_req;
	pcap_compile(pcap, &filter_probe_req, "type mgt subtype probe-req", 1, PCAP_NETMASK_UNKNOWN);
	pcap_setfilter(pcap, &filter_probe_req);

	int link_layer_type = pcap_datalink(pcap);
	if (link_layer_type != DLT_IEEE802_11_RADIO) {
		const char *lln_pre = pcap_datalink_val_to_name(link_layer_type);
		const char *lln_req = pcap_datalink_val_to_name(DLT_IEEE802_11_RADIO);
		fprintf(stderr, "Unsupported link layer format (%s), '%s' is required\n", lln_pre, lln_req);
		pcap_close(pcap);
		exit(1);
	}
	char beacon[1024];
	time_t t;
	struct tm *tmp;
	int count = 0;
	printf("transmitting beacons for %d network%s via '%s'", ssids, (ssids == 1 ? "" : "s"), if_name);
	printf(" to ");
	print_mac(dest_mac);
	printf("\n");
	while (1) {
		mac_t ap_mac;
		memcpy(ap_mac, &ap_base_mac, sizeof(mac_t));
		ap_mac[5] += count;
		char network[33];
		if (time_ssid && count == netc+time_ssid-1) {
			t = time(NULL);
			tmp = localtime(&t);
			if (!tmp) {
				perror("localtime");
				exit(1);
			}
			strftime(network, 32, "%Y-%m-%d %H:%M", tmp);
		} else {
			strncpy(network, netp[count], 32);
		}
		int buffersize = build_beacon(beacon, network, &ap_mac, use_wpa);
		int s = pcap_inject(pcap, beacon, buffersize);
		
		if (verbose) {
			printf("sending beacon '%s'", network);
			printf(" (AP: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx)", ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5]);
			printf("\n");
		}

		usleep(100000/ssids);
		count++;
		if (count >= ssids) count = 0;

		pcap_dispatch(pcap, -1, &process_probe, "beacon");
	}
	pcap_close(pcap);
	return 0;
}
