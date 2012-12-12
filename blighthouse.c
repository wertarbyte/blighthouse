#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

static uint8_t verbose = 0;

typedef uint8_t mac_t[6];

static uint8_t timestamp[8] = {0xFF};

static mac_t ap_base_mac = {0x02, 0xDE, 0xAD, 0xBE, 0xEF, 0x42};
static mac_t brd_mac     = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static mac_t dest_mac    = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#define NETWORK_FLAG_WPA  (1<<0)
#define NETWORK_FLAG_TIME (1<<1)

struct network_t {
	char ssid[33]; /* ESSID name (0-terminated string) */
	mac_t mac;
	mac_t dst;
	uint16_t seq;
	uint8_t channel;
	uint8_t flags;
	struct network_t *next;
};

static struct network_t *network_list = NULL;

struct network_t *network_add(struct network_t **list, char *ssid, mac_t *m, uint8_t flags) {
	while (*list) {
		list = &(*list)->next;
	}
	*list = malloc(sizeof(**list));
	strncpy((*list)->ssid, ssid, sizeof((*list)->ssid));
	(*list)->ssid[32] = '\0';
	memcpy(&((*list)->mac), m, sizeof(*m));
	memcpy(&((*list)->dst), dest_mac, sizeof(*m));
	(*list)->seq = 0;
	(*list)->flags = flags;
	(*list)->next = NULL;
}

int network_count(struct network_t **list) {
	int i = 0;
	while (*list) {
		list = &(*list)->next;
		i++;
	}
	return i;
}

struct network_t *network_find(struct network_t **list, char *ssid) {
	while (*list) {
		if (strcmp(ssid, (*list)->ssid) == 0) {
			return *list;
		}
		list = &(*list)->next;
	}
	return NULL;
}

static char *append_to_buf(char *buf, char *data, int size) {
	memcpy(buf, data, size);
	return buf+size;
}

static char *append_str(char *buf, char *data) {
	int size = strlen(data);
	return append_to_buf(buf, data, size);
}

int build_beacon(char *buf, struct network_t *n) {
	char *b = buf;
	/* prepend a minimal radiotap header */
	memset(b, 0x00, 8);
	b[2] = 8;
	b += 8;
	b = append_to_buf(b, "\x80\x00\x00\x00", 4); /* IEEE802.11 beacon frame */
	b = append_to_buf(b, n->dst, sizeof(mac_t)); /* destination */
	b = append_to_buf(b, n->mac, sizeof(mac_t)); /* source */
	b = append_to_buf(b, n->mac, sizeof(mac_t)); /* BSSID */
	/* sequence number */
	*(b++) = n->seq >> 8;
	*(b++) = n->seq & 0x00FF;
	n->seq++;
	b = append_to_buf(b, timestamp, sizeof(timestamp)); /* time stamp */
	b = append_to_buf(b, "\x64\x00", 2); /* beacon interval */
	b = append_to_buf(b, "\x01\x04", 2); /* capabilities */

	*(b++) = 0; /* tag essid */
	*(b++) = strlen(n->ssid);
	b = append_str(b, n->ssid);

	b = append_to_buf(b, "\x01\x01\x82", 3); /* We only support 1 MBit */
	b = append_to_buf(b, "\x03\x01", 2); /* the channel we are curently on... */
	*(b++) = n->channel;

	/* WPA tags */
	if (n->flags & NETWORK_FLAG_WPA) {
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

void get_essid(char *essid, const uint8_t *p, const size_t max_psize) {
	const uint8_t *end = p+max_psize;
	p += 4+6+6+6+2;
	while (p < end) {
		if (*p == 0x00) {
			if (p[1] == 0) {
				/* nothing to do */
			} else {
				strncpy(essid, &p[2], p[1]);
			}
			essid[p[1]] = '\0';
			break;
		} else {
			p += 1+p[1];
		}
	}
}

void process_probe(u_char *user, const struct pcap_pkthdr *h, const uint8_t *b) {
	/* where does the wifi header start? */
	uint16_t rt_length = (b[2] | (uint16_t)b[3]>>8);
	const uint8_t *p = &b[rt_length];
	char essid[0xFF];
	get_essid(essid, p, h->caplen);
	if (verbose) {
		printf("Incoming request\n");
		printf("DST: "); print_mac(&p[4]); printf("\n");
		printf("SRC: "); print_mac(&p[4+6]); printf("\n");
		printf("BSS: "); print_mac(&p[4+6+6]); printf("\n");
		printf("SSID <%s>\n", essid);
	}
	struct network_t *n = network_find(&network_list, essid);
	if (n) {
		printf("Incoming probe from ");
		print_mac(&p[4+6]);
		printf(" for ssid <%s>\n", essid);
	}
}

int main(int argc, char *argv[]) {
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_errbuf[0] = '\0';

	char *if_name = NULL;
	uint8_t use_wpa = 0;
	uint8_t time_ssid = 0;
	uint8_t listen = 0;
	int channel = 1;
	
	int c;
	opterr = 0;
	while ((c = getopt(argc, argv, "i:d:c:tlwv")) != -1) {
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
			case 'c':
				sscanf(optarg, "%d", &channel);
				printf("Advertising our presence on channel %d\n", channel);
				break;
			case 'l':
				listen = 1;
				break;
			case 'w':
				use_wpa = 1;
				break;
			case '?':
				if (optopt == 'i' || optopt == 'd' || optopt == 'c')
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
	/* populate the data structures */
	int i;
	if (time_ssid) {
		uint8_t flags = NETWORK_FLAG_TIME;
		flags |= (use_wpa ? NETWORK_FLAG_WPA : 0);
		struct network_t *n = network_add(&network_list, "", &ap_base_mac, flags);
		n->channel = channel;
	}
	for (i=0; i<netc; i++) {
		struct network_t *n = network_add(&network_list, netp[i], &ap_base_mac, 0);
		/* generate a MAC address */
		n->mac[5] += (i+1);
		if (use_wpa) {
			n->flags |= NETWORK_FLAG_WPA;
		}
		n->channel = channel;
	}
	int quantity = network_count(&network_list);
	if (!if_name || quantity < 1) {
		fprintf(stderr, "Please specify interface and network names\n");
		exit(1);
	}
	pcap_t *pcap = pcap_open_live(if_name, 1024, 0, 1, pcap_errbuf);
	if (!pcap) {
		printf("%s\n", pcap_errbuf);
		exit(1);
	}
	if (listen) {
		struct bpf_program filter_probe_req;
		pcap_compile(pcap, &filter_probe_req, "type mgt subtype probe-req", 1, PCAP_NETMASK_UNKNOWN);
		pcap_setfilter(pcap, &filter_probe_req);
	}

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
	printf("transmitting beacons for %d network%s via '%s'", quantity, (quantity == 1 ? "" : "s"), if_name);
	printf(" to ");
	print_mac(dest_mac);
	printf("\n");
	struct network_t *nw = network_list;
	while (1) {
		if (nw->flags & NETWORK_FLAG_TIME) {
			t = time(NULL);
			tmp = localtime(&t);
			if (!tmp) {
				perror("localtime");
				exit(1);
			}
			strftime(nw->ssid, 32, "%Y-%m-%d %H:%M", tmp);
		}
		int buffersize = build_beacon(beacon, nw);
		int s = pcap_inject(pcap, beacon, buffersize);
		
		if (verbose) {
			printf("sending beacon '%s'", nw->ssid);
			printf(" (AP: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx)", nw->mac[0], nw->mac[1], nw->mac[2], nw->mac[3], nw->mac[4], nw->mac[5]);
			printf("\n");
		}

		usleep(100000/network_count(&network_list));
		nw = nw->next;
		if (nw == NULL) nw = network_list;

		if (listen) {
			pcap_dispatch(pcap, -1, &process_probe, "beacon");
		}
	}
	pcap_close(pcap);
	return 0;
}
