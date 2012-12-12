#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "packet.h"

static uint8_t timestamp[8] = {0xFF};

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
