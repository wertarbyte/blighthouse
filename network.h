#ifndef NETWORK_H_
#define NETWORK_H_

#include <stdint.h>

#include "types.h"

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

struct network_t *network_add(struct network_t **list, char *ssid, mac_t m, mac_t d, uint8_t flags);

int network_count(struct network_t **list);

struct network_t *network_find(struct network_t **list, char *ssid);
#endif
