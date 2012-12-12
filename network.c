#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "network.h"

struct network_t *network_add(struct network_t **list, char *ssid, mac_t *m, mac_t *d, uint8_t flags) {
	while (*list) {
		list = &(*list)->next;
	}
	*list = malloc(sizeof(**list));
	strncpy((*list)->ssid, ssid, sizeof((*list)->ssid));
	(*list)->ssid[32] = '\0';
	memcpy(&((*list)->mac), m, sizeof(*m));
	memcpy(&((*list)->dst), d, sizeof(*d));
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
