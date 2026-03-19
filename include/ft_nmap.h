#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>

#define FTN_MAX_THREADS 250
#define FTN_MAX_PORTS   1024

#define FTN_DEFAULT_PORT_MIN 1
#define FTN_DEFAULT_PORT_MAX 1024

#define FTN_DEFAULT_TIMEOUT_MS 1200

typedef enum e_scan_type {
	SCAN_SYN  = 1 << 0,
	SCAN_NULL = 1 << 1,
	SCAN_ACK  = 1 << 2,
	SCAN_FIN  = 1 << 3,
	SCAN_XMAS = 1 << 4,
	SCAN_UDP  = 1 << 5,
} t_scan_type;

typedef enum e_port_state {
	PS_UNKNOWN = 0,
	PS_OPEN,
	PS_CLOSED,
	PS_FILTERED,
	PS_UNFILTERED,
	PS_OPEN_FILTERED
} t_port_state;

typedef struct s_port_result {
	uint16_t    port;
	char        service[64];
	t_port_state syn;
	t_port_state nulls;
	t_port_state ack;
	t_port_state fin;
	t_port_state xmas;
	t_port_state udp;
} t_port_result;

typedef struct s_config {
	char      **targets;
	size_t      target_count;

	uint16_t   *ports;
	size_t      port_count;

	int         threads;
	uint32_t    scans_mask;

	uint32_t    timeout_ms;
} t_config;

static inline double now_seconds(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

#endif