#ifndef PROBES_H
#define PROBES_H

#include "ft_nmap.h"
#include <netinet/in.h>

#include <stdint.h>
#include <netinet/in.h>

/*
** TCP observation result
*/
typedef enum e_tcp_obs
{
	TCP_OBS_OPEN,
	TCP_OBS_CLOSED,
	TCP_OBS_FILTERED
}	t_tcp_obs;

/*
** TCP connect probe
*/
t_tcp_obs probe_tcp_connect(
	const struct sockaddr_in *dst,
	uint16_t port,
	uint32_t timeout_ms);

/*
** UDP probe (simple)
*/
t_port_state probe_udp_basic(
	const struct sockaddr_in *dst,
	uint16_t port,
	uint32_t timeout_ms);


// Resolves IPv4 string or hostname into sockaddr_in.
// Returns 0 on success, -1 on error.
int resolve_loopback_ipv4(const char *target, struct sockaddr_in *out);

// TCP probe for SYN/ACK/FIN/NULL/XMAS.
// Returns one of t_port_state.
//t_port_state probe_tcp_connect(const char *target, uint16_t port, t_scan_type scan_type, uint32_t timeout_ms);

// UDP probe: sends UDP packet, listens for ICMP unreachable or UDP reply.
// Returns PS_OPEN / PS_CLOSED / PS_OPEN_FILTERED / PS_FILTERED / PS_UNKNOWN (should rarely be unknown).
//t_port_state probe_udp_basic(const char *target, uint16_t port, uint32_t timeout_ms);

#endif