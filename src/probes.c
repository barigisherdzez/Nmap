#include "probes.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#define SNAPLEN 65535

static uint16_t csum16(const void *data, size_t len)
{
	const uint16_t *p = (const uint16_t *)data;
	uint32_t sum = 0;

	while (len > 1) {
		sum += *p++;
		len -= 2;
	}
	if (len == 1) {
		sum += *(const uint8_t *)p;
	}

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return (uint16_t)~sum;
}

static uint16_t tcp_checksum(const struct iphdr *ip, const struct tcphdr *tcp, const uint8_t *payload, size_t payload_len)
{
	// Pseudo-header + TCP header + payload
	struct {
		uint32_t src;
		uint32_t dst;
		uint8_t  zero;
		uint8_t  proto;
		uint16_t tcp_len;
	} pseudo;

	pseudo.src = ip->saddr;
	pseudo.dst = ip->daddr;
	pseudo.zero = 0;
	pseudo.proto = IPPROTO_TCP;
	pseudo.tcp_len = htons((uint16_t)(sizeof(struct tcphdr) + payload_len));

	uint32_t sum = 0;
	sum += ~csum16(&pseudo, sizeof(pseudo)) & 0xFFFF;
	sum += ~csum16(tcp, sizeof(struct tcphdr)) & 0xFFFF;
	if (payload_len)
		sum += ~csum16(payload, payload_len) & 0xFFFF;

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return (uint16_t)~sum;
}

static uint16_t udp_checksum(const struct iphdr *ip, const struct udphdr *udp, const uint8_t *payload, size_t payload_len)
{
	struct {
		uint32_t src;
		uint32_t dst;
		uint8_t  zero;
		uint8_t  proto;
		uint16_t udp_len;
	} pseudo;

	pseudo.src = ip->saddr;
	pseudo.dst = ip->daddr;
	pseudo.zero = 0;
	pseudo.proto = IPPROTO_UDP;
	pseudo.udp_len = udp->len;

	uint32_t sum = 0;
	sum += ~csum16(&pseudo, sizeof(pseudo)) & 0xFFFF;
	sum += ~csum16(udp, sizeof(struct udphdr)) & 0xFFFF;
	if (payload_len)
		sum += ~csum16(payload, payload_len) & 0xFFFF;

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return (uint16_t)~sum;
}

static uint16_t pick_src_port(void)
{
	static int seeded = 0;
	if (!seeded) {
		srand((unsigned)time(NULL) ^ (unsigned)getpid());
		seeded = 1;
	}
	// ephemeral-ish range
	return (uint16_t)(40000 + (rand() % 20000));
}

static int get_local_ip_for_target(struct sockaddr_in dst, struct in_addr *out_local)
{
	if (!out_local) return -1;

	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) return -1;

	// connect UDP socket to target to let kernel choose route + local IP
	dst.sin_port = htons(53);
	if (connect(s, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
		close(s);
		return -1;
	}

	struct sockaddr_in local;
	socklen_t slen = sizeof(local);
	memset(&local, 0, sizeof(local));
	if (getsockname(s, (struct sockaddr *)&local, &slen) < 0) {
		close(s);
		return -1;
	}

	*out_local = local.sin_addr;
	close(s);
	return 0;
}

static pcap_t *pcap_open_any(char *errbuf, int timeout_ms)
{
	// "any" works on Linux; if it fails, fallback to default device.
	pcap_t *p = pcap_open_live("any", SNAPLEN, 0, timeout_ms, errbuf);
	if (p) return p;

	char *dev = pcap_lookupdev(errbuf);
	if (!dev) return NULL;
	return pcap_open_live(dev, SNAPLEN, 0, timeout_ms, errbuf);
}

static int pcap_set_filter_or_fail(pcap_t *p, const char *filter)
{
	struct bpf_program fp;
	if (pcap_compile(p, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) != 0)
		return -1;
	if (pcap_setfilter(p, &fp) != 0) {
		pcap_freecode(&fp);
		return -1;
	}
	pcap_freecode(&fp);
	return 0;
}

static t_port_state parse_tcp_reply(uint8_t flags, t_scan_type scan_type)
{
	// For SYN scan:
	// - SYN+ACK => Open
	// - RST => Closed
	// - no reply => Filtered
	if (scan_type == SCAN_SYN) {
		if ((flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) return PS_OPEN;
		if (flags & TH_RST) return PS_CLOSED;
		return PS_UNKNOWN;
	}

	// ACK scan:
	// - RST => Unfiltered
	// - no reply/icmp => Filtered
	if (scan_type == SCAN_ACK) {
		if (flags & TH_RST) return PS_UNFILTERED;
		return PS_UNKNOWN;
	}

	// FIN/NULL/XMAS:
	// - RST => Closed
	// - no reply => Open|Filtered
	if (scan_type == SCAN_FIN || scan_type == SCAN_NULL || scan_type == SCAN_XMAS) {
		if (flags & TH_RST) return PS_CLOSED;
		return PS_UNKNOWN;
	}

	return PS_UNKNOWN;
}

t_port_state probe_tcp_connect(const char *target, uint16_t port, t_scan_type scan_type, uint32_t timeout_ms)
{
	struct sockaddr_in dst;
	if (resolve_loopback_ipv4(target, &dst) != 0)
		return PS_UNKNOWN;
	dst.sin_port = htons(port);

	struct in_addr local_ip;
	if (get_local_ip_for_target(dst, &local_ip) != 0)
		return PS_UNKNOWN;

	uint16_t sport = pick_src_port();

	// open pcap first
	char errbuf[PCAP_ERRBUF_SIZE];
	memset(errbuf, 0, sizeof(errbuf));
	pcap_t *pc = pcap_open_any(errbuf, (int)timeout_ms);
	if (!pc) return PS_UNKNOWN;

	// Filter: tcp packets coming back from target:port to our local_ip:sport
	char filter[256];
	snprintf(filter, sizeof(filter),
	         "tcp and src host %s and src port %u and dst host %s and dst port %u",
	         inet_ntoa(dst.sin_addr), (unsigned)port, inet_ntoa(local_ip), (unsigned)sport);

	if (pcap_set_filter_or_fail(pc, filter) != 0) {
		pcap_close(pc);
		return PS_UNKNOWN;
	}

	// raw socket for IPv4 packets
	int rs = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (rs < 0) {
		pcap_close(pc);
		return PS_UNKNOWN;
	}
	int one = 1;
	if (setsockopt(rs, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
		close(rs);
		pcap_close(pc);
		return PS_UNKNOWN;
	}

	uint8_t pkt[sizeof(struct iphdr) + sizeof(struct tcphdr)];
	memset(pkt, 0, sizeof(pkt));

	struct iphdr *ip = (struct iphdr *)pkt;
	struct tcphdr *tcp = (struct tcphdr *)(pkt + sizeof(struct iphdr));

	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = htons((uint16_t)sizeof(pkt));
	ip->id = htons((uint16_t)(rand() & 0xFFFF));
	ip->frag_off = 0;
	ip->ttl = 64;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = local_ip.s_addr;
	ip->daddr = dst.sin_addr.s_addr;
	ip->check = 0;
	ip->check = csum16(ip, sizeof(struct iphdr));

	tcp->source = htons(sport);
	tcp->dest = htons(port);
	tcp->seq = htonl((uint32_t)rand());
	tcp->ack_seq = 0;
	tcp->doff = 5;
	tcp->window = htons(1024);
	tcp->check = 0;
	tcp->urg_ptr = 0;

	// flags by scan type
	if (scan_type == SCAN_SYN) tcp->syn = 1;
	else if (scan_type == SCAN_ACK) tcp->ack = 1;
	else if (scan_type == SCAN_FIN) tcp->fin = 1;
	else if (scan_type == SCAN_NULL) { /* no flags */ }
	else if (scan_type == SCAN_XMAS) { tcp->fin = 1; tcp->psh = 1; tcp->urg = 1; }
	else tcp->syn = 1; // fallback

	tcp->check = tcp_checksum(ip, tcp, NULL, 0);

	// send packet
	if (sendto(rs, pkt, sizeof(pkt), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
		close(rs);
		pcap_close(pc);
		return PS_UNKNOWN;
	}

	// wait for reply until timeout
	double start = now_seconds();
	t_port_state result = PS_UNKNOWN;

	while ((now_seconds() - start) * 1000.0 < (double)timeout_ms) {
		struct pcap_pkthdr *hdr = NULL;
		const u_char *data = NULL;
		int r = pcap_next_ex(pc, &hdr, &data);
		if (r == 0) continue;          // timeout chunk, keep waiting
		if (r < 0) break;              // error/break

		// packet may have link-layer header; let pcap give us raw IP by checking DLT
		int dlt = pcap_datalink(pc);
		const u_char *ip_data = data;
		if (dlt == DLT_EN10MB) ip_data = data + 14; // ethernet
		else if (dlt == DLT_LINUX_SLL) ip_data = data + 16;

		const struct iphdr *rip = (const struct iphdr *)ip_data;
		if (rip->version != 4 || rip->protocol != IPPROTO_TCP) continue;

		const struct tcphdr *rtcp = (const struct tcphdr *)(ip_data + rip->ihl * 4);
		uint16_t rsrc = ntohs(rtcp->source);
		uint16_t rdst = ntohs(rtcp->dest);
		if (rsrc != port || rdst != sport) continue;

		uint8_t flags = 0;
		if (rtcp->rst) flags |= TH_RST;
		if (rtcp->syn) flags |= TH_SYN;
		if (rtcp->ack) flags |= TH_ACK;
		if (rtcp->fin) flags |= TH_FIN;
		if (rtcp->psh) flags |= TH_PUSH;
		if (rtcp->urg) flags |= TH_URG;

		result = parse_tcp_reply(flags, scan_type);

		// Map missing-reply meaning depending on scan type
		if (result != PS_UNKNOWN) break;
	}

	// no reply: interpret
	if (result == PS_UNKNOWN) {
		if (scan_type == SCAN_SYN) result = PS_FILTERED;
		else if (scan_type == SCAN_ACK) result = PS_FILTERED;
		else if (scan_type == SCAN_FIN || scan_type == SCAN_NULL || scan_type == SCAN_XMAS)
			result = PS_OPEN_FILTERED;
	}

	close(rs);
	pcap_close(pc);
	return result;
}

t_port_state probe_udp_basic(const char *target, uint16_t port, uint32_t timeout_ms)
{
	struct sockaddr_in dst;
	if (resolve_loopback_ipv4(target, &dst) != 0)
		return PS_UNKNOWN;
	dst.sin_port = htons(port);

	struct in_addr local_ip;
	if (get_local_ip_for_target(dst, &local_ip) != 0)
		return PS_UNKNOWN;

	uint16_t sport = pick_src_port();

	char errbuf[PCAP_ERRBUF_SIZE];
	memset(errbuf, 0, sizeof(errbuf));
	pcap_t *pc = pcap_open_any(errbuf, (int)timeout_ms);
	if (!pc) return PS_UNKNOWN;

	// We want:
	// 1) UDP reply from target:port to our sport  => Open
	// 2) ICMP dest-unreach port-unreach referencing our UDP packet => Closed
	//
	// BPF:
	// - udp from target:port to local:sport
	// - OR icmp from target to local (port unreachable)
	char filter[512];
	snprintf(filter, sizeof(filter),
	         "(udp and src host %s and src port %u and dst host %s and dst port %u) "
	         "or (icmp and src host %s and dst host %s)",
	         inet_ntoa(dst.sin_addr), (unsigned)port, inet_ntoa(local_ip), (unsigned)sport,
	         inet_ntoa(dst.sin_addr), inet_ntoa(local_ip));

	if (pcap_set_filter_or_fail(pc, filter) != 0) {
		pcap_close(pc);
		return PS_UNKNOWN;
	}

	// raw socket to craft UDP (optional), but easier: normal UDP send
	int us = socket(AF_INET, SOCK_DGRAM, 0);
	if (us < 0) {
		pcap_close(pc);
		return PS_UNKNOWN;
	}

	// bind to chosen sport
	struct sockaddr_in local;
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr = local_ip;
	local.sin_port = htons(sport);

	if (bind(us, (struct sockaddr *)&local, sizeof(local)) < 0) {
		// if bind fails, still try without fixed sport (but then filter might miss)
		// For correctness, fail.
		close(us);
		pcap_close(pc);
		return PS_UNKNOWN;
	}

	uint8_t payload[1] = {0};
	(void)sendto(us, payload, sizeof(payload), 0, (struct sockaddr *)&dst, sizeof(dst));

	double start = now_seconds();
	t_port_state result = PS_OPEN_FILTERED; // default for UDP: no response => Open|Filtered

	while ((now_seconds() - start) * 1000.0 < (double)timeout_ms) {
		struct pcap_pkthdr *hdr = NULL;
		const u_char *data = NULL;
		int r = pcap_next_ex(pc, &hdr, &data);
		if (r == 0) continue;
		if (r < 0) break;

		int dlt = pcap_datalink(pc);
		const u_char *ip_data = data;
		if (dlt == DLT_EN10MB) ip_data = data + 14;
		else if (dlt == DLT_LINUX_SLL) ip_data = data + 16;

		const struct iphdr *rip = (const struct iphdr *)ip_data;
		if (rip->version != 4) continue;

		if (rip->protocol == IPPROTO_UDP) {
			const struct udphdr *u = (const struct udphdr *)(ip_data + rip->ihl * 4);
			uint16_t rsrc = ntohs(u->source);
			uint16_t rdst = ntohs(u->dest);
			if (rsrc == port && rdst == sport) {
				result = PS_OPEN;
				break;
			}
		} else if (rip->protocol == IPPROTO_ICMP) {
			// Minimal ICMP parsing: type 3 = dest unreachable, code 3 = port unreachable
			const uint8_t *icmp = ip_data + rip->ihl * 4;
			uint8_t type = icmp[0];
			uint8_t code = icmp[1];
			if (type == 3 && code == 3) {
				// Inside ICMP payload there is original IP header + 8 bytes
				const uint8_t *inner_ip = icmp + 8;
				const struct iphdr *oip = (const struct iphdr *)inner_ip;
				if (oip->version != 4) continue;
				if (oip->protocol != IPPROTO_UDP) continue;

				const struct udphdr *oudp = (const struct udphdr *)(inner_ip + oip->ihl * 4);
				uint16_t osrc = ntohs(oudp->source);
				uint16_t odst = ntohs(oudp->dest);

				if (osrc == sport && odst == port) {
					result = PS_CLOSED;
					break;
				}
			}
		}
	}

	close(us);
	pcap_close(pc);
	return result;
}