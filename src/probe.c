#include "probe.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>


int resolve_loopback_ipv4(const char *target, struct sockaddr_in *out)
{
	if (!target || !out)
		return -1;

	memset(out, 0, sizeof(*out));
	out->sin_family = AF_INET;

	if (strcmp(target, "localhost") == 0) {
		out->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		return 0;
	}

	if (inet_pton(AF_INET, target, &out->sin_addr) == 1)
		return 0;

	return -1;
}

static int set_nonblock(int fd, bool nb)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) return -1;
	if (nb) flags |= O_NONBLOCK;
	else flags &= ~O_NONBLOCK;
	return fcntl(fd, F_SETFL, flags);
}

int resolve_loopback_ipv4(const char *target, struct sockaddr_in *out)
{
	if (!target || !out) return -1;
	memset(out, 0, sizeof(*out));
	out->sin_family = AF_INET;

	// SAFE MODE: only allow localhost targets
	if (strcmp(target, "127.0.0.1") == 0 || strcmp(target, "localhost") == 0) {
		out->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		return 0;
	}
	return -1;
}

t_tcp_obs probe_tcp_connect(const struct sockaddr_in *dst, uint16_t port, uint32_t timeout_ms)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return TCP_OBS_FILTERED;

	if (set_nonblock(fd, true) != 0) {
		close(fd);
		return TCP_OBS_FILTERED;
	}

	struct sockaddr_in sa = *dst;
	sa.sin_port = htons(port);

	int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (rc == 0) {
		close(fd);
		return TCP_OBS_OPEN;
	}
	if (errno != EINPROGRESS && errno != EALREADY) {
		// Immediate failure usually means RST/refused
		t_tcp_obs obs = (errno == ECONNREFUSED) ? TCP_OBS_CLOSED : TCP_OBS_FILTERED;
		close(fd);
		return obs;
	}

	fd_set wfds;
	FD_ZERO(&wfds);
	FD_SET(fd, &wfds);

	struct timeval tv;
	tv.tv_sec = (time_t)(timeout_ms / 1000);
	tv.tv_usec = (suseconds_t)((timeout_ms % 1000) * 1000);

	rc = select(fd + 1, NULL, &wfds, NULL, &tv);
	if (rc == 0) {
		// Timeout
		close(fd);
		return TCP_OBS_FILTERED;
	}
	if (rc < 0) {
		close(fd);
		return TCP_OBS_FILTERED;
	}

	int soerr = 0;
	socklen_t slen = (socklen_t)sizeof(soerr);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) != 0) {
		close(fd);
		return TCP_OBS_FILTERED;
	}

	close(fd);

	if (soerr == 0) return TCP_OBS_OPEN;
	if (soerr == ECONNREFUSED) return TCP_OBS_CLOSED;
	return TCP_OBS_FILTERED;
}

t_port_state probe_udp_basic(const struct sockaddr_in *dst, uint16_t port, uint32_t timeout_ms)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return PS_OPEN_FILTERED;

	// Use connect() so ICMP errors can be reported as ECONNREFUSED on recv()
	struct sockaddr_in sa = *dst;
	sa.sin_port = htons(port);

	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		// Rare for UDP, treat as open|filtered
		close(fd);
		return PS_OPEN_FILTERED;
	}

	// Send a minimal datagram
	const char payload[1] = {0};
	(void)send(fd, payload, sizeof(payload), 0);

	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	struct timeval tv;
	tv.tv_sec = (time_t)(timeout_ms / 1000);
	tv.tv_usec = (suseconds_t)((timeout_ms % 1000) * 1000);

	int rc = select(fd + 1, &rfds, NULL, NULL, &tv);
	if (rc == 0) {
		// No reply: open|filtered is the standard conclusion for UDP
		close(fd);
		return PS_OPEN_FILTERED;
	}
	if (rc < 0) {
		close(fd);
		return PS_OPEN_FILTERED;
	}

	char buf[256];
	ssize_t n = recv(fd, buf, sizeof(buf), 0);
	if (n > 0) {
		close(fd);
		return PS_OPEN; // got UDP response
	}

	// recv failed: on localhost you may get ECONNREFUSED => closed
	if (errno == ECONNREFUSED) {
		close(fd);
		return PS_CLOSED;
	}

	close(fd);
	return PS_OPEN_FILTERED;
}