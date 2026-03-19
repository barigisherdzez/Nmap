#include "services.h"
#include <netdb.h>
#include <arpa/inet.h>

static const char *fallback(void)
{
	return "Unassigned";
}

static const char *svc_name(uint16_t port, const char *proto)
{
	// Thread-safe getservbyport_r + thread-local output buffer
	static __thread char out[64];
	struct servent se;
	struct servent *res = NULL;
	char buf[4096];

	int rc = getservbyport_r(htons(port), proto, &se, buf, sizeof(buf), &res);
	if (rc != 0 || !res || !res->s_name)
		return fallback();

	snprintf(out, sizeof(out), "%s", res->s_name);
	return out;
}

const char *service_name_tcp(uint16_t port)
{
	return svc_name(port, "tcp");
}

const char *service_name_udp(uint16_t port)
{
	return svc_name(port, "udp");
}