#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

int resolve_loopback_ipv4(const char *target, struct sockaddr_in *out)
{
	if (!target || !out) return -1;

	memset(out, 0, sizeof(*out));
	out->sin_family = AF_INET;

	// Fast path: literal IPv4
	if (inet_pton(AF_INET, target, &out->sin_addr) == 1)
		return 0;

	// Allow "localhost" as a special case
	if (strcmp(target, "localhost") == 0) {
		out->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		return 0;
	}

	// Optional DNS resolve (still "standard C lib")
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	struct addrinfo *res = NULL;
	if (getaddrinfo(target, NULL, &hints, &res) != 0 || !res)
		return -1;

	struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
	out->sin_addr = sin->sin_addr;

	freeaddrinfo(res);
	return 0;
}