#include "ports.h"

static int cmp_u16(const void *a, const void *b)
{
	uint16_t x = *(const uint16_t *)a;
	uint16_t y = *(const uint16_t *)b;
	return (x > y) - (x < y);
}

static char *trim_inplace(char *s)
{
	char *end;

	while (*s && isspace((unsigned char)*s))
		s++;

	if (*s == '\0')
		return s;

	end = s + strlen(s) - 1;
	while (end > s && isspace((unsigned char)*end))
		*end-- = '\0';

	return s;
}

static int add_port(uint16_t **arr, size_t *n, size_t *cap, uint16_t p)
{
	if (*n >= *cap) {
		size_t ncap = (*cap == 0) ? 64 : (*cap * 2);
		uint16_t *tmp = realloc(*arr, ncap * sizeof(uint16_t));
		if (!tmp) return -1;
		*arr = tmp;
		*cap = ncap;
	}
	(*arr)[(*n)++] = p;
	return 0;
}

static int parse_u16_strict(const char *s, uint16_t *out)
{
	char *end = NULL;
	long v;

	if (!s) return -1;

	while (*s && isspace((unsigned char)*s))
		s++;

	if (*s == '\0') return -1;

	errno = 0;
	v = strtol(s, &end, 10);
	if (errno != 0 || end == s) return -1;

	while (*end && isspace((unsigned char)*end))
		end++;

	if (*end != '\0') return -1;
	if (v < 1 || v > 65535) return -1;

	*out = (uint16_t)v;
	return 0;
}

int parse_ports(const char *spec, uint16_t **out_ports, size_t *out_count)
{
	char *tmp = strdup(spec);
	char *save = NULL;
	char *tok;
	uint16_t *ports = NULL;
	size_t n = 0, cap = 0;

	if (!tmp) return -1;

	for (tok = strtok_r(tmp, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		char *t = trim_inplace(tok);
		if (*t == '\0')
			continue;

		char *dash = strchr(t, '-');
		if (!dash) {
			uint16_t p;
			if (parse_u16_strict(t, &p) != 0 || add_port(&ports, &n, &cap, p) != 0) {
				free(tmp);
				free(ports);
				return -1;
			}
		} else {
			*dash = '\0';
			char *a = trim_inplace(t);
			char *b = trim_inplace(dash + 1);

			uint16_t pa, pb;
			if (parse_u16_strict(a, &pa) != 0 || parse_u16_strict(b, &pb) != 0) {
				free(tmp);
				free(ports);
				return -1;
			}

			if (pa > pb) {
				uint16_t sw = pa;
				pa = pb;
				pb = sw;
			}

			for (uint32_t p = pa; p <= pb; p++) {
				if (add_port(&ports, &n, &cap, (uint16_t)p) != 0) {
					free(tmp);
					free(ports);
					return -1;
				}
				if (p == 65535) break;
			}
		}
	}

	free(tmp);

	if (n == 0) {
		free(ports);
		return -1;
	}

	qsort(ports, n, sizeof(uint16_t), cmp_u16);

	// unique
	size_t w = 0;
	for (size_t i = 0; i < n; i++) {
		if (i == 0 || ports[i] != ports[i - 1])
			ports[w++] = ports[i];
	}

	*out_ports = ports;
	*out_count = w;
	return 0;
}

int default_ports(uint16_t **out_ports, size_t *out_count)
{
	uint16_t *p = malloc((FTN_DEFAULT_PORT_MAX) * sizeof(uint16_t));
	if (!p) return -1;

	for (int i = FTN_DEFAULT_PORT_MIN; i <= FTN_DEFAULT_PORT_MAX; i++)
		p[i - 1] = (uint16_t)i;

	*out_ports = p;
	*out_count = (size_t)FTN_DEFAULT_PORT_MAX;
	return 0;
}