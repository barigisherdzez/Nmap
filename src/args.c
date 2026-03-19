#include "args.h"
#include "ports.h"
#include "targets.h"

void print_help(const char *prog)
{
	(void)prog;
	printf("Help Screen\n");
	printf("ft_nmap [OPTIONS]\n");
	printf("--help                          Print this help screen\n");
	printf("--ports  ports                  ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n");
	printf("--port   ports                  same as --ports (compat)\n");
	printf("--ip     ip_or_hostname         ip/hostname to scan (IPv4 or FQDN)\n");
	printf("--file   filename               file containing targets to scan (formatting is free)\n");
	printf("--speedup [250 max]             number of parallel threads to use (default: 0)\n");
	printf("--scan   SYN/NULL/FIN/XMAS/ACK/UDP  scan types (comma-separated)\n");
}

static int parse_int(const char *s, int *out)
{
	char *end = NULL;
	long v;

	if (!s || !*s) return -1;
	errno = 0;
	v = strtol(s, &end, 10);
	if (errno != 0 || end == s) return -1;
	while (*end && isspace((unsigned char)*end)) end++;
	if (*end != '\0') return -1;
	if (v < -2147483648L || v > 2147483647L) return -1;
	*out = (int)v;
	return 0;
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

static uint32_t scan_token_to_mask(const char *tok)
{
	if (strcasecmp(tok, "SYN") == 0)  return SCAN_SYN;
	if (strcasecmp(tok, "NULL") == 0) return SCAN_NULL;
	if (strcasecmp(tok, "ACK") == 0)  return SCAN_ACK;
	if (strcasecmp(tok, "FIN") == 0)  return SCAN_FIN;
	if (strcasecmp(tok, "XMAS") == 0) return SCAN_XMAS;
	if (strcasecmp(tok, "UDP") == 0)  return SCAN_UDP;
	return 0;
}

static int parse_scans(const char *spec, uint32_t *out_mask)
{
	char *tmp = strdup(spec);
	char *save = NULL;
	char *tok;

	if (!tmp) return -1;
	*out_mask = 0;

	for (tok = strtok_r(tmp, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		char *t = trim_inplace(tok);
		if (*t == '\0')
			continue;
		uint32_t m = scan_token_to_mask(t);
		if (!m) {
			free(tmp);
			return -1;
		}
		*out_mask |= m;
	}

	free(tmp);
	return (*out_mask == 0) ? -1 : 0;
}

int parse_args(int argc, char **argv, t_config *cfg)
{
	const char *ports_spec = NULL;
	const char *ip_spec = NULL;
	const char *file_spec = NULL;
	const char *scan_spec = NULL;
	int speedup = 0;

	if (argc <= 1) {
		print_help(argv[0]);
		return -1;
	}

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--help") == 0) {
			print_help(argv[0]);
			return -1;
		} else if (strcmp(argv[i], "--ports") == 0 || strcmp(argv[i], "--port") == 0) {
			if (i + 1 >= argc) return -1;
			ports_spec = argv[++i];
		} else if (strcmp(argv[i], "--ip") == 0) {
			if (i + 1 >= argc) return -1;
			ip_spec = argv[++i];
		} else if (strcmp(argv[i], "--file") == 0) {
			if (i + 1 >= argc) return -1;
			file_spec = argv[++i];
		} else if (strcmp(argv[i], "--speedup") == 0) {
			if (i + 1 >= argc) return -1;
			if (parse_int(argv[++i], &speedup) != 0) return -1;
		} else if (strcmp(argv[i], "--scan") == 0) {
			if (i + 1 >= argc) return -1;
			scan_spec = argv[++i];
		} else {
			fprintf(stderr, "Unknown option: %s\n", argv[i]);
			return -1;
		}
	}

	if ((ip_spec && file_spec) || (!ip_spec && !file_spec)) {
		fprintf(stderr, "Error: use exactly one of --ip or --file\n");
		return -1;
	}

	cfg->threads = speedup;
	if (cfg->threads < 0) cfg->threads = 0;
	if (cfg->threads > FTN_MAX_THREADS) cfg->threads = FTN_MAX_THREADS;

	cfg->timeout_ms = FTN_DEFAULT_TIMEOUT_MS;

	if (scan_spec) {
		if (parse_scans(scan_spec, &cfg->scans_mask) != 0) {
			fprintf(stderr, "Error: invalid --scan\n");
			return -1;
		}
	} else {
		cfg->scans_mask = (SCAN_SYN | SCAN_NULL | SCAN_ACK | SCAN_FIN | SCAN_XMAS | SCAN_UDP);
	}

	if (ports_spec) {
		if (parse_ports(ports_spec, &cfg->ports, &cfg->port_count) != 0) {
			fprintf(stderr, "Error: invalid --ports\n");
			return -1;
		}
	} else {
		if (default_ports(&cfg->ports, &cfg->port_count) != 0) {
			fprintf(stderr, "Error: failed to build default ports\n");
			return -1;
		}
	}

	if (cfg->port_count > FTN_MAX_PORTS) {
		fprintf(stderr, "Error: number of ports exceeds %d\n", FTN_MAX_PORTS);
		return -1;
	}

	if (ip_spec) {
		if (set_single_target(cfg, ip_spec) != 0) {
			fprintf(stderr, "Error: invalid --ip\n");
			return -1;
		}
	} else {
		if (load_targets_from_file(cfg, file_spec) != 0) {
			fprintf(stderr, "Error: invalid --file\n");
			return -1;
		}
	}

	// NEW: remove duplicates (127.0.0.1 twice, etc.)
	dedupe_targets(cfg);

	return 0;
}