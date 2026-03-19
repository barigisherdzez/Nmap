#include "output.h"
#include <stdbool.h>

static void print_scans_mask(uint32_t m)
{
	if (m & SCAN_SYN)  printf("SYN ");
	if (m & SCAN_NULL) printf("NULL ");
	if (m & SCAN_FIN)  printf("FIN ");
	if (m & SCAN_XMAS) printf("XMAS ");
	if (m & SCAN_ACK)  printf("ACK ");
	if (m & SCAN_UDP)  printf("UDP ");
}

static void print_sep(void)
{
	// fixed width separator: clean output on most terminals
	for (int i = 0; i < 110; i++)
		putchar('-');
	putchar('\n');
}

const char *state_str(t_port_state s)
{
	if (s == PS_OPEN) return "Open";
	if (s == PS_CLOSED) return "Closed";
	if (s == PS_FILTERED) return "Filtered";
	if (s == PS_UNFILTERED) return "Unfiltered";
	if (s == PS_OPEN_FILTERED) return "Open|Filtered";
	return "Unknown";
}

void print_config(const char *target, const t_config *cfg)
{
	printf("Scan Configurations\n");
	printf("Target Ip-Address : %s\n", target);
	printf("No of Ports to scan : %zu\n", cfg->port_count);
	printf("Scans to be performed : ");
	print_scans_mask(cfg->scans_mask);
	printf("\n");
	printf("No of threads : %d\n", cfg->threads);
}

t_port_state aggregate_conclusion(const t_config *cfg, const t_port_result *r)
{
	bool any_open = false;
	bool any_closed = false;
	bool any_filtered = false;

	if (cfg->scans_mask & SCAN_SYN) {
		any_open |= (r->syn == PS_OPEN);
		any_closed |= (r->syn == PS_CLOSED);
		any_filtered |= (r->syn == PS_FILTERED || r->syn == PS_OPEN_FILTERED);
	}
	if (cfg->scans_mask & SCAN_NULL) {
		any_open |= (r->nulls == PS_OPEN);
		any_closed |= (r->nulls == PS_CLOSED);
		any_filtered |= (r->nulls == PS_FILTERED || r->nulls == PS_OPEN_FILTERED);
	}
	if (cfg->scans_mask & SCAN_ACK) {
		any_open |= (r->ack == PS_OPEN);
		any_closed |= (r->ack == PS_CLOSED);
		any_filtered |= (r->ack == PS_FILTERED || r->ack == PS_OPEN_FILTERED);
	}
	if (cfg->scans_mask & SCAN_FIN) {
		any_open |= (r->fin == PS_OPEN);
		any_closed |= (r->fin == PS_CLOSED);
		any_filtered |= (r->fin == PS_FILTERED || r->fin == PS_OPEN_FILTERED);
	}
	if (cfg->scans_mask & SCAN_XMAS) {
		any_open |= (r->xmas == PS_OPEN);
		any_closed |= (r->xmas == PS_CLOSED);
		any_filtered |= (r->xmas == PS_FILTERED || r->xmas == PS_OPEN_FILTERED);
	}
	if (cfg->scans_mask & SCAN_UDP) {
		any_open |= (r->udp == PS_OPEN);
		any_closed |= (r->udp == PS_CLOSED);
		any_filtered |= (r->udp == PS_FILTERED || r->udp == PS_OPEN_FILTERED);
	}

	if (any_open) return PS_OPEN;
	if (any_closed) return PS_CLOSED;
	if (any_filtered) return PS_FILTERED;
	return PS_UNKNOWN;
}

static void print_scan_states_inline(const t_config *cfg, const t_port_result *r, int *printed)
{
	// prints up to 3 scan tokens per line, then wrap
	int per_line = 3;

	if (cfg->scans_mask & SCAN_SYN) {
		if (*printed && (*printed % per_line == 0)) printf("\n%18s", "");
		printf("SYN(%s) ", state_str(r->syn));
		(*printed)++;
	}
	if (cfg->scans_mask & SCAN_NULL) {
		if (*printed && (*printed % per_line == 0)) printf("\n%18s", "");
		printf("NULL(%s) ", state_str(r->nulls));
		(*printed)++;
	}
	if (cfg->scans_mask & SCAN_FIN) {
		if (*printed && (*printed % per_line == 0)) printf("\n%18s", "");
		printf("FIN(%s) ", state_str(r->fin));
		(*printed)++;
	}
	if (cfg->scans_mask & SCAN_XMAS) {
		if (*printed && (*printed % per_line == 0)) printf("\n%18s", "");
		printf("XMAS(%s) ", state_str(r->xmas));
		(*printed)++;
	}
	if (cfg->scans_mask & SCAN_ACK) {
		if (*printed && (*printed % per_line == 0)) printf("\n%18s", "");
		printf("ACK(%s) ", state_str(r->ack));
		(*printed)++;
	}
	if (cfg->scans_mask & SCAN_UDP) {
		if (*printed && (*printed % per_line == 0)) printf("\n%18s", "");
		printf("UDP(%s) ", state_str(r->udp));
		(*printed)++;
	}
}

static void print_row(const t_config *cfg, const t_port_result *r)
{
	// Start row
	printf("%5u %-12s ", r->port, r->service);

	int printed = 0;
	print_scan_states_inline(cfg, r, &printed);

	// Conclusion at end (always on last line)
	printf("=> %s\n", state_str(aggregate_conclusion(cfg, r)));
}

void print_results(const char *target, const t_config *cfg, t_port_result *res)
{
	printf("\nIP address: %s\n", target);

	printf("Open ports:\n");
	printf("Port  Service      Results Conclusion\n");
	print_sep();
	for (size_t i = 0; i < cfg->port_count; i++) {
		if (aggregate_conclusion(cfg, &res[i]) == PS_OPEN)
			print_row(cfg, &res[i]);
	}

	printf("Closed/Filtered/Unfiltered ports:\n");
	printf("Port  Service      Results Conclusion\n");
	print_sep();
	for (size_t i = 0; i < cfg->port_count; i++) {
		if (aggregate_conclusion(cfg, &res[i]) != PS_OPEN)
			print_row(cfg, &res[i]);
	}
}