#include "scan.h"
#include "output.h"
#include "services.h"
#include "probe.h"

#include <pthread.h>

typedef struct s_task {
	const char      *target;
	const t_config  *cfg;
	t_port_result   *res;
	size_t           idx;
	struct sockaddr_in dst;
} t_task;

static void apply_tcp_mapping(t_port_result *r, uint32_t scans_mask, t_tcp_obs obs)
{
	// SYN: Open/Closed/Filtered
	if (scans_mask & SCAN_SYN) {
		r->syn = (obs == TCP_OBS_OPEN) ? PS_OPEN :
		         (obs == TCP_OBS_CLOSED) ? PS_CLOSED : PS_FILTERED;
	}

	// NULL/FIN/XMAS: Closed if RST, else Open|Filtered
	if (scans_mask & SCAN_NULL) {
		r->nulls = (obs == TCP_OBS_CLOSED) ? PS_CLOSED : PS_OPEN_FILTERED;
	}
	if (scans_mask & SCAN_FIN) {
		r->fin = (obs == TCP_OBS_CLOSED) ? PS_CLOSED : PS_OPEN_FILTERED;
	}
	if (scans_mask & SCAN_XMAS) {
		r->xmas = (obs == TCP_OBS_CLOSED) ? PS_CLOSED : PS_OPEN_FILTERED;
	}

	// ACK: Unfiltered if RST (closed), else Filtered
	if (scans_mask & SCAN_ACK) {
		r->ack = (obs == TCP_OBS_CLOSED) ? PS_UNFILTERED : PS_FILTERED;
	}
}

static void do_probe_one_port(void *arg)
{
	t_task *t = (t_task *)arg;
	const t_config *cfg = t->cfg;
	size_t idx = t->idx;
	uint16_t port = cfg->ports[idx];

	t_port_result *r = &t->res[idx];
	memset(r, 0, sizeof(*r));

	r->port = port;
	snprintf(r->service, sizeof(r->service), "%s", service_name_tcp(port));

	// default states
	r->syn   = PS_UNKNOWN;
	r->nulls = PS_UNKNOWN;
	r->ack   = PS_UNKNOWN;
	r->fin   = PS_UNKNOWN;
	r->xmas  = PS_UNKNOWN;
	r->udp   = PS_UNKNOWN;

	// Safe mode: ONLY localhost/127.0.0.1
	// (resolve_loopback_ipv4 already enforced in run_scan_for_target)
	uint32_t m = cfg->scans_mask;

	// If any TCP scan is requested, do one TCP observation
	if (m & (SCAN_SYN | SCAN_NULL | SCAN_FIN | SCAN_XMAS | SCAN_ACK)) {
		t_tcp_obs obs = probe_tcp_connect(&t->dst, port, cfg->timeout_ms);
		apply_tcp_mapping(r, m, obs);
	}

	// UDP scan
	if (m & SCAN_UDP) {
		r->udp = probe_udp_basic(&t->dst, port, cfg->timeout_ms);
	}

	free(t);
}

int run_scan_for_target(const char *target, const t_config *cfg, double *out_seconds)
{
	double t0 = now_seconds();

	struct sockaddr_in dst;
	if (resolve_loopback_ipv4(target, &dst) != 0) {
		fprintf(stderr, "Error: this build only allows scanning 127.0.0.1/localhost\n");
		return -1;
	}

	t_port_result *res = calloc(cfg->port_count, sizeof(*res));
	if (!res) return -1;

	print_config(target, cfg);

	// Nicer dots: always show at least 8, at most 64
	size_t dots = cfg->port_count;
	if (dots < 8) dots = 8;
	if (dots > 64) dots = 64;

	int nthreads = (cfg->threads <= 0) ? 1 : cfg->threads;

	t_threadpool tp;
	if (tp_init(&tp, nthreads) != 0) {
		free(res);
		return -1;
	}

	for (size_t i = 0; i < cfg->port_count; i++) {
		t_task *task = calloc(1, sizeof(*task));
		if (!task) continue;
		task->target = target;
		task->cfg = cfg;
		task->res = res;
		task->idx = i;
		task->dst = dst;

		if (tp_submit(&tp, do_probe_one_port, task) != 0)
			free(task);
	}

	printf("Scanning..\n");
	for (size_t i = 0; i < dots; i++) {
		printf(".");
		fflush(stdout);
	}
	printf("\n\n");

	tp_wait(&tp);
	tp_destroy(&tp);

	print_results(target, cfg, res);

	free(res);

	double t1 = now_seconds();
	if (out_seconds)
		*out_seconds = (t1 - t0);
	return 0;
}