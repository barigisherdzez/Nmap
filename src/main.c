#include "ft_nmap.h"
#include "args.h"
#include "targets.h"
#include "ports.h"
#include "scan.h"

static void free_config(t_config *cfg)
{
	free_targets(cfg);
	free(cfg->ports);
	memset(cfg, 0, sizeof(*cfg));
}

int main(int argc, char **argv)
{
	t_config cfg;
	memset(&cfg, 0, sizeof(cfg));

	if (parse_args(argc, argv, &cfg) != 0) {
		free_config(&cfg);
		return 1;
	}

	double all0 = now_seconds();

	for (size_t i = 0; i < cfg.target_count; i++) {
		double sec = 0.0;

		if (i > 0)
			printf("\n"); // blank line between targets

		if (run_scan_for_target(cfg.targets[i], &cfg, &sec) != 0) {
			fprintf(stderr, "Error: scan failed for target: %s\n", cfg.targets[i]);
		} else {
			printf("\nScan took %.5f secs\n", sec);
		}
	}

	double all1 = now_seconds();
	if (cfg.target_count > 1)
		printf("\nTotal scan time: %.5f secs\n", (all1 - all0));

	free_config(&cfg);
	return 0;
}