#ifndef SCAN_H
#define SCAN_H

#include "ft_nmap.h"
#include "threadpool.h"

// Returns 0 on success, -1 on error. If out_seconds != NULL, writes per-target elapsed seconds.
int run_scan_for_target(const char *target, const t_config *cfg, double *out_seconds);

#endif