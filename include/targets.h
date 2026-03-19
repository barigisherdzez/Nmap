#ifndef TARGETS_H
#define TARGETS_H

#include "ft_nmap.h"

int  set_single_target(t_config *cfg, const char *ip_or_host);
int  load_targets_from_file(t_config *cfg, const char *path);
void dedupe_targets(t_config *cfg);
void free_targets(t_config *cfg);

#endif