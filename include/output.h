#ifndef OUTPUT_H
#define OUTPUT_H

#include "ft_nmap.h"

void print_config(const char *target, const t_config *cfg);
void print_results(const char *target, const t_config *cfg, t_port_result *res);

const char *state_str(t_port_state s);
t_port_state aggregate_conclusion(const t_config *cfg, const t_port_result *r);

#endif