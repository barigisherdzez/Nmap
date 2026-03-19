#ifndef ARGS_H
#define ARGS_H

#include "ft_nmap.h"

void print_help(const char *prog);
int  parse_args(int argc, char **argv, t_config *cfg);

#endif