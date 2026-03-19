#ifndef PORTS_H
#define PORTS_H

#include "ft_nmap.h"

int  parse_ports(const char *spec, uint16_t **out_ports, size_t *out_count);
int  default_ports(uint16_t **out_ports, size_t *out_count);

#endif