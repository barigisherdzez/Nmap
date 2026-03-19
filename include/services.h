#ifndef SERVICES_H
#define SERVICES_H

#include "ft_nmap.h"

const char *service_name_tcp(uint16_t port);
const char *service_name_udp(uint16_t port);

#endif