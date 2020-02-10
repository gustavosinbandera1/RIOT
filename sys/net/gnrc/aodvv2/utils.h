/*
                    
 * Copyright (C) 2014 Freie Universität Berlin
 * Copyright (C) 2014 Lotte Steenbrink <lotte.steenbrink@fu-berlin.de>
 * Copyright (C) 2020 Locha Inc
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */
/**
                    
 * @ingroup     aodvv2
 *
 * @file        aodv.c|
 * @brief       aodvv2 routing protocol
 *
 * @author      Lotte Steenbrink <lotte.steenbrink@fu-berlin.de>
 * @author Gustavo Grisales <gustavosinbandera1@hotmail.com>
 */
#ifndef AODVV2_UTILS_H_
#define AODVV2_UTILS_H_

#include <stdio.h>

#include "ipv6.h"

#include "common/netaddr.h"
#include "constants.h"


#ifdef __cplusplus
extern "C" {
#endif


#define AODVV2_RIOT_PREFIXLEN  128  /* Prefix length of the IPv6 addresses  used in the network served by AODVv2 () */

/**
 * Convert an IP stored as an ipv6_addr_t to a netaddr
 * @param src       ipv6_addr_t to convert
 * @param dst       (empty) netaddr to convert into
 */
void ipv6_addr_t_to_netaddr(ipv6_addr_t *src, struct netaddr *dst);

/**
 * Convert an IP stored as a netaddr to an ipv6_addr_t
 * @param src       (empty) netaddr to convert into
 * @param dst       ipv6_addr_t to convert
 */
void netaddr_to_ipv6_addr_t(struct netaddr *src, ipv6_addr_t *dst);

#ifdef  __cplusplus
}
#endif

#endif /* AODVV2_UTILS_H_ */
