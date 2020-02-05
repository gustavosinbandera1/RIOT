/*
 * Copyright (C) 2014 Freie Universität Berlin
 * Copyright (C) 2014 Lotte Steenbrink <lotte.steenbrink@fu-berlin.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     aodvv2
 * @{
 *
 * @file        utils.c
 * @brief       client- and RREQ-table, ipv6 address representation converters
 *
 * @author      Lotte Steenbrink <lotte.steenbrink@fu-berlin.de>
 */

#include "utils.h"
#define ENABLE_DEBUG (1)
#include "debug.h"


void ipv6_addr_t_to_netaddr(ipv6_addr_t *src, struct netaddr *dst)
{
    dst->_type = AF_INET6;
    dst->_prefix_len = AODVV2_RIOT_PREFIXLEN;
    memcpy(dst->_addr, src, sizeof(dst->_addr));
}

void netaddr_to_ipv6_addr_t(struct netaddr *src, ipv6_addr_t *dst)
{
    memcpy(dst, src->_addr, sizeof(uint8_t) * NETADDR_MAX_LENGTH);
}
