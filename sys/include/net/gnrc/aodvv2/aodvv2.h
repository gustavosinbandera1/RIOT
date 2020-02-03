
/* Copyright (C) 2014 Freie Universität Berlin
 * Copyright (C) 2014 Lotte Steenbrink <lotte.steenbrink@fu-berlin.de>
 * Copyright (C) 2020 Locha Inc
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     aodvv2
 * @{
 *
 * @file        aodvv2/types.h
 * @brief       data types for the aodvv2 routing protocol
 *
 * @author      Lotte Steenbrink <lotte.steenbrink@fu-berlin.de>
 * @author      Gustavo Grisales <gustavosinbandera1@hotmail.com.com>
 */

#ifndef AODVV2_H_
#define AODVV2_H_

#include "common/netaddr.h"
#include "rfc5444/rfc5444_print.h"

#include "net/gnrc/aodvv2/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Initialize the AODVv2 routing protocol.
 */
void gnrc_aodvv2_init(void);

/**
 * @brief   Set the metric type. If metric_type does not match any known metric
 *          types, no changes will be made.
 *
 * @param[in] metric_type       type of new metric
 */
void gnrc_aodv2_set_metric_type(aodvv2_metric_t metric_type);

#ifdef __cplusplus
}
#endif

#endif /* AODVV2_H_ */
/** @} */
