
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

#ifndef AODV_H_
#define AODV_H_

#include "constants.h"
#include "seqnum.h"
#include "net/gnrc/aodvv2/types.h"
#include "thread.h"
#include "udp.h"
#include "reader.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief   This struct contains data which needs to be put into a RREQ or RREP.
     *          It is used to transport this data in a message to the sender_thread.
     * @note    Please note that it is for internal use only. To send a RREQ or
     * RREP, please use the aodv_send_rreq() and aodv_send_rrep() functions.
     */
    struct rreq_rrep_data
    {
        struct aodvv2_packet_data *packet_data; /**< Data for the RREQ or RREP */
        struct netaddr *next_hop;               /**< Next hop to which the RREQ
                                           *   or RREP should be sent */
    };

/**
 * @brief   This struct contains data which needs to be put into a RERR.
 *          It is used to transport this data in a message to the sender_thread.
 * @note    Please note that it is for internal use only. To send a RERR,
 *          please use the aodv_send_rerr() function.
 */
    struct rerr_data
    {
        struct unreachable_node
            *unreachable_nodes;   /**< All unreachable nodes. Beware,
                             *   this is the start of an array */
        size_t len;               /**< Length of the unreachable_nodes array */
        int hoplimit;             /**< hoplimit for the RERR */
        struct netaddr *next_hop; /**< Next hop to which the RERR
                             *   should be sent */
    };

/**
 * @brief   This struct holds the data for a RREQ, RREP or RERR (contained
 *          in a rreq_rrep_data or rerr_data struct) and the next hop the RREQ,
 * RREP or RERR should be sent to. It used for message communication with the
 * sender_thread.
 * @note    Please note that it is for internal use only. To send a RERR,
 *          please use the aodv_send_rerr() function.
 */
    struct msg_container
    {
        int type;   /**< Message type (i.e. one of
               *   rfc5444_msg_type) */
        void *data; /**< Pointer to the message data
               * (i.e. rreq_rrep_data or rerr_data) */
    };

/**
 * @brief   When set as ipv6_iface_routing_provider, this function is called by
 *          ipv6_sendto() to determine the next hop towards dest. This function
 *          is non-blocking.
 *
 * @param[in] dest  destination of the packet
 * @return          Address of the next hop towards dest if there is any,
 *                  NULL if there is none (yet)
 */
    // ipv6_addr_t *aodv_get_next_hop(ipv6_addr_t *dest);

/**
 * @brief   Dispatch a RREQ
 *
 * @param[in] packet_data  Payload of the RREQ
 */
    void gnrc_aodv_send_rreq(struct aodvv2_packet_data *packet_data);
    ipv6_addr_t *gnrc_aodv_get_next_hop(ipv6_addr_t *dest);
    static int udp_send(ipv6_addr_t dest_addr, uint16_t port, void *data, size_t len);
#ifdef __cplusplus
}
#endif

#endif /* AODV_H_ */
