
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


#define ENABLE_DEBUG (1)
#include "debug.h"
#include "reader.h"



static enum rfc5444_result _cb_rreq_blocktlv_addresstlvs_okay(
    struct rfc5444_reader_tlvblock_context *cont);
static enum rfc5444_result _cb_rreq_blocktlv_messagetlvs_okay(
    struct rfc5444_reader_tlvblock_context *cont);
static enum rfc5444_result _cb_rreq_end_callback(
    struct rfc5444_reader_tlvblock_context *cont, bool dropped);


/* helper functions */
static uint8_t _get_link_cost(aodvv2_metric_t metricType);
static uint8_t _get_max_metric(aodvv2_metric_t metricType);
static void _update_metric(aodvv2_metric_t metricType, uint8_t *metric);

/* This is where we store data gathered from packets */
static struct aodvv2_packet_data packet_data;
//static struct unreachable_node unreachable_nodes[AODVV2_MAX_UNREACHABLE_NODES];
//static int num_unreachable_nodes;

static struct rfc5444_reader reader;
#ifdef DEBUG_ENABLED
static struct netaddr_str nbuf;
#endif

/*
 * Message consumer, will be called once for every message of
 * type RFC5444_MSGTYPE_RREQ that contains all the mandatory message TLVs
 */
static struct rfc5444_reader_tlvblock_consumer _rreq_consumer =
{
    .msg_id = RFC5444_MSGTYPE_RREQ,
    .block_callback = _cb_rreq_blocktlv_messagetlvs_okay,
    .end_callback = _cb_rreq_end_callback,
};

/*
 * Address consumer. Will be called once for every address in a message of
 * type RFC5444_MSGTYPE_RREQ.
 */
static struct rfc5444_reader_tlvblock_consumer _rreq_address_consumer =
{
    .msg_id = RFC5444_MSGTYPE_RREQ,
    .addrblock_consumer = true,
    .block_callback = _cb_rreq_blocktlv_addresstlvs_okay,
};


/*
 * Address consumer entries definition
 * TLV types RFC5444_MSGTLV__SEQNUM and RFC5444_MSGTLV_METRIC
 */
static struct rfc5444_reader_tlvblock_consumer_entry _rreq_rrep_address_consumer_entries[] =
{
    [RFC5444_MSGTLV_ORIGSEQNUM] = { .type = RFC5444_MSGTLV_ORIGSEQNUM},
    [RFC5444_MSGTLV_TARGSEQNUM] = { .type = RFC5444_MSGTLV_TARGSEQNUM},
    [RFC5444_MSGTLV_METRIC] = { .type = RFC5444_MSGTLV_METRIC }
};

/**
 * This block callback is called for every address
 *
 * @param cont
 * @return
 */
static enum rfc5444_result _cb_rreq_blocktlv_messagetlvs_okay(struct rfc5444_reader_tlvblock_context *cont)
{
    DEBUG("%s()\n", __func__);

    if (!cont->has_hoplimit) {
        DEBUG("\tERROR: missing hop limit\n");
        return RFC5444_DROP_PACKET;
    }

    packet_data.hoplimit = cont->hoplimit;
    if (packet_data.hoplimit == 0) {
        DEBUG("\tERROR: Hoplimit is 0.\n");
        return RFC5444_DROP_PACKET;
    }
    packet_data.hoplimit--;
    return RFC5444_OKAY;
}

/**
 * This block callback is called for every address of a RREQ Message.
 *
 * @param cont
 * @return
 */
static enum rfc5444_result _cb_rreq_blocktlv_addresstlvs_okay(struct rfc5444_reader_tlvblock_context *cont)
{
#ifdef DEBUG_ENABLED
    struct netaddr_str nbuf;
#endif
    struct rfc5444_reader_tlvblock_entry *tlv;
    bool is_origNode_addr = false;
    bool is_targNode_addr = false;

    DEBUG("%s()\n", __func__);
   // DEBUG("\taddr: %s\n", netaddr_to_string(&nbuf, &cont->addr));

    /* handle OrigNode SeqNum TLV */
    tlv = _rreq_rrep_address_consumer_entries[RFC5444_MSGTLV_ORIGSEQNUM].tlv;
    if (tlv) {
        DEBUG("\ttlv RFC5444_MSGTLV_ORIGSEQNUM: %d\n", *tlv->single_value);
        is_origNode_addr = true;
        packet_data.origNode.addr = cont->addr;
        packet_data.origNode.seqnum = *tlv->single_value;
    }

    /* handle TargNode SeqNum TLV */
    tlv = _rreq_rrep_address_consumer_entries[RFC5444_MSGTLV_TARGSEQNUM].tlv;
    if (tlv) {
        DEBUG("\ttlv RFC5444_MSGTLV_TARGSEQNUM: %d\n", *tlv->single_value);
        is_targNode_addr = true;
        packet_data.targNode.addr = cont->addr;
        packet_data.targNode.seqnum = *tlv->single_value;
    }
    if (!tlv && !is_origNode_addr) {
        /* assume that tlv missing => targNode Address */
        is_targNode_addr = true;
        packet_data.targNode.addr = cont->addr;
    }
    if (!is_origNode_addr && !is_targNode_addr) {
        DEBUG("\tERROR: mandatory RFC5444_MSGTLV_ORIGSEQNUM TLV missing.\n");
        return RFC5444_DROP_PACKET;
    }

    /* handle Metric TLV */
    /* cppcheck: suppress false positive on non-trivially initialized arrays.
     *           this is a known bug: http://trac.cppcheck.net/ticket/5497 */
    /* cppcheck-suppress arrayIndexOutOfBounds */
    tlv = _rreq_rrep_address_consumer_entries[RFC5444_MSGTLV_METRIC].tlv;
    if (!tlv && is_origNode_addr) {
        DEBUG("\tERROR: Missing or unknown metric TLV.\n");
        return RFC5444_DROP_PACKET;
    }
    if (tlv) {
        if (!is_origNode_addr) {
            DEBUG("\tERROR: Metric TLV belongs to wrong address.\n");
            return RFC5444_DROP_PACKET;
        }
        DEBUG("\ttlv RFC5444_MSGTLV_METRIC val: %d, exttype: %d\n",
               *tlv->single_value, tlv->type_ext);
        packet_data.metricType = tlv->type_ext;
        packet_data.origNode.metric = *tlv->single_value;
    }
    return RFC5444_OKAY;
}

/**
 * This callback is called every time the _rreq_consumer finishes reading a
 * packet.
 * @param cont
 * @param dropped indicates whether the packet has been dropped previously by
 *                another callback
 */
static enum rfc5444_result _cb_rreq_end_callback(
    struct rfc5444_reader_tlvblock_context *cont, bool dropped)
{
    (void) cont;

   // struct aodvv2_routing_entry_t *rt_entry;
   // timex_t now;
    uint8_t link_cost = _get_link_cost(packet_data.metricType);

    /* Check if packet contains the required information */
    if (dropped) {
        DEBUG("\t Dropping packet.\n");
        return RFC5444_DROP_PACKET;
    }
    if ((packet_data.origNode.addr._type == AF_UNSPEC) || !packet_data.origNode.seqnum) {
        DEBUG("\tERROR: missing OrigNode Address or SeqNum. Dropping packet.\n");
        return RFC5444_DROP_PACKET;
    }
    if (packet_data.targNode.addr._type == AF_UNSPEC) {
        DEBUG("\tERROR: missing TargNode Address. Dropping packet.\n");
        return RFC5444_DROP_PACKET;
    }
    if (packet_data.hoplimit == 0) {
        DEBUG("\tERROR: Hoplimit is 0. Dropping packet.\n");
        return RFC5444_DROP_PACKET;
    }
    if ((_get_max_metric(packet_data.metricType) - link_cost)
        <= packet_data.origNode.metric) {
        DEBUG("\tMetric Limit reached. Dropping packet.\n");
        return RFC5444_DROP_PACKET;
    }

    DEBUG("IN THIS POINT READER PACKET IS OK !!!!!!!\n\n");
    return RFC5444_OKAY;
}



void aodv_packet_reader_init(void)
{
    DEBUG("%s()\n", __func__);

    /* initialize reader */
    rfc5444_reader_init(&reader);

    /* register message consumers. We have no message TLVs, so we can leave the
     * rfc5444_reader_tlvblock_consumer_entry empty */
    rfc5444_reader_add_message_consumer(&reader, &_rreq_consumer,
                                        NULL, 0);

    /* register address consumer */
    rfc5444_reader_add_message_consumer(&reader, &_rreq_address_consumer,
                                        _rreq_rrep_address_consumer_entries,
                                        ARRAYSIZE(_rreq_rrep_address_consumer_entries));
}

void aodv_packet_reader_cleanup(void)
{
    DEBUG("%s()\n", __func__);
    rfc5444_reader_cleanup(&reader);
}

int aodv_packet_reader_handle_packet(void *buffer, size_t length, struct netaddr *sender)
{
    DEBUG("%s()\n", __func__);
    static struct netaddr_str nbuf;
    memcpy(&packet_data.sender, sender, sizeof(*sender));
    DEBUG("\t sender: %s\n", netaddr_to_string(&nbuf, &packet_data.sender));

    return rfc5444_reader_handle_packet(&reader, buffer, length);
}

/*============= HELPER FUNCTIONS =============================================*/

/*
 * Cost(L): Get Cost of a Link regarding the specified metric.
 * (currently only AODVV2_DEFAULT_METRIC_TYPE (HopCt) implemented)
 * returns cost if metric is known, NULL otherwise
 */
static uint8_t _get_link_cost(aodvv2_metric_t metricType)
{
    if (metricType == AODVV2_DEFAULT_METRIC_TYPE) {
        return 1;
    }
    return 0;
}

/*
 * MAX_METRIC[MetricType]:
 * returns maximum value of the given metric if metric is known, NULL otherwise.
 */
static uint8_t _get_max_metric(aodvv2_metric_t metricType)
{
    if (metricType == AODVV2_DEFAULT_METRIC_TYPE) {
        return AODVV2_MAX_HOPCOUNT;
    }
    return 0;
}

/*
 * Calculate a metric's new value according to the specified MetricType
 * (currently only implemented for AODVV2_DEFAULT_METRIC_TYPE (HopCt))
 */
static void _update_metric(aodvv2_metric_t metricType, uint8_t *metric)
{
    if (metricType == AODVV2_DEFAULT_METRIC_TYPE){
        *metric = *metric + 1;
    }
}