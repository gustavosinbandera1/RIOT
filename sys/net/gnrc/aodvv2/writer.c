
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
#include "writer.h"
#include "debug.h"



static void _cb_addMessageHeader(struct rfc5444_writer *wr,
                                 struct rfc5444_writer_message *message);

static void _cb_rreq_addAddresses(struct rfc5444_writer *wr);

static mutex_t writer_mutex;

struct rfc5444_writer writer;
static struct writer_target _target;
static uint8_t _msg_buffer[128];
static uint8_t _msg_addrtlvs[1000];
static uint8_t _packet_buffer[128];

static struct rfc5444_writer_message *_rreq_msg;

/*
 * message content provider that will add message TLVs,
 * addresses and address block TLVs to all messages of type RREQ.
 */
static struct rfc5444_writer_content_provider _rreq_message_content_provider =
{
    .msg_type = RFC5444_MSGTYPE_RREQ,
    .addAddresses = _cb_rreq_addAddresses,
};

/* declaration of all address TLVs added to the RREQ message */
static struct rfc5444_writer_tlvtype _rreq_addrtlvs[] =
{
    [RFC5444_MSGTLV_ORIGSEQNUM] = { .type = RFC5444_MSGTLV_ORIGSEQNUM },
    [RFC5444_MSGTLV_METRIC] = {
        .type = RFC5444_MSGTLV_METRIC,
        .exttype = AODVV2_DEFAULT_METRIC_TYPE
    },
};


/**
 * Callback to define the message header for a RFC5444 RREQ message
 * @param message
 */
static void
_cb_addMessageHeader(struct rfc5444_writer *wr, struct rfc5444_writer_message *message)
{
    

    /* no originator, no hopcount, has hoplimit, no seqno */
    rfc5444_writer_set_msg_header(wr, message, false, false, true, false);
    rfc5444_writer_set_msg_hoplimit(wr, message, _target.packet_data.hoplimit);
}

/**
 * Callback to add addresses and address TLVs to a RFC5444 RREQ message
 */
static void
_cb_rreq_addAddresses(struct rfc5444_writer *wr)
{
   

    struct rfc5444_writer_address *origNode_addr;

    /* add origNode address (has no address tlv); is mandatory address */
    origNode_addr = rfc5444_writer_add_address(wr, _rreq_message_content_provider.creator,
                    &_target.packet_data.origNode.addr, true);

    /* add targNode address (has no address tlv); is mandatory address */
    rfc5444_writer_add_address(wr, _rreq_message_content_provider.creator,
                               &_target.packet_data.targNode.addr, true);

    /* add SeqNum TLV and metric TLV to origNode */
    /* TODO: allow_dup true or false? */
    rfc5444_writer_add_addrtlv(wr, origNode_addr, &_rreq_addrtlvs[RFC5444_MSGTLV_ORIGSEQNUM],
                               &_target.packet_data.origNode.seqnum,
                               sizeof(_target.packet_data.origNode.seqnum), false);
    /* cppcheck: suppress false positive on non-trivially initialized arrays.
     *           this is a known bug: http://trac.cppcheck.net/ticket/5497 */
    /* cppcheck-suppress arrayIndexOutOfBounds */
    rfc5444_writer_add_addrtlv(wr, origNode_addr, &_rreq_addrtlvs[RFC5444_MSGTLV_METRIC],
                               &_target.packet_data.origNode.metric,
                               sizeof(_target.packet_data.origNode.metric), false);
}


void gnrc_aodvv2_packet_writer_init(write_packet_func_ptr ptr)
{
    mutex_init(&writer_mutex);

    /* define interface for generating rfc5444 packets */
    _target.interface.packet_buffer = _packet_buffer;
    _target.interface.packet_size = sizeof(_packet_buffer);

    /* set function to send binary packet content */
    _target.interface.sendPacket = ptr;

    /* define the rfc5444 writer */
    writer.msg_buffer = _msg_buffer;
    writer.msg_size = sizeof(_msg_buffer);
    writer.addrtlv_buffer = _msg_addrtlvs;
    writer.addrtlv_size = sizeof(_msg_addrtlvs);

    /* initialize writer */
    rfc5444_writer_init(&writer);

    /* register a target (for sending messages to) in writer */
    rfc5444_writer_register_target(&writer, &_target.interface);

    /* register a message content providers for RREQ and RREP */
    rfc5444_writer_register_msgcontentprovider(&writer, &_rreq_message_content_provider,
                                               _rreq_addrtlvs, ARRAYSIZE(_rreq_addrtlvs));

    /* register rreq and rrep messages with 16 byte (ipv6) addresses.
     * AddPacketHeader & addMessageHeader callbacks are triggered here. */
    _rreq_msg = rfc5444_writer_register_message(&writer, RFC5444_MSGTYPE_RREQ,
                                                false, RFC5444_MAX_ADDRLEN);


    _rreq_msg->addMessageHeader = _cb_addMessageHeader;
}

/**
 * Send a RREQ. DO NOT use this function to dispatch packets from anything else
 * than the sender_thread. To send RREQs, use aodv_send_rreq().
 * @param packet_data parameters of the RREQ
 * @param next_hop Address the RREP is sent to
 */
void gnrc_aodvv2_packet_writer_send_rreq(struct aodvv2_packet_data *packet_data, struct netaddr *next_hop)
{
    (void)packet_data;
    (void)next_hop;

    if ((packet_data == NULL) || (next_hop == NULL)) {
        return;
    }

    // /* Make sure no other thread is using the writer right now */
    mutex_lock(&writer_mutex);
    memcpy(&_target.packet_data, packet_data, sizeof(struct aodvv2_packet_data));
    _target.type = RFC5444_MSGTYPE_RREQ;
    _target.packet_data.hoplimit = packet_data->hoplimit;

    // /* set address to which the write_packet callback should send our RREQ */
    memcpy(&_target.target_addr, next_hop, sizeof (struct netaddr));

    rfc5444_writer_create_message_alltarget(&writer, RFC5444_MSGTYPE_RREQ);
    rfc5444_writer_flush(&writer, &_target.interface, false);
    mutex_unlock(&writer_mutex);
}
