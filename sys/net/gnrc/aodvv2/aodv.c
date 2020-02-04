/**
 * @file main.c
 * @author Locha Mesh Developers (contact@locha.io)
 * @brief Main firmware file
 * @version 0.1
 * @date 2020-02-02
 * 
 * @copyright Copyright (c) 2020 Locha Mesh project developers
 * @license Apache 2.0, see LICENSE file for details
 * 
 */

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
 * @{
 *
 * @file        aodv.c
 * @brief       aodvv2 routing protocol
 *
 * @author      Lotte Steenbrink <lotte.steenbrink@fu-berlin.de>
 * @author Gustavo Grisales <correo@dominio.com>
 */

#define ENABLE_DEBUG (1)
#include "aodv.h"
#include "debug.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include "assert.h"
#include "net/gnrc/udp.h"
#include "net/netdev_test.h"
#include "writer.h"

#define RCV_MSG_Q_SIZE (32) 

static char aodv_snd_stack_buf[GNRC_UDP_STACK_SIZE];
static gnrc_netif_t *ieee802154_netif = NULL;

static kernel_pid_t _pid = KERNEL_PID_UNDEF;
static char _stack[GNRC_UDP_STACK_SIZE];

static int sender_thread;
static int _sock_snd;
struct netaddr na_mcast = (struct netaddr){};
ipv6_addr_t ipv6_addrs = {0};

static void _init_sock_snd(void);
static void *_event_loop(void *arg);
static void *_aodv_sender_thread(void *arg);




void aodv_init(void) {
  DEBUG("listening on port \n");
  DEBUG("%s()\n", __func__);

  // get netif interface
  ieee802154_netif = gnrc_netif_iter(ieee802154_netif);
  if (ieee802154_netif != NULL) {
    DEBUG("interface: %d\n", ieee802154_netif->pid);
  }

  // get ipv6 address
  int r = gnrc_netapi_get(ieee802154_netif->pid, NETOPT_IPV6_ADDR, 0,
                          &ipv6_addrs, sizeof(ipv6_addrs));
  if (r < 0) {
    return;
  }

  for (unsigned i = 0; i < (unsigned)(r / sizeof(ipv6_addr_t)); i++) {
    char ipv6_addr[IPV6_ADDR_MAX_STR_LEN];
    ipv6_addr_to_str(ipv6_addr, &ipv6_addrs, IPV6_ADDR_MAX_STR_LEN);
    DEBUG("IPV6 address:  %s\n", ipv6_addr);
  }

  if (_pid == KERNEL_PID_UNDEF) {
    /* start thread */
    _pid = thread_create(_stack, sizeof(_stack), GNRC_UDP_PRIO,
                         THREAD_CREATE_STACKTEST, _event_loop, NULL, "IPV6");
  }

  sender_thread = thread_create(aodv_snd_stack_buf, sizeof(aodv_snd_stack_buf),
                                  THREAD_PRIORITY_MAIN-1, THREAD_CREATE_STACKTEST, _aodv_sender_thread,
                                  NULL, "_aodv_sender_thread");
  _init_sock_snd();
}


static void *_event_loop(void *arg) {
  (void)arg;
  msg_t msg, reply;
  msg_t msg_queue[GNRC_UDP_MSG_QUEUE_SIZE];
  gnrc_netreg_entry_t netreg =
      GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL, sched_active_pid);
  /* preset reply message */
  reply.type = GNRC_NETAPI_MSG_TYPE_ACK;
  reply.content.value = (uint32_t)-ENOTSUP;
  /* initialize message queue */
  msg_init_queue(msg_queue, GNRC_UDP_MSG_QUEUE_SIZE);
  /* register UPD at netreg */
  gnrc_netreg_register(GNRC_NETTYPE_UDP, &netreg);

  /* dispatch NETAPI messages */
  DEBUG("==========GNRC_AODVV2===========EVENT LOOP "
        "INIT========================================\n");
  while (1) {
    msg_receive(&msg);
    switch (msg.type) {
    case GNRC_NETAPI_MSG_TYPE_RCV:
      break;
    case GNRC_NETAPI_MSG_TYPE_SND:
     
      break;
    case GNRC_NETAPI_MSG_TYPE_SET:
    case GNRC_NETAPI_MSG_TYPE_GET:
      msg_reply(&msg, &reply);
      break;
    default:
      DEBUG("udp: received unidentified message\n");
      break;
    }
  }

  /* never reached */
  return NULL;
}

// init socket communication for sender
static void _init_sock_snd(void) {
  _sock_snd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (_sock_snd < 0) {
    DEBUG("Error Creating Socket!\n");
  }
}


void aodv_send_rreq(struct aodvv2_packet_data *packet_data)
{
    struct aodvv2_packet_data *pd = malloc(sizeof(struct aodvv2_packet_data));
    memcpy(pd, packet_data, sizeof(struct aodvv2_packet_data));

    struct rreq_rrep_data *rd = malloc(sizeof(struct rreq_rrep_data));
    *rd = (struct rreq_rrep_data) {
        .next_hop = &na_mcast,
        .packet_data = pd,
    };

    struct msg_container *mc = malloc(sizeof(struct msg_container));
    *mc = (struct msg_container) {
        .type = RFC5444_MSGTYPE_RREQ,
        .data = rd
    };

    msg_t msg;
    msg.content.ptr = (char *) mc;

    msg_try_send(&msg, sender_thread);
}


// Build RREQs, RREPs and RERRs from the information contained in the thread's
// message queue and send them
static void *_aodv_sender_thread(void *arg) {
  (void)arg;

  msg_t msgq[RCV_MSG_Q_SIZE];
  msg_init_queue(msgq, sizeof msgq);
  DEBUG("_aodv_sender_thread initialized.\n");

  while (true) {
    DEBUG("%s()\n", __func__);
    msg_t msg;
    msg_receive(&msg);
    DEBUG("AODV SENDER THREAD--------->>>>\n");
    struct msg_container *mc = (struct msg_container *)msg.content.ptr;

    if (mc->type == RFC5444_MSGTYPE_RREQ) {
      struct rreq_rrep_data *rreq_data = (struct rreq_rrep_data *)mc->data;
      aodv_packet_writer_send_rreq(rreq_data->packet_data, rreq_data->next_hop);
    }  else {
      DEBUG("ERROR: Couldn't identify Message\n");
    }
  }

  return NULL;
}