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
#include "aodvv2.h"
#include "debug.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

//#include "net/gnrc/netif/ieee802154.h"
//#include "net/netdev_test.h"

#include <stdio.h>

#include "net/gnrc/netapi.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netif/conf.h"
#include "net/gnrc/netreg.h"
#include "net/gnrc/pkt.h"
#include "net/gnrc/pktbuf.h"
#include "net/ipv6/addr.h"

#include "assert.h"
#include "net/gnrc/udp.h"


#include "net/gnrc/icmpv6/error.h"
//#include "net/inet_csum.h"

static gnrc_netif_t *ieee802154_netif = NULL;

#define _MSG_QUEUE_SIZE (2)
#define UDP_BUFFER_SIZE (128) /** with respect to IEEE 802.15.4's MTU */
#define RCV_MSG_Q_SIZE (32)   /* TODO: check if smaller values work, too */
#define IEEE802154_MAX_FRAG_SIZE (102)

static void _init_sock_snd(void);
static void *_event_loop(void *arg);

#ifdef ENABLE_DEBUG
char addr_str[IPV6_ADDR_MAX_STR_LEN];
#endif

static kernel_pid_t _pid = KERNEL_PID_UNDEF;
/**
 * @brief   Allocate memory for the UDP thread's stack
 */
//#define GNRC_UDP_STACK_SIZE     (THREAD_STACKSIZE_DEFAULT)
#if ENABLE_DEBUG
static char _stack[GNRC_UDP_STACK_SIZE + THREAD_EXTRA_STACKSIZE_PRINTF];
#else
static char _stack[GNRC_UDP_STACK_SIZE];
#endif

static int _sock_snd;
struct netaddr na_mcast = (struct netaddr){};
ipv6_addr_t ipv6_addrs = {0};

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

  _init_sock_snd();

}

static void _send(gnrc_pktsnip_t *pkt) {
  udp_hdr_t *hdr;
  gnrc_pktsnip_t *udp_snip, *tmp;
  gnrc_nettype_t target_type = pkt->type;

  /* write protect first header */
  tmp = gnrc_pktbuf_start_write(pkt);
  if (tmp == NULL) {
    DEBUG("AODV: cannot send packet: unable to allocate packet\n");
    gnrc_pktbuf_release(pkt);
    return;
  }
  pkt = tmp;
  udp_snip = tmp->next;
  /* get and write protect until udp snip */
  while ((udp_snip != NULL) && (udp_snip->type != GNRC_NETTYPE_UDP)) {
    udp_snip = gnrc_pktbuf_start_write(udp_snip);
    if (udp_snip == NULL) {
      DEBUG("AODV: cannot send packet: unable to allocate packet\n");
      gnrc_pktbuf_release(pkt);
      return;
    }
    tmp->next = udp_snip;
    tmp = udp_snip;
    udp_snip = udp_snip->next;
  }

  assert(udp_snip != NULL);

  /* write protect UDP snip */
  udp_snip = gnrc_pktbuf_start_write(udp_snip);
  if (udp_snip == NULL) {
    DEBUG("AODV: cannot send packet: unable to allocate packet\n");
    gnrc_pktbuf_release(pkt);
    return;
  }
  tmp->next = udp_snip;
  hdr = (udp_hdr_t *)udp_snip->data;
  /* fill in size field */
  hdr->length = byteorder_htons(gnrc_pkt_len(udp_snip));

  /* set to IPv6, if first header is netif header */
  if (target_type == GNRC_NETTYPE_NETIF) {
    target_type = pkt->next->type;
  }

  /* and forward packet to the network layer */
  DEBUG("AODV: Sending packet to the network layer!!!\n");
  //*_event_loop gnrc_ipv6.c receiving the data
  if (!gnrc_netapi_dispatch_send(target_type, GNRC_NETREG_DEMUX_CTX_ALL, pkt)) {
    DEBUG("AODV: cannot send packet: network layer not found\n");
    gnrc_pktbuf_release(pkt);
  }
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
      _send(msg.content.ptr);
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
