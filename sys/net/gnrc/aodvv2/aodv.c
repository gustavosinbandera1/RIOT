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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aodv.h"
#include "assert.h"
#include "debug.h"
#include "net/gnrc/udp.h"
#include "net/netdev_test.h"
#include "writer.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>

#include "net/gnrc/icmpv6/error.h"
#include "net/inet_csum.h"
#include "utils.h"

#define RCV_MSG_Q_SIZE (32)

static char aodv_snd_stack_buf[GNRC_UDP_STACK_SIZE];
static gnrc_netif_t *ieee802154_netif = NULL;

static kernel_pid_t _pid = KERNEL_PID_UNDEF;
static char _stack[GNRC_UDP_STACK_SIZE];

static int sender_thread;
static int _sock_snd;

struct netaddr na_mcast = (struct netaddr){};
static struct netaddr
    na_local; /* the same as _v6_addr_local, but to save us
               * constant calls to ipv6_addr_t_to_netaddr()... */

static ipv6_addr_t _v6_addr_local, _v6_addr_mcast, _v6_addr_loopback;
char addr_str[IPV6_ADDR_MAX_STR_LEN];

gnrc_pktsnip_t **pkt_temp;

static void _init_sock_snd(void);
static void *_event_loop(void *arg);
static void *gnrc_aodvv2_sender_thread(void *arg);
static void _send(gnrc_pktsnip_t *pkt);
static void _receive(gnrc_pktsnip_t *pkt);
static uint16_t _calc_csum(gnrc_pktsnip_t *hdr, gnrc_pktsnip_t *pseudo_hdr,
                           gnrc_pktsnip_t *payload);
static void gnrc_process_message(gnrc_pktsnip_t *pkt);
ipv6_addr_t gnrc_get_ipv6_from_iface(gnrc_netif_t *netif);
static void _write_packet(struct rfc5444_writer *wr __attribute__((unused)),
                          struct rfc5444_writer_target *iface
                          __attribute__((unused)),
                          void *buffer, size_t length);

void gnrc_aodvv2_init(void) {
  (void)_v6_addr_local;
  (void)_v6_addr_mcast;
  (void)_v6_addr_loopback;
  DEBUG("listening on port \n");
  DEBUG("%s()\n", __func__);

  // get netif interface
  ieee802154_netif = gnrc_netif_iter(ieee802154_netif);
  if (ieee802154_netif != NULL) {
    DEBUG("interface: %d\n", ieee802154_netif->pid);
  }
  gnrc_get_ipv6_from_iface(ieee802154_netif);

  if (_pid == KERNEL_PID_UNDEF) {
    /* start thread */
    _pid = thread_create(_stack, sizeof(_stack), GNRC_UDP_PRIO,
                         THREAD_CREATE_STACKTEST, _event_loop, NULL, "IPV6");
  }

  sender_thread = thread_create(
      aodv_snd_stack_buf, sizeof(aodv_snd_stack_buf), THREAD_PRIORITY_MAIN - 1,
      THREAD_CREATE_STACKTEST, gnrc_aodvv2_sender_thread, NULL,
      "gnrc_aodvv2_sender_thread");

  _init_sock_snd();
  gnrc_aodvv2_packet_writer_init(_write_packet);
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
  //
  while (1) {
    msg_receive(&msg);
    switch (msg.type) {
    case GNRC_NETAPI_MSG_TYPE_RCV:
      DEBUG("*****AODV**** CAPTURING MESSAGE FROM REMOTE CLIENT \n");
      _receive(msg.content.ptr);
      break;
    case GNRC_NETAPI_MSG_TYPE_SND:
      DEBUG("*****AODV**** CAPTURING MESSAGE FROM APPLICATION");
      //  aodv_get_next_hop();
      pkt_temp = (gnrc_pktsnip_t **)&msg.content.ptr;
      gnrc_process_message(msg.content.ptr);

      msg.content.ptr = *pkt_temp;
      //_send(msg.content.ptr);
      // _send(*pkt_temp);

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

void gnrc_aodv_send_rreq(struct aodvv2_packet_data *packet_data) {
  struct aodvv2_packet_data *pd = malloc(sizeof(struct aodvv2_packet_data));
  memcpy(pd, packet_data, sizeof(struct aodvv2_packet_data));

  struct rreq_rrep_data *rd = malloc(sizeof(struct rreq_rrep_data));
  *rd = (struct rreq_rrep_data){
      .next_hop = &na_mcast,
      .packet_data = pd,
  };

  struct msg_container *mc = malloc(sizeof(struct msg_container));

  *mc = (struct msg_container){.type = RFC5444_MSGTYPE_RREQ, .data = rd};

  msg_t msg;
  msg.content.ptr = (char *)mc;

  msg_try_send(&msg, sender_thread);
}

// Build RREQs, RREPs and RERRs from the information contained in the thread's
// message queue and send them
static void *gnrc_aodvv2_sender_thread(void *arg) {
  (void)arg;

  msg_t msgq[RCV_MSG_Q_SIZE];
  msg_init_queue(msgq, sizeof msgq);
  DEBUG("===================================================\n");
  DEBUG("===================================================\n");
  DEBUG("===================================================\n");
  DEBUG("===================================================\n");
  DEBUG("gnrc_aodvv2_sender_thread initialized.\n");

  while (true) {
    DEBUG("%s()\n", __func__);
    msg_t msg;
    msg_receive(&msg);
    DEBUG("***************************************\n");
    DEBUG("***************************************\n");
    DEBUG("***************************************\n");
    DEBUG("***************************************\n");
    DEBUG("AODV SENDER THREAD--------->>>>\n");
    struct msg_container *mc = (struct msg_container *)msg.content.ptr;

    if (mc->type == RFC5444_MSGTYPE_RREQ) {
      DEBUG("++++++++++++++++++++++++++++++++++++++\n");
      DEBUG("++++++++++++++++++++++++++++++++++++++\n");
      DEBUG("++++++++++++++++++++++++++++++++++++++\n");
      DEBUG("++++++++++++++++++++++++++++++++++++++\n");
      struct rreq_rrep_data *rreq_data = (struct rreq_rrep_data *)mc->data;
      gnrc_aodvv2_packet_writer_send_rreq(rreq_data->packet_data,
                                          rreq_data->next_hop);

    } else {
      DEBUG("ERROR: Couldn't identify Message\n");
    }
  }

  return NULL;
}

static void _send(gnrc_pktsnip_t *pkt) {
  udp_hdr_t *hdr;
  gnrc_pktsnip_t *udp_snip, *tmp;
  gnrc_nettype_t target_type = pkt->type;

  DEBUG("AODV---- _send(packet)\n");
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
  DEBUG("AODV: enviando paquete a la network layer!!!\n");
  if (!gnrc_netapi_dispatch_send(target_type, GNRC_NETREG_DEMUX_CTX_ALL, pkt)) {
    DEBUG("AODV: cannot send packet: network layer not found\n");
    gnrc_pktbuf_release(pkt);
  }
}

static void _receive(gnrc_pktsnip_t *pkt) {
  gnrc_pktsnip_t *udp, *ipv6;
  udp_hdr_t *hdr;
  uint32_t port;

  /* mark UDP header */
  udp = gnrc_pktbuf_start_write(pkt);
  if (udp == NULL) {
    DEBUG("udp: unable to get write access to packet\n");
    gnrc_pktbuf_release(pkt);
    return;
  }
  pkt = udp;

  ipv6 = gnrc_pktsnip_search_type(pkt, GNRC_NETTYPE_IPV6);

  assert(ipv6 != NULL);
  if(pkt->next != NULL) {
      DEBUG("////////PKT->NEXT ES DIFERENTE DE NULL/////////////////////////////////////////////////////\n");
  }

  if(pkt->type == GNRC_NETTYPE_UDP) {
    DEBUG("/////////nettype igual a UDP////////////////////////////////////////////////////\n");
    DEBUG("EL TAMANO DEL PAQUETE ES %s", (char*)pkt->data);
  } else {
    DEBUG("EL TIPO ES %d", pkt->type);
  }

  if(pkt != NULL) {
      DEBUG("////////////////ES DIFERENTE DE NULL/////////////////////////////////////////////\n");
  }

    DEBUG("//////////////////////////////////////////////PACKET SIZE/%d//////////////\n",pkt->size);
 DEBUG("//////////////////////////////////////////////PACKET SIZE/%d//////////////\n",sizeof(udp_hdr_t));
  if ((pkt != NULL) && (pkt->type == GNRC_NETTYPE_UDP) /* &&
      (pkt->size == sizeof(udp_hdr_t)) */) {
    /* UDP header was already marked. Take it. */
    udp = pkt;
    DEBUG("/////////////////////////////////////////////////////////////\n");
    DEBUG("/////////////////////////////////////////////////////////////\n");
    DEBUG("/////////////////////////////////////////////////////////////\n");
    DEBUG("/////////////////////////////////////////////////////////////\n");
    DEBUG("/////////////////////////////////////////////////////////////\n");
    DEBUG("/////////////////////////////////////////////////////////////\n");
    DEBUG("/////////////////////////////////////////////////////////////\n");
  } else {
     DEBUG("////////////////ENTRAMOS AQUI/////////////////////////////////////////////\n");
    udp = gnrc_pktbuf_mark(pkt, sizeof(udp_hdr_t), GNRC_NETTYPE_UDP);
    if (udp == NULL) {
      DEBUG("udp: error marking UDP header, dropping packet\n");
      gnrc_pktbuf_release(pkt);
      return;
    } else {
      DEBUG("/////////////TODO SALIO COMO SE QUERIA////////////////////////////////////////////////\n");
    }
  }
  /* mark payload as Type: UNDEF */
  pkt->type = GNRC_NETTYPE_UNDEF;
  /* get explicit pointer to UDP header */
  hdr = (udp_hdr_t *)udp->data;

  /* validate checksum */
  if (byteorder_ntohs(hdr->checksum) == 0) {
    /* RFC 8200 Section 8.1
     * "IPv6 receivers must discard UDP packets containing a zero checksum,
     * and should log the error."
     */
    DEBUG("udp: received packet with zero checksum, dropping it\n");
    gnrc_pktbuf_release(pkt);
    return;
  }
  if (_calc_csum(udp, ipv6, pkt) != 0xFFFF) {
    DEBUG("udp: received packet with invalid checksum, dropping it\n");
    gnrc_pktbuf_release(pkt);
    return;
  }

  /* get port (netreg demux context) */
  port = (uint32_t)byteorder_ntohs(hdr->dst_port);

  /* send payload to receivers */
  if (!gnrc_netapi_dispatch_receive(GNRC_NETTYPE_UDP, port, pkt)) {
    DEBUG("udp: unable to forward packet as no one is interested in it\n");
    /* TODO determine if IPv6 packet, when IPv4 is implemented */
    gnrc_icmpv6_error_dst_unr_send(ICMPV6_ERROR_DST_UNR_PORT, pkt);
    gnrc_pktbuf_release(pkt);
  }
}

/**
 * @brief   Calculate the UDP checksum dependent on the network protocol
 *
 * @note    If the checksum turns out to be 0x0000, the function returns 0xffff
 *          as specified in RFC768
 *
 * @param[in] pkt           pointer to the packet in the packet buffer
 * @param[in] pseudo_hdr    pointer to the network layer header
 * @param[in] payload       pointer to the payload
 *
 * @return                  the checksum of the pkt in host byte order
 * @return                  0 on error
 */
static uint16_t _calc_csum(gnrc_pktsnip_t *hdr, gnrc_pktsnip_t *pseudo_hdr,
                           gnrc_pktsnip_t *payload) {
  uint16_t csum = 0;
  uint16_t len = (uint16_t)hdr->size;

  /* process the payload */
  while (payload && payload != hdr && payload != pseudo_hdr) {
    csum =
        inet_csum_slice(csum, (uint8_t *)(payload->data), payload->size, len);
    len += (uint16_t)payload->size;
    payload = payload->next;
  }
  /* process applicable UDP header bytes */
  csum = inet_csum(csum, (uint8_t *)hdr->data, sizeof(udp_hdr_t));

  switch (pseudo_hdr->type) {
#ifdef MODULE_GNRC_IPV6
  case GNRC_NETTYPE_IPV6:
    csum = ipv6_hdr_inet_csum(csum, pseudo_hdr->data, PROTNUM_UDP, len);
    break;
#endif
  default:
    (void)len;
    return 0;
  }
  /* return inverted results */
  if (csum == 0xFFFF) {
    /* https://tools.ietf.org/html/rfc8200#section-8.1
     * bullet 4
     * "if that computation yields a result of zero, it must be changed
     * to hex FFFF for placement in the UDP header."
     */
    return 0xFFFF;
  } else {
    return ~csum;
  }
}

static void gnrc_process_message(gnrc_pktsnip_t *pkt) {
  gnrc_pktsnip_t *ipv6_snip, *udp_snip, *tmp_pkt;
  gnrc_netif_t *netif = NULL;

  DEBUG("AODV---- porcessing packet\n");
  /* write protect first header */
  tmp_pkt = gnrc_pktbuf_start_write(pkt);
  if (tmp_pkt == NULL) {
    DEBUG("AODV: cannot send packet: unable to allocate packet\n");
    gnrc_pktbuf_release(pkt);
    return;
  }
  pkt = tmp_pkt;
  ipv6_snip = tmp_pkt->next;
  udp_snip = ipv6_snip->next;
  (void)ipv6_snip;
  (void)udp_snip;
  DEBUG("debugeando: %d\n", (int)pkt->type);
  if (pkt->type == GNRC_NETTYPE_NETIF) {
    gnrc_netif_hdr_t *netif_hdr = pkt->data;
    gnrc_netif_hdr_print(netif_hdr);
    netif = gnrc_netif_hdr_get_netif(pkt->data);
    (void)netif;
    (void)netif_hdr;

    char ipv6_addr[IPV6_ADDR_MAX_STR_LEN];
    ipv6_addr_to_str(ipv6_addr, &((ipv6_hdr_t *)pkt->data)->dst,
                     IPV6_ADDR_MAX_STR_LEN);
    DEBUG("AODB TEST -------target address --> %s\n", ipv6_addr);

    memset(ipv6_addr, 0, sizeof(ipv6_addr));
    ipv6_addr_to_str(ipv6_addr, &((ipv6_hdr_t *)pkt->data)->src,
                     IPV6_ADDR_MAX_STR_LEN);
    DEBUG("AODB TEST -------source address --> %s\n", ipv6_addr);
  }

  if (ipv6_snip->type == GNRC_NETTYPE_IPV6) {
    if (ipv6_addr_is_unspecified(&((ipv6_hdr_t *)ipv6_snip->data)->dst)) {
      DEBUG("ipv6: destination address is unspecified address (::), "
            "dropping packet \n");
      gnrc_pktbuf_release_error(pkt, EINVAL);
      return;
    }
    char ipv6_addr[IPV6_ADDR_MAX_STR_LEN];
    ipv6_addr_to_str(ipv6_addr, &((ipv6_hdr_t *)ipv6_snip->data)->dst,
                     IPV6_ADDR_MAX_STR_LEN);
    DEBUG("AODB TEST -------target address --> %s\n", ipv6_addr);

    // init multicast address: set to to a link-local all nodes multicast
    // address
    _v6_addr_mcast = ipv6_addr_all_nodes_link_local;
    DEBUG("my multicast address is: %s\n",
          ipv6_addr_to_str(addr_str, &_v6_addr_mcast, IPV6_ADDR_MAX_STR_LEN));
    ((ipv6_hdr_t *)ipv6_snip->data)->dst = _v6_addr_mcast;
  }

  tmp_pkt = gnrc_pktsnip_search_type(pkt, GNRC_NETTYPE_UDP);
  if (tmp_pkt != NULL) {
    DEBUG("DATA FROM APP LAYER IS: %s\n", (char *)tmp_pkt->next->data);
  }

  ipv6_addr_t *addr;
  addr = &((ipv6_hdr_t *)ipv6_snip->data)->dst;

  gnrc_aodv_get_next_hop(addr);
}

ipv6_addr_t *gnrc_aodv_get_next_hop(ipv6_addr_t *dest) {
  DEBUG("aodv_get_next_hop() %s:",
        ipv6_addr_to_str(addr_str, &_v6_addr_local, IPV6_ADDR_MAX_STR_LEN));
  DEBUG(" getting next hop for %s\n",
        ipv6_addr_to_str(addr_str, dest, IPV6_ADDR_MAX_STR_LEN));

  DEBUG("---------------------------------------------------\n");
  DEBUG("el ID exz :%d", ieee802154_netif->pid);
  // int pid = ieee802154_netif->pid;
  aodvv2_metric_t _metric_type = AODVV2_DEFAULT_METRIC_TYPE;
  ipv6_addr_t v6_addr_local = gnrc_get_ipv6_from_iface(ieee802154_netif);
  (void)v6_addr_local;

  struct netaddr na_dest;

  // get network address local and network address target
  ipv6_addr_t_to_netaddr(&v6_addr_local, &na_local);
  ipv6_addr_t_to_netaddr(dest, &na_dest);
  ipv6_addr_t_to_netaddr(&_v6_addr_mcast, &na_mcast);

  aodvv2_seqnum_t seqnum = seqnum_get();
  seqnum_inc();

  struct aodvv2_packet_data rreq_data = (struct aodvv2_packet_data){
      .hoplimit = AODVV2_MAX_HOPCOUNT,
      .metricType = _metric_type,
      .origNode =
          (struct node_data){
              .addr = na_local,
              .metric = 0,
              .seqnum = seqnum,
          },
      .targNode =
          (struct node_data){
              .addr = na_dest,
          },
      .timestamp = (timex_t){0, 0} /* this timestamp is never used, it exists
                                    * merely to make the compiler shut up */
  };
  (void)rreq_data;
  gnrc_aodv_send_rreq(&rreq_data);

  return 0;
}

ipv6_addr_t gnrc_get_ipv6_from_iface(gnrc_netif_t *netif) {
  ipv6_addr_t ipv6_addr;
  int r = gnrc_netapi_get(netif->pid, NETOPT_IPV6_ADDR, 0, &ipv6_addr,
                          sizeof(ipv6_addr));
  if (r < 0) {
    DEBUG("unspecified address\n");
    return (ipv6_addr_t)IPV6_ADDR_UNSPECIFIED;
  }

  for (unsigned i = 0; i < (unsigned)(r / sizeof(ipv6_addr_t)); i++) {
    char ipv6_address[IPV6_ADDR_MAX_STR_LEN];
    ipv6_addr_to_str(ipv6_address, &ipv6_addr, IPV6_ADDR_MAX_STR_LEN);
  }
  return ipv6_addr;
}

/**
 * Handle the output of the RFC5444 packet creation process. This callback is
 * called by every writer_send_* function.
 */
static void _write_packet(struct rfc5444_writer *wr __attribute__((unused)),
                          struct rfc5444_writer_target *iface
                          __attribute__((unused)),
                          void *buffer, size_t length) {
  (void)buffer;
  (void)length;

  DEBUG("*******************************************\n");
  DEBUG("*******************************************\n");
  DEBUG("*******************************************\n");
  DEBUG("*******************************************\n");
  DEBUG("GOING TO WRITE THE PACKETY\n");

  gnrc_pktsnip_t *ipv6_snip, *udp_snip, *tmp_pkt;
  //gnrc_netif_t *netif = NULL;

  gnrc_pktsnip_t *temp_packet = *pkt_temp;

  DEBUG("AODV---- porcessing packet\n");
  /* write protect first header */
  tmp_pkt = gnrc_pktbuf_start_write(temp_packet);
  if (tmp_pkt == NULL) {
    DEBUG("AODV: cannot send packet: unable to allocate packet\n");
    gnrc_pktbuf_release(temp_packet);
    // return;
  }
  temp_packet = tmp_pkt;
  ipv6_snip = tmp_pkt->next;
  udp_snip = ipv6_snip->next;
  (void)ipv6_snip;
  (void)udp_snip;
  DEBUG("debugeando: %d\n", (int)temp_packet->type);


  tmp_pkt = gnrc_pktsnip_search_type(temp_packet, GNRC_NETTYPE_UDP);
  if (tmp_pkt != NULL) {
    DEBUG("DATA FROM APP LAYER IS: %s\n", (char *)tmp_pkt->next->data);
  }

  tmp_pkt->next->data = buffer;
  _send(temp_packet);

  // if (temp_packet->type == GNRC_NETTYPE_NETIF) {
  //   gnrc_netif_hdr_t *netif_hdr = temp_packet->data;
  //   gnrc_netif_hdr_print(netif_hdr);
  //   netif = gnrc_netif_hdr_get_netif(temp_packet->data);
  //   (void)netif;
  //   (void)netif_hdr;

  //   char ipv6_addr[IPV6_ADDR_MAX_STR_LEN];
  //   ipv6_addr_to_str(ipv6_addr, &((ipv6_hdr_t *)temp_packet->data)->dst,
  //                    IPV6_ADDR_MAX_STR_LEN);
  //   DEBUG("AODB TEST -------target address --> %s\n", ipv6_addr);

  //   memset(ipv6_addr, 0, sizeof(ipv6_addr));
  //   ipv6_addr_to_str(ipv6_addr, &((ipv6_hdr_t *)temp_packet->data)->src,
  //                    IPV6_ADDR_MAX_STR_LEN);
  //   DEBUG("AODB TEST -------source address --> %s\n", ipv6_addr);
  // }

  // if (ipv6_snip->type == GNRC_NETTYPE_IPV6) {
  //   if (ipv6_addr_is_unspecified(&((ipv6_hdr_t *)ipv6_snip->data)->dst)) {
  //     DEBUG("ipv6: destination address is unspecified address (::), "
  //           "dropping packet \n");
  //     gnrc_pktbuf_release_error(temp_packet, EINVAL);
  //     // return;
  //   }
  //   char ipv6_addr[IPV6_ADDR_MAX_STR_LEN];
  //   ipv6_addr_to_str(ipv6_addr, &((ipv6_hdr_t *)ipv6_snip->data)->dst,
  //                    IPV6_ADDR_MAX_STR_LEN);
  //   DEBUG("AODB TEST -------target address --> %s\n", ipv6_addr);

  //   // init multicast address: set to to a link-local all nodes multicast
  //   // address
  //   _v6_addr_mcast = ipv6_addr_all_nodes_link_local;
  //   DEBUG("my multicast address is: %s\n",
  //         ipv6_addr_to_str(addr_str, &_v6_addr_mcast, IPV6_ADDR_MAX_STR_LEN));
  //   ((ipv6_hdr_t *)ipv6_snip->data)->dst = _v6_addr_mcast;
  // }


}