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
 * @file        aodv.c
 * @brief       aodvv2 routing protocol
 *
 * @author      Lotte Steenbrink <lotte.steenbrink@fu-berlin.de>
 */

#define ENABLE_DEBUG (1)
#include "aodv.h"
#include "aodvv2/aodvv2.h"
#include "debug.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "net/gnrc/netif/ieee802154.h"
#include "net/netdev_test.h"

#include <stdio.h>

#include "net/gnrc/netapi.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netif/conf.h"
#include "net/gnrc/netreg.h"
#include "net/gnrc/pkt.h"
#include "net/gnrc/pktbuf.h"
#include "net/ipv6/addr.h"

#include "assert.h"
//#include "xtimer.h"

// for neighbords
#include "msg.h"
#include "net/gnrc/netif/internal.h"
#include "sched.h"
#include "thread.h"
#include "net/gnrc/udp.h"

#include "net/gnrc/icmpv6/error.h"
#include "net/inet_csum.h"

static gnrc_netif_t *ieee802154_netif = NULL;

#define _MSG_QUEUE_SIZE (2)

#define UDP_BUFFER_SIZE (128) /** with respect to IEEE 802.15.4's MTU */
#define RCV_MSG_Q_SIZE (32)   /* TODO: check if smaller values work, too */

#define IEEE802154_MAX_FRAG_SIZE (102)
#define IEEE802154_LOCAL_EUI64                                                 \
  { 0x02, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x01 }
#define IEEE802154_REMOTE_EUI64                                                \
  { 0x02, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x02 }

static void _init_addresses(void);
static void _init_sock_snd(void);
static void *_aodv_receiver_thread(void *arg);
static void *_aodv_sender_thread(void *arg);
static void _deep_free_msg_container(struct msg_container *msg_container);
static void _write_packet(struct rfc5444_writer *wr __attribute__((unused)),
                          struct rfc5444_writer_target *iface
                          __attribute__((unused)),
                          void *buffer, size_t length);
static void *_event_loop(void *arg);

// static void _send_packet(void);
#ifdef ENABLE_DEBUG
// char addr_str[IPV6_MAX_ADDR_STR_LEN];
char addr_str[IPV6_ADDR_MAX_STR_LEN];
// static struct netaddr_str nbuf;
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


// static char aodv_rcv_stack_buf[KERNEL_CONF_STACKSIZE_MAIN];
// static char aodv_snd_stack_buf[KERNEL_CONF_STACKSIZE_MAIN];

static char aodv_rcv_stack_buf[THREAD_STACKSIZE_DEFAULT];
static char aodv_snd_stack_buf[THREAD_STACKSIZE_DEFAULT];

static aodvv2_metric_t _metric_type;
static int sender_thread;
static int _sock_snd;
static struct autobuf _hexbuf;
// static struct sockaddr_in6 sa_wp;

static ipv6_addr_t _v6_addr_local, _v6_addr_mcast /*, _v6_addr_loopback*/;
static struct netaddr na_local; /* the same as _v6_addr_local, but to save us
//   //                               * constant calls to
ipv6_addr_t_to_netaddr()... */
// static struct writer_target *wt;
struct netaddr na_mcast = (struct netaddr){};

#define IEEE802154_STACKSIZE (THREAD_STACKSIZE_MAIN)

ipv6_addr_t ipv6_addrs = {0};

void aodv_init(void) {
  printf("hola gustavo despierta\n");
  DEBUG("listening on port \n");
  DEBUG("%s()\n", __func__);

  (void)ieee802154_netif;

  // get netif interface
  ieee802154_netif = gnrc_netif_iter(ieee802154_netif);
  if (ieee802154_netif != NULL) {
    DEBUG("tenemos una interface: %d\n", ieee802154_netif->pid);
  }

  uint16_t temp;
  uint16_t res = gnrc_netapi_get(ieee802154_netif->pid, NETOPT_CHANNEL, 0,
                                 &temp, sizeof(temp));
  (void)res;
  printf("EL CANAL ES :%u\n", temp);

  int r = gnrc_netapi_get(ieee802154_netif->pid, NETOPT_IPV6_ADDR, 0,
                          &ipv6_addrs, sizeof(ipv6_addrs));
  if (r < 0) {
    return;
  }
  for (unsigned i = 0; i < (unsigned)(r / sizeof(ipv6_addr_t)); i++) {
    char ipv6_addr[IPV6_ADDR_MAX_STR_LEN];
    ipv6_addr_to_str(ipv6_addr, &ipv6_addrs, IPV6_ADDR_MAX_STR_LEN);
    printf("My address is %s\n", ipv6_addr);
  }

  aodv_set_metric_type(AODVV2_DEFAULT_METRIC_TYPE);
  _init_addresses();
  _init_sock_snd();

  seqnum_init();
  routingtable_init();
  clienttable_init();

  // // every node is its own client.
  clienttable_add_client(&na_local);
  rreqtable_init();

  // init reader and writer
  aodv_packet_reader_init();
  aodv_packet_writer_init(_write_packet);

   if (_pid == KERNEL_PID_UNDEF) {
        /* start UDP thread */
        _pid = thread_create(_stack, sizeof(_stack), GNRC_UDP_PRIO,
                             THREAD_CREATE_STACKTEST, _event_loop, NULL, "udp");
    }

  // TODO: set if_id properly
  /*int if_id = 0;
  net_if_set_src_address_mode(if_id, NET_IF_TRANS_ADDR_M_SHORT);*/

  // net_if_set_src_address_mode(if_id, NET_IF_TRANS_ADDR_M_SHORT);

  // start listening & enable sending
  thread_create(aodv_rcv_stack_buf, sizeof(aodv_rcv_stack_buf),
                THREAD_PRIORITY_MAIN - 1, THREAD_CREATE_STACKTEST,
                _aodv_receiver_thread, NULL, "_aodv_receiver_thread");

  // DEBUG("listening on port %d\n", HTONS(MANET_PORT));
  sender_thread =
    thread_create(aodv_snd_stack_buf, sizeof(aodv_snd_stack_buf),
                    THREAD_PRIORITY_MAIN - 1, THREAD_CREATE_STACKTEST,
                    _aodv_sender_thread, NULL, "_aodv_sender_thread");

  // register aodv for routing
  // ipv6_iface_set_routing_provider(aodv_get_next_hop);
}

static uint16_t _calc_csum(gnrc_pktsnip_t *hdr, gnrc_pktsnip_t *pseudo_hdr,
                           gnrc_pktsnip_t *payload)
{
    uint16_t csum = 0;
    uint16_t len = (uint16_t)hdr->size;

    /* process the payload */
    while (payload && payload != hdr && payload != pseudo_hdr) {
        csum = inet_csum_slice(csum, (uint8_t *)(payload->data), payload->size, len);
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


static void _send(gnrc_pktsnip_t *pkt)
{
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
    if (!gnrc_netapi_dispatch_send(target_type, GNRC_NETREG_DEMUX_CTX_ALL,
                                   pkt)) {
        DEBUG("AODV: cannot send packet: network layer not found\n");
        gnrc_pktbuf_release(pkt);
    }
}

static void _receive(gnrc_pktsnip_t *pkt)
{
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

    if ((pkt->next != NULL) && (pkt->next->type == GNRC_NETTYPE_UDP) &&
        (pkt->next->size == sizeof(udp_hdr_t))) {
        /* UDP header was already marked. Take it. */
        udp = pkt->next;
    }
    else {
        udp = gnrc_pktbuf_mark(pkt, sizeof(udp_hdr_t), GNRC_NETTYPE_UDP);
        if (udp == NULL) {
            DEBUG("udp: error marking UDP header, dropping packet\n");
            gnrc_pktbuf_release(pkt);
            return;
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



static void *_event_loop(void *arg)
{
    (void)arg;
    msg_t msg, reply;
    msg_t msg_queue[GNRC_UDP_MSG_QUEUE_SIZE];
    gnrc_netreg_entry_t netreg = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL,
                                                            sched_active_pid);
    /* preset reply message */
    reply.type = GNRC_NETAPI_MSG_TYPE_ACK;
    reply.content.value = (uint32_t)-ENOTSUP;
    /* initialize message queue */
    msg_init_queue(msg_queue, GNRC_UDP_MSG_QUEUE_SIZE);
    /* register UPD at netreg */
    gnrc_netreg_register(GNRC_NETTYPE_UDP, &netreg);

    /* dispatch NETAPI messages */
    while (1) {
        msg_receive(&msg);
        switch (msg.type) {
            case GNRC_NETAPI_MSG_TYPE_RCV:
                DEBUG("<-----AODV--loop-->: GNRC_NETAPI_MSG_TYPE_RCV\n");
                _receive(msg.content.ptr);
                break;
            case GNRC_NETAPI_MSG_TYPE_SND:
                DEBUG("<----AODB--loop---->: GNRC_NETAPI_MSG_TYPE_SND\n");
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

void aodv_set_metric_type(aodvv2_metric_t metric_type) {
  if (metric_type != AODVV2_DEFAULT_METRIC_TYPE) {
    return;
  }
  _metric_type = metric_type;
}

void aodv_send_rreq(struct aodvv2_packet_data *packet_data) {
  DEBUG("%s()\n", __func__);

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


//  init the multicast address all RREQ and RERRS are sent to
//   and the local address (source address) of this node

static void _init_addresses(void) {

  // init multicast address: set to to a link-local all nodes multicast address
  _v6_addr_mcast = ipv6_addr_all_nodes_link_local;
  DEBUG("my multicast address is: %s\n",
        ipv6_addr_to_str(addr_str, &_v6_addr_mcast, IPV6_ADDR_MAX_STR_LEN));

  DEBUG("my src address is:       %s\n",
        ipv6_addr_to_str(addr_str, &_v6_addr_local, IPV6_ADDR_MAX_STR_LEN));
}

// init socket communication for sender
static void _init_sock_snd(void) {
  _sock_snd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (_sock_snd < 0) {
    DEBUG("Error Creating Socket!\n");
  }
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
    } else if (mc->type == RFC5444_MSGTYPE_RREP) {
      struct rreq_rrep_data *rrep_data = (struct rreq_rrep_data *)mc->data;
      aodv_packet_writer_send_rrep(rrep_data->packet_data, rrep_data->next_hop);
    } else if (mc->type == RFC5444_MSGTYPE_RERR) {
      struct rerr_data *rerr_data = (struct rerr_data *)mc->data;
      aodv_packet_writer_send_rerr(rerr_data->unreachable_nodes, rerr_data->len,
                                   rerr_data->hoplimit, rerr_data->next_hop);
    } else {
      DEBUG("ERROR: Couldn't identify Message\n");
    }
    _deep_free_msg_container(mc);
  }

  return NULL;
}

// receive RREQs, RREPs and RERRs and handle them
static void *_aodv_receiver_thread(void *arg) {
  (void)arg;

  DEBUG("%s()\n", __func__);
  char buf_rcv[UDP_BUFFER_SIZE];

  struct sockaddr_in6 sa_rcv;
  sa_rcv.sin6_family = AF_INET;
  sa_rcv.sin6_port = htons(MANET_PORT);

  msg_t rcv_msg_q[RCV_MSG_Q_SIZE];
  msg_init_queue(rcv_msg_q, RCV_MSG_Q_SIZE);
  int _socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

  sa_rcv.sin6_family = AF_INET6;
  memset(&sa_rcv.sin6_addr, 0, sizeof(sa_rcv.sin6_addr));
  if (_socket < 0) {
    puts("error initializing socket");
    _socket = 0;
    return NULL;
  }

  if (bind(_socket, (struct sockaddr *)&sa_rcv, sizeof(sa_rcv)) < 0) {
    _socket = -1;
    puts("error binding socket");
    return NULL;
  }
  printf("Success: started UDP>>>to receive ROUTE MESSAGES");
  while (1) {
    int res;
    struct sockaddr_in6 src;
    socklen_t src_len = sizeof(struct sockaddr_in6);
    if ((res = recvfrom(_socket, buf_rcv, sizeof(buf_rcv), 0,
                        (struct sockaddr *)&src, &src_len)) < 0) {
      puts("Error on receive");
    } else if (res == 0) {
      puts("Peer did shut down");
    } else {
      printf("<AODV RECEIVER THREAD >Received data: >>>>>>>>>>>>>>> ");
      close(_socket);
      puts(buf_rcv);

    }
  }

  

  return NULL;
}



/**
 * Handle the output of the RFC5444 packet creation process. This callback is
 * called by every writer_send_* function.
 */
static void _write_packet(struct rfc5444_writer *wr __attribute__((unused)),
                          struct rfc5444_writer_target *iface
                          __attribute__((unused)),
                          void *buffer, size_t length) {
  DEBUG("%s()\n", __func__);
  (void)buffer;
  (void)length;
  // // generate hexdump and human readable representation of packet
  //  //and print to console
  abuf_hexdump(&_hexbuf, "\t", buffer, length);
  // rfc5444_print_direct(&_hexbuf, buffer, length);
  // DEBUG("%s", abuf_getptr(&_hexbuf));
  // abuf_clear(&_hexbuf);

  // //  fetch the address the packet is supposed to be sent to (i.e. to a
  // //   specific node or the multicast address) from the writer_target struct
  // //  iface* is stored in. This is a bit hacky, but it does the trick.
  // wt = container_of(iface, struct writer_target, interface);
  // netaddr_to_ipv6_addr_t(&wt->target_addr, (ipv6_addr_t*)&sa_wp.sin6_addr);

  // // When originating a RREQ, add it to our RREQ table/update its predecessor
  // if (wt->type == RFC5444_MSGTYPE_RREQ
  //     && netaddr_cmp(&wt->packet_data.origNode.addr, &na_local) == 0) {
  //     AODV_DEBUG("originating RREQ with SeqNum %d towards %s via %s; updating
  //     RREQ table...\n",
  //           wt->packet_data.origNode.seqnum,
  //           netaddr_to_string(&nbuf, &wt->packet_data.targNode.addr),
  //           ipv6_addr_to_str(addr_str, IPV6_MAX_ADDR_STR_LEN,
  //           &sa_wp.sin6_addr));
  //     rreqtable_is_redundant(&wt->packet_data);
  // }

  // size_t bytes_sent =  sendto(_sock_snd, buffer, length, 0, (struct
  // sockaddr*)&sa_wp, sizeof(sa_wp)); (void) bytes_sent; AODV_DEBUG("%d bytes
  // sent.\n", bytes_sent);
}

// free the matryoshka doll of cobbled-together structs that the sender_thread
// receives
static void _deep_free_msg_container(struct msg_container *mc) {
  (void)mc;
  // int type = mc->type;
  // if ((type == RFC5444_MSGTYPE_RREQ) || (type == RFC5444_MSGTYPE_RREP)) {
  //     struct rreq_rrep_data *rreq_rrep_data = (struct rreq_rrep_data *)
  //     mc->data; free(rreq_rrep_data->packet_data); if
  //     (netaddr_cmp(rreq_rrep_data->next_hop, &na_mcast) != 0) {
  //         free(rreq_rrep_data->next_hop);
  //     }
  // }
  // else if (type == RFC5444_MSGTYPE_RERR) {
  //     struct rerr_data *rerr_data = (struct rerr_data *) mc->data;
  //     if (netaddr_cmp(rerr_data->next_hop, &na_mcast) != 0) {
  //         free(rerr_data->next_hop);
  //     }
  // }
  // free(mc->data);
  // free(mc);
}
