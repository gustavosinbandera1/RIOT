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
#include "debug.h"
#include "aodv.h"
#include "aodvv2/aodvv2.h"



#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "net/gnrc/netif/ieee802154.h"
#include "net/netdev_test.h"



#include <stdio.h>

#include "net/ipv6/addr.h"
#include "net/gnrc/pkt.h"
#include "net/gnrc/pktbuf.h"
#include "net/gnrc/netreg.h"
#include "net/gnrc/netapi.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netif/conf.h"



#include "assert.h"
//#include "xtimer.h"



//for neighbords
#include "msg.h"
#include "net/gnrc/netif/internal.h"
#include "sched.h"
#include "thread.h"


static gnrc_netif_t *ieee802154_netif = NULL;


#define _MSG_QUEUE_SIZE  (2)


#define UDP_BUFFER_SIZE     (128) /** with respect to IEEE 802.15.4's MTU */
#define RCV_MSG_Q_SIZE      (32)  /* TODO: check if smaller values work, too */

#define IEEE802154_MAX_FRAG_SIZE    (102)
#define IEEE802154_LOCAL_EUI64     { \
        0x02, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x01 \
    }
#define IEEE802154_REMOTE_EUI64     { \
        0x02, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x02 \
    }





static void _init_addresses(void);
static void _init_sock_snd(void);
static void *_aodv_receiver_thread(void *arg);
static void *_aodv_sender_thread(void *arg);
static void _deep_free_msg_container(struct msg_container *msg_container);
static void _write_packet(struct rfc5444_writer *wr __attribute__ ((unused)),
                        struct rfc5444_writer_target *iface __attribute__((unused)),
                        void *buffer, size_t length);






//static void _send_packet(void);
#ifdef ENABLE_DEBUG
//char addr_str[IPV6_MAX_ADDR_STR_LEN];
char addr_str[IPV6_ADDR_MAX_STR_LEN];
//static struct netaddr_str nbuf;
#endif

//static char aodv_rcv_stack_buf[KERNEL_CONF_STACKSIZE_MAIN];
//static char aodv_snd_stack_buf[KERNEL_CONF_STACKSIZE_MAIN];

static char aodv_rcv_stack_buf[THREAD_STACKSIZE_DEFAULT];
static char aodv_snd_stack_buf[THREAD_STACKSIZE_DEFAULT];

static aodvv2_metric_t _metric_type;
static int sender_thread;
static int _sock_snd;
static struct autobuf _hexbuf;
// static struct sockaddr_in6 sa_wp;

static ipv6_addr_t _v6_addr_local, _v6_addr_mcast/*, _v6_addr_loopback*/;
static struct netaddr na_local;  /* the same as _v6_addr_local, but to save us
//   //                               * constant calls to ipv6_addr_t_to_netaddr()... */
// static struct writer_target *wt;
struct netaddr na_mcast = (struct netaddr){};




#define IEEE802154_STACKSIZE        (THREAD_STACKSIZE_MAIN)


ipv6_addr_t ipv6_addrs = {0};



void aodv_init(void)
{
    printf("hola gustavo despierta\n");
    DEBUG("listening on port \n");
    DEBUG("%s()\n", __func__);

    (void)ieee802154_netif;

    //get netif interface
    ieee802154_netif = gnrc_netif_iter(ieee802154_netif);
    if (ieee802154_netif != NULL) {
        DEBUG("tenemos una interface workaround: %d\n",ieee802154_netif->pid);
    }

     uint16_t temp; 
     uint16_t res = gnrc_netapi_get(ieee802154_netif->pid, NETOPT_CHANNEL, 0, &temp, sizeof(temp));
     (void)res;
     printf("EL CANAL ES :%u\n",temp );
    
    int r = gnrc_netapi_get(ieee802154_netif->pid, NETOPT_IPV6_ADDR, 0, &ipv6_addrs, sizeof(ipv6_addrs));
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

   
    

    // TODO: set if_id properly
    /*int if_id = 0;
    net_if_set_src_address_mode(if_id, NET_IF_TRANS_ADDR_M_SHORT);*/

   //net_if_set_src_address_mode(if_id, NET_IF_TRANS_ADDR_M_SHORT);



    // start listening & enable sending 
    thread_create(aodv_rcv_stack_buf, sizeof(aodv_rcv_stack_buf),
                  THREAD_PRIORITY_MAIN -1 ,THREAD_CREATE_STACKTEST, _aodv_receiver_thread, NULL, "_aodv_receiver_thread"); 
    
    //DEBUG("listening on port %d\n", HTONS(MANET_PORT));
    sender_thread = thread_create(aodv_snd_stack_buf, sizeof(aodv_snd_stack_buf),
                                  THREAD_PRIORITY_MAIN - 1, THREAD_CREATE_STACKTEST, _aodv_sender_thread,
                                  NULL, "_aodv_sender_thread");

    // register aodv for routing 
    //ipv6_iface_set_routing_provider(aodv_get_next_hop); 

}

// static void _send_packet(void)
// {
//     gnrc_netif_t *netif = gnrc_netif_iter(NULL);
//     (void)netif;
//     struct {
//         gnrc_netif_hdr_t netif_hdr;
//         uint8_t src[8];
//         uint8_t dst[8];
//     } netif_hdr = {
//         .src = IEEE802154_REMOTE_EUI64,
//         .dst = IEEE802154_LOCAL_EUI64,
//     };

//     gnrc_netif_hdr_init(&(netif_hdr.netif_hdr), 8, 8);

//     gnrc_netif_hdr_set_netif(&netif_hdr.netif_hdr, netif);

//     uint8_t data1[] = {
//         /* 6LoWPAN Header */
//         /* Fragmentation Header (first) */
//         0xc0, 0x94, /* 0b11000: frag1, 0b00010010100: datagram_size (148) */
//         0x00, 0x01, /* datagram_tag */
//         /* 0b011: LOWPAN_IPHC */
//         /* 0b11: Traffic Class and Flow Label are elided */
//         /* 0b1: Next Header is compressed */
//         /* 0b11: The Hop Limit field is compressed and the hop limit is 255 */
//         0x7f,
//         /* 0b0: No additional 8-bit Context Identifier Extension is used */
//         /* 0b0: Source address compression uses stateless compression */
//         /* 0b11: source address mode is 0 bits */
//         /* 0b0: Destination address is not a multicast address */
//         /* 0x0: Destination address compression uses stateless compression */
//         /* 0x00: destination address mode is 128 bits */
//         0x30,

//         /* destination address: fd01::1 */
//         // 0xfd, 0x01, 0x00, 0x00,
//         // 0x00, 0x00, 0x00, 0x00,
//         // 0x00, 0x00, 0x00, 0x00,
//         // 0x00, 0x00, 0x00, 0x01,

//         0xff, 0x02, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x01,

//         /* 0b11110: UDP LOWPAN_NHC */
//         /* 0b0: Checksum is carried in-line */
//         /* 0b11: First 12 bits of both Source Port and Destination Port are 0xf0b and elided */
//         0xf3,
//         0x00, /* Source Port and Destination Port (4 bits each) */
//         0x23, 0x2f, /* Checksum */

//         /* payload */
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//     };

//     uint8_t data2[] = {
//         /* 6LoWPAN Header */
//         /* Fragmentation Header (rest) */
//         0xe0, 0x94, /* 0b11100: frag1, 0b00010010100: datagram_size (148) */
//         0x00, 0x01, /* datagram_tag */
//         0x0c,       /* datagram_offset (12 * 8 = 96) */

//         /* payload */
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00,
//     };

//     gnrc_netreg_entry_t dump_6lowpan = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL, gnrc_pktdump_pid);
//     gnrc_netreg_entry_t dump_ipv6 = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL, gnrc_pktdump_pid);
//     gnrc_netreg_entry_t dump_udp = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL, gnrc_pktdump_pid);
//     gnrc_netreg_entry_t dump_udp_61616 = GNRC_NETREG_ENTRY_INIT_PID(61616, gnrc_pktdump_pid);

//     gnrc_netreg_register(GNRC_NETTYPE_SIXLOWPAN, &dump_6lowpan);
//     gnrc_netreg_register(GNRC_NETTYPE_IPV6, &dump_ipv6);
//     gnrc_netreg_register(GNRC_NETTYPE_UDP, &dump_udp);
//     gnrc_netreg_register(GNRC_NETTYPE_UDP, &dump_udp_61616);

//     gnrc_pktsnip_t *netif1 = gnrc_pktbuf_add(NULL,
//                                             &netif_hdr,
//                                             sizeof(netif_hdr),
//                                             GNRC_NETTYPE_NETIF);
//     gnrc_pktsnip_t *pkt1 = gnrc_pktbuf_add(netif1,
//                                            data1,
//                                            sizeof(data1),
//                                            GNRC_NETTYPE_SIXLOWPAN);

//     gnrc_netapi_dispatch_receive(GNRC_NETTYPE_SIXLOWPAN, GNRC_NETREG_DEMUX_CTX_ALL, pkt1);

//     gnrc_pktsnip_t *netif2 = gnrc_pktbuf_add(NULL,
//                                              &netif_hdr,
//                                              sizeof(netif_hdr),
//                                              GNRC_NETTYPE_NETIF);
//     gnrc_pktsnip_t *pkt2 = gnrc_pktbuf_add(netif2,
//                                            data2,
//                                            sizeof(data2),
//                                            GNRC_NETTYPE_SIXLOWPAN);

//     gnrc_netapi_dispatch_receive(GNRC_NETTYPE_SIXLOWPAN, GNRC_NETREG_DEMUX_CTX_ALL, pkt2);
// }


 void aodv_set_metric_type(aodvv2_metric_t metric_type)
{
    if (metric_type != AODVV2_DEFAULT_METRIC_TYPE) {
        return;
    }
    _metric_type = metric_type;
}

void aodv_send_rreq(struct aodvv2_packet_data *packet_data)
{
    DEBUG("%s()\n", __func__);

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

/* void aodv_send_rrep(struct aodvv2_packet_data *packet_data, struct netaddr *next_hop)
{
    AODV_DEBUG("%s()\n", __func__);

    struct aodvv2_packet_data *pd = malloc(sizeof(struct aodvv2_packet_data));
    memcpy(pd, packet_data, sizeof(struct aodvv2_packet_data));

    struct netaddr *nh = malloc(sizeof(struct netaddr));
    memcpy(nh, next_hop, sizeof(struct netaddr));

    struct rreq_rrep_data *rd = malloc(sizeof(struct rreq_rrep_data));
    *rd = (struct rreq_rrep_data) {
        .next_hop = nh,
        .packet_data = pd,
    };

    struct msg_container *mc = malloc(sizeof(struct msg_container));
    *mc = (struct msg_container) {
        .type = RFC5444_MSGTYPE_RREP,
        .data = rd
    };

    msg_t msg;
    msg.content.ptr = (char *) mc;

    msg_try_send(&msg, sender_thread);
} */

/* void aodv_send_rerr(struct unreachable_node unreachable_nodes[], size_t len, struct netaddr *next_hop)
{
    AODV_DEBUG("%s()\n", __func__);

    struct rerr_data *rerrd = malloc(sizeof(struct rerr_data));
    *rerrd = (struct rerr_data) {
        .unreachable_nodes = unreachable_nodes,
        .len = len,
        .hoplimit = AODVV2_MAX_HOPCOUNT,
        .next_hop = next_hop
    };

    struct msg_container *mc2 = malloc(sizeof(struct msg_container));
    *mc2 = (struct msg_container) {
        .type = RFC5444_MSGTYPE_RERR,
        .data = rerrd
    };

    msg_t msg2;
    msg2.content.ptr = (char *) mc2;

    msg_try_send(&msg2, sender_thread);
} */


//  init the multicast address all RREQ and RERRS are sent to
//   and the local address (source address) of this node
 
static void _init_addresses(void)
{



    // init multicast address: set to to a link-local all nodes multicast address 
    _v6_addr_mcast = ipv6_addr_all_nodes_link_local;
    DEBUG("my multicast address is: %s\n",ipv6_addr_to_str(addr_str, &_v6_addr_mcast,IPV6_ADDR_MAX_STR_LEN));

  DEBUG("my src address is:       %s\n",
          ipv6_addr_to_str(addr_str, &_v6_addr_local, IPV6_ADDR_MAX_STR_LEN));
    /*//get best IP for sending 
    ipv6_net_if_get_best_src_addr(&_v6_addr_local, &_v6_addr_mcast);
    AODV_DEBUG("my src address is:       %s\n",
          ipv6_addr_to_str(addr_str, IPV6_MAX_ADDR_STR_LEN, &_v6_addr_local));

    //  store src & multicast address as netaddr as well for easy interaction
    //  with oonf based stuff 
    ipv6_addr_t_to_netaddr(&_v6_addr_local, &na_local);
    ipv6_addr_t_to_netaddr(&_v6_addr_mcast, &na_mcast);
    ipv6_addr_set_loopback_addr(&_v6_addr_loopback);

    //init sockaddr that write_packet will use to send data 
    sa_wp.sin6_family = AF_INET6;
    sa_wp.sin6_port = HTONS(MANET_PORT); */
}

// init socket communication for sender 
static void _init_sock_snd(void)
{
    _sock_snd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if(_sock_snd < 0) {
        DEBUG("Error Creating Socket!\n");
    }
} 

// Build RREQs, RREPs and RERRs from the information contained in the thread's
 // message queue and send them 
static void *_aodv_sender_thread(void *arg)
{
    (void) arg;

    msg_t msgq[RCV_MSG_Q_SIZE];
    msg_init_queue(msgq, sizeof msgq);
    DEBUG("_aodv_sender_thread initialized.\n");

    while (true) {
        DEBUG("%s()\n", __func__);
        msg_t msg;
        msg_receive(&msg);
         DEBUG("TESTING: RECIVIENDO MENSAJE\n");
        struct msg_container *mc = (struct msg_container *) msg.content.ptr;

        if (mc->type == RFC5444_MSGTYPE_RREQ) {
            struct rreq_rrep_data *rreq_data = (struct rreq_rrep_data *) mc->data;
            aodv_packet_writer_send_rreq(rreq_data->packet_data, rreq_data->next_hop);
        }
        else if (mc->type == RFC5444_MSGTYPE_RREP) {
            struct rreq_rrep_data *rrep_data = (struct rreq_rrep_data *) mc->data;
            aodv_packet_writer_send_rrep(rrep_data->packet_data, rrep_data->next_hop);
        }
        else if (mc->type == RFC5444_MSGTYPE_RERR) {
            struct rerr_data *rerr_data = (struct rerr_data *) mc->data;
            aodv_packet_writer_send_rerr(rerr_data->unreachable_nodes, rerr_data->len,
                             rerr_data->hoplimit, rerr_data->next_hop);
        }
        else {
            DEBUG("ERROR: Couldn't identify Message\n");
        }
        _deep_free_msg_container(mc);
    }

    return NULL;
}

// receive RREQs, RREPs and RERRs and handle them 
static void *_aodv_receiver_thread(void *arg)
{
    (void) arg;

    // AODV_DEBUG("%s()\n", __func__);
    // uint32_t fromlen;
    // char buf_rcv[UDP_BUFFER_SIZE];
    // msg_t msg_q[RCV_MSG_Q_SIZE];

    // msg_init_queue(msg_q, RCV_MSG_Q_SIZE);

    // sockaddr6_t sa_rcv = { .sin6_family = AF_INET6,
    //                        .sin6_port = HTONS(MANET_PORT)
    //                      };

    // int sock_rcv = socket_base_socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    // if (-1 == socket_base_bind(sock_rcv, &sa_rcv, sizeof(sa_rcv))) {
    //     DEBUG("Error: bind to receive socket failed!\n");
    //     socket_base_close(sock_rcv);
    // }

    // AODV_DEBUG("ready to receive data\n");
    // while (true) {
    //     int32_t rcv_size = socket_base_recvfrom(sock_rcv, (void *)buf_rcv, UDP_BUFFER_SIZE, 0,
    //                                     &sa_rcv, &fromlen);

    //     if (rcv_size < 0) {
    //         AODV_DEBUG("ERROR receiving data!\n");
    //     }

    //     AODV_DEBUG("_aodv_receiver_thread() %s:",
    //           ipv6_addr_to_str(addr_str, IPV6_MAX_ADDR_STR_LEN, &_v6_addr_local));
    //     DEBUG(" UDP packet received from %s\n",
    //           ipv6_addr_to_str(addr_str, IPV6_MAX_ADDR_STR_LEN, &sa_rcv.sin6_addr));

    //     struct netaddr _sender;
    //     ipv6_addr_t_to_netaddr(&sa_rcv.sin6_addr, &_sender);

    //     // For some reason we sometimes get passed our own packets. drop them. 
    //     if (netaddr_cmp(&_sender, &na_local) == 0) {
    //         AODV_DEBUG("received our own packet, dropping it.\n");
    //         aodv_packet_reader_handle_packet((void *) buf_rcv, rcv_size, &_sender);
    //     }
    // }

    // socket_base_close(sock_rcv);

    return NULL;
} 

/* ipv6_addr_t *aodv_get_next_hop(ipv6_addr_t *dest)
{
    AODV_DEBUG("aodv_get_next_hop() %s:",
          ipv6_addr_to_str(addr_str, IPV6_MAX_ADDR_STR_LEN, &_v6_addr_local));
    DEBUG(" getting next hop for %s\n",
          ipv6_addr_to_str(addr_str, IPV6_MAX_ADDR_STR_LEN, dest));

    struct netaddr _tmp_dest;
    ipv6_addr_t_to_netaddr(dest, &_tmp_dest);
    timex_t now;
    struct unreachable_node unreachable_nodes[AODVV2_MAX_UNREACHABLE_NODES];
    size_t len;

    // The network stack sometimes asks us for the next hop towards our own IP 
    if (memcmp(dest, &_v6_addr_local, sizeof(ipv6_addr_t)) == 0) {
        AODV_DEBUG("That's me, returning loopback\n");
        return &_v6_addr_loopback;
    }

    
    //   TODO use ndp_neighbor_get_ll_address() as soon as it's available.
    //   note: delete check for active/stale/delayed entries, get_ll_address
    //   does that for us then
    
    ndp_neighbor_cache_t *ndp_nc_entry = ndp_neighbor_cache_search(dest);
    struct aodvv2_routing_entry_t *rt_entry = routingtable_get_entry(&_tmp_dest, _metric_type);

    if (ndp_nc_entry != NULL) {
        // Case 2: Broken Link (detected by lower layer) 
        int link_broken = (ndp_nc_entry->state == NDP_NCE_STATUS_INCOMPLETE ||
                           ndp_nc_entry->state == NDP_NCE_STATUS_PROBE) &&
                          (rt_entry != NULL && rt_entry->state != ROUTE_STATE_BROKEN);

        if (link_broken) {
            DEBUG("\tNeighbor Cache entry found, but invalid (state: %i). Sending RERR.\n",
                  ndp_nc_entry->state);

            //  mark all routes (active, idle, expired) that use next_hop as broken
            //   and add all *Active* routes to the list of unreachable nodes 
            routingtable_break_and_get_all_hopping_over(&_tmp_dest, unreachable_nodes, &len);

            aodv_send_rerr(unreachable_nodes, len, &na_mcast);
            return NULL;
        }

        DEBUG("[aodvv2][ndp] found NC entry. Returning dest addr.\n");
        return dest;
    }
    DEBUG("\t[ndp] no entry for addr %s found\n",
          ipv6_addr_to_str(addr_str, IPV6_MAX_ADDR_STR_LEN, dest));

    if (rt_entry) {
        //Case 1: Undeliverable Packet 
        int packet_indeliverable = rt_entry->state == ROUTE_STATE_BROKEN ||
                                   rt_entry->state == ROUTE_STATE_EXPIRED;
        if (packet_indeliverable) {
            DEBUG("\tRouting table entry found, but invalid (state %i). Sending RERR.\n",
                  rt_entry->state);
            unreachable_nodes[0].addr = _tmp_dest;
            unreachable_nodes[0].seqnum = rt_entry->seqnum;
            aodv_send_rerr(unreachable_nodes, 1, &na_mcast);
            return NULL;
        }

        DEBUG("\tfound dest %s in routing table\n",
              ipv6_addr_to_str(addr_str, IPV6_MAX_ADDR_STR_LEN, dest));

        vtimer_now(&now);
        rt_entry->lastUsed = now;
        if (rt_entry->state == ROUTE_STATE_IDLE) {
            rt_entry->state = ROUTE_STATE_ACTIVE;
        }

        //  Currently, there is no way to do this, so I'm doing it the worst
        //   possible, but safe way: I can't make sure that the current call to
        //   aodv_get_next_hop() is overridden by another call to aodv_get_next_hop()
        //   by a thread with higher priority, thus messing up return values if I just
        //   use a static ipv6_addr_t.
        //   The following malloc will never be free()'d. TODO: FIX THIS ASAP.
        
        ipv6_addr_t *next_hop = (ipv6_addr_t *) malloc(sizeof(ipv6_addr_t));
        netaddr_to_ipv6_addr_t(&rt_entry->nextHopAddr, next_hop);

        return next_hop;
    }

    aodvv2_seqnum_t seqnum = seqnum_get();
    seqnum_inc();

    struct aodvv2_packet_data rreq_data = (struct aodvv2_packet_data) {
        .hoplimit = AODVV2_MAX_HOPCOUNT,
        .metricType = _metric_type,
        .origNode = (struct node_data) {
            .addr = na_local,
            .metric = 0,
            .seqnum = seqnum,
        },
        .targNode = (struct node_data) {
            .addr = _tmp_dest,
        },
        .timestamp = (timex_t) {0,0} // this timestamp is never used, it exists
                                      //merely to make the compiler shut up 
    };

    DEBUG("\tNo route found towards %s, starting route discovery... \n",
          ipv6_addr_to_str(addr_str, IPV6_MAX_ADDR_STR_LEN, dest));
    aodv_send_rreq(&rreq_data);

    return NULL;
} */

/**
 * Handle the output of the RFC5444 packet creation process. This callback is
 * called by every writer_send_* function.
 */
static void _write_packet(struct rfc5444_writer *wr __attribute__ ((unused)),
                          struct rfc5444_writer_target *iface __attribute__((unused)),
                          void *buffer, size_t length)
{
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
    //     AODV_DEBUG("originating RREQ with SeqNum %d towards %s via %s; updating RREQ table...\n",
    //           wt->packet_data.origNode.seqnum,
    //           netaddr_to_string(&nbuf, &wt->packet_data.targNode.addr),
    //           ipv6_addr_to_str(addr_str, IPV6_MAX_ADDR_STR_LEN, &sa_wp.sin6_addr));
    //     rreqtable_is_redundant(&wt->packet_data);
    // }

    // size_t bytes_sent =  sendto(_sock_snd, buffer, length, 0, (struct sockaddr*)&sa_wp, sizeof(sa_wp));
    // (void) bytes_sent;
    // AODV_DEBUG("%d bytes sent.\n", bytes_sent);
}


// free the matryoshka doll of cobbled-together structs that the sender_thread receives 
static void _deep_free_msg_container(struct msg_container *mc)
{
    (void)mc;
    // int type = mc->type;
    // if ((type == RFC5444_MSGTYPE_RREQ) || (type == RFC5444_MSGTYPE_RREP)) {
    //     struct rreq_rrep_data *rreq_rrep_data = (struct rreq_rrep_data *) mc->data;
    //     free(rreq_rrep_data->packet_data);
    //     if (netaddr_cmp(rreq_rrep_data->next_hop, &na_mcast) != 0) {
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
