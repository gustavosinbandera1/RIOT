
/* Copyright (C) 2020 Locha Inc
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
 * @file        aodvv2/types.h
 * @brief       data types for the aodvv2 routing protocol
 *
 * @author      Lotte Steenbrink <lotte.steenbrink@fu-berlin.de>
 * @author      Gustavo Grisales <gustavosinbandera1@hotmail.com.com>
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

#include "xtimer.h"

#include "net/protnum.h"
#include "net/sock/ip.h"
#include "net/sock/udp.h"

#include "rfc5444/rfc5444_print.h"
uint8_t buf[128];

#define RCV_MSG_Q_SIZE (32)

static char aodv_snd_stack_buf[GNRC_UDP_STACK_SIZE];
static char aodv_rcv_stack_buf[THREAD_STACKSIZE_DEFAULT];
static gnrc_netif_t *ieee802154_netif = NULL;

static kernel_pid_t _pid = KERNEL_PID_UNDEF;
static char _stack[GNRC_UDP_STACK_SIZE];

ipv6_addr_t dest_addr;
ipv6_addr_t sender_addr;
static int sender_thread;

static struct autobuf _hexbuf;
static struct writer_target *wt;

#define UDP_BUFFER_SIZE (128) /** with respect to IEEE 802.15.4's MTU */

struct netaddr na_mcast = (struct netaddr){};
static struct netaddr
    na_local; /* the same as _v6_addr_local, but to save us
               * constant calls to ipv6_addr_t_to_netaddr()... */

static ipv6_addr_t _v6_addr_local, _v6_addr_mcast, _v6_addr_loopback;
char addr_str[IPV6_ADDR_MAX_STR_LEN];

static void *_event_loop(void *arg);
static void *gnrc_aodvv2_sender_thread(void *arg);
static void *_aodv_receiver_thread(void *arg);
static void _send(gnrc_pktsnip_t *pkt);
static void _receive(gnrc_pktsnip_t *pkt);

static uint16_t _calc_csum(gnrc_pktsnip_t *hdr, gnrc_pktsnip_t *pseudo_hdr, 
    gnrc_pktsnip_t *payload);
static void gnrc_process_message(gnrc_pktsnip_t *pkt);

ipv6_addr_t gnrc_get_ipv6_from_iface(gnrc_netif_t *netif);

static void _write_packet(struct rfc5444_writer *wr __attribute__((unused)), 
    struct rfc5444_writer_target *iface __attribute__((unused)),void *buffer, size_t length);

void gnrc_aodvv2_init(void) {
    (void)_v6_addr_local;
    (void)_v6_addr_mcast;
    (void)_v6_addr_loopback;

    // get netif interface
    ieee802154_netif = gnrc_netif_iter(ieee802154_netif);
    if (ieee802154_netif != NULL)
    {
        DEBUG("interface: %d\n", ieee802154_netif->pid);
    }

    sender_addr = gnrc_get_ipv6_from_iface(ieee802154_netif);

    if (_pid == KERNEL_PID_UNDEF)
    {
        /* start thread */
        _pid = thread_create(_stack, sizeof(_stack), GNRC_UDP_PRIO, THREAD_CREATE_STACKTEST, _event_loop, NULL, "IPV6");
    }

    sender_thread = thread_create(
        aodv_snd_stack_buf, sizeof(aodv_snd_stack_buf), THREAD_PRIORITY_MAIN - 1,
        THREAD_CREATE_STACKTEST, gnrc_aodvv2_sender_thread, NULL,
        "gnrc_aodvv2_sender_thread");

    // start listening & enable sending
    thread_create(aodv_rcv_stack_buf, sizeof(aodv_rcv_stack_buf),
        THREAD_PRIORITY_MAIN - 1, THREAD_CREATE_STACKTEST,
        _aodv_receiver_thread, NULL, "_aodv_receiver_thread");
        (void)aodv_rcv_stack_buf;
        gnrc_aodvv2_packet_writer_init(_write_packet);
        aodv_packet_reader_init();
        //seqnum_init();
}

static void *_event_loop(void *arg){
    (void)arg;
    msg_t msg, reply;
    msg_t msg_queue[GNRC_UDP_MSG_QUEUE_SIZE];

    reply.type = GNRC_NETAPI_MSG_TYPE_ACK;
    reply.content.value = -ENOTSUP;
    msg_init_queue(msg_queue, GNRC_UDP_MSG_QUEUE_SIZE);
    gnrc_pktsnip_t *pkt = NULL;
    (void)pkt;

    gnrc_netreg_entry_t netreg = GNRC_NETREG_ENTRY_INIT_PID(80, thread_getpid());
    gnrc_netreg_register(GNRC_NETTYPE_UDP, &netreg);

    while (1)
    {
        msg_receive(&msg);
        switch (msg.type)
        {
        case GNRC_NETAPI_MSG_TYPE_RCV:
            pkt = msg.content.ptr;
            break;
        case GNRC_NETAPI_MSG_TYPE_SND:
            DEBUG("GETTING MESSAGE FROM" "FROM APP\n");
            pkt = msg.content.ptr;
            gnrc_process_message(msg.content.ptr);
            break;
        case GNRC_NETAPI_MSG_TYPE_SET:
        case GNRC_NETAPI_MSG_TYPE_GET:
            msg_reply(&msg, &reply);
            break;
        default:
            break;
        }
    }
    return NULL;
}

/**
 * @brief this function is in order to handle packets from app layer, create and send RFC 5444 packets
 * 
 * @param pkt pkt represents the block of memory with the header with all data from app layer 
 */

static void gnrc_process_message(gnrc_pktsnip_t *pkt)
{
    (void)pkt;
    char temp[] = "fe80::200:2:0:0";
    char *target_addr = 0;
    memcpy(target_addr, temp, strlen(temp));
    ipv6_addr_from_str(&dest_addr, temp);
    gnrc_aodv_get_next_hop(&dest_addr);
}

/**
 * @brief This function is to create the aodv package and send it to be processed by the api RFC 5444
 * 
 * @param dest destination address where the package is supposed to go
 * @return ipv6_addr_t* 
 */
ipv6_addr_t *gnrc_aodv_get_next_hop(ipv6_addr_t *dest)
{

    DEBUG(" getting next hop for %s\n",
          ipv6_addr_to_str(addr_str, dest, IPV6_ADDR_MAX_STR_LEN));
    (void)na_local;
    aodvv2_metric_t _metric_type = AODVV2_DEFAULT_METRIC_TYPE;
    ipv6_addr_t v6_addr_local = gnrc_get_ipv6_from_iface(ieee802154_netif);

    DEBUG("aodv_get_next_hop() %s:",
          ipv6_addr_to_str(addr_str, &v6_addr_local, IPV6_ADDR_MAX_STR_LEN));
    (void)v6_addr_local;
    struct netaddr na_dest;
    _v6_addr_mcast = ipv6_addr_all_nodes_link_local;
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
        .timestamp = (timex_t){0, 0} /* this timestamp is never used, it exists, merely to make the compiler shut up */
    };
    (void)rreq_data;
    gnrc_aodv_send_rreq(&rreq_data);
    return 0;
}

/**
 * @brief this function creates a wraper for the aodv package to send it to the thread responsible for handling the packet and use RFC 5444 api
 * 
 * @param packet_data the aodv packet with indformation realte with the protocol 
 */
void gnrc_aodv_send_rreq(struct aodvv2_packet_data *packet_data)
{
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


/**
 * @brief Build RREQs, RREPs and RERRs from the information contained in the thread's message queue and send them
 * 
 * @param arg this variabe is not used in this section
 * @return void* 
 */
static void *gnrc_aodvv2_sender_thread(void *arg)
{
    (void)arg;

    msg_t msgq[RCV_MSG_Q_SIZE];
    msg_init_queue(msgq, sizeof msgq);
    while (true)
    {
        DEBUG("%s()\n", __func__);
        msg_t msg;
        msg_receive(&msg);
        struct msg_container *mc = (struct msg_container *)msg.content.ptr;

        if (mc->type == RFC5444_MSGTYPE_RREQ)
        {
            struct rreq_rrep_data *rreq_data = (struct rreq_rrep_data *)mc->data;
            gnrc_aodvv2_packet_writer_send_rreq(rreq_data->packet_data,
                                                rreq_data->next_hop);
        }
        else
        {
            DEBUG("ERROR: Couldn't identify Message\n");
        }
    }

    return NULL;
}

/**
 * @brief this function can return IPV^ address version with just knowing the network interface
 * 
 * @param netif 
 * @return ipv6_addr_t 
 */

ipv6_addr_t gnrc_get_ipv6_from_iface(gnrc_netif_t *netif)
{
    ipv6_addr_t ipv6_addr;
    int r = gnrc_netapi_get(netif->pid, NETOPT_IPV6_ADDR, 0, &ipv6_addr,
                            sizeof(ipv6_addr));
    if (r < 0)
    {
        DEBUG("unspecified address\n");
        return (ipv6_addr_t)IPV6_ADDR_UNSPECIFIED;
    }

    for (unsigned i = 0; i < (unsigned)(r / sizeof(ipv6_addr_t)); i++)
    {
        char ipv6_address[IPV6_ADDR_MAX_STR_LEN];
        ipv6_addr_to_str(ipv6_address, &ipv6_addr, IPV6_ADDR_MAX_STR_LEN);
    }
                                                                                return ipv6_addr;
}

/**
 * @brief Handle the output of the RFC5444 packet creation process. This callback iscalled by every writer_send_* function.
 * 
 * @param wr 
 * @param iface 
 * @param buffer 
 * @param length 
 */
static void _write_packet(struct rfc5444_writer *wr __attribute__((unused)),
                        struct rfc5444_writer_target *iface __attribute__((unused)),
                        void *buffer, size_t length)
{

    ipv6_addr_t temp_addr_dest;
    char *addr_str = 0;

    abuf_hexdump(&_hexbuf, "\t", buffer, length);
    rfc5444_print_direct(&_hexbuf, buffer, length);
    DEBUG("%s", abuf_getptr(&_hexbuf));
    abuf_clear(&_hexbuf);

    wt = container_of(iface, struct writer_target, interface);

    netaddr_to_ipv6_addr_t(&wt->target_addr, &temp_addr_dest);
    DEBUG("!!!!!!!!!!!!!!!!!!!MIRA ESTA IP: %s",
          ipv6_addr_to_str(addr_str, &temp_addr_dest, IPV6_ADDR_MAX_STR_LEN));

    if (wt->type == RFC5444_MSGTYPE_RREQ)
    {
        DEBUG("<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>ESTO ES UN ROUTE REQUEST\n");
        udp_send(ipv6_addr_all_nodes_link_local, MANET_PORT, buffer, length);
    }
    else
    {
        udp_send(temp_addr_dest, MANET_PORT, buffer, length);
    }
}

/**
 * @brief This function sends packets to remote nodes
 * 
 * @param dest_addr 
 * @param port 
 * @param data 
 * @param len 
 * @return int 
 */
static int udp_send(ipv6_addr_t dest_addr, uint16_t port, void *data,
                    size_t len)
{
    sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
    sock_udp_t sock;
    local.port = port;
    (void)dest_addr;
    if (sock_udp_create(&sock, &local, NULL, 0) < 0)
    {
        puts("Error creating UDP sock");
        return 1;
    }

    sock_udp_ep_t remote = {.family = AF_INET6};
    remote.port = MANET_PORT;
    memcpy(&remote.addr, &dest_addr, sizeof(remote.addr));

    if (sock_udp_send(&sock, data, len, &remote) < 0)
    {
        DEBUG("Error sending message");
        sock_udp_close(&sock);
        return 1;
    }

    return 0;
}


/**
 * @brief receive RREQs, RREPs and RERRs and handle them
 * 
 * @param arg 
 * @return void* 
 */
static void *_aodv_receiver_thread(void *arg)
{
    (void)arg;

    DEBUG("%s()\n", __func__);
    char buf_rcv[UDP_BUFFER_SIZE];
    memset(buf_rcv, 0, sizeof(buf_rcv));

    struct sockaddr_in6 sa_rcv;
    sa_rcv.sin6_family = AF_INET;
    sa_rcv.sin6_port = htons(MANET_PORT);

    msg_t rcv_msg_q[RCV_MSG_Q_SIZE];
    msg_init_queue(rcv_msg_q, RCV_MSG_Q_SIZE);
    int _socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    sa_rcv.sin6_family = AF_INET6;
    memset(&sa_rcv.sin6_addr, 0, sizeof(sa_rcv.sin6_addr));
    if (_socket < 0)
    {
        DEBUG("error initializing socket\n");
        _socket = 0;
        return NULL;
    }

    if (bind(_socket, (struct sockaddr *)&sa_rcv, sizeof(sa_rcv)) < 0)
    {
        _socket = -1;
        DEBUG("error binding socket\n");
        return NULL;
    }
    DEBUG("Success: started UDP>>>to receive ROUTE MESSAGES");
    while (1)
    {
        int res;
        struct sockaddr_in6 src;
        socklen_t src_len = sizeof(struct sockaddr_in6);
        if ((res = recvfrom(_socket, buf_rcv, sizeof(buf_rcv), 0,
                            (struct sockaddr *)&src, &src_len)) < 0)
        {
            DEBUG("Error on receive\n");
        }
        else if (res == 0)
        {
            DEBUG("Peer did shut down\n");
        }
        else
        {
            DEBUG("<RECEIVING DATA FROM REMOTE\n");
            struct netaddr _sender_net_addr;
            ipv6_addr_t temp_ipv6_addr;
            memcpy(&temp_ipv6_addr, &src.sin6_addr, sizeof(temp_ipv6_addr));
            char temp_ipv_str[IPV6_ADDR_MAX_STR_LEN];
            ipv6_addr_to_str(temp_ipv_str, &temp_ipv6_addr, IPV6_ADDR_MAX_STR_LEN);

            DEBUG("GETTING DATA FROM AODV PACKET %s ", temp_ipv_str);
            ipv6_addr_t_to_netaddr(&temp_ipv6_addr, &_sender_net_addr);
            close(_socket);
            puts(buf_rcv);
            int state = aodv_packet_reader_handle_packet((void *)buf_rcv, sizeof(buf_rcv),
                                                     &_sender_net_addr);
            DEBUG("\n\n\nstate of RFC5444 transaction %d\n\n", state);
        }
    }

    return NULL;
}