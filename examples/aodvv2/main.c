#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // for getting the pid

#define ENABLE_DEBUG (1)
#include "debug.h"
#include <inttypes.h>

#include "aodvv2/aodvv2.h"
#include "routingtable.h"

#include "msg.h"
#include "shell.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "eui64.h"
#include "net/gnrc/ipv6/nib.h"

#include "net/gnrc/ipv6/nib.h"
#include "net/gnrc/ipv6/nib/nc.h"

//#include "netreg.h"

#include "net/gnrc.h"
#include "net/gnrc/pktdump.h"
#include "net/netdev_test.h"
#include "od.h"
#include "xtimer.h"

//#include "udp.h"
//#include "byteorder.h"

//#include "net/gnrc/netif.h"
// add_neighbor fe80::55:44:33:ff:fe:22:11:00 57:44:33:22:11:00
#define DUMPER_QUEUE_SIZE (16)

#define NBR_MAC                                                                \
  { 0x57, 0x44, 0x33, 0x22, 0x11, 0x00, }
#define NBR_LINK_LOCAL                                                         \
  {                                                                            \
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x44, 0x33, 0xff,    \
        0xfe, 0x22, 0x11, 0x00,                                                \
  }
#define DST                                                                    \
  {                                                                            \
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0xab, 0xcd, 0x55, 0x44, 0x33, 0xff,    \
        0xfe, 0x22, 0x11, 0x00,                                                \
  }
#define DST_PFX_LEN (64U)

/* IPv6 header + payload:https://github.com/gustavosinbandera1/RIOT version+TC
 * FL: 0       plen: 16    NH:17 HL:64 */
#define L2_PAYLOAD                                                             \
  {                                                                            \
    0x60, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11,                                  \
        0x40, /* source: random address */                                     \
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0xef, 0x01, 0x02, 0xca, 0x4b,      \
        0xef, 0xf4, 0xc2, 0xde, 0x01, /* destination: DST */                   \
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0xab, 0xcd, 0x55, 0x44, 0x33,      \
        0xff, 0xfe, 0x22, 0x11, 0x00, /* random payload of length 16 */        \
        0x54, 0xb8, 0x59, 0xaf, 0x3a, 0xb4, 0x5c, 0x85, 0x1e, 0xce, 0xe2,      \
        0xeb, 0x05, 0x4e, 0xa3, 0x85,                                          \
  }

// static char addr_str[IPV6_ADDR_MAX_STR_LEN];
static const uint8_t _nbr_mac[] = NBR_MAC;
static const ipv6_addr_t _nbr_link_local = {.u8 = NBR_LINK_LOCAL};
// static const ipv6_addr_t _dst = { .u8 = DST };
// static const uint8_t _l2_payload[] = L2_PAYLOAD;
// static gnrc_netreg_entry_t _dumper;
// static msg_t _dumper_queue[DUMPER_QUEUE_SIZE];
// static char _dumper_stack[THREAD_STACKSIZE_MAIN];

#define RANDOM_PORT (1337)
#define UDP_BUFFER_SIZE (128)
#define RCV_MSG_Q_SIZE (64)
#define DATA_SIZE (20)
#define STREAM_INTERVAL (2000000) // microseconds
#define NUM_PKTS (100)

// constants from the AODVv2 Draft, version 03
#define DISCOVERY_ATTEMPTS_MAX (1) //(3)
#define RREQ_WAIT_TIME (2000000)   // microseconds = 2 seconds

static int _sock_snd;
struct sockaddr_in6 _sockaddr;

msg_t msg_q[RCV_MSG_Q_SIZE];
gnrc_netif_t *_mock_netif = NULL;
timex_t _now;

char _rcv_stack_buf[THREAD_STACKSIZE_MAIN];

static void init_socket(void);
int show_routingtable(int argc, char **argv);
int demo_send(int argc, char **argv);
int demo_attempt_to_send(char *dest_str, char *msg);
static void *_demo_receiver_thread(void *arg);

extern int udp_cmd(int argc, char **argv);
int demo_add_neighbor(int argc, char **argv);
// static void *_demo_receiver_thread(void *arg);

const shell_command_t shell_commands[] = {
    {"print_rt", "print routingtable", show_routingtable},
    {"udp", "send data over UDP and listen on UDP ports", udp_cmd},
    {"add_neighbor", "add neighbor to Neighbor Cache", demo_add_neighbor},
    {"send", "send message to ip", demo_send},
    {NULL, NULL, NULL}};

int main(void) {
  void *iter_state = NULL;
  gnrc_ipv6_nib_nc_t nce;

  msg_init_queue(msg_q, RCV_MSG_Q_SIZE);
  init_socket();
  aodv_init();
  (void)puts("Welcome to RIOT!");
  _mock_netif = gnrc_netif_iter(_mock_netif);
  if (_mock_netif != NULL) {
    DEBUG("tenemos una interface PID: %d\n", _mock_netif->pid);
  }

  gnrc_ipv6_nib_init();
  gnrc_netif_acquire(_mock_netif);
  gnrc_ipv6_nib_init_iface(_mock_netif);
  gnrc_netif_release(_mock_netif);

  while (gnrc_ipv6_nib_nc_iter(0, &iter_state, &nce)) {
    gnrc_ipv6_nib_nc_print(&nce);
  }
  printf("LA IFACE ES: %u", gnrc_ipv6_nib_nc_get_iface(&nce));

  thread_create(_rcv_stack_buf, sizeof(_rcv_stack_buf), THREAD_PRIORITY_MAIN,
                THREAD_CREATE_STACKTEST, _demo_receiver_thread, NULL,
                "_demo_rcv_thread");

  puts("All up, running the shell now");
  char line_buf[SHELL_DEFAULT_BUFSIZE];
  shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

  return 0;
}

static void init_socket(void) {
  _sockaddr.sin6_family = AF_INET6;
  _sockaddr.sin6_port = (int)htons(RANDOM_PORT);

  _sock_snd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

  if (-1 == _sock_snd) {
    printf("[demo]   Error Creating Socket!\n");
    return;
  }
}

int show_routingtable(int argc, char **argv) {
  (void)argc;
  (void)argv;
  print_routingtable();
  return 0;
}

/*
    Help emulate a functional NDP implementation (this should be called for
   every neighbor of the node on the grid)
*/
int demo_add_neighbor(int argc, char **argv) {
  if (argc != 3) {
    printf("Usage: add_neighbor <neighbor ip> <neighbor ll-addr>\n");
    // return 1;
  }
  (void)_nbr_link_local;
  (void)_mock_netif;

  void *iter_state = NULL;
  gnrc_ipv6_nib_nc_t nce;
  int res;
  (void)argv;
  eui64_t eut_eui64;
  (void)eut_eui64;
  ipv6_addr_t neighbor;
  (void)neighbor;
  (void)_nbr_mac;
  // inet_pton(AF_INET6, argv[1], &neighbor); //converts an IPv4 or IPv6
  // Internet network address in its standard text presentation form into its
  // numeric binary form.
  // inet_pton(AF_INET6, (char*)&_nbr_link_local, &neighbor);
  inet_pton(AF_INET6, argv[1], &neighbor);

  /* define neighbor to forward to */
  // res = gnrc_ipv6_nib_nc_set(&_nbr_link_local, _mock_netif->pid,
  //                             _nbr_mac, sizeof(_nbr_mac));

    //res = gnrc_ipv6_nib_nc_set(&neighbor, _mock_netif->pid,
  //                              (uint8_t*)&neighbor.u8[16],
  //                              sizeof(neighbor.u8[14]));

  (void)res;

  while (gnrc_ipv6_nib_nc_iter(0, &iter_state, &nce)) {
    gnrc_ipv6_nib_nc_print(&nce);
  }
  printf("la iface es %u", gnrc_ipv6_nib_nc_get_iface(&nce));

  printf("el estado es %d", gnrc_ipv6_nib_nc_get_nud_state(&nce));

  return 1;
}

int demo_send(int argc, char **argv) {
  if (argc != 3) {
    printf("Usage: send <destination ip> <message>\n");
    return 1;
  }

  char *dest_str = argv[1];
  char *msg = argv[2];

  return demo_attempt_to_send(dest_str, msg);
}

int demo_attempt_to_send(char *dest_str, char *msg) {
  uint8_t num_attempts = 0;

  // turn dest_str into ipv6_addr_t
  inet_pton(AF_INET6, dest_str, &_sockaddr.sin6_addr);
  int msg_len = strlen(msg) + 1;
  (void)msg_len;
  xtimer_now_timex(&_now);

  printf("{%" PRIu32 ":%" PRIu32
         "}[demo]   sending packet of %i bytes towards %s...\n",
         _now.seconds, _now.microseconds, msg_len, dest_str);

  while (num_attempts < DISCOVERY_ATTEMPTS_MAX) {
    int bytes_sent = sendto(_sock_snd, msg, msg_len, 0,
                            (struct sockaddr *)&_sockaddr, sizeof _sockaddr);

    printf("los bytes enviados son %d", bytes_sent);

    xtimer_now_timex(&_now);
    if (bytes_sent == -1) {
      printf(
          "{%" PRIu32 ":%" PRIu32
          "}[demo]   no bytes sent, probably because there is no route yet.\n",
          _now.seconds, _now.microseconds);
      num_attempts++;
      xtimer_usleep(RREQ_WAIT_TIME);
    } else {
      printf("{%" PRIu32 ":%" PRIu32
             "}[demo]   Success sending Data: %d bytes sent.\n",
             _now.seconds, _now.microseconds, bytes_sent);
      return 0;
    }
  }
  printf("{%" PRIu32 ":%" PRIu32
         "}[demo]  Error sending Data: no route found\n",
         _now.seconds, _now.microseconds);
  return -1;
}

static void *_demo_receiver_thread(void *args) {
  (void)args;
  struct sockaddr_in6 sa_rcv;
  uint16_t port;
  msg_t rcv_msg_q[RCV_MSG_Q_SIZE];
  msg_init_queue(rcv_msg_q, RCV_MSG_Q_SIZE);
  int _socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

  port = RANDOM_PORT;
  if (port == 0) {
    puts("Error: invalid port specified");
    return NULL;
  }
  sa_rcv.sin6_family = AF_INET6;
  memset(&sa_rcv.sin6_addr, 0, sizeof(sa_rcv.sin6_addr));
  sa_rcv.sin6_port = htons(port);
  if (_socket < 0) {
    puts("error initializing socket");
    _socket = 0;
    return NULL;
  }

  if (bind(_socket, (struct sockaddr *)&sa_rcv,
           sizeof(sa_rcv)) < 0) {
    _socket = -1;
    puts("error binding socket");
    return NULL;
  }
  printf("Success: started UDP server on port %" PRIu16 "\n", port);
  while (1) {
    int res;
    struct sockaddr_in6 src;
    socklen_t src_len = sizeof(struct sockaddr_in6);
    if ((res = recvfrom(_socket, _rcv_stack_buf, sizeof(_rcv_stack_buf),
                        0, (struct sockaddr *)&src, &src_len)) < 0) {
      puts("Error on receive");
    } else if (res == 0) {
      puts("Peer did shut down");
    } else {
      printf("Received data: ");
      puts(_rcv_stack_buf);
    }
  }
  return NULL;
}