// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
#include <unistd.h> // for getting the pid

#define ENABLE_DEBUG (1)
#include "debug.h"
// #include <inttypes.h>

#include "aodvv2/aodvv2.h"
// #include "routingtable.h"

#include "msg.h"
#include "shell.h"

// #include <arpa/inet.h>
// #include <netinet/in.h>
// #include <sys/socket.h>

#include "eui64.h"
#include "net/gnrc/ipv6/nib.h"

#include "net/gnrc/ipv6/nib.h"
#include "net/gnrc/ipv6/nib/nc.h"

#include "net/gnrc.h"
// #include "net/gnrc/pktdump.h"
#include "net/netdev_test.h"
#include "od.h"
#include "xtimer.h"

#include "net/gnrc/ipv6.h"

#include "shell_functions.c"

// static gnrc_netreg_entry_t _dumper;
// static msg_t _dumper_queue[DUMPER_QUEUE_SIZE];
// static char _dumper_stack[THREAD_STACKSIZE_MAIN];


extern void init_socket(void);
extern int show_routingtable(int argc, char **argv);
extern int demo_send(int argc, char **argv);
extern int udp_cmd(int argc, char **argv);
extern int demo_add_neighbor(int argc, char **argv);
extern void *_demo_receiver_thread(void *arg);

const shell_command_t shell_commands[] = {
    {"print_rt", "print routingtable", show_routingtable},
    {"add_neighbor", "add neighbor to Neighbor Cache", demo_add_neighbor},
    {"send", "send message to ip", demo_send},
    {NULL, NULL, NULL}};

int main(void) {
  void *iter_state = NULL;
  gnrc_ipv6_nib_nc_t nce;

  msg_init_queue(msg_q, RCV_MSG_Q_SIZE);
  init_socket();
  aodv_init();
  //gnrc_ipv6_init(); // to capture message from app inside network layer

  (void)puts("Welcome to RIOT!");
  _mock_netif = gnrc_netif_iter(_mock_netif);
  if (_mock_netif != NULL) {
    DEBUG("tenemos una interface PID: %d\n", _mock_netif->pid);
  }

  // neighbor information base init
  gnrc_ipv6_nib_init();
  gnrc_netif_acquire(_mock_netif);
  // to bind desired iface to nib
  gnrc_ipv6_nib_init_iface(_mock_netif);
  gnrc_netif_release(_mock_netif);

  // this should print the neighbord list but I cannnot see anything
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

