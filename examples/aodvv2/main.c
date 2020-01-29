#include <stdio.h>
#include <string.h>
#include <unistd.h> // for getting the pid
#include <stdlib.h>

#define ENABLE_DEBUG (1)
#include "debug.h"
#include <inttypes.h>

#include "aodvv2/aodvv2.h"
#include "routingtable.h"


#include "shell.h"
#include "msg.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>


//#include "udp.h"
//#include "byteorder.h"

//#include "net/gnrc/netif.h"





#define RANDOM_PORT         (1337)
#define UDP_BUFFER_SIZE     (128)
#define RCV_MSG_Q_SIZE      (64)
#define DATA_SIZE           (20)
#define STREAM_INTERVAL     (2000000)     // microseconds
#define NUM_PKTS            (100)

// constants from the AODVv2 Draft, version 03
#define DISCOVERY_ATTEMPTS_MAX (1) //(3)
#define RREQ_WAIT_TIME         (2000000) // microseconds = 2 seconds

static int _sock_snd;
struct sockaddr_in6 _sockaddr;

msg_t msg_q[RCV_MSG_Q_SIZE];
//gnrc_netif_t *ieee802154_netif;

char _rcv_stack_buf[THREAD_STACKSIZE_MAIN];

static void _demo_init_socket(void);
int demo_print_routingtable(int argc, char** argv);
static void *_demo_receiver_thread(void *arg);



const shell_command_t shell_commands[] = {
    {"print_rt", "print routingtable", demo_print_routingtable},
    {NULL, NULL, NULL}
};

int main(void)
{ 
    msg_init_queue(msg_q, RCV_MSG_Q_SIZE);
    _demo_init_socket();
    aodv_init();
    (void) puts("Welcome to RIOT!");


    thread_create(_rcv_stack_buf, sizeof(_rcv_stack_buf), 
                THREAD_PRIORITY_MAIN, THREAD_CREATE_STACKTEST, 
                _demo_receiver_thread, 
                NULL, "_demo_rcv_thread");

    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}

static void _demo_init_socket(void)
{
    _sockaddr.sin6_family = AF_INET6;
    _sockaddr.sin6_port = (int) byteorder_htons(RANDOM_PORT).u8;

    _sock_snd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    if(-1 == _sock_snd) {
        printf("[demo]   Error Creating Socket!\n");
        return;
    }
}


int demo_print_routingtable(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    print_routingtable();
    return 0;
}


static void *_demo_receiver_thread(void *arg)
{
    (void)arg;

    // uint32_t fromlen;
    // int32_t rcv_size;
    // char buf_rcv[UDP_BUFFER_SIZE];
    // char addr_str_rec[IPV6_ADDR_MAX_STR_LEN];
    msg_t rcv_msg_q[RCV_MSG_Q_SIZE];


    // timex_t _now2;

    msg_init_queue(rcv_msg_q, RCV_MSG_Q_SIZE);
    //struct sockaddr sa_rcv;
    struct sockaddr_in6 sa_rcv;
    sa_rcv.sin6_family = AF_INET;
    sa_rcv.sin6_port = htons(RANDOM_PORT);
    int sock_rcv = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    if(sock_rcv > 0) {
       puts("success initializing socket\n");
    } else {
       puts("errors initializing socket\n");
    }

    if (-1 == bind(sock_rcv,(struct sockaddr*)&sa_rcv, sizeof(sa_rcv))) {
         DEBUG("[demo]   Error: bind to receive socket failed!\n");
         close(sock_rcv);
         
     }

    DEBUG("[demo]   ready to receive data\n");
    // for(;;) {
    //     rcv_size = socket_base_recvfrom(sock_rcv, (void *)buf_rcv, UDP_BUFFER_SIZE, 0,
    //                                       &sa_rcv, &fromlen);

    //     vtimer_now(&_now2);

    //     if(rcv_size < 0) {
    //         DEBUG("{%" PRIu32 ":%" PRIu32 "}[demo]   ERROR receiving data!\n", _now2.seconds, _now2.microseconds);
    //     }
    //     DEBUG("{%" PRIu32 ":%" PRIu32 "}[demo]   UDP packet received from %s: %s\n", _now2.seconds, _now2.microseconds, ipv6_addr_to_str(addr_str_rec, IPV6_MAX_ADDR_STR_LEN, &sa_rcv.sin6_addr), buf_rcv);
    // }

    // socket_base_close(sock_rcv);
    return NULL;
}