# name of your application
APPLICATION = aodvv2

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

# Modules to include:
USEMODULE += shell
USEMODULE += shell_commands
USEMODULE += ps

USEPKG += oonf_api


BOARD_PROVIDES_NETIF := acd52832 airfy-beacon atmega256rfr2-xpro avr-rss2 b-l072z-lrwan1 cc2538dk fox \
        derfmega128 derfmega256 hamilton iotlab-m3 iotlab-a8-m3 lobaro-lorabox lsn50 mulle microbit msba2 \
        microduino-corerf native nrf51dk nrf51dongle nrf52dk nrf52840dk nrf52840-mdk nrf6310 \
        nucleo-f207zg nucleo-f767zi openmote-b openmote-cc2538 pba-d-01-kw2x remote-pa \
        remote-reva ruuvitag samr21-xpro samr30-xpro spark-core telosb thingy52 yunjia-nrf51822 z1

ifneq (,$(filter $(BOARD),$(BOARD_PROVIDES_NETIF)))
  # Use modules for networking
  # gnrc is a meta module including all required, basic gnrc networking modules
  USEMODULE += gnrc
  # use the default network interface for the board
  USEMODULE += gnrc_netdev_default
  # automatically initialize the network interface
  USEMODULE += auto_init_gnrc_netif


  # the application dumps received packets to stdout
  USEMODULE += gnrc_pktdump

  USEMODULE += gnrc_ipv6_default #All networking modules are loaded
  
  # Import posix sockets
  USEMODULE += gnrc_sock_udp
  USEMODULE += posix_sockets
  USEMODULE += posix_inet

  USEMODULE += xtimer
  USEMODULE += timex

  # We use only the lower layers of the GNRC network stack, hence, we can
  # reduce the size of the packet buffer a bit
  CFLAGS += -DGNRC_PKTBUF_SIZE=512
endif

USERMODULE += aodvv2



export INCLUDES += -I${RIOTBASE}/sys/include/net/
export INCLUDES += -I${RIOTBASE}/sys/net/routing/aodvv2/

include $(RIOTBASE)/Makefile.include

# Set a custom channel if needed
#include $(RIOTMAKE)/default-radio-settings.inc.mk
