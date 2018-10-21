CONTIKI=../contiki
CONTIKI_WITH_IPV4 = 0
CONTIKI_WITH_IPV6 = 1
CONTIKI_WITH_RPL = 0
CONTIKI_WITH_TCP = 0
CONTIKI_WITH_WOLFSSL = 1
DEBUG=0
UIP_TCP=0
SMALL=1
CFLAGS+=-DWOLFSSL_USER_SETTINGS -I. -DUIP_CONF_ND6_SEND_NS=1 -DUIP_CONF_ND6_SEND_NA=1 \
		-I../wolfBoot/include -I../wolfBoot/lib/bootutil/include \
		-DWOLFBOOT_OVERWRITE_ONLY

CONTIKI_PROJECT=dtls-ota
all: $(CONTIKI_PROJECT)


APPS=wolfssl

PROJECT_SOURCEFILES += cert.c run.c nrf52.c

include $(CONTIKI)/Makefile.include
vpath %c ../wolfBoot/src
vpath %c ../wolfBoot/hal
