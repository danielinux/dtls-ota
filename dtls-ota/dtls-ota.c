/*
 * **** This file incorporates work covered by the following copyright and ****
 * **** permission notice:                                                 ****
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 *
 */

#include "contiki-net.h"
#include "sys/cc.h"
#include "wolfssl.h"
#include "uip-debug.h"

/* wolfboot includes */
#include "flash.h"
#include "target.h"
#include "bootutil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define SERVER_PORT 11111
#define FLASH_AREA_IMAGE_1 2

extern const unsigned char server_cert[788];
extern const unsigned long server_cert_len;

#define MSGLEN (4+ 512)
#define PAGE_SIZE (4 * 1024)

static uint8_t buf[MSGLEN];
struct ota_ack {
    uint32_t error;
    uint32_t offset;
};

static void print_local_addresses(void)
{
  int i;
  uint8_t state;

  printf("Client IPv6 address:\n");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused && (state == ADDR_TENTATIVE || state
                                          == ADDR_PREFERRED)) {
      printf("  ");
      uip_debug_ipaddr_print(&uip_ds6_if.addr_list[i].ipaddr);
      printf("\n");
      if(state == ADDR_TENTATIVE) {
        uip_ds6_if.addr_list[i].state = ADDR_PREFERRED;
      }
    }
  }
}

static struct uip_wolfssl_ctx *sk = NULL;

static struct etimer et;

PROCESS(dtls_client_process, "DTLS process");
AUTOSTART_PROCESSES(&dtls_client_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(dtls_client_process, ev, data)
{
    PROCESS_BEGIN();
    static int ret = 0;
    uip_ipaddr_t server, ipaddr;
    static struct ota_ack ack;
    static uint32_t tot_len = 0;
    static uint32_t offset = 0;
    static const struct flash_area *fap;

    uip_ip6addr(&ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0);
    uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
    uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);
    print_local_addresses();


    sk = dtls_socket_register(wolfDTLSv1_2_client_method());
    if (!sk) {
        while(1)
            ;
    }
    sk->process = &dtls_client_process;
    /* Load certificate file for the DTLS client */
    if (wolfSSL_CTX_use_certificate_buffer(sk->ctx, server_cert,
                server_cert_len, SSL_FILETYPE_ASN1 ) != SSL_SUCCESS)
        while(1)
            ;

    sk->ssl = wolfSSL_new(sk->ctx);
    wolfSSL_CTX_set_verify(sk->ctx, SSL_VERIFY_NONE, 0);
    wolfSSL_SetIOReadCtx(sk->ssl, sk);
    wolfSSL_SetIOWriteCtx(sk->ssl, sk);

    if (sk->ssl == NULL) {
        while(1)
            ;
    }
    wolfSSL_dtls_set_using_nonblock(sk->ssl, 0);

#ifdef NETSTACK_CONF_WITH_IPV4
    uip_ipaddr(&server, 172, 18, 0, 1);
#else
    uip_ip6addr(&server, 0xfd00, 0xa, 0, 0, 0, 0, 0, 1);
#endif
    dtls_set_endpoint(sk, &server, SERVER_PORT);
    printf("connecting to server...\n");
    do {
        ret = wolfSSL_connect(sk->ssl);
        if (ret != SSL_SUCCESS) {
            etimer_set(&et, 5 * CLOCK_SECOND);
            PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et) || (sk->ssl_rb_len > sk->ssl_rb_off));
            if (sk->ssl_rb_len > sk->ssl_rb_off)
                continue;
            printf("\nTimeout!\nRetrying...\n");
            free(sk->ssl);
            sk->ssl = wolfSSL_new(sk->ctx);
            wolfSSL_SetIOReadCtx(sk->ssl, sk);
            wolfSSL_SetIOWriteCtx(sk->ssl, sk);
        }
    } while(ret != SSL_SUCCESS);

    printf("Connected to OTA server.\n");

    do {
        PROCESS_WAIT_EVENT_UNTIL(sk->ssl_rb_len > sk->ssl_rb_off);
        ret = wolfSSL_read(sk->ssl, &tot_len, sizeof(uint32_t));
        if (ret != sizeof(uint32_t)) {
            printf("wolfSSL_read returned %d\r\n", ret);
        }
    } while (ret <= 0);
    etimer_set(&et, 1 * CLOCK_SECOND);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

    if ((tot_len < 256) || (tot_len > FLASH_AREA_IMAGE_1_SIZE)) {
        printf("Wrong firmware size received: %lu\r\n", tot_len);
        ack.error = 1;
        ack.offset = 0;
        wolfSSL_write(sk->ssl, &ack, sizeof(ack));
        goto cleanup;
    }
    printf("Firmware size: %lu\n", tot_len);
    etimer_set(&et, 1 * CLOCK_SECOND);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    ret = flash_area_open(FLASH_AREA_IMAGE_1, &fap);
    if (ret != 0) {
        printf("Cannot open flash partition\r\n");
        goto cleanup;
    }
    flash_area_erase(fap, 0, tot_len);
    printf("Erase complete. Start flashing\n");
    etimer_set(&et, 1 * CLOCK_SECOND);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    ack.offset = offset;
    wolfSSL_write(sk->ssl, &ack, sizeof(ack));
    while (offset < tot_len) {
        static uint32_t *server_offset;
        ack.error = 0;
        ack.offset = offset;
        do {
            ret = wolfSSL_read(sk->ssl, buf, MSGLEN);
            if (ret <= 0) {
                printf("wolfSSL_read returned %d\r\n", ret);
            }
            server_offset = (uint32_t *)buf;
            if (*server_offset != offset) {
                wolfSSL_write(sk->ssl, &ack, sizeof(ack));
            } else {
                flash_area_write(fap, offset, buf + sizeof(uint32_t), ret);
                offset += ret;
                ack.offset = offset;
                wolfSSL_write(sk->ssl, &ack, sizeof(ack));
                printf("RECV: %lu/%lu\r\n", offset, tot_len);
            }
        } while (ret <= 0);
    }
    if (offset == tot_len) {
        printf("Firmware transferred. Triggering upgrade. \r\n");
        boot_set_pending(1);
    }

cleanup:
    printf("Closing connection.\r\n");
    dtls_socket_close(sk);
    sk->ssl = NULL;
    sk->peer_port = 0;
    PROCESS_END();
}
/*---------------------------------------------------------------------------*/
