/* coap_io.h -- Default network I/O functions for libcoap
 *
 * Copyright (C) 2012,2014 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_config.h"

#ifdef HAVE_STDIO_H
#  include <stdio.h>
#endif

#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <errno.h>

#ifdef WITH_CONTIKI
# include "uip.h"
#endif

#include "debug.h"
#include "mem.h"
#include "coap_io.h"
#include "pdu.h"

#ifdef WITH_POSIX
struct coap_packet_t {
  coap_if_handle_t hnd;	      /**< the interface handle */
  coap_address_t src;	      /**< the packet's source address */
  coap_address_t dst;	      /**< the packet's destination address */
  const coap_endpoint_t *interface;

  int ifindex;
  void *session;		/**< opaque session data */

  size_t length;		/**< length of payload */
  unsigned char payload[];	/**< payload */
};
#endif

#ifndef CUSTOM_COAP_NETWORK_ENDPOINT

#ifdef WITH_CONTIKI
static int ep_initialized = 0;

static inline struct coap_endpoint_t *
coap_malloc_contiki_endpoint() {
  static struct coap_endpoint_t ep;

  if (ep_initialized) {
    return NULL;
  } else {
    ep_initialized = 1;
    return &ep;
  }
}

static inline void
coap_free_contiki_endpoint(struct coap_endpoint_t *ep) {
  ep_initialized = 0;
}

coap_endpoint_t *
coap_new_endpoint(const coap_address_t *addr, int flags) {
  struct coap_endpoint_t *ep = coap_malloc_contiki_endpoint();

  if (ep) {
    memset(ep, 0, sizeof(struct coap_endpoint_t));
    ep->handle.conn = udp_new(NULL, 0, NULL);

    if (!ep->handle.conn) {
      coap_free_endpoint(ep);
      return NULL;
    }

    coap_address_init(&ep->addr);
    uip_ipaddr_copy(&ep->addr.addr, &addr->addr);
    ep->addr.port = addr->port;
    udp_bind((struct uip_udp_conn *)ep->handle.conn, addr->port);
  }
  return ep;
}

void
coap_free_endpoint(coap_endpoint_t *ep) {
  if (ep) {
    if (ep->handle.conn) {
      uip_udp_remove((struct uip_udp_conn *)ep->handle.conn);
    }
    coap_free_contiki_endpoint(ep);
  }
}

#else /* WITH_CONTIKI */
static inline struct coap_endpoint_t *
coap_malloc_posix_endpoint(void) {
  return (struct coap_endpoint_t *)coap_malloc(sizeof(struct coap_endpoint_t));
}

static inline void
coap_free_posix_endpoint(struct coap_endpoint_t *ep) {
  coap_free(ep);
}

coap_endpoint_t *
coap_new_endpoint(const coap_address_t *addr, int flags)
{
    struct coap_endpoint_t *ep;
    WSADATA Data;
    DWORD On = 1;
    SOCKET WinSockFd = INVALID_SOCKET;

    if (WSAStartup(MAKEWORD(2, 2), &Data) != NO_ERROR)
    {
        coap_log(LOG_WARNING, "coap_new_endpoint: WSAStartup failed");
        return NULL;
    }

    WinSockFd = WSASocket(addr->addr.sa.sa_family, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);

    if (WinSockFd == INVALID_SOCKET)
    {
        WSACleanup();
        coap_log(LOG_WARNING, "coap_new_endpoint: socket");
        return NULL;
    }

    if (setsockopt(WinSockFd, SOL_SOCKET, SO_REUSEADDR, (const char*)&On, sizeof(DWORD)) == SOCKET_ERROR)
    {
        coap_log(LOG_WARNING, "coap_new_endpoint: setsockopt SO_REUSEADDR");
    }

    switch(addr->addr.sa.sa_family)
    {
        case AF_INET:
            if (setsockopt(WinSockFd, IPPROTO_IP, IP_PKTINFO, (const char*)&On, sizeof(DWORD)) == SOCKET_ERROR)
            {
                coap_log(LOG_ALERT, "coap_new_endpoint: setsockopt IP_PKTINFO\n");
            }

            break;

        case AF_INET6:
#ifdef IPV6_RECVPKTINFO

            if (setsockopt(WinSockFd, IPPROTO_IPV6, IPV6_RECVPKTINFO, (const char*)&On, sizeof(DWORD)) == SOCKET_ERROR)
            {
                coap_log(LOG_ALERT, "coap_new_endpoint: setsockopt IPV6_RECVPKTINFO\n");
            }

#else /* IPV6_RECVPKTINFO */

            if (setsockopt(WinSockFd, IPPROTO_IPV6, IPV6_PKTINFO, (const char*)&On, sizeof(DWORD)) == SOCKET_ERROR)
            {
                coap_log(LOG_ALERT, "coap_new_endpoint: setsockopt IPV6_PKTINFO\n");
            }

#endif /* IPV6_RECVPKTINFO */
            break;

        default:
            coap_log(LOG_ALERT, "coap_new_endpoint: unsupported sa_family\n");
    }

    if (bind(WinSockFd,(SOCKADDR *)&addr->addr.sa, addr->size) == SOCKET_ERROR)
    {
      coap_log(LOG_WARNING, "coap_new_endpoint: bind");
      closesocket(WinSockFd);
      WSACleanup();
      return NULL;
    }

    ep = coap_malloc_posix_endpoint();

    if (ep == NULL)
    {
        coap_log(LOG_WARNING, "coap_new_endpoint: malloc");
        closesocket(WinSockFd);
        return NULL;
    }

    memset(ep, 0, sizeof(struct coap_endpoint_t));
    ep->handle.fd = WinSockFd;
    ep->flags = flags;
    ep->addr.size = addr->size;

    if (getsockname(WinSockFd, &ep->addr.addr.sa, &ep->addr.size) == SOCKET_ERROR)
    {
        coap_log(LOG_WARNING, "coap_new_endpoint: cannot determine local address");
        closesocket(WinSockFd);
        return NULL;
    }

#ifndef NDEBUG
      if (LOG_DEBUG <= coap_get_log_level()) {
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 40
#endif
        unsigned char addr_str[INET6_ADDRSTRLEN+8];

        if (coap_print_addr(&ep->addr, addr_str, INET6_ADDRSTRLEN+8)) {
          debug("created %sendpoint %s\n",
            ep->flags & COAP_ENDPOINT_DTLS ? "DTLS " : "",
            addr_str);
        }
      }
#endif /*NDEBUG */

  return (coap_endpoint_t *)ep;
}

void
coap_free_endpoint(coap_endpoint_t *ep) {
  if(ep) {

#ifdef WINSOCK
    if (ep->handle.fd != INVALID_SOCKET)
    {
        closesocket(ep->handle.fd);
    }
#else
    if (ep->handle.fd >= 0)
      close(ep->handle.fd);
#endif
    coap_free_posix_endpoint((struct coap_endpoint_t *)ep);
  }
}

#endif /* WITH_CONTIKI */
#endif /* CUSTOM_COAP_NETWORK_ENDPOINT */

#ifndef CUSTOM_COAP_NETWORK_SEND

#if defined(WITH_POSIX) != defined(HAVE_NETINET_IN_H)
/* define struct in6_pktinfo and struct in_pktinfo if not available
   FIXME: check with configure
*/

#ifndef WINSOCK
struct in6_pktinfo {
  struct in6_addr ipi6_addr;	/* src/dst IPv6 address */
  unsigned int ipi6_ifindex;	/* send/recv interface index */
};

struct in_pktinfo {
  int ipi_ifindex;
  struct in_addr ipi_spec_dst;
  struct in_addr ipi_addr;
};
#endif

#endif /* WINSOCK */

#if defined(WITH_POSIX) && !defined(SOL_IP)
/* Solaris expects level IPPROTO_IP for ancillary data. */
#define SOL_IP IPPROTO_IP
#endif

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

ssize_t
coap_network_send(
    struct coap_context_t *context UNUSED_PARAM,
    const coap_endpoint_t *local_interface,
    const coap_address_t *dst,
    unsigned char *data,
    size_t datalen)
{
    struct coap_endpoint_t *ep = (struct coap_endpoint_t *)local_interface;
    BYTE CtrlV4[WSA_CMSG_SPACE(sizeof(struct in_pktinfo))];
    BYTE CtrlV6[WSA_CMSG_SPACE(sizeof(struct in6_pktinfo))];
    WSAMSG WSAMhdr;
    WSABUF DataBuf;
    PWSACMSGHDR cmsg = NULL;
    struct in_pktinfo *pktinfo = NULL;
    struct in6_pktinfo *pktinfoin6 = NULL;
    DWORD BytesSent;
    DWORD LastError = NO_ERROR;

    UNREFERENCED_PARAMETER(context);

    assert(local_interface);

    DataBuf.buf = (PCHAR)data;
    DataBuf.len = (ULONG)datalen;

    memset(&WSAMhdr, 0, sizeof(WSAMSG));

    WSAMhdr.name = (LPSOCKADDR)&dst->addr.sa;
    WSAMhdr.lpBuffers = &DataBuf;
    WSAMhdr.dwBufferCount = 1;

    switch (dst->addr.sa.sa_family)
    {
        case AF_INET6:
            WSAMhdr.namelen = sizeof(SOCKADDR_IN6);

            WSAMhdr.Control.buf = (PCHAR)CtrlV6;
            WSAMhdr.Control.len = WSA_CMSG_SPACE(sizeof(struct in6_pktinfo));

            cmsg = WSA_CMSG_FIRSTHDR(&WSAMhdr);
            cmsg->cmsg_level = IPPROTO_IPV6;
            cmsg->cmsg_type = IPV6_PKTINFO;
            cmsg->cmsg_len = WSA_CMSG_LEN(sizeof(struct in6_pktinfo));

            pktinfoin6 = (struct in6_pktinfo *)WSA_CMSG_DATA(cmsg);
            memset(pktinfoin6, 0, sizeof(struct in6_pktinfo));

            if (coap_is_mcast(&local_interface->addr))
            {
                /* We cannot send with multicast address as source address
                 * and hence let the kernel pick the outgoing interface. */

                pktinfoin6->ipi6_ifindex = 0;
                memset(&pktinfoin6->ipi6_addr, 0, sizeof(pktinfoin6->ipi6_addr));
            }
            else
            {
                pktinfoin6->ipi6_ifindex = ep->ifindex;
                pktinfoin6->ipi6_addr = local_interface->addr.addr.sin6.sin6_addr;
            }

            break;

        case AF_INET:
            WSAMhdr.namelen = sizeof(SOCKADDR_IN);

            WSAMhdr.Control.buf = (PCHAR)CtrlV4;
            WSAMhdr.Control.len = WSA_CMSG_SPACE(sizeof(struct in_pktinfo));

            cmsg = WSA_CMSG_FIRSTHDR(&WSAMhdr);
            cmsg->cmsg_level = IPPROTO_IP;
            cmsg->cmsg_type = IP_PKTINFO;
            cmsg->cmsg_len = WSA_CMSG_LEN(sizeof(struct in_pktinfo));

            pktinfo = (struct in_pktinfo *)WSA_CMSG_DATA(cmsg);
            memset(pktinfo, 0, sizeof(struct in_pktinfo));

            if (coap_is_mcast(&local_interface->addr))
            {
                /* We cannot send with multicast address as source address
                 * and hence let the kernel pick the outgoing interface. */

                pktinfo->ipi_ifindex = 0;
                memset(&pktinfo->ipi_addr, 0, sizeof(pktinfo->ipi_addr));
            }
            else
            {
                pktinfo->ipi_ifindex = ep->ifindex;
                pktinfo->ipi_addr = local_interface->addr.addr.sin.sin_addr;
            }

            break;

        default:
            /* error */
            coap_log(LOG_WARNING, "protocol not supported\n");
            return -1;
    }

    if (WSASendMsg(ep->handle.fd, &WSAMhdr, 0, &BytesSent, NULL, NULL) == SOCKET_ERROR)
    {
        LastError = WSAGetLastError();
        coap_log(LOG_CRIT, "WSASendMsg error = %d\n", LastError);
        return -1;
    }
    else
    {
        return BytesSent;
    }

}

#endif /* CUSTOM_COAP_NETWORK_SEND */

#ifndef CUSTOM_COAP_NETWORK_READ

#define SIN6(A) ((struct sockaddr_in6 *)(A))

#ifdef WITH_POSIX
static coap_packet_t *
coap_malloc_packet(void) {
  coap_packet_t *packet;
  const size_t need = sizeof(coap_packet_t) + COAP_MAX_PDU_SIZE;

  packet = (coap_packet_t *)coap_malloc(need);
  if (packet) {
    memset(packet, 0, need);
  }
  return packet;
}

void
coap_free_packet(coap_packet_t *packet) {
  coap_free(packet);
}
#endif /* WITH_POSIX */
#ifdef WITH_CONTIKI
static inline coap_packet_t *
coap_malloc_packet(void) {
  return (coap_packet_t *)coap_malloc_type(COAP_PACKET, 0);
}

void
coap_free_packet(coap_packet_t *packet) {
  coap_free_type(COAP_PACKET, packet);
}
#endif /* WITH_CONTIKI */

static inline size_t
coap_get_max_packetlength(const coap_packet_t *packet UNUSED_PARAM) {

  UNREFERENCED_PARAMETER(packet);

  return COAP_MAX_PDU_SIZE;
}

void
coap_packet_populate_endpoint(coap_packet_t *packet, coap_endpoint_t *target)
{
  target->handle = packet->interface->handle;
  memcpy(&target->addr, &packet->dst, sizeof(target->addr));
  target->ifindex = packet->ifindex;
  target->flags = 0; /* FIXME */
}
void
coap_packet_copy_source(coap_packet_t *packet, coap_address_t *target)
{
  memcpy(target, &packet->src, sizeof(coap_address_t));
}
void
coap_packet_get_memmapped(coap_packet_t *packet, unsigned char **address, size_t *length)
{
	*address = packet->payload;
	*length = packet->length;
}

/**
 * Checks if a message with destination address @p dst matches the
 * local interface with address @p local. This function returns @c 1
 * if @p dst is a valid match, and @c 0 otherwise.
 */
static inline int
is_local_if(const coap_address_t *local, const coap_address_t *dst) {
  return coap_address_isany(local) || coap_address_equals(dst, local) ||
    coap_is_mcast(dst);
}

ssize_t
coap_network_read(coap_endpoint_t *ep, coap_packet_t **packet)
{
    DWORD BytesReceived;
    DWORD BytesIDontKnowWhatTheseAre;
    char msg_control[WSA_CMSG_LEN(sizeof(struct sockaddr_storage))];
    WSAMSG WSAMhdr;
    WSABUF DataBuf[1];
    WSACMSGHDR *cmsg;
    LPFN_WSARECVMSG WSARecvMsg = NULL;
    GUID RecvMsgGuid = WSAID_WSARECVMSG;

    assert(ep);
    assert(packet);

    *packet = coap_malloc_packet();

    if (!*packet)
    {
        warn("coap_network_read: insufficient memory, drop packet\n");
        return -1;
    }

    coap_address_init(&(*packet)->dst); /* the local interface address */
    coap_address_init(&(*packet)->src); /* the remote peer */

    DataBuf[0].buf = (char*)((*packet)->payload);
    DataBuf[0].len = (ULONG)coap_get_max_packetlength(*packet);

    memset(&WSAMhdr, 0, sizeof(WSAMSG));

    WSAMhdr.name = (PSOCKADDR)&(*packet)->src.addr.st;
    WSAMhdr.namelen = sizeof((*packet)->src.addr.st);

    WSAMhdr.lpBuffers = DataBuf;
    WSAMhdr.dwBufferCount = 1;

    WSAMhdr.Control.buf = msg_control;
    WSAMhdr.Control.len = sizeof(msg_control);
    assert(sizeof(msg_control) == WSA_CMSG_LEN(sizeof(struct sockaddr_storage)));

    if (WSAIoctl(ep->handle.fd,
                 SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &RecvMsgGuid,
                 sizeof(GUID),
                 &WSARecvMsg,
                 sizeof(WSARecvMsg),
                 &BytesIDontKnowWhatTheseAre,
                 NULL,
                 NULL) != 0)
     {
        coap_log(LOG_WARNING, "coap_network_read: %d\n", WSAGetLastError());
        goto error;
     }

    if (WSARecvMsg(ep->handle.fd, &WSAMhdr, &BytesReceived, NULL, NULL) == SOCKET_ERROR)
    {
      coap_log(LOG_WARNING, "coap_network_read: %d\n", WSAGetLastError());
      goto error;
    }

    coap_log(LOG_DEBUG, "received %d bytes on fd %d\n", (int)BytesReceived, ep->handle.fd);

    /* use getsockname() to get the local port */
    (*packet)->dst.size = sizeof((*packet)->dst.addr);

    if (getsockname(ep->handle.fd, &(*packet)->dst.addr.sa, &(*packet)->dst.size) == SOCKET_ERROR)
    {
        coap_log(LOG_DEBUG, "cannot determine local port\n");
        goto error;
    }

    (*packet)->length = BytesReceived;

    /* Walk through ancillary data records until the local interface
     * is found where the data was received. */

    for (cmsg = WSA_CMSG_FIRSTHDR(&WSAMhdr); cmsg != NULL; cmsg = WSA_CMSG_NXTHDR(&WSAMhdr, cmsg))
    {

        /* get the local interface for IPv6 */
        if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO)
        {
            union
            {
                unsigned char *c;
                struct in6_pktinfo *p;
            } u;

            u.c = WSA_CMSG_DATA(cmsg);
            (*packet)->ifindex = (int)(u.p->ipi6_ifindex);

            memcpy(&(*packet)->dst.addr.sin6.sin6_addr,
                   &u.p->ipi6_addr,
                   sizeof(struct in6_addr));

            (*packet)->src.size = WSAMhdr.namelen;
            assert((*packet)->src.size == sizeof(struct sockaddr_in6));

            (*packet)->src.addr.sin6.sin6_family = SIN6(WSAMhdr.name)->sin6_family;
            (*packet)->src.addr.sin6.sin6_addr = SIN6(WSAMhdr.name)->sin6_addr;
            (*packet)->src.addr.sin6.sin6_port = SIN6(WSAMhdr.name)->sin6_port;

            break;
        }

        /* local interface for IPv4 */
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO)
        {
            union
            {
                unsigned char *c;
                struct in_pktinfo *p;
            } u;

            u.c = WSA_CMSG_DATA(cmsg);
            (*packet)->ifindex = u.p->ipi_ifindex;

            memcpy(&(*packet)->dst.addr.sin.sin_addr,
                   &u.p->ipi_addr,
                   sizeof(struct in_addr));

            (*packet)->src.size = WSAMhdr.namelen;
            memcpy(&(*packet)->src.addr.st, WSAMhdr.name, (*packet)->src.size);

            break;
        }
    }

    if (!is_local_if(&ep->addr, &(*packet)->dst))
    {
        coap_log(LOG_DEBUG, "packet received on wrong interface, dropped\n");
        goto error;
    }

    (*packet)->interface = ep;

    return BytesReceived;

 error:

    coap_free_packet(*packet);
    *packet = NULL;
    return -1;
}

#undef SIN6

#endif /*  CUSTOM_COAP_NETWORK_READ */
