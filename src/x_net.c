/* Copyright (c) 1997-1999 Miller Puckette.
* For information on usage and redistribution, and for a DISCLAIMER OF ALL
* WARRANTIES, see the file, "LICENSE.txt," in this distribution.  */

/* network */

#include "m_pd.h"
#include "m_imp.h"
#include "s_stuff.h"
#include "s_net.h"

#include <string.h>
#include "m_private_utils.h"

#ifndef _WIN32
#include <fcntl.h>
#include <errno.h>
#endif
#if PDTHREADS
#include <pthread.h>
#endif

/* print addrinfo lists for debugging */
/* #define PRINT_ADDRINFO */

/* ----------------------------- helpers ------------------------- */

void socketreceiver_free(t_socketreceiver *x);

static void outlet_sockaddr(t_outlet *o, const struct sockaddr *sa)
{
    char addrstr[INET6_ADDRSTRLEN];
    unsigned short port = sockaddr_get_port(sa);
    if (sockaddr_get_addrstr(sa, addrstr, INET6_ADDRSTRLEN))
    {
        t_atom ap[2];
        SETSYMBOL(&ap[0], gensym(addrstr));
        SETFLOAT(&ap[1], (t_float)port);
        outlet_list(o, NULL, 2, ap);
    }
}

/* ----------------------------- net ------------------------- */

static t_class *netsend_class;

typedef struct _netsend
{
    t_object x_obj;
    t_outlet *x_msgout;
    t_outlet *x_connectout;
    t_outlet *x_fromout;
    int x_sockfd;
    int x_protocol;
    int x_bin;
    t_socketreceiver *x_receiver;
    struct sockaddr_storage x_server;
    t_float x_timeout; /* TCP connect timeout in seconds */
} t_netsend;

static t_class *netreceive_class;

typedef struct _netreceive
{
    t_netsend x_ns;
    int x_nconnections;
    int x_sockfd;
    int *x_connections;
    int x_old;
    t_socketreceiver **x_receivers;
    struct _udpsub *x_udpsub; /* shared UDP subscription, or NULL */
} t_netreceive;

static void netsend_disconnect(t_netsend *x);
static void netreceive_notify(t_netreceive *x, int fd);

/* ----------------------------- netsend ------------------------- */

static void *netsend_new(t_symbol *s, int argc, t_atom *argv)
{
    t_netsend *x = (t_netsend *)pd_new(netsend_class);
    outlet_new(&x->x_obj, &s_float);
    x->x_protocol = SOCK_STREAM;
    x->x_bin = 0;
    if (argc && argv->a_type == A_FLOAT)
    {
        x->x_protocol = (argv->a_w.w_float != 0 ? SOCK_DGRAM : SOCK_STREAM);
        argc = 0;
    }
    else while (argc && argv->a_type == A_SYMBOL &&
        *argv->a_w.w_symbol->s_name == '-')
    {
        if (!strcmp(argv->a_w.w_symbol->s_name, "-b"))
            x->x_bin = 1;
        else if (!strcmp(argv->a_w.w_symbol->s_name, "-u"))
            x->x_protocol = SOCK_DGRAM;
        else
        {
            pd_error(x, "netsend: unknown flag ...");
            postatom(argc, argv); endpost();
        }
        argc--; argv++;
    }
    if (argc)
    {
        pd_error(x, "netsend: extra arguments ignored:");
        postatom(argc, argv); endpost();
    }
    x->x_sockfd = -1;
    x->x_receiver = NULL;
    x->x_msgout = outlet_new(&x->x_obj, &s_anything);
    x->x_connectout = NULL;
    x->x_fromout = NULL;
    x->x_timeout = 10;
    memset(&x->x_server, 0, sizeof(struct sockaddr_storage));
    return (x);
}

static void netsend_readbin(t_netsend *x, int fd)
{
    unsigned char *inbuf = sys_getrecvbuf(0);
    int ret = 0, readbytes = 0, i;
    struct sockaddr_storage fromaddr = {0};
    socklen_t fromaddrlen = sizeof(struct sockaddr_storage);
    if (!x->x_msgout)
    {
        bug("netsend_readbin");
        return;
    }
    while (1)
    {
        if (x->x_protocol == SOCK_DGRAM)
            ret = (int)recvfrom(fd, inbuf, NET_MAXPACKETSIZE, 0,
                (struct sockaddr *)&fromaddr, &fromaddrlen);
        else
            ret = (int)recv(fd, inbuf, NET_MAXPACKETSIZE, 0);
        if (ret <= 0)
        {
            if (ret < 0)
            {
                /* socket_errno_udp() ignores some error codes */
                if (x->x_protocol == SOCK_DGRAM && !socket_errno_udp())
                    return;
                sys_sockerror("recv (bin)");
            }
            if (x->x_obj.ob_pd == netreceive_class)
            {
                    /* never close UDP socket because we can't really notify it */
                if (x->x_protocol != SOCK_DGRAM)
                {
                    sys_rmpollfn(fd);
                    sys_closesocket(fd);
                    netreceive_notify((t_netreceive *)x, fd);
                }
            }
            else /* properly shutdown netsend */
                netsend_disconnect(x);
            return;
        }
        if (x->x_protocol == SOCK_DGRAM)
        {
            t_atom *ap;
            if (x->x_fromout)
                outlet_sockaddr(x->x_fromout, (const struct sockaddr *)&fromaddr);
                /* handle too large UDP packets */
            if (ret > NET_MAXPACKETSIZE)
            {
                post("warning: incoming UDP packet truncated from %d to %d bytes.",
                    ret, NET_MAXPACKETSIZE);
                ret = NET_MAXPACKETSIZE;
            }
            ap = (t_atom *)alloca(ret * sizeof(t_atom));
            for (i = 0; i < ret; i++)
                SETFLOAT(ap+i, inbuf[i]);
            outlet_list(x->x_msgout, 0, ret, ap);
            readbytes += ret;
            /* throttle */
            if (readbytes >= NET_MAXPACKETSIZE)
                return;
            /* check for pending UDP packets */
            if (socket_bytes_available(fd) <= 0)
                return;
        }
        else
        {
            if (x->x_fromout &&
                !getpeername(fd, (struct sockaddr *)&fromaddr, &fromaddrlen))
                    outlet_sockaddr(x->x_fromout, (const struct sockaddr *)&fromaddr);
            for (i = 0; i < ret; i++)
                outlet_float(x->x_msgout, inbuf[i]);
            return;
        }
    }
}

static void netsend_read(void *z, t_binbuf *b)
{
    t_netsend *x = (t_netsend *)z;
    int msg, natom = binbuf_getnatom(b);
    t_atom *at = binbuf_getvec(b);
    for (msg = 0; msg < natom;)
    {
        int emsg;
        for (emsg = msg; emsg < natom && at[emsg].a_type != A_COMMA
             && at[emsg].a_type != A_SEMI; emsg++)
            ;
        if (emsg > msg)
        {
            int i;
            for (i = msg; i < emsg; i++)
                if (at[i].a_type == A_DOLLAR || at[i].a_type == A_DOLLSYM)
                {
                    pd_error(x, "netreceive: got dollar sign in message");
                    goto nodice;
                }
            if (at[msg].a_type == A_FLOAT)
            {
                if (emsg > msg + 1)
                    outlet_list(x->x_msgout, 0, emsg-msg, at + msg);
                else outlet_float(x->x_msgout, at[msg].a_w.w_float);
            }
            else if (at[msg].a_type == A_SYMBOL)
                outlet_anything(x->x_msgout, at[msg].a_w.w_symbol,
                    emsg-msg-1, at + msg + 1);
        }
    nodice:
        msg = emsg + 1;
    }
}

static void netsend_notify(void *z, int fd)
{
    t_netsend *x = (t_netsend *)z;
    if (x->x_sockfd >= 0)
    {
        /* sys_rmpollfn() and sys_closesocket() are
           already called in socketreceiver_read */
        x->x_sockfd = -1;
        if (x->x_receiver)
            socketreceiver_free(x->x_receiver);
        x->x_receiver = NULL;
        memset(&x->x_server, 0, sizeof(struct sockaddr_storage));
        outlet_float(x->x_obj.ob_outlet, 0);
    }
}

static void netsend_connect(t_netsend *x, t_symbol *s, int argc, t_atom *argv)
{
    int portno, sportno, sockfd, multicast = 0, status;
    struct addrinfo *ailist = NULL, *ai;
    const char *hostname = NULL;
    char hostbuf[256];

    /* check argument types */
    if ((argc < 2) ||
        argv[0].a_type != A_SYMBOL ||
        argv[1].a_type != A_FLOAT ||
        ((argc > 2) && argv[2].a_type != A_FLOAT))
    {
        pd_error(0, "netsend: bad connect arguments");
        return;
    }
    hostname = argv[0].a_w.w_symbol->s_name;
    portno = (int)argv[1].a_w.w_float;
    sportno = (argc > 2 ? (int)argv[2].a_w.w_float : 0);
    if (x->x_sockfd >= 0)
    {
        pd_error(0, "netsend: already connected");
        return;
    }

    /* get addrinfo list using hostname & port */
    status = addrinfo_get_list(&ailist, hostname, portno, x->x_protocol);
    if (status != 0)
    {
        pd_error(x, "netsend: bad host or port? %s (%d)",
            gai_strerror(status), status);
        return;
    }
    addrinfo_sort_list(&ailist, addrinfo_ipv4_first); /* IPv4 first! */
#ifdef PRINT_ADDRINFO
    addrinfo_print_list(ailist);
#endif
    /* try each addr until we find one that works */
    for (ai = ailist; ai != NULL; ai = ai->ai_next)
    {
        /* create a socket */
        sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
#if 0
        fprintf(stderr, "send socket %d\n", sockfd);
#endif
        if (sockfd < 0)
            continue;

#ifndef _WIN32
        if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) < 0)
            pd_error(x, "netsend: CLOEXEC failed: %s", strerror(errno));
#endif

#if 0
        if (socket_set_boolopt(sockfd, SOL_SOCKET, SO_SNDBUF, 0) < 0)
            post("netsend: setsockopt (SO_RCVBUF) failed");
#endif
        /* for stream (TCP) sockets, specify "nodelay" */
        if (x->x_protocol == SOCK_STREAM)
        {
            if (socket_set_boolopt(sockfd, IPPROTO_TCP, TCP_NODELAY, 1) < 0)
                post("netsend: setsockopt (TCP_NODELAY) failed");
        }
        else /* datagram (UDP) broadcasting */
        {
            if (socket_set_boolopt(sockfd, SOL_SOCKET, SO_BROADCAST, 1) < 0)
                post("netsend: setsockopt (SO_BROADCAST) failed");
            multicast = sockaddr_is_multicast(ai->ai_addr);
        }
        /* if this is an IPv6 address, also listen to IPv4 adapters */
        if (ai->ai_family == AF_INET6 &&
            socket_set_boolopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, 0) < 0)
        {
            /* post("netreceive: setsockopt (IPV6_V6ONLY) failed"); */
        }

        sockaddr_get_addrstr(ai->ai_addr, hostbuf, sizeof(hostbuf));

        /* bind optional src listening port */
        if (sportno != 0)
        {
            int bound = 0;
            struct addrinfo *sailist = NULL, *sai;
            logpost(NULL, PD_VERBOSE, "connecting to %s %d, src port %d", hostbuf, portno, sportno);
            status = addrinfo_get_list(&sailist, NULL, sportno, x->x_protocol);
            if (status != 0)
            {
                pd_error(x, "netsend: could not set src port: %s (%d)",
                    gai_strerror(status), status);
                freeaddrinfo(sailist);
                goto connect_fail;
            }
            addrinfo_sort_list(&sailist, addrinfo_ipv6_first); /* IPv6 first! */
            for (sai = sailist; sai != NULL; sai = sai->ai_next)
            {
                /* if this is an IPv6 address, also listen to IPv4 adapters
                   (if not supported, fall back to IPv4) */
                if (sai->ai_family == AF_INET6 &&
                        socket_set_boolopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, 0) < 0)
                {
                    /* post("netreceive: setsockopt (IPV6_V6ONLY) failed"); */
                    continue;
                }
                if (bind(sockfd, sai->ai_addr, sai->ai_addrlen) < 0)
                    continue;
                bound = 1;
                break;
            }
            freeaddrinfo(sailist);
            if (!bound)
            {
                sys_sockerror("setting source port");
                goto connect_fail;
            }
        }
        else if (hostname && multicast)
            logpost(NULL, PD_VERBOSE, "connecting to %s %d (multicast)", hostbuf, portno);
        else
            logpost(NULL, PD_VERBOSE, "connecting to %s %d", hostbuf, portno);

        if (x->x_protocol == SOCK_STREAM)
        {
            if (socket_connect(sockfd, ai->ai_addr, ai->ai_addrlen,
                                    x->x_timeout) < 0)
            {
                sys_sockerror("connecting stream socket");
                sys_closesocket(sockfd);
                freeaddrinfo(ailist);
                /* output 0 on connection failure so the user
                   can easily retry in a loop */
                outlet_float(x->x_obj.ob_outlet, 0);
                return;
            }
        }

        /* this addr worked */
        memcpy(&x->x_server, ai->ai_addr, ai->ai_addrlen);
        break;
    }
    freeaddrinfo(ailist);

    /* confirm that socket worked */
    if (sockfd < 0)
    {
        int err = socket_errno();
        char buf[MAXPDSTRING];
        socket_strerror(err, buf, sizeof(buf));
        pd_error(x, "netsend: connect failed: %s (%d)", buf, err);
        return;
    }

    x->x_sockfd = sockfd;
    if (x->x_msgout) /* add polling function for return messages */
    {
        if (x->x_bin)
            sys_addpollfn(x->x_sockfd, (t_fdpollfn)netsend_readbin, x);
        else
        {
            t_socketreceiver *y =
              socketreceiver_new((void *)x, netsend_notify, netsend_read,
                                 x->x_protocol == SOCK_DGRAM);
            sys_addpollfn(x->x_sockfd, (t_fdpollfn)socketreceiver_read, y);
            x->x_receiver = y;
        }
    }
    outlet_float(x->x_obj.ob_outlet, 1);
    return;
connect_fail:
    freeaddrinfo(ailist);
    if (sockfd > 0)
        sys_closesocket(sockfd);
}

static void netsend_disconnect(t_netsend *x)
{
    if (x->x_sockfd >= 0)
    {
        sys_rmpollfn(x->x_sockfd);
        sys_closesocket(x->x_sockfd);
        x->x_sockfd = -1;
        if (x->x_receiver)
            socketreceiver_free(x->x_receiver);
        x->x_receiver = NULL;
        memset(&x->x_server, 0, sizeof(struct sockaddr_storage));
        outlet_float(x->x_obj.ob_outlet, 0);
    }
}

static int netsend_dosend(t_netsend *x, int sockfd, int argc, t_atom *argv)
{
    char *buf, *bp;
    int length, sent, fail = 0;
    t_binbuf *b = 0;
    if (x->x_bin)
    {
        int i;
        buf = alloca(argc);
        for (i = 0; i < argc; i++)
            ((unsigned char *)buf)[i] = atom_getfloatarg(i, argc, argv);
        length = argc;
    }
    else
    {
        t_atom at;
        b = binbuf_new();
        binbuf_add(b, argc, argv);
        SETSEMI(&at);
        binbuf_add(b, 1, &at);
        binbuf_gettext(b, &buf, &length);
    }
    for (bp = buf, sent = 0; sent < length;)
    {
        static double lastwarntime;
        static double pleasewarn;
        double timebefore = sys_getrealtime(), timeafter;
        int late;

        int res = 0;
        if (x->x_protocol == SOCK_DGRAM)
        {
            socklen_t addrlen = (x->x_server.ss_family == AF_INET6 ?
                sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
            res = (int)sendto(sockfd, bp, length-sent, 0,
                (struct sockaddr *)&x->x_server, addrlen);
        }
        else
            res = (int)send(sockfd, bp, length-sent, 0);

        timeafter = sys_getrealtime();
        late = (timeafter - timebefore > 0.005);
        if (late || pleasewarn)
        {
            if (timeafter > lastwarntime + 2)
            {
                logpost(NULL, PD_DEBUG, "netsend/netreceive: blocked %d msec",
                     (int)(1000 * ((timeafter - timebefore) +
                     pleasewarn)));
                pleasewarn = 0;
                lastwarntime = timeafter;
            }
            else if (late) pleasewarn += timeafter - timebefore;
        }
        if (res <= 0)
        {
            sys_sockerror("send");
            fail = 1;
            break;
        }
        else
        {
            sent += res;
            bp += res;
        }
    }
    done:
    if (!x->x_bin)
    {
        t_freebytes(buf, length);
        binbuf_free(b);
    }
    return (fail);
}

static void netsend_send(t_netsend *x, t_symbol *s, int argc, t_atom *argv)
{
    if (x->x_sockfd >= 0)
    {
        if (netsend_dosend(x, x->x_sockfd, argc, argv))
            netsend_disconnect(x);
    }
}

static void netsend_timeout(t_netsend *x, t_float timeout)
{
    if (timeout >= 0)
        x->x_timeout = timeout * 0.001;
}

static void netsend_free(t_netsend *x)
{
    netsend_disconnect(x);
}

static void netsend_setup(void)
{
    netsend_class = class_new(gensym("netsend"), (t_newmethod)netsend_new,
        (t_method)netsend_free,
        sizeof(t_netsend), 0, A_GIMME, 0);
    class_addmethod(netsend_class, (t_method)netsend_connect,
        gensym("connect"), A_GIMME, 0);
    class_addmethod(netsend_class, (t_method)netsend_disconnect,
        gensym("disconnect"), 0);
    class_addmethod(netsend_class, (t_method)netsend_send,
        gensym("send"), A_GIMME, 0);
    class_addlist(netsend_class, (t_method)netsend_send);
    class_addmethod(netsend_class, (t_method)netsend_timeout,
        gensym("timeout"), A_DEFFLOAT, 0);
    class_sethelpsymbol(netsend_class, gensym("netsend-receive"));
}

/* ----------------------------- netreceive ------------------------- */

static void netreceive_notify(t_netreceive *x, int fd)
{
    int i;
    for (i = 0; i < x->x_nconnections; i++)
    {
        if (x->x_connections[i] == fd)
        {
            memmove(x->x_connections+i, x->x_connections+(i+1),
                sizeof(int) * (x->x_nconnections - (i+1)));
            x->x_connections = (int *)t_resizebytes(x->x_connections,
                x->x_nconnections * sizeof(int),
                    (x->x_nconnections-1) * sizeof(int));

            if (x->x_receivers[i])
                socketreceiver_free(x->x_receivers[i]);
            memmove(x->x_receivers+i, x->x_receivers+(i+1),
                sizeof(t_socketreceiver*) * (x->x_nconnections - (i+1)));

            x->x_receivers = (t_socketreceiver **)t_resizebytes(x->x_receivers,
                x->x_nconnections * sizeof(t_socketreceiver*),
                    (x->x_nconnections-1) * sizeof(t_socketreceiver*));
            x->x_nconnections--;
        }
    }
    if (x->x_ns.x_connectout)
    {
        outlet_float(x->x_ns.x_connectout, x->x_nconnections);
    }
    else
        bug("netreceive_notify");
}

    /* socketreceiver from sockaddr_in */
static void netreceive_fromaddr(void *z, const void *fromaddr)
{
    t_netreceive *x = (t_netreceive *)z;
    if (x->x_ns.x_fromout)
        outlet_sockaddr(x->x_ns.x_fromout, (const struct sockaddr *)fromaddr);
}

static void netreceive_connectpoll(t_netreceive *x)
{
    int fd = accept(x->x_ns.x_sockfd, 0, 0);
    if (fd < 0) post("netreceive: accept failed");
    else
    {
        int nconnections = x->x_nconnections+1;

        x->x_connections = (int *)t_resizebytes(x->x_connections,
            x->x_nconnections * sizeof(int), nconnections * sizeof(int));
        x->x_connections[x->x_nconnections] = fd;
        x->x_receivers = (t_socketreceiver **)t_resizebytes(x->x_receivers,
            x->x_nconnections * sizeof(t_socketreceiver*),
            nconnections * sizeof(t_socketreceiver*));
        x->x_receivers[x->x_nconnections] = NULL;
        if (x->x_ns.x_bin)
            sys_addpollfn(fd, (t_fdpollfn)netsend_readbin, x);
        else
        {
            t_socketreceiver *y = socketreceiver_new((void *)x,
            (t_socketnotifier)netreceive_notify,
                (x->x_ns.x_msgout ? netsend_read : 0), 0);
            if (x->x_ns.x_fromout)
                socketreceiver_set_fromaddrfn(y,
                    (t_socketfromaddrfn)netreceive_fromaddr);
            sys_addpollfn(fd, (t_fdpollfn)socketreceiver_read, y);
            x->x_receivers[x->x_nconnections] = y;
        }
        outlet_float(x->x_ns.x_connectout, (x->x_nconnections = nconnections));
    }
}

/* ----------------------- shared UDP port ----------------------- */
/*
 * One UDP socket per local address/port inside this process. Every
 * [netreceive] on that port, including ones in other libpd instances,
 * gets a copy of each datagram. The socket is polled by a single
 * instance; other instances receive the packet via pd_queue_mess().
 * TCP listeners stay exclusive. Separate OS processes still cannot
 * share a unicast port.
 */

struct _udpsub
{
    t_netreceive *sub_obj;          /* NULL once the object is gone */
    t_pdinstance *sub_instance;
    struct _udpport *sub_port;
    int sub_multicast;
    int sub_refs;                   /* object + queued/in-flight deliveries */
    struct sockaddr_storage sub_group;
    struct _udpsub *sub_next;
};

typedef struct _udpport
{
    int up_port;
    int up_family;
    char up_bindhost[INET6_ADDRSTRLEN]; /* "::" / "0.0.0.0" or a unicast addr */
    int up_fd;
    int up_polling;                 /* fd is in up_owner's poll set */
    int up_inpoll;                  /* owner is inside the poll callback */
    int up_adopt_pending;           /* a handoff message is queued */
    t_pdinstance *up_owner;         /* instance whose poll set owns the fd */
    struct _udpsub *up_subs;
    struct _udpport *up_next;
} t_udpport;

typedef struct _udpmsg
{
    struct _udpsub *sub;
    int size;
    struct sockaddr_storage from;
    char *buf;
} t_udpmsg;

static t_udpport *udpshared_ports = 0;

#if PDTHREADS
static pthread_mutex_t udpshared_mutex = PTHREAD_MUTEX_INITIALIZER;
#define udpshared_lock() pthread_mutex_lock(&udpshared_mutex)
#define udpshared_unlock() pthread_mutex_unlock(&udpshared_mutex)
#else
#define udpshared_lock()
#define udpshared_unlock()
#endif

static void udpshared_bindkey(int family, int wildcard,
    const struct sockaddr *sa, char *buf, int buflen)
{
    if (buflen < 1)
        return;
    if (wildcard)
        strcpy(buf, family == AF_INET6 ? "::" : "0.0.0.0");
    else if (!sa || !sockaddr_get_addrstr(sa, buf, buflen))
        buf[0] = 0;
}

static int udpshared_same_addr(const struct sockaddr *a, const struct sockaddr *b)
{
    if (a->sa_family != b->sa_family)
        return 0;
    if (a->sa_family == AF_INET)
        return (((struct sockaddr_in *)a)->sin_addr.s_addr ==
            ((struct sockaddr_in *)b)->sin_addr.s_addr);
    if (a->sa_family == AF_INET6)
        return (!memcmp(&((struct sockaddr_in6 *)a)->sin6_addr,
            &((struct sockaddr_in6 *)b)->sin6_addr, sizeof(struct in6_addr)));
    return 0;
}

static t_udpport *udpshared_find(int port, int family, const char *bindhost)
{
    t_udpport *p;
    for (p = udpshared_ports; p; p = p->up_next)
        if (p->up_fd >= 0 && p->up_port == port && p->up_family == family &&
            !strcmp(p->up_bindhost, bindhost))
            return p;
    return 0;
}

static int udpshared_has_instance(t_udpport *port, t_pdinstance *instance)
{
    struct _udpsub *s;
    for (s = port->up_subs; s; s = s->sub_next)
        if (s->sub_instance == instance)
            return 1;
    return 0;
}

    /* lock held. returns 1 and fills errbuf if IP_ADD_MEMBERSHIP failed. */
static int udpshared_join_locked(t_udpport *port, const struct sockaddr *group,
    int *errp, char *errbuf, int errsize)
{
    struct _udpsub *s;
    for (s = port->up_subs; s; s = s->sub_next)
        if (s->sub_multicast &&
            udpshared_same_addr((struct sockaddr *)&s->sub_group, group))
            return 0;
    if (socket_join_multicast_group(port->up_fd, group) < 0)
    {
        int err = socket_errno();
        if (errp)
            *errp = err;
        if (errbuf)
            socket_strerror(err, errbuf, errsize);
        return 1;
    }
    return 0;
}

    /* lock held. drop membership when the last subscriber of this group leaves. */
static void udpshared_leave_locked(t_udpport *port, struct _udpsub *leaving)
{
    struct _udpsub *s;
    if (!leaving->sub_multicast || port->up_fd < 0)
        return;
    for (s = port->up_subs; s; s = s->sub_next)
        if (s != leaving && s->sub_multicast &&
            udpshared_same_addr((struct sockaddr *)&s->sub_group,
                (struct sockaddr *)&leaving->sub_group))
            return;
    socket_leave_multicast_group(port->up_fd,
        (struct sockaddr *)&leaving->sub_group);
}

static void udpshared_addsub(t_udpport *port, t_netreceive *x,
    int multicast, const struct sockaddr *group)
{
    struct _udpsub *s = (struct _udpsub *)t_getbytes(sizeof(*s));
    s->sub_obj = x;
    s->sub_instance = pd_this;
    s->sub_port = port;
    s->sub_multicast = multicast;
    s->sub_refs = 1;
    if (multicast && group)
        memcpy(&s->sub_group, group, sizeof(s->sub_group));
    s->sub_next = 0;
    if (!port->up_subs)
        port->up_subs = s;
    else
    {
        struct _udpsub *tail;
        for (tail = port->up_subs; tail->sub_next; tail = tail->sub_next)
            ;
        tail->sub_next = s;
    }
    x->x_udpsub = s;
}

static void udpshared_deliver_one(t_netreceive *x, const char *data, int size,
    const struct sockaddr *from)
{
    if (x->x_ns.x_bin)
    {
        int i;
        t_atom *ap;
        if (size <= 0)
            return;
        if (from && x->x_ns.x_fromout)
            outlet_sockaddr(x->x_ns.x_fromout, from);
        if (!x->x_ns.x_msgout)
            return;
        ap = (t_atom *)t_getbytes(size * sizeof(*ap));
        for (i = 0; i < size; i++)
            SETFLOAT(ap + i, (unsigned char)data[i]);
        outlet_setstacklim();
        outlet_list(x->x_ns.x_msgout, 0, size, ap);
        t_freebytes(ap, size * sizeof(*ap));
        return;
    }
        /* FUDI: same filter as socketreceiver_getudp() */
    if (size <= 0 || data[size - 1] != '\n')
        return;
    {
        char *buf = (char *)t_getbytes(size + 1);
        char *semi;
        t_binbuf *b;
        memcpy(buf, data, size);
        buf[size] = 0;
        semi = strchr(buf, ';');
        if (semi)
            *semi = 0;
        if (from && x->x_ns.x_fromout)
            outlet_sockaddr(x->x_ns.x_fromout, from);
        if (!x->x_ns.x_msgout)
        {
            t_freebytes(buf, size + 1);
            return;
        }
        b = binbuf_new();
        binbuf_text(b, buf, strlen(buf));
        t_freebytes(buf, size + 1);
        outlet_setstacklim();
        netsend_read(&x->x_ns, b);
        binbuf_free(b);
    }
}

static void udpshared_queued_deliver(t_pd *obj, void *data)
{
    t_udpmsg *m = (t_udpmsg *)data;
    struct _udpsub *sub = m->sub;
    t_netreceive *x = 0;
    (void)obj;
    udpshared_lock();
    x = sub->sub_obj;
    udpshared_unlock();
    if (x)
        udpshared_deliver_one(x, m->buf, m->size, (struct sockaddr *)&m->from);
    t_freebytes(m->buf, m->size);
    udpshared_lock();
    sub->sub_refs--;
    if (sub->sub_refs <= 0)
        t_freebytes(sub, sizeof(*sub));
    udpshared_unlock();
    t_freebytes(m, sizeof(*m));
}

    /* lock held */
static void udpshared_queue_deliver(struct _udpsub *s, const char *data,
    int size, const struct sockaddr *from)
{
    t_udpmsg *m = (t_udpmsg *)t_getbytes(sizeof(*m));
    m->sub = s;
    m->size = size;
    m->buf = (char *)t_getbytes(size ? size : 1);
    if (size)
        memcpy(m->buf, data, size);
    if (from)
        memcpy(&m->from, from, sizeof(m->from));
    s->sub_refs++;
    pd_queue_mess(s->sub_instance, 0, m, udpshared_queued_deliver);
}

static void udpshared_poll(t_udpport *port, int fd);
static void udpshared_unlink_and_close(t_udpport *port);
static void udpshared_handoff_or_close(t_udpport *port);
static void udpshared_adopt(t_pd *obj, void *data);

static void udpshared_queue_adopt(t_udpport *port, t_pdinstance *inst)
{
    port->up_adopt_pending = 1;
        /* non-NULL obj so instance teardown (which calls fn with NULL)
           can be told apart from a normal handoff */
    pd_queue_mess(inst, (t_pd *)port, port, udpshared_adopt);
}

    /* lock held. port is no longer in the list; fd is closed. */
static void udpshared_unlink_and_close(t_udpport *port)
{
    t_udpport **pp;
    for (pp = &udpshared_ports; *pp; pp = &(*pp)->up_next)
        if (*pp == port)
        {
            *pp = port->up_next;
            break;
        }
    if (port->up_polling && port->up_owner == pd_this)
    {
        sys_rmpollfn(port->up_fd);
        port->up_polling = 0;
    }
    if (port->up_fd >= 0)
    {
        sys_closesocket(port->up_fd);
        port->up_fd = -1;
    }
    if (port->up_inpoll || port->up_adopt_pending)
        return;
    t_freebytes(port, sizeof(*port));
}

    /*
     * lock held. The polling instance has no subscribers left.
     * Move the poll to another instance, or close the socket.
     */
static void udpshared_handoff_or_close(t_udpport *port)
{
    struct _udpsub *s;
    if (port->up_fd < 0)
        return;
    if (port->up_polling && port->up_owner == pd_this)
    {
        sys_rmpollfn(port->up_fd);
        port->up_polling = 0;
    }
    if (!port->up_subs)
    {
        if (port->up_polling && port->up_owner != pd_this)
        {
                /* poll set belongs to an instance we can't touch from here */
            if (!port->up_adopt_pending)
                udpshared_queue_adopt(port, port->up_owner);
            return;
        }
        udpshared_unlink_and_close(port);
        return;
    }
    if (!udpshared_has_instance(port, port->up_owner))
        port->up_owner = port->up_subs->sub_instance;
    if (port->up_adopt_pending)
        return;
    if (port->up_owner == pd_this)
    {
        sys_addpollfn(port->up_fd, (t_fdpollfn)udpshared_poll, port);
        port->up_polling = 1;
        return;
    }
    s = port->up_subs;
    port->up_owner = s->sub_instance;
    udpshared_queue_adopt(port, s->sub_instance);
}

static void udpshared_adopt(t_pd *obj, void *data)
{
    t_udpport *port = (t_udpport *)data;
    udpshared_lock();
    port->up_adopt_pending = 0;
    if (!obj)
    {
            /* polling instance is being destroyed; its poll set is already
               gone, so don't call sys_rmpollfn */
        port->up_polling = 0;
        if (port->up_fd >= 0 && port->up_subs)
        {
            port->up_owner = port->up_subs->sub_instance;
            udpshared_queue_adopt(port, port->up_owner);
        }
        else if (port->up_fd >= 0)
            udpshared_unlink_and_close(port);
        else if (!port->up_inpoll)
            t_freebytes(port, sizeof(*port));
        udpshared_unlock();
        return;
    }
    if (port->up_fd >= 0 && port->up_subs)
    {
        if (!udpshared_has_instance(port, pd_this))
        {
            if (!udpshared_has_instance(port, port->up_owner))
                udpshared_handoff_or_close(port);
        }
        else if (!port->up_polling && port->up_owner == pd_this)
        {
            sys_addpollfn(port->up_fd, (t_fdpollfn)udpshared_poll, port);
            port->up_polling = 1;
        }
    }
    else if (port->up_fd >= 0)
        udpshared_handoff_or_close(port);
    else if (!port->up_subs && !port->up_inpoll && !port->up_adopt_pending)
        t_freebytes(port, sizeof(*port));
    udpshared_unlock();
}

static void udpshared_fanout(t_udpport *port, const char *data, int size,
    const struct sockaddr *from)
{
    struct _udpsub *s, **local = 0;
    int nlocal = 0, i;
    udpshared_lock();
    if (port->up_fd < 0)
    {
        udpshared_unlock();
        return;
    }
    for (s = port->up_subs; s; s = s->sub_next)
        if (s->sub_instance == pd_this)
            nlocal++;
    if (nlocal)
        local = (struct _udpsub **)t_getbytes(nlocal * sizeof(*local));
    i = 0;
    for (s = port->up_subs; s; s = s->sub_next)
    {
        if (s->sub_instance == pd_this)
        {
            if (local)
            {
                local[i++] = s;
                s->sub_refs++;
            }
        }
        else
            udpshared_queue_deliver(s, data, size, from);
    }
    udpshared_unlock();
    for (i = 0; i < nlocal; i++)
    {
        t_netreceive *x;
        udpshared_lock();
        x = local[i]->sub_obj;
        udpshared_unlock();
        if (x)
            udpshared_deliver_one(x, data, size, from);
        udpshared_lock();
        local[i]->sub_refs--;
        if (local[i]->sub_refs <= 0)
            t_freebytes(local[i], sizeof(*local[i]));
        udpshared_unlock();
    }
    if (local)
        t_freebytes(local, nlocal * sizeof(*local));
}

static void udpshared_poll(t_udpport *port, int fd)
{
    char *inbuf = (char *)sys_getrecvbuf(0);
    int readbytes = 0;
    udpshared_lock();
    port->up_inpoll++;
    udpshared_unlock();
    while (1)
    {
        struct sockaddr_storage from;
        socklen_t fromlen = sizeof(from);
        int ret = (int)recvfrom(fd, inbuf, NET_MAXPACKETSIZE - 1, 0,
            (struct sockaddr *)&from, &fromlen);
        if (ret < 0)
        {
            if (socket_errno_udp())
                sys_sockerror("recv (udp)");
            break;
        }
        if (ret == 0)
            break;
        if (ret > NET_MAXPACKETSIZE - 1)
        {
            post("warning: incoming UDP packet truncated from %d to %d bytes.",
                ret, NET_MAXPACKETSIZE - 1);
            ret = NET_MAXPACKETSIZE - 1;
        }
        udpshared_fanout(port, inbuf, ret, (struct sockaddr *)&from);
        readbytes += ret;
        if (readbytes >= NET_MAXPACKETSIZE)
            break;
        if (socket_bytes_available(fd) <= 0)
            break;
        if (port->up_fd != fd || !port->up_polling || port->up_owner != pd_this)
            break;
    }
    udpshared_lock();
    port->up_inpoll--;
    if (port->up_fd < 0 && !port->up_subs && !port->up_inpoll &&
        !port->up_adopt_pending)
        t_freebytes(port, sizeof(*port));
    udpshared_unlock();
}

static void udpshared_unsubscribe(t_netreceive *x)
{
    struct _udpsub *s = x->x_udpsub;
    t_udpport *port;
    struct _udpsub **sp;
    if (!s)
        return;
    x->x_udpsub = NULL;
    port = s->sub_port;
    udpshared_lock();
    udpshared_leave_locked(port, s);
    for (sp = &port->up_subs; *sp; sp = &(*sp)->sub_next)
        if (*sp == s)
        {
            *sp = s->sub_next;
            break;
        }
    s->sub_obj = NULL;
    s->sub_refs--;
    if (s->sub_refs <= 0)
        t_freebytes(s, sizeof(*s));
    if (port->up_fd >= 0 && !udpshared_has_instance(port, port->up_owner))
        udpshared_handoff_or_close(port);
    udpshared_unlock();
}

    /* returns 1 if this object subscribed to a socket that already existed */
static int udpshared_try_existing(t_netreceive *x, int portno, const char *hostname)
{
    struct addrinfo *ailist = 0, *ai;
    char bindhost[INET6_ADDRSTRLEN];
    struct sockaddr_storage group;
    int family, multicast = 0, status, joinerr = 0, err = 0;
    char errbuf[MAXPDSTRING];
    t_udpport *port;
    status = addrinfo_get_list(&ailist, hostname, portno, SOCK_DGRAM);
    if (status != 0 || !ailist)
    {
        if (ailist)
            freeaddrinfo(ailist);
        return 0;
    }
    addrinfo_sort_list(&ailist,
        hostname ? addrinfo_ipv4_first : addrinfo_ipv6_first);
    ai = ailist;
    family = ai->ai_family;
    multicast = (hostname && sockaddr_is_multicast(ai->ai_addr));
    if (multicast)
        memcpy(&group, ai->ai_addr, ai->ai_addrlen);
    udpshared_bindkey(family, !hostname || multicast, ai->ai_addr,
        bindhost, sizeof(bindhost));
    freeaddrinfo(ailist);
    udpshared_lock();
    port = udpshared_find(portno, family, bindhost);
    if (!port)
    {
        udpshared_unlock();
        return 0;
    }
    if (multicast)
        joinerr = udpshared_join_locked(port, (struct sockaddr *)&group,
            &err, errbuf, sizeof(errbuf));
    udpshared_addsub(port, x, multicast, multicast ? (struct sockaddr *)&group : 0);
    udpshared_unlock();
    if (joinerr)
        pd_error(x, "netreceive: joining multicast group %s failed: %s (%d)",
            hostname ? hostname : "", errbuf, err);
    logpost(NULL, PD_VERBOSE, "sharing UDP port %d", portno);
    return 1;
}

static void udpshared_take_socket(t_netreceive *x, int fd, int portno,
    int family, const char *bindhost, int multicast,
    const struct sockaddr *group, const char *hostname)
{
    t_udpport *port;
    int joinerr = 0, err = 0;
    char errbuf[MAXPDSTRING];
    udpshared_lock();
    port = udpshared_find(portno, family, bindhost);
    if (port)
    {
        sys_closesocket(fd);
        if (multicast && group)
            joinerr = udpshared_join_locked(port, group,
                &err, errbuf, sizeof(errbuf));
        udpshared_addsub(port, x, multicast, group);
        udpshared_unlock();
        if (joinerr)
            pd_error(x, "netreceive: joining multicast group %s failed: %s (%d)",
                hostname ? hostname : "", errbuf, err);
        logpost(NULL, PD_VERBOSE, "sharing UDP port %d", portno);
        return;
    }
    port = (t_udpport *)t_getbytes(sizeof(*port));
    port->up_port = portno;
    port->up_family = family;
    strncpy(port->up_bindhost, bindhost, sizeof(port->up_bindhost) - 1);
    port->up_bindhost[sizeof(port->up_bindhost) - 1] = 0;
    port->up_fd = fd;
    port->up_owner = pd_this;
    port->up_next = udpshared_ports;
    udpshared_ports = port;
    udpshared_addsub(port, x, multicast, group);
    sys_addpollfn(fd, (t_fdpollfn)udpshared_poll, port);
    port->up_polling = 1;
    udpshared_unlock();
}

static void netreceive_closeall(t_netreceive *x)
{
    int i;
    if (x->x_udpsub)
        udpshared_unsubscribe(x);
    for (i = 0; i < x->x_nconnections; i++)
    {
        sys_rmpollfn(x->x_connections[i]);
        sys_closesocket(x->x_connections[i]);
        if (x->x_receivers[i])
        {
            socketreceiver_free(x->x_receivers[i]);
            x->x_receivers[i] = NULL;
        }
    }
    x->x_connections = (int *)t_resizebytes(x->x_connections,
        x->x_nconnections * sizeof(int), 0);
    x->x_receivers = (t_socketreceiver**)t_resizebytes(x->x_receivers,
                x->x_nconnections * sizeof(t_socketreceiver*), 0);
    x->x_nconnections = 0;
    if (x->x_ns.x_sockfd >= 0)
    {
        sys_rmpollfn(x->x_ns.x_sockfd);
        sys_closesocket(x->x_ns.x_sockfd);
    }
    x->x_ns.x_sockfd = -1;
    if (x->x_ns.x_receiver)
        socketreceiver_free(x->x_ns.x_receiver);
    x->x_ns.x_receiver = NULL;
    if (x->x_ns.x_connectout)
        outlet_float(x->x_ns.x_connectout, x->x_nconnections);
}

static void netreceive_listen(t_netreceive *x, t_symbol *s, int argc, t_atom *argv)
{
    int portno = 0, sockfd = -1, status, protocol = x->x_ns.x_protocol, multicast = 0;
    struct addrinfo *ailist = NULL, *ai;
    const char *hostname = NULL; /* allowed or UDP multicast hostname */

    netreceive_closeall(x);

    if (argc && argv->a_type == A_FLOAT)
        portno = argv->a_w.w_float, argc--, argv++;
    if (argc && argv->a_type == A_SYMBOL)
    {
        hostname = argv->a_w.w_symbol->s_name;
        argv++; argc--;
    }
    if (argc)
    {
        pd_error(x, "netreceive: extra arguments ignored:");
        postatom(argc, argv); endpost();
    }
    if (portno <= 0)
        return;
    if (protocol == SOCK_DGRAM && udpshared_try_existing(x, portno, hostname))
        return;
    status = addrinfo_get_list(&ailist, hostname, portno, protocol);
    if (status != 0)
    {
        pd_error(x, "netreceive: bad host or port? %s (%d)",
            gai_strerror(status), status);
        return;
    }
    if (hostname)
    {
        /* If we specify a hostname or IP address we can only listen to a single adapter.
         * For host names, we prefer IPv4 for now. LATER we might create several sockets */
        addrinfo_sort_list(&ailist, addrinfo_ipv4_first);
    }
    else
    {
        /* For the "any" address we want to prefer IPv6, so we can create a dual stack socket */
        addrinfo_sort_list(&ailist, addrinfo_ipv6_first);
    }
#ifdef PRINT_ADDRINFO
    addrinfo_print_list(ailist);
#endif
    /* try each addr until we find one that works */
    for (ai = ailist; ai != NULL; ai = ai->ai_next)
    {
        /* create a socket */
        sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sockfd < 0)
            continue;

#ifndef _WIN32
        if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) < 0)
            pd_error(x, "netsend: CLOEXEC failed: %s", strerror(errno));
#endif
    #if 0
        fprintf(stderr, "receive socket %d\n", sockfd);
    #endif

    #if 1
        /* ask OS to allow another Pd to reopen this port after we close it */
        if (socket_set_boolopt(sockfd, SOL_SOCKET, SO_REUSEADDR, 1) < 0)
            post("netreceive: setsockopt (SO_REUSEADDR) failed");
    #endif
    #if 0
        intarg = 0;
        if (socket_set_boolopt(sockfd, SOL_SOCKET, SO_RCVBUF, 0) < 0)
            post("netreceive: setsockopt (SO_RCVBUF) failed");
    #endif
        if (protocol == SOCK_STREAM)
        {
            /* stream (TCP) sockets are set NODELAY */
            if (socket_set_boolopt(sockfd, IPPROTO_TCP, TCP_NODELAY, 1) < 0)
                post("netreceive: setsockopt (TCP_NODELAY) failed");
        }
        else if (protocol == SOCK_DGRAM && ai->ai_family == AF_INET)
        {
            /* enable IPv4 UDP broadcasting */
            if (socket_set_boolopt(sockfd, SOL_SOCKET, SO_BROADCAST, 1) < 0)
                post("netreceive: setsockopt (SO_BROADCAST) failed");
        }
        /* if this is the IPv6 "any" address, also listen to IPv4 adapters
           (if not supported, fall back to IPv4) */
        if (!hostname && ai->ai_family == AF_INET6 &&
                socket_set_boolopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, 0) < 0)
        {
            /* post("netreceive: setsockopt (IPV6_V6ONLY) failed"); */
            sys_closesocket(sockfd);
            sockfd = -1;
            continue;
        }
        multicast = sockaddr_is_multicast(ai->ai_addr);
#if 1
        if (multicast)
        {
            /* binding to the multicast address doesn't work on Windows and on Linux
               it doesn't seem to work for IPv6 multicast addresses, so we bind to
               the "any" address instead */
            struct addrinfo *any;
            int status = addrinfo_get_list(&any,
                (ai->ai_family == AF_INET6) ? "::" : "0.0.0.0", portno, protocol);
            if (status != 0)
            {
                pd_error(x,
                    "netreceive: getting \"any\" address for multicast failed %s (%d)",
                    gai_strerror(status), status);
                sys_closesocket(sockfd);
                return;
            }
            /* name the socket */
            status = bind(sockfd, any->ai_addr, any->ai_addrlen);
            freeaddrinfo(any);
            if (status < 0)
            {
                sys_closesocket(sockfd);
                sockfd = -1;
                continue;
            }
        }
        else
#endif
        {
            /* name the socket */
            if (bind(sockfd, ai->ai_addr, ai->ai_addrlen) < 0)
            {
                sys_closesocket(sockfd);
                sockfd = -1;
                continue;
            }
        }
        /* join multicast group */
        if (multicast && socket_join_multicast_group(sockfd, ai->ai_addr) < 0)
        {
            int err = socket_errno();
            char buf[MAXPDSTRING];
            socket_strerror(err, buf, sizeof(buf));
            pd_error(x,
                "netreceive: joining multicast group %s failed: %s (%d)",
                hostname, buf, err);
        }
        /* this addr worked */
        if (hostname)
        {
            char hostbuf[256];
            sockaddr_get_addrstr(ai->ai_addr,
                hostbuf, sizeof(hostbuf));
            logpost(NULL, PD_VERBOSE, "listening on %s %d%s", hostbuf, portno,
                (multicast ? " (multicast)" : ""));
        }
        else
            logpost(NULL, PD_VERBOSE, "listening on %d", portno);
        break;
    }
    /* copy the bound address before ailist (and ai) is freed */
    {
        int boundfamily = 0;
        char udpbindhost[INET6_ADDRSTRLEN];
        struct sockaddr_storage udpgroup;
        udpbindhost[0] = 0;
        memset(&udpgroup, 0, sizeof(udpgroup));
        if (sockfd >= 0 && protocol == SOCK_DGRAM)
        {
            boundfamily = ai->ai_family;
            udpshared_bindkey(boundfamily, !hostname || multicast,
                ai->ai_addr, udpbindhost, sizeof(udpbindhost));
            if (multicast)
                memcpy(&udpgroup, ai->ai_addr, ai->ai_addrlen);
        }
        freeaddrinfo(ailist);

        /* confirm that socket/bind worked */
        if (sockfd < 0)
        {
            int err = socket_errno();
            char buf[MAXPDSTRING];
                /* another listener in this process may have won the bind */
            if (protocol == SOCK_DGRAM &&
                udpshared_try_existing(x, portno, hostname))
                return;
            socket_strerror(err, buf, sizeof(buf));
            pd_error(x, "netreceive: listen failed: %s (%d)",
                buf, err);
            return;
        }
        if (protocol == SOCK_DGRAM) /* shared with other listeners on this port */
        {
            udpshared_take_socket(x, sockfd, portno, boundfamily, udpbindhost,
                multicast, multicast ? (struct sockaddr *)&udpgroup : 0,
                hostname);
            return;
        }
    }
    x->x_ns.x_sockfd = sockfd;
    /* streaming protocol */
    {
        if (listen(x->x_ns.x_sockfd, 5) < 0)
        {
            sys_sockerror("listen");
            sys_closesocket(x->x_ns.x_sockfd);
            x->x_ns.x_sockfd = -1;
        }
        else
        {
            sys_addpollfn(x->x_ns.x_sockfd,
                (t_fdpollfn)netreceive_connectpoll,x);
        }
    }
}

static void netreceive_send(t_netreceive *x,
    t_symbol *s, int argc, t_atom *argv)
{
    int i;
    if (x->x_ns.x_protocol != SOCK_STREAM)
    {
        pd_error(x, "netreceive: 'send' only works for TCP");
        return;
    }
    for (i = 0; i < x->x_nconnections; i++)
    {
        if (netsend_dosend(&x->x_ns, x->x_connections[i], argc, argv))
            pd_error(x, "netreceive: send message failed");
                /* should we now close the connection? */
    }
}

static void *netreceive_new(t_symbol *s, int argc, t_atom *argv)
{
    t_netreceive *x = (t_netreceive *)pd_new(netreceive_class);
    int from = 0;
    x->x_ns.x_protocol = SOCK_STREAM;
    x->x_old = 0;
    x->x_ns.x_bin = 0;
    x->x_nconnections = 0;
    x->x_connections = (int *)t_getbytes(0);
    x->x_receivers = (t_socketreceiver **)t_getbytes(0);
    x->x_udpsub = 0;
    x->x_ns.x_sockfd = -1;
    if (argc && argv->a_type == A_FLOAT)
    {
        /* port argument is later passed to netreceive_listen */
        x->x_ns.x_protocol = (atom_getfloatarg(1, argc, argv) != 0 ?
            SOCK_DGRAM : SOCK_STREAM);
        x->x_old = (!strcmp(atom_getsymbolarg(2, argc, argv)->s_name, "old"));
        argc = 1; /* don't pass other arguments */
    }
    else
    {
        while (argc && argv->a_type == A_SYMBOL &&
            *argv->a_w.w_symbol->s_name == '-')
        {
            if (!strcmp(argv->a_w.w_symbol->s_name, "-b"))
                x->x_ns.x_bin = 1;
            else if (!strcmp(argv->a_w.w_symbol->s_name, "-u"))
                x->x_ns.x_protocol = SOCK_DGRAM;
            else if (!strcmp(argv->a_w.w_symbol->s_name, "-f"))
                from = 1;
            else
            {
                pd_error(x, "netreceive: unknown flag ...");
                postatom(argc, argv); endpost();
            }
            argc--; argv++;
        }
    }
    if (x->x_old)
    {
        /* old style, nonsecure version */
        x->x_ns.x_msgout = 0;
    }
    else x->x_ns.x_msgout = outlet_new(&x->x_ns.x_obj, &s_anything);
    if (x->x_ns.x_protocol == SOCK_STREAM)
        x->x_ns.x_connectout = outlet_new(&x->x_ns.x_obj, &s_float);
    else
        x->x_ns.x_connectout = 0;
    if (from)
        x->x_ns.x_fromout = outlet_new(&x->x_ns.x_obj, &s_symbol);
    else
        x->x_ns.x_fromout = NULL;
        /* create a socket */
    netreceive_listen(x, 0, argc, argv); /* pass arguments */

    return (x);
}

static void netreceive_free(t_netreceive *x)
{
    netreceive_closeall(x);
}

static void netreceive_setup(void)
{
    netreceive_class = class_new(gensym("netreceive"),
        (t_newmethod)netreceive_new, (t_method)netreceive_free,
        sizeof(t_netreceive), 0, A_GIMME, 0);
    class_addmethod(netreceive_class, (t_method)netreceive_listen,
        gensym("listen"), A_GIMME, 0);
    class_addmethod(netreceive_class, (t_method)netreceive_send,
        gensym("send"), A_GIMME, 0);
    class_addlist(netreceive_class, (t_method)netreceive_send);
    class_sethelpsymbol(netreceive_class, gensym("netsend-receive"));
}

void x_net_setup(void)
{
    netsend_setup();
    netreceive_setup();
}
