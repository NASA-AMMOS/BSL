/*
 * Copyright (c) 2024 The Johns Hopkins University Applied Physics
 * Laboratory LLC.
 *
 * This file is part of the Bundle Protocol Security Library (BSL).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This work was performed for the Jet Propulsion Laboratory, California
 * Institute of Technology, sponsored by the United States Government under
 * the prime contract 80NM0018D0004 between the Caltech and NASA under
 * subcontract 1700763.
 */
/** @file
 * This is the main entry for a mock BPA daemon that communicates through
 * unix domain sockets.
 */
#include "bsl_mock_bpa.h"
#include "mock_bpa_ctr.h"
#include <Logging.h>
#include <backend/DeprecatedLibContext.h>

#include <arpa/inet.h>
#include <errno.h>
#include <m-atomic.h>
#include <m-buffer.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

static atomic_bool stop_state;

#define DATA_QUEUE_SIZE 100

BUFFER_DEF(data_queue, mock_bpa_ctr_t, DATA_QUEUE_SIZE,
           BUFFER_QUEUE | BUFFER_THREAD_SAFE | BUFFER_PUSH_INIT_POP_MOVE | BUFFER_BLOCKING)

static data_queue_t over_rx;
static data_queue_t over_tx;
static data_queue_t under_rx;
static data_queue_t under_tx;
static data_queue_t deliver;
static data_queue_t forward;

static pthread_t thr_over_rx, thr_under_rx, thr_deliver, thr_forward;

// Library context
static BSL_LibCtx_t bsl;

// Configuration
static BSL_HostEID_t       app_eid;
static struct sockaddr_in6 over_addr   = { .sin6_family = 0 };
static struct sockaddr_in6 app_addr    = { .sin6_family = 0 };
static struct sockaddr_in6 under_addr  = { .sin6_family = 0 };
static struct sockaddr_in6 router_addr = { .sin6_family = 0 };
static int                 tx_notify_r, tx_notify_w;
static BSL_HostEID_t       sec_eid;

#if 0
static int bind_unix(int *sock)
{
    if (access(over_addr.sun_path, F_OK) == 0)
    {
        if (unlink(over_addr.sun_path))
        {
            BSL_LOG_ERR("Failed to clean up over-socket");
            return 1;
        }
    }

    *sock = socket(over_addr.sun_family, SOCK_SEQPACKET, 0);
    if (*sock < 0)
    {
        BSL_LOG_ERR("Failed to open over-socket");
        return 2;
    }
    {
        BSL_LOG_DEBUG("Binding over-socket to %s", over_addr.sun_path);

        int res = bind(*sock, (struct sockaddr *)&over_addr, sizeof(over_addr));
        if (res)
        {
            close(*sock);
            BSL_LOG_ERR("Failed to bind over-socket %d", res);
            return 3;
        }
    }

    if (listen(*sock, 10))
    {
        close(*sock);
        BSL_LOG_ERR("Failed to listen on over-socket");
        return 3;
    }

    return 0;
}
#endif

static int ingest_netaddr(struct sockaddr_in6 *addr, const char *optarg)
{
    const char *node    = optarg;
    const char *service = "4556";
    char       *sep     = strchr(optarg, ':');
    if (sep)
    {
        *sep    = '\0';
        service = sep + 1; // might be at the terminator
    }
    struct addrinfo hints = {
        .ai_family   = AF_INET6,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP,
        .ai_flags    = AI_ADDRCONFIG | AI_NUMERICSERV,
    };
    struct addrinfo *result;

    BSL_LOG_DEBUG("Resolving under address: %s %s", node, service);
    int res = getaddrinfo(node, service, &hints, &result);
    if (res)
    {
        BSL_LOG_ERR("Failed to resolve router address: %s", optarg);
        return 1;
    }
    else
    {
        for (const struct addrinfo *rp = result; rp != NULL; rp = rp->ai_next)
        {
            // use first address
            if (rp->ai_family == AF_INET6)
            {
                memcpy(addr, rp->ai_addr, rp->ai_addrlen);
                break;
            }
        }
        freeaddrinfo(result);
    }
    return 0;
}

static int bind_udp(int *sock, const struct sockaddr_in6 *addr)
{
    *sock = socket(addr->sin6_family, SOCK_DGRAM, IPPROTO_UDP);
    if (*sock < 0)
    {
        BSL_LOG_ERR("Failed to open UDP socket");
        return 2;
    }
    {
        char nodebuf[INET6_ADDRSTRLEN];
        inet_ntop(addr->sin6_family, &addr->sin6_addr, nodebuf, sizeof(nodebuf));
        BSL_LOG_DEBUG("Binding UDP socket to [%s]:%d", nodebuf, ntohs(addr->sin6_port));

        int res = bind(*sock, (struct sockaddr *)addr, sizeof(*addr));
        if (res)
        {
            close(*sock);
            BSL_LOG_ERR("Failed to bind UDP socket, errno %d", errno);
            return 3;
        }
    }

    return 0;
}

static int mock_bpa_process(BSL_PolicyLocation_e loc, BSL_BundleCtx_t *bundle)
{
    BSL_LOG_DEBUG("starting security processing at loc %d", loc);
    BSL_PolicyActionDeprecatedIList_t acts;
    BSL_PolicyActionDeprecatedIList_init(acts);
    if (BSL_PolicyRegistry_Inspect(&bsl, loc, bundle, acts))
    {
        BSL_LOG_ERR("BSL_PolicyRegistry_Inspect failed");
        BSL_LibCtx_FreePolicyActionDeprecatedList(&bsl, acts);
        BSL_PolicyActionDeprecatedIList_clear(acts);
        return 1;
    }
    BSL_LOG_DEBUG("BSL_PolicyRegistry_Inspect got %d actions", BSL_PolicyActionDeprecatedIList_size(acts));

    BSL_PolicyActionDeprecatedIList_t badacts;
    BSL_PolicyActionDeprecatedIList_init(badacts);
    BSL_PolicyActionDeprecatedIList_it_t it;
    for (BSL_PolicyActionDeprecatedIList_it(it, acts); !BSL_PolicyActionDeprecatedIList_end_p(it);)
    {
        BSL_PolicyActionDeprecated_t *act = BSL_PolicyActionDeprecatedIList_ref(it);
        // advance iterator before possibly removing item from acts list
        BSL_PolicyActionDeprecatedIList_next(it);

        if (!BSL_SecCtx_ValidatePolicyActionDeprecated(&bsl, bundle, act))
        {
            BSL_LOG_ERR("BSL_SecCtx_ValidatePolicyActionDeprecated failed for one action");
            BSL_PolicyActionDeprecatedIList_unlink(act);
            BSL_PolicyActionDeprecatedIList_push_back(badacts, act);
            return 2;
        }
    }
    BSL_LibCtx_FreePolicyActionDeprecatedList(&bsl, badacts);
    BSL_PolicyActionDeprecatedIList_clear(badacts);

    for (BSL_PolicyActionDeprecatedIList_it(it, acts); !BSL_PolicyActionDeprecatedIList_end_p(it); BSL_PolicyActionDeprecatedIList_next(it))
    {
        BSL_PolicyActionDeprecated_t *act = BSL_PolicyActionDeprecatedIList_ref(it);

        BSL_SecCtx_ExecutePolicyActionDeprecated(&bsl, bundle, act);
    }

    if (BSL_PolicyRegistry_Finalize(&bsl, loc, bundle, acts))
    {
        BSL_LOG_ERR("BSL_PolicyRegistry_Finalize failed");
        // FIXME what else to do?
    }

    BSL_LibCtx_FreePolicyActionDeprecatedList(&bsl, acts);
    BSL_PolicyActionDeprecatedIList_clear(acts);
    BSL_LOG_DEBUG("finished security processing at loc %d", loc);
    return 0;
}

static void sig_stop(int signum _U_)
{
    atomic_store(&stop_state, true);
    BSL_LOG_INFO("signal received %d", signum);
}

static void *work_over_rx(void *arg _U_)
{
    BSL_LOG_INFO("work_over_rx started");
    while (true)
    {
        mock_bpa_ctr_t item;
        data_queue_pop(&item, over_rx);
        if (item.encoded.len == 0)
        {
            break;
        }
        BSL_LOG_INFO("over_rx");
        mock_bpa_decode(&item, &bsl);

        if (mock_bpa_process(BSL_POLICYLOCATION_APPIN, item.bundle))
        {
            BSL_LOG_ERR("work_over_rx failed security processing");
            mock_bpa_ctr_deinit(&item);
            continue;
        }

        // loopback
        data_queue_push(deliver, item);
    }
    BSL_LOG_INFO("work_over_rx stopped");

    return NULL;
}

static void *work_under_rx(void *arg _U_)
{
    BSL_LOG_INFO("work_under_rx started");
    while (true)
    {
        mock_bpa_ctr_t item;
        data_queue_pop(&item, under_rx);
        if (item.encoded.len == 0)
        {
            break;
        }

        BSL_LOG_INFO("under_rx");
        if (mock_bpa_decode(&item, &bsl))
        {
            BSL_LOG_ERR("work_under_rx failed to decode bundle");
            mock_bpa_ctr_deinit(&item);
            continue;
        }

        if (mock_bpa_process(BSL_POLICYLOCATION_CLIN, item.bundle))
        {
            BSL_LOG_ERR("work_under_rx failed security processing");
            mock_bpa_ctr_deinit(&item);
            continue;
        }

        // loopback
        data_queue_push(forward, item);
    }
    BSL_LOG_INFO("work_under_rx stopped");

    return NULL;
}

static void *work_deliver(void *arg _U_)
{
    BSL_LOG_INFO("work_deliver started");
    while (true)
    {
        mock_bpa_ctr_t item;
        data_queue_pop(&item, deliver);
        if (item.encoded.len == 0)
        {
            break;
        }
        BSL_LOG_INFO("deliver");

        if (mock_bpa_process(BSL_POLICYLOCATION_APPOUT, item.bundle))
        {
            BSL_LOG_ERR("work_deliver failed security processing");
            mock_bpa_ctr_deinit(&item);
            continue;
        }

        mock_bpa_encode(&item);
        data_queue_push(over_tx, item);
        {
            uint8_t buf    = 0;
            int     nbytes = write(tx_notify_w, &buf, sizeof(uint8_t));
            if (nbytes < 0)
            {
                BSL_LOG_ERR("Failed to write: %ld", nbytes);
            }
        }
    }
    BSL_LOG_INFO("work_deliver stopped");

    return NULL;
}

static void *work_forward(void *arg _U_)
{
    BSL_LOG_INFO("work_forward started");
    while (true)
    {
        mock_bpa_ctr_t item;
        data_queue_pop(&item, forward);
        if (item.encoded.len == 0)
        {
            break;
        }
        BSL_LOG_INFO("forward");

        if (mock_bpa_process(BSL_POLICYLOCATION_CLOUT, item.bundle))
        {
            BSL_LOG_ERR("work_forward failed security processing");
            mock_bpa_ctr_deinit(&item);
            continue;
        }

        mock_bpa_encode(&item);
        data_queue_push(under_tx, item);
        {
            uint8_t buf    = 0;
            int     nbytes = write(tx_notify_w, &buf, sizeof(uint8_t));
            if (nbytes < 0)
            {
                BSL_LOG_ERR("Failed to write, got %ld", nbytes);
            }
        }
    }
    BSL_LOG_INFO("work_forward stopped");

    return NULL;
}

static int bpa_init(void)
{
    {
        struct sigaction stopper = {
            .sa_handler = sig_stop,
        };
        sigaction(SIGINT, &stopper, NULL);
        sigaction(SIGTERM, &stopper, NULL);
    }

    data_queue_init(over_rx, DATA_QUEUE_SIZE);
    data_queue_init(over_tx, DATA_QUEUE_SIZE);
    data_queue_init(under_rx, DATA_QUEUE_SIZE);
    data_queue_init(under_tx, DATA_QUEUE_SIZE);
    data_queue_init(deliver, DATA_QUEUE_SIZE);
    data_queue_init(forward, DATA_QUEUE_SIZE);

    {
        // event socket for waking the I/O thread
        int fds[2];
        if (pipe(fds) != 0)
        {
            return 3;
        }
        tx_notify_r = fds[0];
        tx_notify_w = fds[1];
    }

    if (pthread_create(&thr_under_rx, NULL, work_under_rx, NULL))
    {
        return 2;
    }
    if (pthread_create(&thr_over_rx, NULL, work_over_rx, NULL))
    {
        return 2;
    }
    if (pthread_create(&thr_deliver, NULL, work_deliver, NULL))
    {
        return 2;
    }
    if (pthread_create(&thr_forward, NULL, work_forward, NULL))
    {
        return 2;
    }
    return 0;
}

static int bpa_exec(void)
{
    int retval = 0;

    int over_sock, under_sock;
    if (bind_udp(&over_sock, &over_addr))
    {
        return 3;
    }
    if (bind_udp(&under_sock, &under_addr))
    {
        return 3;
    }

    struct pollfd pfds[] = {
        { .fd = tx_notify_r, .events = POLLIN },
        { .fd = under_sock },
        { .fd = over_sock },
    };
    struct pollfd *const tx_notify_pfd = pfds;
    struct pollfd *const under_pfd     = pfds + 1;
    struct pollfd *const over_pfd      = pfds + 2;

    BSL_LOG_INFO("READY");

    while (!atomic_load(&stop_state))
    {
        under_pfd->events = POLLIN;
        if (!data_queue_empty_p(under_tx))
        {
            under_pfd->events |= POLLOUT;
        }

        over_pfd->events = POLLIN;
        if (!data_queue_empty_p(over_tx))
        {
            over_pfd->events |= POLLOUT;
        }

        int res = poll(pfds, sizeof(pfds) / sizeof(struct pollfd), -1);
        if (res < 0)
        {
            retval = 4;
            break;
        }

        if (tx_notify_pfd->revents & POLLIN)
        {
            // no actual data, just clear the pipe
            uint8_t buf;
            int     nbytes = read(tx_notify_r, &buf, sizeof(uint8_t));
            if (nbytes < 0)
            {
                BSL_LOG_ERR("Cannot read: %ld", nbytes);
            }
        }

        if (over_pfd->revents & POLLIN)
        {
            uint8_t      buf[65536];
            struct iovec iov = {
                .iov_base = buf,
                .iov_len  = sizeof(buf),
            };
            struct msghdr msg = {
                .msg_iovlen = 1,
                .msg_iov    = &iov,
            };
            ssize_t got = recvmsg(over_sock, &msg, 0);
            if (got > 0)
            {
                BSL_LOG_DEBUG("over_sock recv %zd", got);
                mock_bpa_ctr_t item;
                mock_bpa_ctr_init(&item);
                BSL_Data_AppendFrom(&item.encoded, got, buf);

                data_queue_push(over_rx, item);
            }
        }
        if (over_pfd->revents & POLLOUT)
        {
            mock_bpa_ctr_t item;
            data_queue_pop(&item, over_tx);

            BSL_LOG_DEBUG("over_sock send %zd", item.encoded.len);
            struct iovec iov = {
                .iov_base = item.encoded.ptr,
                .iov_len  = item.encoded.len,
            };
            struct msghdr msg = {
                .msg_name    = &app_addr,
                .msg_namelen = sizeof(app_addr),
                .msg_iovlen  = 1,
                .msg_iov     = &iov,
            };
            ssize_t got = sendmsg(over_sock, &msg, 0);
            if (got != (ssize_t)item.encoded.len)
            {
                BSL_LOG_ERR("over_sock failed to send all %zd bytes, only %zd sent: %d", item.encoded.len, got, errno);
            }
            mock_bpa_ctr_deinit(&item);
        }

        if (under_pfd->revents & POLLIN)
        {
            uint8_t      buf[65536];
            struct iovec iov = {
                .iov_base = buf,
                .iov_len  = sizeof(buf),
            };
            struct msghdr msg = {
                .msg_iovlen = 1,
                .msg_iov    = &iov,
            };
            ssize_t got = recvmsg(under_sock, &msg, 0);
            if (got > 0)
            {
                BSL_LOG_DEBUG("under_sock recv %zd", got);
                mock_bpa_ctr_t item;
                mock_bpa_ctr_init(&item);
                BSL_Data_AppendFrom(&item.encoded, got, buf);

                data_queue_push(under_rx, item);
            }
        }
        if (under_pfd->revents & POLLOUT)
        {
            mock_bpa_ctr_t item;
            data_queue_pop(&item, under_tx);

            BSL_LOG_DEBUG("under_sock send %zd", item.encoded.len);
            struct iovec iov = {
                .iov_base = item.encoded.ptr,
                .iov_len  = item.encoded.len,
            };
            struct msghdr msg = {
                .msg_name    = &router_addr,
                .msg_namelen = sizeof(router_addr),
                .msg_iovlen  = 1,
                .msg_iov     = &iov,
            };
            ssize_t got = sendmsg(under_sock, &msg, 0);
            if (got != (ssize_t)item.encoded.len)
            {
                BSL_LOG_ERR("under_sock failed to send all %zd bytes, only %zd sent", item.encoded.len, got);
            }
            mock_bpa_ctr_deinit(&item);
        }
    }

    close(over_sock);
    close(under_sock);
    return retval;
}

static void bpa_cleanup(void)
{
    mock_bpa_ctr_t item;

    // join RX workers first
    mock_bpa_ctr_init(&item);
    data_queue_push(under_rx, item);
    mock_bpa_ctr_init(&item);
    data_queue_push(over_rx, item);
    if (pthread_join(thr_under_rx, NULL))
    {
        BSL_LOG_ERR("Failed to join the work_under_rx");
    }
    if (pthread_join(thr_over_rx, NULL))
    {
        BSL_LOG_ERR("Failed to join the work_over_rx");
    }

    // then delivery/forward workers after RX are all flushed
    mock_bpa_ctr_init(&item);
    data_queue_push(forward, item);
    mock_bpa_ctr_init(&item);
    data_queue_push(deliver, item);
    if (pthread_join(thr_forward, NULL))
    {
        BSL_LOG_ERR("Failed to join the work_forward");
    }
    if (pthread_join(thr_deliver, NULL))
    {
        BSL_LOG_ERR("Failed to join the work_deliver");
    }

    close(tx_notify_r);
    close(tx_notify_w);
    data_queue_clear(over_rx);
    data_queue_clear(over_tx);
    data_queue_clear(under_rx);
    data_queue_clear(under_tx);
    data_queue_clear(deliver);
    data_queue_clear(forward);

    BSL_HostEID_Deinit(&sec_eid);
    BSL_HostEID_Deinit(&app_eid);
    BSL_LibCtx_Deinit(&bsl);
}

static void show_usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s -o <over-socket address:port> -a <application address:port>\n"
            "          -u <under-socket address:port> -r <router address:port>\n"
            "          -e <app-EID> -s <sec-src-EID>\n",
            argv0);
}

int main(int argc, char **argv)
{
    BSL_openlog();
    int retval = 0;

    atomic_init(&stop_state, false);

    if (bsl_mock_bpa_init())
    {
        BSL_LOG_ERR("Failed to initialize mock BPA");
        retval = 2;
    }

    if (BSL_LibCtx_Init(&bsl))
    {
        BSL_LOG_ERR("Failed to initialize BSL");
        retval = 2;
    }

    BSL_HostEID_Init(&app_eid);
    BSL_HostEID_Init(&sec_eid);
    if (!retval)
    {
        int opt;
        while ((opt = getopt(argc, argv, "ha:o:a:u:r:e:s:")) != -1)
        {
            switch (opt)
            {
                case 'o':
                    ingest_netaddr(&over_addr, optarg);
                    break;
                case 'a':
                    ingest_netaddr(&app_addr, optarg);
                    break;
                case 'u':
                    ingest_netaddr(&under_addr, optarg);
                    break;
                case 'r':
                    ingest_netaddr(&router_addr, optarg);
                    break;
                case 'e':
                    if (BSL_HostEID_DecodeFromText(&app_eid, optarg))
                    {
                        BSL_LOG_ERR("Failed to decode app EID: %s", optarg);
                        retval = 1;
                    }
                    break;
                case 's':
                    if (BSL_HostEID_DecodeFromText(&sec_eid, optarg))
                    {
                        BSL_LOG_ERR("Failed to decode BPSec EID: %s", optarg);
                        retval = 1;
                    }
                    break;
                case 'h':
                default:
                    show_usage(argv[0]);
                    retval = 1;
                    break;
            }
        }
        if (!retval && (over_addr.sin6_family != AF_INET6))
        {
            BSL_LOG_ERR("Missing over-socket address\n");
            show_usage(argv[0]);
            retval = 1;
        }
        if (!retval && (app_addr.sin6_family != AF_INET6))
        {
            BSL_LOG_ERR("Missing application address\n");
            show_usage(argv[0]);
            retval = 1;
        }
        if (!retval && (under_addr.sin6_family != AF_INET6))
        {
            BSL_LOG_ERR("Missing under-socket address\n");
            show_usage(argv[0]);
            retval = 1;
        }
        if (!retval && (router_addr.sin6_family != AF_INET6))
        {
            BSL_LOG_ERR("Missing router address\n");
            show_usage(argv[0]);
            retval = 1;
        }
    }

    if (!retval)
    {
        retval = bpa_init();
    }
    if (!retval)
    {
        retval = bpa_exec();
    }

    if (retval != 1)
    {
        bpa_cleanup();
    }
    bsl_mock_bpa_deinit();
    BSL_closelog();
    return retval;
}
