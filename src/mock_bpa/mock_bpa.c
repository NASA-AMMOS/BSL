/*
 * Copyright (c) 2025 The Johns Hopkins University Applied Physics
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
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <BPSecLib_Private.h>
#include <BPSecLib_Public.h>
#include <CryptoInterface.h>

#include "agent.h"
#include "policy_config.h"

// Configuration
static BSL_HostEID_t app_eid;
static BSL_HostEID_t sec_eid;
/// Agent for this process
static MockBPA_Agent_t agent;

static int ingest_netaddr(struct sockaddr_in *addr, const char *arg)
{
    const char *node    = arg;
    const char *service = "4556";
    char       *sep     = strrchr(arg, ':');
    if (sep)
    {
        *sep    = '\0';
        service = sep + 1; // might be at the terminator
    }
    struct addrinfo hints = {
        .ai_family   = AF_INET,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP,
        .ai_flags    = AI_ADDRCONFIG | AI_NUMERICSERV,
    };
    struct addrinfo *result;

    BSL_LOG_DEBUG("Resolving under address: %s %s", node, service);
    int res = getaddrinfo(node, service, &hints, &result);
    if (res)
    {
        BSL_LOG_ERR("Failed to resolve router address: %s", arg);
        return 1;
    }
    else
    {
        for (const struct addrinfo *rp = result; rp != NULL; rp = rp->ai_next)
        {
            // use first address
            if (rp->ai_family == AF_INET)
            {
                memcpy(addr, rp->ai_addr, rp->ai_addrlen);
                break;
            }
        }
        freeaddrinfo(result);
    }
    return 0;
}

static void sig_stop(int signum)
{
    BSL_LOG_INFO("signal received %d", signum);
    MockBPA_Agent_Stop(&agent);
}

static void show_usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s -o <over-socket address:port> -a <application address:port>\n"
            "          -u <under-socket address:port> -r <router address:port>\n"
            "          -e <app-EID> -s <sec-src-EID>\n"
            "          -p (optional - defaults to none) comma delimited hex list of <bsl_mock_policy_configuration_t>, "
            "e.g. '0x000f,0x0021'\n",
            argv0);
}

int main(int argc, char **argv)
{
    BSL_openlog();
    int retval = 0;
    int res;

    BSL_CryptoInit();
    if ((res = MockBPA_Agent_Init(&agent)))
    {
        BSL_LOG_ERR("Failed to initialize mock BPA, error %d", res);
        retval = 2;
    }
    {
        struct sigaction stopper = {
            .sa_handler = sig_stop,
        };
        sigaction(SIGINT, &stopper, NULL);
        sigaction(SIGTERM, &stopper, NULL);
    }
    // always run these steps
    if (BSL_HostDescriptors_Set(MockBPA_Agent_Descriptors(&agent)))
    {
        retval = 2;
    }
    BSL_HostEID_Init(&app_eid);
    BSL_HostEID_Init(&sec_eid);

    /// Definitions of policy for all BSL instances
    mock_bpa_policy_registry_t policy_registry;
    mock_bpa_policy_registry_init(&policy_registry);

    if (!retval)
    {
        int opt;
        while ((opt = getopt(argc, argv, "ha:o:a:u:r:e:s:p:k:")) != -1)
        {
            switch (opt)
            {
                case 'o':
                    ingest_netaddr(&agent.over_addr, optarg);
                    break;
                case 'a':
                    ingest_netaddr(&agent.app_addr, optarg);
                    break;
                case 'u':
                    ingest_netaddr(&agent.under_addr, optarg);
                    break;
                case 'r':
                    ingest_netaddr(&agent.router_addr, optarg);
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
                    setenv("BSL_TEST_LOCAL_IPN_EID", optarg, 1);
                    break;
                case 'p':
                {
                    // TODO better way to handle this
                    int anyerr = 0;
                    anyerr += abs(mock_bpa_handle_policy_config(optarg, agent.appin.policy, &policy_registry));
                    anyerr += abs(mock_bpa_handle_policy_config(optarg, agent.appout.policy, &policy_registry));
                    anyerr += abs(mock_bpa_handle_policy_config(optarg, agent.clin.policy, &policy_registry));
                    anyerr += abs(mock_bpa_handle_policy_config(optarg, agent.clout.policy, &policy_registry));
                    if (anyerr)
                    {
                        retval = 1;
                    }

                    // TODO JSON parsing
                    // // mock_bpa_handle_policy_config_from_json("src/mock_bpa/policy_provider_test.json",
                    // policy_callbacks.user_data);

                    break;
                }
                case 'k':
                    if (mock_bpa_key_registry_init(optarg))
                        retval = 1;
                    break;
                case 'h':
                    // fall-through to default
                default:
                    show_usage(argv[0]);
                    retval = 1;
                    break;
            }
        }
        if (!retval && (agent.over_addr.sin_family != AF_INET))
        {
            BSL_LOG_ERR("Missing over-socket address");
            show_usage(argv[0]);
            retval = 1;
        }
        if (!retval && (agent.app_addr.sin_family != AF_INET))
        {
            BSL_LOG_ERR("Missing application address");
            show_usage(argv[0]);
            retval = 1;
        }
        if (!retval && (agent.under_addr.sin_family != AF_INET))
        {
            BSL_LOG_ERR("Missing under-socket address");
            show_usage(argv[0]);
            retval = 1;
        }
        if (!retval && (agent.router_addr.sin_family != AF_INET))
        {
            BSL_LOG_ERR("Missing router address");
            show_usage(argv[0]);
            retval = 1;
        }
    }

    if (!retval)
    {
        retval = MockBPA_Agent_Start(&agent);
    }
    if (!retval)
    {
        retval = MockBPA_Agent_Exec(&agent);
    }

    if (retval != 1)
    {
        MockBPA_Agent_Join(&agent);
    }

    mock_bpa_policy_registry_deinit(&policy_registry);
    MockBPA_Agent_Deinit(&agent);
    BSL_HostEID_Deinit(&sec_eid);
    BSL_HostEID_Deinit(&app_eid);

    BSL_HostDescriptors_Clear();
    BSL_CryptoDeinit();
    BSL_closelog();
    return retval;
}
