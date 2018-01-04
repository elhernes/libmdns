/*******************************************************************************
 * file: /github:elhernes/libmdns/tmain.cpp
 *
 * born-on: Thu Jan  4 08:54:42 2018
 * creator: Eric L. Hernes
 *
 * C++ module implementing something
 *
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "mdns.h"

#include <map>

const std::map<std::string, std::function<void(MdnsRR &mdns, const std::vector<std::string> &sr)> > sk_commands = {
    { "discover", [](MdnsRR &mdns, const std::vector<std::string> &) ->void {
            printf("Sending DNS-SD discovery\n");
            if (mdns.discover(2*1000)) {
            } else {
                printf("Failed to send DNS-DS discovery: %s\n", strerror(errno));
            }
        } },

    { "host", [](MdnsRR &mdns, const std::vector<std::string> &av) ->void {
            printf("Sending DNS-SD host [%s]\n", av[1].c_str());
            if (mdns.query(2*1000, mdns_recordtype::AAAA, av[1])) {
            } else {
                printf("Failed to send DNS-DS query: %s\n", strerror(errno));
            }
        } },

    { "service", [](MdnsRR &mdns, const std::vector<std::string> &av) ->void {
            printf("Sending DNS-SD service [%s]\n", av[1].c_str());
            if (mdns.query(2*1000, mdns_recordtype::PTR, av[1])) {
            } else {
                printf("Failed to send DNS-DS query: %s\n", strerror(errno));
            }
        } },
    { "help", [](MdnsRR &mdns, const std::vector<std::string> &av) ->void {
            unsigned i=0;
            printf("help: %lu parameters\n", av.size());
            for(auto p : av) {
                printf("av[%d]=%s\n", i, av[i].c_str());
                i++;
            }
        } },
};

static void usage(const char *prog);

int
main(int ac, char **av) {
    //    const char *netif= ac==1? "" :av[1];
    const char *netif="wlan0";
    MdnsRR mdns(netif);

    const char *prog=av[0];
    if (ac<2) {
        usage(prog);
        return 1;
    }

    std::string cmd=av[1];
    std::vector<std::string> argv;
    for(int i=1; i<ac; i++) {
        argv.push_back(av[i]);
    }

    auto cc=sk_commands.find(cmd);
    if (cc!=sk_commands.end()) {
        cc->second(mdns, argv);
    } else {
        printf("%s: not found\n", cmd.c_str());
        usage(prog);
        return 2;
    }

    std::vector<MdnsRecord> rsp;
    mdns.responses(rsp);
    for(auto r : rsp) {
        printf("%s %s? %s\n", r.ip.c_str(), r.question.c_str(), r.data.c_str());
    }

    return 0;
}

void
usage(const char *prog) {
    printf("usage: %s <command> <args..>\n", prog);
    printf("commands: \n");
    for(auto c : sk_commands) {
        printf(" %s\n", c.first.c_str());
    }
}

/*
 * Local Variables:
 * mode: C++
 * mode: font-lock
 * c-basic-offset: 4
 * tab-width: 8
 * compile-command: "make.rmk MK=tmain.mk"
 * End:
 */

/* end of /github:elhernes/libmdns/tmain.cpp */
