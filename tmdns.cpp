/*******************************************************************************
 * file: /github:elhernes/libmdns/tmdns.cpp
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
#include <future>
#include <unistd.h>

static const char *skProg=0;
static void usage();

const std::map<std::string, std::function<bool(MdnsRR &mdns, const std::vector<std::string> &sr)> > sk_commands = {
    { "discover", [](MdnsRR &mdns, const std::vector<std::string> &) ->bool {
            printf("Sending DNS-SD discovery\n");
            bool rv=mdns.discover();
            if (rv) {
            } else {
                printf("Failed to send DNS-DS discovery: %s\n", strerror(errno));
            }
            return rv;
        } },

    { "host", [](MdnsRR &mdns, const std::vector<std::string> &av) ->bool {
            printf("Sending DNS-SD host [%s]\n", av[1].c_str());
            bool rv = mdns.query(mdns_recordtype::AAAA, av[1]);
            if (rv) {
            } else {
                printf("Failed to send DNS-DS query: %s\n", strerror(errno));
            }
            return rv;
        } },

    { "service", [](MdnsRR &mdns, const std::vector<std::string> &av) ->bool {
            printf("Sending DNS-SD service [%s]\n", av[1].c_str());
            bool rv = mdns.query(mdns_recordtype::PTR, av[1]);
            if (rv) {
            } else {
                printf("Failed to send DNS-DS query: %s\n", strerror(errno));
            }
            return rv;
        } },

    { "help", [](MdnsRR &mdns, const std::vector<std::string> &av) ->bool {
            usage();
            return false;
        } },

    { "async", [](MdnsRR &mdns, const std::vector<std::string> &av) ->bool {
            bool rv=false;
            bool done=false;
            std::vector<MdnsRecord> responses;
            
            auto arv = std::async(std::launch::async, [&mdns, &done, &responses]() -> int {
                    for(;!done;) {
                        mdns.responses(responses, 1000);
                    }
                    return 0;
                });

            static const std::map<std::string,mdns_recordtype> skQueryType = {
                { "discover", mdns_recordtype::IGNORE }, 
                { "host", mdns_recordtype::AAAA }, 
                { "service", mdns_recordtype::PTR }, 
                { "svc", mdns_recordtype::PTR }, 
                { "text", mdns_recordtype::TXT }, 
            };

            for(auto q=av.begin()+1; q!=av.end(); q++) {
                auto dd = q->find_first_of(":", 0);
                auto qtype = skQueryType.find(q->substr(0,dd));
                if(qtype != skQueryType.end()) {
                    switch (qtype->second) {
                    case mdns_recordtype::IGNORE:
                        printf("mdns.discover()\n");
                        mdns.discover();
                        break;
                    default:
                        //                    case mdns_recordtype::AAAA:
                        //                    case mdns_recordtype::PTR:
                        //                    case mdns_recordtype::TXT:
                        printf("mdns.query(%d, %s)\n", qtype->second, q->substr(dd+1).c_str());
                        mdns.query(qtype->second, q->substr(dd+1));
                        break;
                    }
                    //                    usleep(1000);
                } else {
                    printf("%s: unknown query type\n", q->substr(0,dd).c_str());
                }
            }

            done=true;
            auto status = arv.wait_for(std::chrono::milliseconds(5*1000));
            int32_t arr=(status == std::future_status::ready);

            printf("got %lu responses\n", responses.size());
            for(auto r : responses) {
                printf("%s %s? %s\n", r.ip.c_str(), r.question.c_str(), r.data.c_str());
            }


            return rv;
        } },

    { "test", [](MdnsRR &mdns, const std::vector<std::string> &av) ->bool {
            printf("test: %lu parameters\n", av.size());
            unsigned i=0;
            for(auto p : av) {
                printf("av[%d]=%s\n", i, av[i].c_str());
                i++;
            }
            return false;
        } }
};

int
main(int ac, char **av) {
    //    const char *netif= ac==1? "" :av[1];
    const char *netif="wlan0";
    MdnsRR mdns(netif);

    skProg=av[0];
    if (ac<2) {
        usage();
        return 1;
    }

    std::string cmd=av[1];
    std::vector<std::string> argv;
    for(int i=1; i<ac; i++) {
        argv.push_back(av[i]);
    }
    bool doReceive=true;
    auto cc=sk_commands.find(cmd);
    if (cc!=sk_commands.end()) {
        doReceive=cc->second(mdns, argv);
    } else {
        printf("%s: not found\n", cmd.c_str());
        usage();
        return 2;
    }

    if (doReceive) {
        std::vector<MdnsRecord> rsp;
        mdns.responses(rsp, 2*1000);
        for(auto r : rsp) {
            printf("%s %s? %s\n", r.ip.c_str(), r.question.c_str(), r.data.c_str());
        }
    }

    return 0;
}

void
usage() {
    unsigned i=0;
    printf("usage: %s <command> <args..>\n", skProg);
    printf("commands: \n");
    for(auto c : sk_commands) {
        printf(" %s\n", c.first.c_str());
    }

    static const std::vector<const char *> skExamples = {
        "discover",
        "service _ssh._tcp.local",
        "host hostname.local",
        "discover",
    };
    printf("\nexamples:\n");
    for(auto e : skExamples) {
        printf(" %s %s\n", skProg, e);
    }

}

/*
 * Local Variables:
 * mode: C++
 * mode: font-lock
 * c-basic-offset: 4
 * tab-width: 8
 * compile-command: "make.rmk MK=tmdns.mk"
 * End:
 */

/* end of /github:elhernes/libmdns/tmdns.cpp */
