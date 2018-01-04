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

int
main(int ac, char **av) {
    //    const char *netif= ac==1? "" :av[1];
    const char *netif="wlan0";
    MdnsRR mdns(netif);

    if (1) {
        printf("Sending DNS-SD discovery\n");
        if (mdns.discover(2*1000)) {
        } else {
            printf("Failed to send DNS-DS discovery: %s\n", strerror(errno));
            return 1;
        }
    }
        

    if (0) {
        //        std::string query="_ssh._tcp.local.";
        std::string query= ac==1 ? "_rvn_id._tcp.local." : av[1];
        
        printf("Sending DNS-SD query [%s]\n", query.c_str());
        if (mdns.query(2*1000, mdns_recordtype::PTR, query)) {
        } else {
            printf("Failed to send DNS-DS query: %s\n", strerror(errno));
            return 2;
        }
    }
	return 0;
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
