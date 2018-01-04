/********************************************************************************
 * file: /github:elhernes/libmdns/mdns.cpp
 *
 * born-on: Wed Jan 3 2018
 * creator: Eric L. Hernes
 *
 * C++ interface for mdns query and discovery requests/responses
 *
 */

#include <stdint.h>  // for uint8_t, uint16_t, uint32_t
#include <stddef.h>  // for size_t

#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <poll.h>
#include <sys/time.h>

#include "mdns.h"
#include "mdns_c.h"  // for MDNS_STRING_FORMAT, mdns_string_t, mdns_discover...

#include <iomanip>
#include <sstream>


MdnsRR::MdnsRR(const std::string &netif) : m_tid(0) {
    m_4sock = mdns_socket_open_ipv6();
    m_6sock = mdns_socket_open_ipv4();
    if (netif.size()>0) {
        unsigned ifindex = if_nametoindex(netif.c_str());
        printf("%s: index %d\n", netif.c_str(), ifindex);
        if (setsockopt(m_6sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex))) {
            perror("setsockopt: IPV6_MULTICAST_IF");
        }
        if (setsockopt(m_4sock, IPPROTO_IP, IP_MULTICAST_IF, &ifindex, sizeof(ifindex))) {
            perror("setsockopt: IP_MULTICAST_IF");
        }
    }
}

MdnsRR::~MdnsRR() {
    if (m_4sock>=0) mdns_socket_close(m_4sock);
    if (m_6sock>=0) mdns_socket_close(m_6sock);
}

bool
MdnsRR::discover(int ms) {
    bool rv=false;
    if (m_4sock>=0) rv|=mdns_discovery_send(m_4sock)==0;
    if (m_6sock>=0) rv|=mdns_discovery_send(m_6sock)==0;
    if (rv) {
        rv = waitForReplies(ms, 0xffff, mdns_discovery_recv,
                            [=](const struct sockaddr* from, mdns_string_t &question, mdns_entrytype entry,
                                uint16_t type, uint16_t rclass, uint32_t ttl, const uint8_t* data, size_t size,
                                size_t offset, size_t length)->int {
                                return onMdnsRecord(from, question, entry, type, rclass, ttl, data, size, offset, length);
                            });
    }
    return rv;
}

bool
MdnsRR::query(int ms, mdns_recordtype type, const std::string &name) {
    bool rv=false;
    if (m_4sock>=0) {
        rv|=mdns_query_send(m_4sock, m_tid, type, name)==0;
    }
    if (m_6sock>=0) {
        rv|=mdns_query_send(m_6sock, m_tid, type, name)==0;
    }
    if (rv) {
        rv = waitForReplies(ms, m_tid, mdns_query_recv,
                            [=](const struct sockaddr* from, mdns_string_t &question, mdns_entrytype entry,
                                uint16_t type, uint16_t rclass, uint32_t ttl, const uint8_t* data, size_t size,
                                size_t offset, size_t length)->int {
                                return onMdnsRecord(from, question, entry, type, rclass, ttl, data, size, offset, length);
                            });
    }
    m_tid++;
    return rv;
}

bool
MdnsRR::responses(std::vector<MdnsRecord> &v) {
    v=m_records;
    return m_records.size()>0;
}

bool
MdnsRR::waitForReplies(int msec, uint16_t tid,  mdns_recv_fn rx, mdns_record_callback_fn cb) {
    bool rv=true;
    struct timeval t0, t1;
    int et = 0;
    gettimeofday(&t0, nullptr);

    for(;et<msec;) {
        struct pollfd fds[] = {
            { .fd = m_4sock, .events=POLLIN, .revents=0 },
            { .fd = m_6sock, .events=POLLIN, .revents=0 }
        };
        int nfd = poll(fds, sizeof(fds)/sizeof(fds[0]), msec-et);
        switch (nfd) {
        case -1:
            // error
            break;
        case 0:
            // timeout
            break;

        default:
            for(unsigned i=0; i<sizeof(fds)/sizeof(fds[0]); i++) {
                if((fds[i].revents & POLLIN)!=0) {
                    uint8_t rxbuffer[2048];
                    rx(fds[i].fd, tid, rxbuffer, sizeof(rxbuffer), cb);
                }
            }
            break;
        }
        gettimeofday(&t1, nullptr);
        et = ((t1.tv_sec - t0.tv_sec) * 1000) + ((t1.tv_usec - t0.tv_usec) / 1000); // in ms
    }
    return rv;
}

mdns_string_t
ipv4_address_to_string(char* buffer, size_t capacity, const struct sockaddr_in* addr) {
	char host[NI_MAXHOST] = {0};
	char service[NI_MAXSERV] = {0};
	int ret = getnameinfo((const struct sockaddr*)addr, sizeof(struct sockaddr_in),
	                      host, NI_MAXHOST, service, NI_MAXSERV,
	                      NI_NUMERICSERV | NI_NUMERICHOST);
	size_t len = 0;
	if (ret == 0) {
#if 0
		if (addr->sin_port != 0)
			len = snprintf(buffer, capacity, "%s:%s", host, service);
		else
#endif
			len = snprintf(buffer, capacity, "%s", host);
	}
	if (len >= capacity)
		len = (int)capacity - 1;
	mdns_string_t str = {buffer, len};
	return str;
}

mdns_string_t
ipv6_address_to_string(char* buffer, size_t capacity, const struct sockaddr_in6* addr) {
	char host[NI_MAXHOST] = {0};
	char service[NI_MAXSERV] = {0};
	int ret = getnameinfo((const struct sockaddr*)addr, sizeof(struct sockaddr_in6),
	                      host, NI_MAXHOST, service, NI_MAXSERV,
	                      NI_NUMERICSERV | NI_NUMERICHOST);
	size_t len = 0;
	if (ret == 0) {
#if 0
		if (addr->sin6_port != 0)
			len = snprintf(buffer, capacity, "[%s]:%s", host, service);
		else
#endif
			len = snprintf(buffer, capacity, "%s", host);
	}
	if (len >= capacity)
		len = (int)capacity - 1;
	mdns_string_t str = {buffer, len};
	return str;
}

mdns_string_t
ip_address_to_string(char* buffer, size_t capacity, const struct sockaddr* addr) {
	if (addr->sa_family == AF_INET6)
		return ipv6_address_to_string(buffer, capacity, (const struct sockaddr_in6*)addr);
	return ipv4_address_to_string(buffer, capacity, (const struct sockaddr_in*)addr);
}

void
hexdump(uint32_t addr, const uint8_t* data, unsigned size, FILE* fp=stdout, unsigned width=16) {
    unsigned i;
    if (fp == 0) {
        fp = stderr;
    }
    for (unsigned offset = 0; offset < size; offset += width) {
        fprintf(fp, "0x%08x: ", addr + offset);
        unsigned index = std::min(size - offset, width);
        for (i = 0; i < index; i++) {
            fprintf(fp, "%02x ", data[offset + i]);
        }

        for (unsigned spacer = index; spacer < width; spacer++)
            fprintf(fp, "   ");
        fprintf(fp, ": ");
        for (i = 0; i < index; i++) {
            fprintf(fp, "%c", (((data[offset + i] > 31) && (data[offset + i] < 127)) ? data[offset + i] : '.'));
        }
        fprintf(fp, "\n");
    }
}

#define MDNS_STD_STRING(ms) std::string(ms.str,ms.length)

int
MdnsRR::onMdnsRecord(const struct sockaddr* from, mdns_string_t &question, mdns_entrytype entry, uint16_t type,
                     uint16_t rclass, uint32_t ttl, const uint8_t* data, size_t size, size_t offset, size_t length) {
    MdnsRecord rr;
    rr.question = MDNS_STD_STRING(question);

    char addrbuffer[64];
    char namebuffer[256];
    mdns_record_txt_t txtbuffer[128];

	mdns_string_t fromaddrstr = ip_address_to_string(addrbuffer, sizeof(addrbuffer), from);
    rr.ip = fromaddrstr.str;
    rr.etype = (mdns_entry::type)entry;
    rr.rtype = (mdns_record::type)type;

    switch (type) {
    case mdns_recordtype::PTR: {
		mdns_string_t namestr = mdns_record_parse_ptr(data, size, offset, length,
		                                              namebuffer, sizeof(namebuffer));
        rr.data = MDNS_STD_STRING(namestr);
        //        hexdump(0, data, size);
#if 0
		printf("%.*s : %s PTR %.*s type %u rclass 0x%x ttl %u length %d\n",
		       MDNS_STRING_FORMAT(fromaddrstr), entrytype,
		       MDNS_STRING_FORMAT(namestr), type, rclass, ttl, (int)length);
        hexdump(0, data+offset, length);
#endif
	}
        break;

    case mdns_recordtype::SRV: {
		mdns_record_srv_t srv = mdns_record_parse_srv(data, size, offset, length,
		                                              namebuffer, sizeof(namebuffer));
        rr.data = MDNS_STD_STRING(srv.name);
#if 0        
        hexdump(0, data, size);
		printf("%.*s : %s SRV %.*s priority %d weight %d port %d\n",
		       MDNS_STRING_FORMAT(fromaddrstr), entrytype,
		       MDNS_STRING_FORMAT(srv.name), srv.priority, srv.weight, srv.port);
#endif
	}
        break;
        
    case mdns_recordtype::A: {
		struct sockaddr_in addr;
		mdns_record_parse_a(data, size, offset, length, &addr);
		mdns_string_t addrstr = ipv4_address_to_string(namebuffer, sizeof(namebuffer), &addr);
        rr.data = MDNS_STD_STRING(addrstr);
#if 0
		printf("%.*s : %s A %.*s\n",
		       MDNS_STRING_FORMAT(fromaddrstr), entrytype,
		       MDNS_STRING_FORMAT(addrstr));
#endif
	}
        break;

    case mdns_recordtype::AAAA: {
		struct sockaddr_in6 addr;
        mdns_string_t name;
		mdns_record_parse_aaaa(data, size, offset, length, &name, &addr);
		mdns_string_t addrstr = ipv6_address_to_string(namebuffer, sizeof(namebuffer), &addr);
        rr.data = MDNS_STD_STRING(name) + "=";
        rr.data += MDNS_STD_STRING(addrstr);
#if 0
        hexdump(0, data, size);
        hexdump(1, data+offset, length);
		printf("%.*s : AAAA %.*s=%.*s\n",
               MDNS_STRING_FORMAT(name),
		       MDNS_STRING_FORMAT(fromaddrstr),
		       MDNS_STRING_FORMAT(addrstr));
#endif
	}
        break;
        
    case mdns_recordtype::TXT: {
		size_t parsed = mdns_record_parse_txt(data, size, offset, length,
		                                      txtbuffer, sizeof(txtbuffer) / sizeof(mdns_record_txt_t));
        rr.data = "";
		for (size_t itxt = 0; itxt < parsed; ++itxt) {
			if (txtbuffer[itxt].value.length) {
                rr.data += MDNS_STD_STRING(txtbuffer[itxt].key);
                rr.data += "=";
                rr.data += MDNS_STD_STRING(txtbuffer[itxt].value);
#if 0
				printf("%.*s : %s TXT %.*s = %.*s\n",
				       MDNS_STRING_FORMAT(fromaddrstr), entrytype,
				       MDNS_STRING_FORMAT(txtbuffer[itxt].key),
				       MDNS_STRING_FORMAT(txtbuffer[itxt].value));
#endif
			}
			else {
                rr.data += MDNS_STD_STRING(txtbuffer[itxt].key);
#if 0
				printf("%.*s : %s TXT %.*s\n",
				       MDNS_STRING_FORMAT(fromaddrstr), entrytype,
				       MDNS_STRING_FORMAT(txtbuffer[itxt].key));
#endif
			}
            rr.data += "; ";
		}
	}
        break;
        
    default: {
        std::stringstream ss;
        ss << std::hex;
        for(unsigned i=0; i<length; i++) {
            ss << data[offset+i];
        }
        rr.data = ss.str();
#if 0
		printf("%.*s : %s type %u rclass 0x%x ttl %u length %d\n",
		       MDNS_STRING_FORMAT(fromaddrstr), entrytype,
		       type, rclass, ttl, (int)length);
        hexdump(0, data+offset, length);
#endif
	}
    }
    m_records.push_back(rr);
	return 0;
}

/*
 * Local Variables:
 * mode: C++
 * mode: font-lock
 * c-basic-offset: 4
 * tab-width: 8
 * compile-command: "make.qmk"
 * End:
 */

/* end of /github:elhernes/libmdns/mdns.cpp */
