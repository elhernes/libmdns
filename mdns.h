/********************************************************************************
 * file: /github:elhernes/libmdns/mdns.h
 *
 * born-on: Wed Jan 3 2018
 * creator: Eric L. Hernes
 *
 * C++ header interface for mdns query and discovery requests/responses
 *
 */

#pragma once

#include <stddef.h>    // for size_t
#include <stdint.h>    // for uint16_t, uint8_t, uint32_t
#include <functional>  // for function
#include <iosfwd>      // for string
#include <string>      // for basic_string
#include <vector>

namespace mdns_record {
    enum type {
        IGNORE = 0,
        //Address
        A = 1,
        //Domain Name pointer
        PTR = 12,
        //Arbitrary text string
        TXT = 16,
        //IP6 Address [Thomson]
        AAAA = 28,
        //Server Selection [RFC2782]
        SRV = 33
    };
}
using mdns_recordtype = mdns_record::type;

namespace mdns_entry {
    enum type {
        ANSWER = 1,
        AUTHORITY = 2,
        ADDITIONAL = 3
    };
}
using mdns_entrytype = mdns_entry::type;

struct MdnsRecord {
    mdns_entry::type etype;
    mdns_record::type rtype;
    std::string ip;
    std::string data;
};

using mdns_record_callback_fn = std::function<int(const struct sockaddr* from, mdns_entrytype entry, uint16_t type,
                                                  uint16_t rclass, uint32_t ttl, const uint8_t* data,
                                                  size_t size, size_t offset, size_t length)>;
using mdns_recv_fn = std::function<int(int sock, uint16_t tid, uint8_t* buffer, size_t capacity,
                                       mdns_record_callback_fn callback)>;

class MdnsRR {
 public:
    MdnsRR(const std::string &netif="");
    virtual ~MdnsRR();

    bool discover(int ms);
    bool query(int ms, mdns_recordtype type, const std::string &name);

    bool responses(std::vector<MdnsRecord> &v);
protected:
    bool waitForReplies(int sec, uint16_t tid, mdns_recv_fn recv, mdns_record_callback_fn cb);
    int onMdnsRecord(const struct sockaddr* from, mdns_entrytype entry, uint16_t type, uint16_t rclass,
                     uint32_t ttl, const uint8_t* data, size_t size, size_t offset, size_t length);
    
    int m_4sock;
    int m_6sock;
    uint16_t m_tid;
    std::vector<MdnsRecord> m_records;
};

/*
 * Local Variables:
 * mode: C++
 * mode: font-lock
 * c-basic-offset: 4
 * tab-width: 8
 * compile-command: "make.qmk"
 * End:
 */

/* end of /github:elhernes/libmdns/mdns.h */
