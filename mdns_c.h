/* mdns_c.h  -  mDNS/DNS-SD library  -  Public Domain  -  2017 Mattias Jansson / Rampant Pixels
 *
 * This library provides a cross-platform mDNS and DNS-SD library in C.
 * The implementation is based on RFC 6762 and RFC 6763.
 *
 * The latest source code maintained by Rampant Pixels is always available at
 *
 * https://github.com/rampantpixels/mdns
 *
 * This library is put in the public domain; you can redistribute it and/or modify it without any restrictions.
 *
 */

#pragma once

#include <stddef.h>    // for size_t
#include <stdint.h>    // for uint8_t, uint16_t, uint32_t
#include <functional>  // for function
#include <iosfwd>      // for string
#include "mdns.h"      // for mdns_recordtype, mdns_entrytype

#define MDNS_INVALID_POS ((size_t)-1)

#define MDNS_STRING_CONST(s) (s), (sizeof((s))-1)
#define MDNS_STRING_FORMAT(s) (int)((s).length), s.str

using mdns_record_callback_fn = std::function<int(const struct sockaddr* from, mdns_entrytype entry, uint16_t type,
                                                  uint16_t rclass, uint32_t ttl, const uint8_t* data,
                                                  size_t size, size_t offset, size_t length)>;

struct mdns_string_t {
	const char* str;
	size_t length;
};

struct mdns_string_pair_t {
	size_t  offset;
	size_t  length;
	int     ref;
};

struct mdns_record_srv_t {
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
	mdns_string_t name;
};

struct mdns_record_txt_t {
	mdns_string_t key;
	mdns_string_t value;
};

int mdns_socket_open_ipv4(void);

int mdns_socket_setup_ipv4(int sock);

int mdns_socket_open_ipv6(void);

int mdns_socket_setup_ipv6(int sock);

void mdns_socket_close(int sock);

int mdns_discovery_send(int sock);

size_t mdns_discovery_recv(int sock, uint16_t tid, uint8_t* buffer, size_t capacity,
                           mdns_record_callback_fn callback);

int mdns_query_send(int sock, uint16_t tid, mdns_recordtype type, const char* name, size_t length);
inline int mdns_query_send(int sock, uint16_t tid, mdns_recordtype type, const std::string &name) {
    return mdns_query_send(sock, tid, type, name.c_str(), name.size());
}

size_t mdns_query_recv(int sock, uint16_t tid, uint8_t* buffer, size_t capacity,
                       mdns_record_callback_fn callback);

mdns_string_t mdns_string_extract(const uint8_t* buffer, size_t size, size_t* offset,
                                  char* str, size_t capacity);

int mdns_string_skip(const uint8_t* buffer, size_t size, size_t* offset);

int mdns_string_equal(const uint8_t* buffer_lhs, size_t size_lhs, size_t* ofs_lhs,
                      const uint8_t* buffer_rhs, size_t size_rhs, size_t* ofs_rhs);

uint8_t *mdns_string_make(uint8_t* data, size_t capacity, const char* name, size_t length);

mdns_string_t mdns_record_parse_ptr(const uint8_t* buffer, size_t size, size_t offset, size_t length,
                                    char* strbuffer, size_t capacity);

mdns_record_srv_t mdns_record_parse_srv(const uint8_t* buffer, size_t size, size_t offset, size_t length,
                                        char* strbuffer, size_t capacity);

struct sockaddr_in* mdns_record_parse_a(const uint8_t* buffer, size_t size, size_t offset, size_t length,
                                        struct sockaddr_in* addr);

struct sockaddr_in6* mdns_record_parse_aaaa(const uint8_t* buffer, size_t size, size_t offset, size_t length,
                                            struct sockaddr_in6* addr);

size_t mdns_record_parse_txt(const uint8_t* buffer, size_t size, size_t offset, size_t length,
                             mdns_record_txt_t* records, size_t capacity);

