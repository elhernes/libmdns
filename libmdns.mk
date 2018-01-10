########################################
## file: /github/mdns/mdns.mk
## born-on: Thu Dec 28 09:54:24 2017
## creator: Elh
##
## Makefile to build something
##

SRCS=mdns_c.cpp mdns.cpp

DEFINES+=

CXXFLAGS-dey=-pthread

include sw.lib.mk

#
# Local Variables:
# mode: Makefile
# mode: font-lock
# tab-width: 8
# compile-command: "make.qmk"
# End:
#
