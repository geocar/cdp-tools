LIBNET_CFLAGS  != libnet-config --cflags --defines
LIBNET_LDFLAGS != libnet-config --libs

CFLAGS  += $(LIBNET_CFLAGS) -Wall
LDFLAGS += $(LIBNET_LDFLAGS) -lpcap

all: cdp-listen cdp-send


cdp-listen.o: cdp-listen.c
	cc $(CFLAGS) -c -o $@ $<
cdp-send.o: cdp-listen.c
	cc $(CFLAGS) -c -o $@ $<

cdp-listen: cdp-listen.o
	cc $(LDFLAGS) -o $@ $>

cdp-send: cdp-send.o
	cc $(LDFLAGS) -o $@ $>


clean:; rm -f cdp-send.o cdp-send cdp-listen.o cdp-listen
