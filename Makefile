CFLAGS += $(shell libnet-config --cflags --defines)
all: cdp-listen cdp-send

cdp-listen: cdp-listen.o -lpcap
cdp-send: cdp-send.o $(shell libnet-config --libs)

clean:; rm -f cdp-send.o cdp-send cdp-listen.o cdp-listen
