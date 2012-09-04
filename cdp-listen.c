/*
 *     cdp-listen is part of cdp-tools.
 *     cdp-tools is (c) 2003-2006 Internet Connection, Inc.
 *     cdp-tools is (c) 2003-2006 Geo Carncross
 *
 *     cdp-listen is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2, or (at your option)
 *     any later version.
 *
 *     cdp-listen is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with cdp-tools; see the file LICENSE.  If not, write to
 *     the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include <stdio.h>
#include <getopt.h>
#include <fcntl.h>
#include <pcap.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

/* Define the constants and text values for the 'type' field: */
#define TYPE_DEVICE_ID			0x0001
#define TYPE_ADDRESS			0x0002
#define TYPE_PORT_ID			0x0003
#define TYPE_CAPABILITIES		0x0004
#define TYPE_IOS_VERSION		0x0005
#define TYPE_PLATFORM			0x0006
#define TYPE_IP_PREFIX			0x0007
#define TYPE_VTP_MGMT_DOMAIN		0x0009
#define TYPE_NATIVE_VLAN		0x000a
#define TYPE_DUPLEX			0x000b

typedef struct _cdp_packet_header
{
	u_int8_t  version;
	u_int8_t  time_to_live;
	u_int16_t checksum;
} CDP_HDR;

typedef struct _cfp_packet_data
{
	u_int16_t type;
	u_int16_t length;
} CDP_DATA;

static int
usage()
{ 
	fprintf(stderr, "Usage: cdp-listen interfaces... | logsomething\n");
	return 0;
};

static int yankdo(int look_type, CDP_DATA *d, unsigned int len, void *x,
		int (*e)(void *x, unsigned char *data, unsigned int len))
{
	int hits = 0;
	while (len > sizeof(CDP_DATA)) {
		int type;
		int length;
		u_char *v;
		int vlen;
		CDP_DATA data;

		memcpy(&data, d, sizeof(CDP_DATA));
		type = ntohs(data.type);
		length = ntohs(data.length);
		v = (u_char *) d + sizeof(CDP_DATA);
		vlen = length - sizeof(CDP_DATA);

		if (vlen < 0 || vlen > len) {
			break;
		}

		if (type == look_type) {
			if (e) {
				if (e(x, v, vlen)) hits++;
			} else {
				hits++;
			}
		}
		len -= length;
		d = (CDP_DATA *)(((u_char *)d) + length);
	}
	return hits;
}

static int n_device_id(void *ignored, unsigned char *vdata, unsigned int len)
{
	putchar('\t');
	while (len > 0) {
		if (isalnum(*vdata) || *vdata == '-' || *vdata == '.') {
			putchar(*vdata);
			vdata++;
			len--;
		} else {
			break;
		}
	}
	return 1;
}
static int n_device_ip4(void *cx, unsigned char *vdata, unsigned int len)
{
	u_int32_t i, number;
	unsigned int q;

	if (len < 4) return 0;
	if (!cx) return 0;
	q = *((unsigned int *)cx);

	memcpy(&number, vdata, sizeof(number));
	number = ntohl(number);

	vdata += sizeof(u_int32_t);
	len -= sizeof(u_int32_t);

	for (i = 0; len >= 3 && i < number; i++) {
		u_char protocol_len = vdata[1];
		u_char *protocol_value = vdata+2;
		u_int16_t address_len;
		u_char *address = ((vdata+4)+protocol_len);

		if (len < protocol_len+4) return 0; /* failed I guess... */
		memcpy(&address_len, vdata+2+protocol_len, sizeof(address_len));
		address_len = ntohs(address_len);
		if (len < protocol_len+address_len+4) return 0; /*failed I guess*/
		if (protocol_len == 1 && *protocol_value == 0xCC &&
				address_len == 4) {
			if (q > 0) {
				q--;
				continue;
			}
			printf("%u.%u.%u.%u",
					(unsigned int)address[0],
					(unsigned int)address[1],
					(unsigned int)address[2],
					(unsigned int)address[3]);
			*((unsigned int *)cx) =
				(*((unsigned int *)cx)) + 1;
			return 1;
		}
	}
	return 0;
}
static int n_device_caps(void *cx, unsigned char *vdata, unsigned int len)
{
	unsigned long *q = (unsigned long *)cx;
	u_int32_t cap;

	if (!q) return 0;

	if (len >= 4) {
		memcpy(&cap, vdata, 4);
	} else if (len < 4)  {
		memset(&cap, 0, sizeof(cap));
		memcpy(&cap, vdata, len);
	}
	(*q) |= ntohl(cap);
	return 1;
}

static int n_ip_prefix(void *cx, unsigned char *vdata, unsigned int len)
{
	unsigned int i, q;

	if (len < 4) return 0;
	if (!cx) return 0;
	q = *((unsigned int *)cx);
	for (i = 0; i < len; i += 5) {
		if (i+4 >= len) break;
		if (q > 0) {
			q--;
			continue;
		}
		printf("%u.%u.%u.%u/%u",
				(unsigned int)vdata[i],
				(unsigned int)vdata[i+1],
				(unsigned int)vdata[i+2],
				(unsigned int)vdata[i+3],
				(unsigned int)vdata[i+4]);
		*((unsigned int *)cx) =
			(*((unsigned int *)cx)) + 1;
		return 1;
	}
	return 0;
}

static void
doit(char *interface, struct pcap_pkthdr *pcap_h, register u_char *pcap_p)
{
	CDP_HDR *h;
	CDP_DATA *d;
	unsigned int len;
	unsigned long cap;

	h = (CDP_HDR *) (((unsigned char *)pcap_p) + 22);

	d = (CDP_DATA *)((((unsigned char *)pcap_p) + 22) + sizeof(CDP_HDR));
	len = (pcap_h->len - 22) - sizeof(CDP_HDR);;

	printf("# Interface:\t%s\n# Hostname:", interface);
	if (!yankdo(TYPE_DEVICE_ID, d, len, 0, n_device_id))
		printf("(unknown)");
	putchar('\n');
	{
		/* draw something that looks something like a /etc/hosts
		 * record
		 */
		unsigned int i = 0;
		printf("# Address:\t");
		while (yankdo(TYPE_ADDRESS, d, len, &i, n_device_ip4)) {
			printf("\n#\t\t");
		}
		putchar('\n');
	};

	printf("# TimeToLive:\t%u\n", h->time_to_live);

	cap = 0;
	yankdo(TYPE_CAPABILITIES, d, len, &cap, n_device_caps);
	printf("# Capabilities:");
	if (cap & 0x01) printf(" L3R(router)");
	if (cap & 0x02) printf(" L2TB(bridge)");
	if (cap & 0x04) printf(" L2SRB(bridge)");
	if (cap & 0x08) printf(" L2SW(switch)");
	if (cap & 0x10) printf(" L3TXRX(host)");
	if (cap & 0x40) printf(" L1(repeater)");
	if (cap & 0x20) printf(" IGRP");
	if (cap & 0xFFFFFF80) printf(" unknown(%08lX)", cap);
	printf("\n#\n");

	{
		/* draw something that looks like it could call route :)
		 */
		unsigned int i = 0;
		printf("# Networks:\t");
		while (yankdo(TYPE_IP_PREFIX, d, len, &i, n_ip_prefix)) {
			printf("\n#\t\t");
		}
		printf("\n");
	}
	printf("\n");
	fflush(stdout);
}

int main(int argc, char *argv[])
{
	int c, i, j, m;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;
	char *filter_app = "ether multicast and ether[20:2] = 0x2000";
	pcap_t **h;

	while((c=getopt(argc,argv,""))!=EOF) {
		switch (c) {
		default:
			usage();
			exit(1);
		};
	}

	if (argc == optind) {
		usage();
		exit(1);
	}

	h = (pcap_t **)malloc(sizeof(pcap_t *) * ((argc - optind)+1));
	if (!h) {
		perror("malloc");
		exit(1);
	}

	for (c = 0, i = optind; i < argc; i++, c++) {
		bpf_u_int32 net, mask;
		pcap_lookupnet(argv[i], &net, &mask, errbuf);
		h[c] = pcap_open_live(argv[i], 65535, 1, 0, errbuf);
		if (!h[c]) {
			fprintf(stderr, "Could not open %s: %s\n", argv[i], errbuf);
			exit(1);
		}

		pcap_compile(h[c], &filter, filter_app, 0, net);
		pcap_setfilter(h[c], &filter);
		pcap_freecode(&filter);
	}

	if (c > 1) {
		u_char *packet;
		struct pcap_pkthdr header;
		fd_set rfds;

		for (i = 0; i < c; i++) {
			j = pcap_fileno(h[i]);
			fcntl(j, F_SETFL, fcntl(j, F_GETFL, 0) | O_NONBLOCK);
		}
		for (;;) {
			FD_ZERO(&rfds);
			for (i = 0, m = -1; i < c; i++) {
                        j = pcap_fileno(h[i]);
				FD_SET(j, &rfds);
				if (j > m) m = j;
			}
			(void) select(m+1, &rfds, 0, 0, 0);
			for (i = 0; i < c; i++) {
				packet = (u_char *)pcap_next(h[i], &header);
				if (packet) {
					doit(argv[i-optind], &header, packet);
				}
			}
		}
	} else {
		if (pcap_loop(h[0], -1, (pcap_handler) doit, argv[optind]) < 0) {
			pcap_perror(h[0], NULL);
			exit(1);
		}
	}
	exit(0);
}
