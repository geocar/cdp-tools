/*
 *     cdp-send is part of cdp-tools.
 *     cdp-tools is (c) 2003-2006 Internet Connection, Inc.
 *     cdp-tools is (c) 2003-2006 Geo Carncross
 *
 *     Voice VLAN support by Kristian Kielhofner <kris@krisk.org>
 * 
 *     cdp-send is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2, or (at your option)
 *     any later version.
 *
 *     cdp-send is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with cdp-tools; see the file LICENSE.  If not, write to
 *     the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/param.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <libnet.h>

static char ebuf[2048];
static char *use_hostname = 0;
static struct utsname myuname;
static char *use_sysname = 0, *use_machine = 0;
static char *use_portname = 0;

static char *use_domain = 0;
static unsigned int use_domain_len = 0;

static unsigned int use_vlanid = 0;

static unsigned int use_voiceid = 0;

static unsigned char *use_ip_prefix = 0;
static unsigned int use_ip_prefix_len = 0;

#ifndef LIBNET_LINK
/* these are hacks for the OLD API (1.0 series libnet) */
#define libnet_ether_addr ether_addr
#define libnet_init(a,b,c)	(struct libnet_link_int *)libnet_open_link_interface(b,c)
#define libnet_t	struct libnet_link_int
#define libnet_get_hwaddr(x) libnet_get_hwaddr(x, cdp->name, ebuf)
#define libnet_write_link(a,b,c) libnet_write_link_layer(a, cifa->name, b, c)
#define libnet_get_ipaddr4(a) htonl(libnet_get_ipaddr(a, cdp->name, ebuf))
#endif


/* the capability masks */
static int cdp_capset;
#define CDP_CAP_RT       0x01    /* Router */
#define CDP_CAP_T        0x02    /* Transparent Bridge */
#define CDP_CAP_B        0x04    /* Source Route Bridge */
#define CDP_CAP_S        0x08    /* Switch */
#define CDP_CAP_H        0x10    /* Host */
#define CDP_CAP_I        0x20    /* IGMP capable */
#define CDP_CAP_R        0x40    /* Repeater */
#define CDP_CAP_P        0x80    /* VoIP Phone */
#define CDP_CAP_D        0x100   /* Remotely Managed Device */
#define CDP_CAP_C        0x200   /* CVTA/STP Dispute Resolution/Cisco VT Camera */
#define CDP_CAP_M        0x400   /* Two Port Mac Relay */

struct cdp_header { 
/* ethernet 802.3 header */
	unsigned char dst_addr[6] __attribute__ ((packed));
	unsigned char src_addr[6] __attribute__ ((packed));
	u_int16_t length __attribute__ ((packed));
/* LLC */
	u_int8_t dsap __attribute__ ((packed));
	u_int8_t ssap __attribute__ ((packed));
/* llc control */
	u_int8_t control __attribute__ ((packed));
	u_int8_t orgcode[3] __attribute__ ((packed));
	u_int16_t protocolId __attribute__ ((packed));
};

static void chomp(char *buf)
{
	while (*buf && *buf != '\n' && *buf != '\r') buf++;
	if (*buf) *buf = 0;
}

static int debug=0;

int
sx_write_long(unsigned char* buffer, u_int32_t data)
{ 
#ifdef LIBNET_LIL_ENDIAN
	buffer[3]=(data>>24)&0xff;
	buffer[2]=(data>>16)&0xff;
	buffer[1]=(data>>8)&0xff;
	buffer[0]=data&0xff;
#else
	buffer[0]=(data>>24)&0xff;
	buffer[1]=(data>>16)&0xff;
	buffer[2]=(data>>8)&0xff;
	buffer[3]=data&0xff;
#endif
	return 1;
};

int
sx_write_short(unsigned char* buffer, u_int16_t data)
{ 
#ifdef LIBNET_LIL_ENDIAN
	buffer[1]=(data>>8)&0xff;
	buffer[0]=data&0xff;
#else
	buffer[0]=(data>>8)&0xff;
	buffer[1]=data&0xff;
#endif
	return 1;
};

#define isoct_digit(x) (isdigit(x) && x != '9' && x != '8')
#define oct_digit(x) \
	(x == '0' ? 0 : \
	 (x == '1' ? 1 : \
	  (x == '2' ? 2 : \
	   (x == '3' ? 3 : \
	    (x == '4' ? 4 : \
	     (x == '5' ? 5 : \
	      (x == '6' ? 6 : \
	       (x == '7' ? 7 : \
		0))))))))

static unsigned int
unoct(char *buf)
{
	unsigned int j;
	int i;

	if (!buf) return 0;

	for (i = j = 0; buf[i]; j++,i++) {
		if (buf[i] == '\\') {
			if (buf[i+1] == '\\') {
				buf[j] = '\\';
				i++;
				continue;
			} else if (isoct_digit(buf[i+1])
			&& isoct_digit(buf[i+2])
			&& isoct_digit(buf[i+3])) {
				buf[j] = 
					oct_digit(buf[i+1]) << 6
					| oct_digit(buf[i+2]) << 3
					| oct_digit(buf[i+3]);
				i++;
				i++;
				i++;
				continue;
			}
		}
		buf[j] = buf[i];
	}
	return j;
}

int
cdp_buffer_init(unsigned char* buffer, int len, struct libnet_ether_addr* myether)
{ 
	memset(buffer,0,len);

	buffer[0]=0x01;
	buffer[1]=0x00;
	buffer[2]=0x0c;
	buffer[3]=buffer[4]=buffer[5]=0xcc; 

	memcpy(buffer+6,myether->ether_addr_octet,6);

	((struct cdp_header*)buffer)->dsap=0xaa;
	((struct cdp_header*)buffer)->ssap=0xaa;
	((struct cdp_header*)buffer)->control=0x03;
	((struct cdp_header*)buffer)->orgcode[2]=0x0c;
	sx_write_short((unsigned char*)&(((struct cdp_header*)buffer)->protocolId),
		htons(0x2000));

	buffer+=sizeof(struct cdp_header);

	buffer[0]=0x2; /* cdp version */
	buffer[1]=0xb4; /* cdp holdtime, 180 sec by default */
	buffer[2]=buffer[3]=0; /* checksum - will calculate later */

	return 4+sizeof(struct cdp_header);
};

int
cdp_add_device_id(unsigned char* buffer, int len)
{ 
	static char s_hostname[256];

	if (!use_hostname) {
		gethostname(s_hostname,sizeof(s_hostname)-1);
		s_hostname[sizeof(s_hostname)-1] = 0;
		use_hostname = s_hostname;
	}

	if((strlen(use_hostname)+4)>len) return 0;

	*(u_int16_t*)buffer=htons(0x0001); /* type=deviceId */
	*((u_int16_t*)(buffer+2))=htons(strlen(use_hostname)+4); /* total length */
	memcpy(buffer+4,use_hostname,strlen(use_hostname));

	return strlen(use_hostname)+4;
};

int
cdp_add_address(unsigned char* buffer, int len, u_int32_t addr)
{ 
	if(!addr) return 0;
	if(len<17) return 0;

	sx_write_short(buffer,htons(0x02)); 
	sx_write_short(buffer+2,htons(17)); 
	sx_write_long(buffer+4,htonl(1));
	buffer[8]=1; /* nlpid */
	buffer[9]=1; /* proto length */
	buffer[10]=0xcc; /* proto id: cc==IP */
	sx_write_short(buffer+11,htons(4));
	memcpy(buffer+13, &addr, 4);

	return 17;
};

int
cdp_add_interface(unsigned char* buffer, int len, char* interface)
{ 
	if(!interface) return 0;
	if(len<(strlen(interface)+4)) return 0;

	sx_write_short(buffer,htons(0x0003)); /* type=PortId */
	sx_write_short(buffer+2,htons(strlen(interface)+4)); /* totallength*/
	memcpy(buffer+4,interface,strlen(interface));

	return strlen(interface)+4;
};

int
cdp_add_capabilities(unsigned char* buffer, int len)
{ 
	if(len<8) return 0;

	sx_write_short(buffer,htons(0x0004)); /* type=Capabilities */
	sx_write_short(buffer+2,htons(8)); /* totallength*/
	sx_write_long(buffer+4,htonl(cdp_capset));

	return 8;
};

int
cdp_add_software_version(unsigned char* buffer, int len)
{ 
	if((strlen(use_sysname)+4)>len) return 0;

	sx_write_short(buffer,htons(0x0005)); /* type=software version */
	sx_write_short(buffer+2,htons(strlen(use_sysname)+4)); /* totallength*/
	memcpy(buffer+4,use_sysname,strlen(use_sysname));

	return strlen(use_sysname)+4;
};

int 
cdp_add_platform(unsigned char* buffer, int len)
{ 
	if((strlen(use_machine)+4)>len) return 0;
	sx_write_short(buffer,htons(0x0006)); /* type=platform */
	sx_write_short(buffer+2,htons(strlen(use_machine)+4)); /* totallength*/
	memcpy(buffer+4,use_machine,strlen(use_machine));

	return strlen(use_machine)+4;
};

int
cdp_add_ip_prefix(unsigned char* buffer, int len)
{
	if (use_ip_prefix == 0 || use_ip_prefix_len == 0) return 0;
	if (use_ip_prefix_len+4 > len) return 0;
	sx_write_short(buffer,htons(0x0007)); /* type = ip prefix */
	sx_write_short(buffer+2, htons(use_ip_prefix_len+4));
	memcpy(buffer+4, use_ip_prefix, use_ip_prefix_len);
	return use_ip_prefix_len+4;
}

int
cdp_add_vtp_domain(unsigned char* buffer, int len)
{
	if (use_domain == 0 || use_domain_len == 0) return 0;
	if (use_domain_len+4>len) return 0;
	sx_write_short(buffer,htons(0x0009)); /* type=vtp management domain */
	sx_write_short(buffer+2,htons(use_domain_len+4));
	memcpy(buffer+4,use_domain,use_domain_len);
	return use_domain_len+4;
}

int
cdp_add_port_duplex(unsigned char* buffer, int len, int duplex)
{
	if (duplex == 0) return 0;
	if (len < 5) return 0;
	sx_write_short(buffer,htons(0x000b)); /* type=port duplex */
	sx_write_short(buffer+2,htons(5)); /* totallength*/
	buffer[4] = (duplex == 1 ? 1 : 0);
	return 5;
}

int
cdp_add_vlanid(unsigned char* buffer, int len)
{
	if (len < 6) return 0;
	sx_write_short(buffer,htons(0x000a)); /* type=vlan id */
	sx_write_short(buffer+2,htons(6)); /* totallength*/
	sx_write_short(buffer+4,htons(use_vlanid));
	return 6;
}

int
cdp_add_voiceid(unsigned char* buffer, int len)
{
	if (len < 7) return 0;
	sx_write_short(buffer,htons(0x000e)); /* type=voice vlan id */
	sx_write_short(buffer+2,htons(7)); /* totallength*/
	sx_write_short(buffer+4,htons(0x1)); /*PAD*/
	sx_write_short(buffer+5,htons(use_voiceid));
	return 7;
}



unsigned short
cdp_checksum(unsigned char *ptr, int length) {
	if (length % 2 == 0) {
		/* The doc says 'standard IP checksum', so this is what we do. */
		return libnet_ip_check((u_short *)ptr, length);
	} else {
		/* An IP checksum is not defined for an odd number of bytes... */
		/* Tricky. */
		/* Treat the last byte as an unsigned short in network order. */

		int c = ptr[length-1];
		unsigned short *sp = (unsigned short *)(&ptr[length-1]);
		unsigned short ret;

		*sp = htons(c);
		ret = libnet_ip_check((u_short *)ptr, length+1);
		ptr[length-1] = c;
		return ret;
	}
}

int
usage()
{ 
	fprintf(stderr,
"Usage: cdp-send [options] interfaces... &\n"
"  -a addr    use specified address instead of that on interface\n"
"  -c caps    enable capabilities (try -c list)\n"
"  -d         enable debugging output\n"
"  -D dom     specify VTP management domain (octal escapes ok)\n"
"  -L vlan    specify native VLAN (vlanid)\n"
"  -V vlan    specify voice VLAN (voiceid)\n"
"  -m mach    specify machine/platform to advertise (e.g. \"%s\")\n"
"  -n name    specify a hostname\n"
"  -p name    override port name (default: interface)\n"
"  -P duplex  specify port duplex (full/half)\n"
"  -o         enable oneshot mode\n"
"  -s vers    specify software/version to advertise (e.g. \"%s %s\")\n"
"  -S subnet  specify ip prefix/subnet (need for routers, etc)\n"
"  -t secs    set wait-time (default: 60 seconds)\n",
		myuname.machine,
		myuname.sysname, myuname.release
);
	return 0;
};

struct cdp_interface {
	struct cdp_interface* next;
	char* name;
	struct sockaddr_in address;
	struct libnet_ether_addr *eaddr;
	libnet_t *llink;
};

struct cdp_interface*
cdp_interface_find(struct cdp_interface* list, char* iface)
{
	while(list) {
		if(list->name && !strcmp(list->name,iface)) return list;
		list=list->next;
	};
	return NULL;
};

struct cdp_interface*
cdp_interface_add(struct cdp_interface** head, char* iface)
{
	struct cdp_interface* cdp;

	if(!iface || !head) return NULL;

	if((cdp=cdp_interface_find(*head,iface))) return cdp;

	cdp=malloc(sizeof(struct cdp_interface));
	if(!cdp) { 
		perror("malloc");
		exit(1);
	};
	memset(cdp,0,sizeof(struct cdp_interface));

	cdp->llink = libnet_init(LIBNET_LINK, iface, ebuf);
	if(!cdp->llink) { 
		chomp(ebuf);
		fprintf(stderr, "Can't open interface %s (%s)\n",iface,ebuf);
		return NULL;
	};

	cdp->name=iface;
	cdp->eaddr = libnet_get_hwaddr(cdp->llink);
	if(!cdp->eaddr) { 
		chomp(ebuf);
		fprintf(stderr, "Can't recognize hardware address of %s (%s)\n",iface,
			ebuf);
		return NULL;
	};

	cdp->address.sin_addr.s_addr=libnet_get_ipaddr4(cdp->llink);

	if(!*head) { 
		*head=cdp;
	} else { 
		struct cdp_interface* b=*head;
		while(b->next) b=b->next;
		b->next=cdp;
	};
	return cdp;
};
	
int
main(int argc, char* argv[])
{ 
	static unsigned char buffer[65535];
	int i, c;
	int timeout=60, ret=0;
	struct in_addr iaddr, *addrp=0;
	int use_addrp=0;
	int offset;
	int once=0;
	struct cdp_interface *ifaces=NULL;
	int specify_duplex = 0;
	int specified_vlan = 0;
	int specified_vvlan = 0;
	int didcap = 0;
	char *q;

	uname(&myuname);
	while((c=getopt(argc,argv,"a:c:dD:L:V:m:n:op:P:s:S:t:"))!=EOF) { 
		switch(c) { 
		case 'a':
			if (inet_aton(optarg, &iaddr)) {
				addrp = (struct in_addr *)realloc(addrp,
						sizeof(struct in_addr)
						* (use_addrp+1));
				if (!addrp) {
					perror("realloc");
					exit(1);
				}
				memcpy(&addrp[use_addrp], &iaddr,
						sizeof(struct in_addr));
				use_addrp++;
			} else {
				fprintf(stderr, "Invalid address ``%s''\n", optarg);
				exit(1);
			}
			break;

		case 'c':
			didcap = 1;
			if (strcasecmp(optarg, "rt") == 0) {
				cdp_capset |= CDP_CAP_RT;
			} else if (strcasecmp(optarg, "t") == 0) {
				cdp_capset |= CDP_CAP_T;
			} else if (strcasecmp(optarg, "b") == 0) {
				cdp_capset |= CDP_CAP_B;
			} else if (strcasecmp(optarg, "s") == 0) {
				cdp_capset |= CDP_CAP_S;
			} else if (strcasecmp(optarg, "j") == 0) {
				cdp_capset |= CDP_CAP_H;
			} else if (strcasecmp(optarg, "i") == 0) {
				cdp_capset |= CDP_CAP_I;
			} else if (strcasecmp(optarg, "r") == 0) {
				cdp_capset |= CDP_CAP_R;
			} else if (strcasecmp(optarg, "p") == 0) {
				cdp_capset |= CDP_CAP_P;
			} else if (strcasecmp(optarg, "d") == 0) {
				cdp_capset |= CDP_CAP_D;
			} else if (strcasecmp(optarg, "c") == 0) {
				cdp_capset |= CDP_CAP_C;
			} else if (strcasecmp(optarg, "m") == 0) {
				cdp_capset |= CDP_CAP_M;
			} else {
				i = strtod(optarg, &q);
				if (!q || !*q) {
					cdp_capset = i;
					continue;
				}
				if (strcasecmp(optarg, "list"))
					fprintf(stderr, "Unknown capability string: %s\n\n", optarg);
				fprintf(stderr, "Known capabilities:\n"
"  rt        Router\n"
"  t         Transparent Bridge\n"
"  b         Source Route Bridge\n"
"  s         Switch\n"
"  h         Host\n"
"  i         IGMP capable\n"
"  r         Repeater\n"
"  p         VoIP Phone\n"
"  d         Remotely Managed Device\n"
"  c         CVTA/STP Dispute Resolution/Cisco VT Camera\n"
"  m         Two Port Mac Relay\n");
				exit(1);
			}
			break;
		case 'd':
			debug++;
			break;
		case 'D':
			use_domain = strdup(optarg);
			if (!use_domain) {
				perror("strdup");
				exit(1);
			}
			use_domain_len = unoct(use_domain);
			break;
		case 'L':
			i = strtod(optarg, &q);
			if ((q && *q) || i < 0 || i > 65535) {
				fprintf(stderr, "VLAN ID is an unsigned 16-bit integer\n");
				exit(1);
			}
			specified_vlan=1;
			use_vlanid = i;
			break;
		case 'V':
			i = strtod(optarg, &q);
			if ((q && *q) || i < 0 || i > 65535) {
				fprintf(stderr, "Voice VLAN ID is an unsigned 16-bit integer\n");
				exit(1);
			}
			specified_vvlan=1;
			use_voiceid = i;
			break;
		case 'm':
			use_machine = strdup(optarg);
			if (!use_machine) {
				perror("strdup");
				exit(1);
			}
			break;
		case 'n':
			use_hostname = strdup(optarg);
			if (!use_hostname) {
				perror("strdup");
				exit(1);
			}
			break;

		case 'o':
			once=1;
			break;
		case 'p':
			use_portname = strdup(optarg);
			if (!use_portname) {
				perror("strdup");
				exit(1);
			}
			break;

		case 'P':
			if (tolower(*optarg) == 'f') {
				/* full duplex */
				specify_duplex = 1;
			} else {
				/* half duplex */
				specify_duplex = -1;
			}
			break;
		case 's':
			use_sysname = strdup(optarg);
			if (!use_sysname) {
				perror("strdup");
				exit(1);
			}
			break;
		case 'S':
			q = strchr(optarg, '/');
			if (!q) {
				fprintf(stderr, "subnet must include IP prefix (addr/subnet)\n");
				exit(1);
			}
			*q = 0;
			q++;

			i = atoi(q);
			if (i < 0 || i > 31) {
				fprintf(stderr, "subnet out of range (use CIDR format only)\n");
				exit(1);
			}

			if (!inet_aton(optarg, &iaddr)) {
				fprintf(stderr, "Invalid address ``%s/%d''\n", optarg, i);
				exit(1);
			}

			use_ip_prefix = realloc(use_ip_prefix,
					use_ip_prefix_len + 5);
			if (!use_ip_prefix) {
				perror("realloc");
				exit(1);
			}
			memcpy(use_ip_prefix+use_ip_prefix_len,
					&iaddr.s_addr, 4);
			use_ip_prefix[use_ip_prefix_len+4] = i;
			use_ip_prefix_len += 5;
			break;
		case 't':
			timeout=atoi(optarg);
			if(timeout<=0) { 
				fprintf(stderr, "wrong value to timeout - reverting to default 60 sec\n");
				timeout=5;
			};
			break;
		default:
			usage();
			exit(1);
		};
	};

	if (!didcap) cdp_capset = CDP_CAP_H;

	if (optind == argc) {
		usage();
		exit(1);
	}

	for (i = optind; i < argc; i++) {
		if (cdp_interface_add(&ifaces, argv[i]) == NULL) {
			exit(1);
		}
	}

	if (!use_machine) {
		use_machine = myuname.machine;
		if (!use_machine) {
			use_machine = "(null)";
		}
	}
	if (!use_sysname) {
		char *qa, *qb;
		int buflen;
		qa = myuname.sysname; if (!qa) qa = "(null)";
		qb = myuname.release; if (!qb) qb = "(null)";
		buflen = strlen(qa) + strlen(qb) + 2;

		use_sysname = (char *)malloc(buflen);
		if (!use_sysname) {
			perror("malloc");
			exit(1);
		}
		sprintf(use_sysname, "%s %s", qa, qb);
		use_sysname[buflen-1] = '\0'; /* terminate if truncated */
	}

	for (;;) { 
		struct cdp_interface* cifa=ifaces;
		while(cifa) { 
			offset=0;
			offset=cdp_buffer_init(buffer,sizeof(buffer),cifa->eaddr);
	
			offset+=cdp_add_device_id(buffer+offset,sizeof(buffer)-offset);

			if (use_addrp) {
				for (i = 0; i < use_addrp; i++) {
					offset+=cdp_add_address(buffer+offset,sizeof(buffer)-offset,
						addrp[i].s_addr);
				}
			} else {
				offset+=cdp_add_address(buffer+offset,sizeof(buffer)-offset,
						cifa->address.sin_addr.s_addr); /* aldready BE */
			}

			offset+=cdp_add_interface(buffer+offset,sizeof(buffer)-offset,
				use_portname ? use_portname : cifa->name);

			offset+=cdp_add_capabilities(buffer+offset,sizeof(buffer)-offset);

			offset+=cdp_add_software_version(buffer+offset,
				sizeof(buffer)-offset);

			offset+=cdp_add_platform(buffer+offset,sizeof(buffer)-offset);
			offset+=cdp_add_ip_prefix(buffer+offset, sizeof(buffer)-offset);
			offset+=cdp_add_vtp_domain(buffer+offset, sizeof(buffer)-offset);
			offset+=cdp_add_port_duplex(buffer+offset, sizeof(buffer)-offset,
					specify_duplex);
			if (specified_vlan) {
				offset+=cdp_add_vlanid(buffer+offset, sizeof(buffer)-offset);
			}

			if (specified_vvlan) {
				offset+=cdp_add_voiceid(buffer+offset, sizeof(buffer)-offset);
			}
			
			((struct cdp_header*)buffer)->length=htons(offset-14);
		
			*(u_short*)(buffer+sizeof(struct cdp_header)+2)=cdp_checksum(
				buffer+sizeof(struct cdp_header),
				offset-sizeof(struct cdp_header));
	
			if((ret=libnet_write_link(cifa->llink,buffer,offset))
				!=offset) {
				fprintf(stderr, "wrote only %i bytes: %s\n",ret,strerror(errno));
			};
	
			if(debug) { 
				int i, j;
				fprintf(stderr, "Sent over: %s, total length: %i\n", cifa->name, offset);
				for(i=0;i<offset/16;i++) { 
					fprintf(stderr, "%4.4x ",i);
					for(j=0;j<16;j++)
						fprintf(stderr,"%2.2x ",buffer[16*i+j]);
					for(j=0;j<16;j++) 
						if(isprint(buffer[16*i+j])) 
							fprintf(stderr,"%c",buffer[16*i+j]);
						else 
							fprintf(stderr,".");
					fprintf(stderr,"\n");
				};
				if(offset%16) { 
					i=offset/16;
	
					fprintf(stderr,"%4.4x ",i);
					for(j=0;j<offset%16;j++)
						fprintf(stderr,"%2.2x ",buffer[16*i+j]);
					for(j=offset%16; j<16; j++) 
						fprintf(stderr,"   ");
					for(j=0;j<offset%16;j++) 
						if(isprint(buffer[16*i+j])) 
							fprintf(stderr,"%c",buffer[16*i+j]);
						else 
							fprintf(stderr,".");
					fprintf(stderr,"\n");
				};
	
			};
			cifa=cifa->next;
		};  /* all interfaces done */
		if(once) return 0;
		sleep(timeout);
	};
	return 0;
};
