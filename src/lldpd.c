#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "libnet.h"


int
usage ()
{
	printf("Usage: lldp -i iface [-t time] [-oh]\n");
	printf("-i iface	: Interface to send announcements\n");
	printf("-t time		: period between lldp announcements\n");
	printf("-o		: run once - send a packet on each interface and exit\n");
	printf("-h		: this help message\n");
	printf("\nlldp by David Williamson\n");
	return 0;
};

int 
lldp_encode_tlv(unsigned char* buf, unsigned tlv, unsigned tlen, 
        unsigned char* data)
{ 
        buf[0]=(tlv<<1)|(tlen>>8);
        buf[1]=(tlen&0xff);
        if(tlen) { 
                memcpy(buf+2,data,tlen);
        };
        return tlen+2;
};

int
tlv0(unsigned char* buf, unsigned size)
{
	if(size<2)
		return 0;
	return lldp_encode_tlv(buf,0,0,NULL);
};

int
tlv1 (unsigned char* buf, unsigned size, char* myip4)
{
	unsigned char intname[128];

	intname[0]=7;
	strlcpy((char*)intname+1,myip4,sizeof(intname)-1);

	return lldp_encode_tlv(buf,1,strlen(myip4)+1,intname);
};

int
tlv2 (unsigned char* buf, unsigned size, char* ifname)
{
        unsigned char hname[128];

        hname[0]=7;
        strlcpy((char*)hname+1,ifname,sizeof(hname)-1);
        if(strlen(ifname)+3>size) 
                return 0;

        return lldp_encode_tlv(buf,2,strlen(ifname)+1,hname);
};

int
tlv3 (unsigned char* buf, unsigned size, unsigned ttl)
{
	u_int16_t tt=htons(ttl);
	
	if (size<4) return 0;

	return lldp_encode_tlv(buf,3,2,(unsigned char*)&tt);
};

int
tlv4 (unsigned char* buf, unsigned size, char* ifname)
{
        return lldp_encode_tlv(buf,4,strlen(ifname),ifname);
};

int
tlv5 (unsigned char* buf, unsigned size, char* fqdn)
{
	return lldp_encode_tlv(buf,5,strlen(fqdn),fqdn);
};

int
tlv7 (unsigned char* buf, unsigned size)
{
	unsigned char cap[4];

	cap[0]=0x00;
	cap[1]=0x80;
	cap[2]=0x00;
	cap[3]=0x80;

	return lldp_encode_tlv(buf,7,4,cap);
};

int
main(int argc, char* argv[])
{ 
        char c;
        int timeout=60;
        int once=0;
	int len;
	int offset=0;
	libnet_t *l;
	libnet_ptag_t t=0;
	char errbuf[LIBNET_ERRBUF_SIZE];
	unsigned char payload[1600];
	struct libnet_ether_addr *hwaddr;
	int i=0;
	int numdevices=0;
	char *devlist[6];
	
	u_int8_t *enet_src;
	u_int8_t *enet_dst = libnet_hex_aton("01:80:c2:00:00:0e", &len);
	u_int16_t protocolId = 0x88cc;

	/*
	 * Initialize the device array
	 */
	for (i = 0; i <= 5; i++)
	{
		devlist[i]="";
	}

	/*
	 * Deal with command line options
	 */
	i=0;
        while((c=getopt(argc,argv,"i:t:ho"))!=EOF) { 
        switch(c) { 
		case 'i': devlist[i]=optarg;
			  i++;
			break;
                case 't': timeout=atoi(optarg);
                        if(timeout<=0) { 
                                printf("Illegal timeout value, reverting to default of 60s\n");
                                timeout=60;
                        };
                        break;
                case 'o': once=1;
                        break;
                default: usage();
                        exit(1);
        	};
        };
	numdevices = i;
	numdevices--;

	/*
	 * Run as a daemon unless told not to
	 */
	if (!once) 
		daemon(0,0);

	/*
	 * Check for devices to use
	 */
	if (devlist[0]=="") 
	{
		fprintf(stderr, "No devices to use - exiting\n");
		exit(1);
	}

/*	for (i = 0; i <= numdevices; i++)
	{
		printf("interface: %s\n", devlist[i]);
	}; */
	while (1) 
	{ 
		for (i = 0; i <= numdevices; i++)
		{

			/*
			 *  Initialize the library.  Root priviledges are required.
			 */
			l = libnet_init(
				LIBNET_LINK,                            /* injection type */
				devlist[i],                             /* network interface */
				errbuf);                                /* errbuf */
	
			if (l == NULL)
			{   
				fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
				exit(EXIT_FAILURE);
			}

			/*
			 * Get MAC addr of interface
			 */
			hwaddr = libnet_get_hwaddr (l);
			enet_src = (u_int8_t *) hwaddr;

			/*
			 * Build the payload
			 */
			offset+=tlv1(payload,sizeof(payload),libnet_addr2name4(libnet_get_ipaddr4(l),LIBNET_DONT_RESOLVE));
			offset+=tlv2(payload+offset,sizeof(payload)-offset,devlist[i]);
			offset+=tlv3(payload+offset,sizeof(payload)-offset,timeout*3);
			offset+=tlv4(payload+offset,sizeof(payload)-offset,devlist[i]);
			offset+=tlv5(payload+offset,sizeof(payload)-offset,libnet_addr2name4(libnet_get_ipaddr4(l),LIBNET_RESOLVE));
			offset+=tlv7(payload+offset,sizeof(payload)-offset);
			offset+=tlv0(payload+offset,sizeof(payload)-offset);
	
			/* 
			 * Build the ethernet frame
			 */
			t = libnet_build_ethernet(
				enet_dst,				/* that might be correct */
				enet_src,				/* is that? */
				protocolId,				/* that's correct, at least */
				payload,				/* payload! */
				offset,					/* compute the length */
				l,					/* context */
				0);					/* ptag */
	
			if (t == -1)
			{   
				fprintf(stderr, "Failed to build ethernet frame %s\n", libnet_geterror (l));
				exit(EXIT_FAILURE);
			}
	
			/*
			 * Send it!
			 */
			if ((libnet_write (l)) == -1)
			{
				fprintf (stderr, "Unable to send packet: %s\n", libnet_geterror (l));
				exit (1);
			}

			/* 
			 * All done with this packet, 
			 * so kill it
			 */
			libnet_destroy(l);
		};
		if (once) return 0;
		sleep(timeout);
	};

};
