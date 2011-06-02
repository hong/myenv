/*
gcc test-netwiz.c eth-linux.c -I libpcap -I dnet -I snmp-lite -L./libpcap -L./snmp-lite -lpcap -lsnmp-lite-x86 -o netwiz-discovery
arm-none-linux-gnueabi-gcc test-netwiz.c eth-linux.c -I libpcap -I dnet -I snmp-lite -L./libpcap -L./snmp-lite -lpcap-arm -lsnmp-lite-arm -o netwiz-discovery
*/
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>

#include <assert.h>

#include "pcap.h"
#include "dnet.h"
#include "snmp-lite.h"

/*************************************************/
#define V300_RAWMAC_SIZE         (8)

#define IS_END_NODE(pNode)       (NULL == pNode ? 0 : (2 == pNode->snmp_scaned && 2 == pNode->ping_scaned))

typedef struct _machineNode {
	char ip[4];
	char mac[6];
	char machineName[32];
	char workgroupName[32];
	char attribute[64];
	char snmp_scaned;	/* 0: Not scaned yet; 1: Scan successfully; -1: Scan failed */
	char ping_scaned;
	struct _machineNode *next;
} machineNode;

typedef struct _networkNode {
	char ip[4];
	struct _networkNode *next;
} networkNode;

/*************************************************/

/************global variable**********************/
machineNode *m_pRootNode = NULL;
networkNode *m_pNetworkNode = NULL;

unsigned int m_nDevicesFound = 0;
unsigned int m_nNetworksFound = 0;

unsigned int m_ulTxFrames_prev = 0;
unsigned int m_ulRxFrames_prev = 0;
unsigned int m_ulRxErrors_prev = 0;

unsigned int m_ulTxFrames = 0;
unsigned int m_ulRxFrames = 0;
unsigned int m_ulRxErrors = 0;

char m_localMAC[18];
char m_localIP[16];
char m_localDEV[10];

const char *msg_eol = "\n";
const char *applet_name = "netwiz-discovery";
/*************************************************/

/*************************************************/
#define TIMEVAL_SUBTRACT(a,b) (((a).tv_sec - (b).tv_sec) * 1000000 + (a).tv_usec - (b).tv_usec)

ssize_t safe_write(int fd, const void *buf, size_t count)
{   
    ssize_t n;
    
    do {
        n = write(fd, buf, count);
    } while (n < 0 && errno == EINTR);
        
    return n;
}

/*  
 * Write all of the supplied buffer out to a file.
 * This does multiple writes as necessary.
 * Returns the amount written, or -1 on an error.
 */
ssize_t full_write(int fd, const void *buf, size_t len)
{
    ssize_t cc;
    ssize_t total;
    
    total = 0;
        
    while (len) {
        cc = safe_write(fd, buf, len);
    
        if (cc < 0) {
            if (total) {
                /* we already wrote some! */
                /* user can do another write to know the error code */
                return total;
            }
            return cc;  /* write() returns -1 on failure. */
        }

        total += cc;
        buf = ((const char *)buf) + cc;
        len -= cc;
    }

    return total;
}

void *xrealloc(void *ptr, size_t size)
{
    ptr = realloc(ptr, size);
    if (ptr == NULL && size != 0)
		exit(-1);
    return ptr;
}

static void __bb_veexinc_msg(const char *s, va_list p, const char* strerr);
void retweet(const char *s, ...)
{
	va_list p;

	va_start(p, s);
	__bb_veexinc_msg(s, p, NULL);
	va_end(p);
}

void __bb_veexinc_msg(const char *s, va_list p, const char* strerr)
{
	char *msg;
	int applet_len, strerr_len, msgeol_len, used;

	if (!s) /* nomsg[_and_die] uses NULL fmt */
		s = ""; /* some libc don't like retweet(NULL) */

	used = vasprintf(&msg, s, p);
	if (used < 0)
		return;

	applet_len = strlen(applet_name) + 2; /* "applet: " */
	strerr_len = strerr ? strlen(strerr) : 0;
	msgeol_len = strlen(msg_eol);
	/* +3 is for ": " before strerr and for terminating NUL */
	msg = xrealloc(msg, applet_len + used + strerr_len + msgeol_len + 3);
	/* TODO: maybe use writev instead of memmoving? Need full_writev? */
	memmove(msg + applet_len, msg, used);
	used += applet_len;
	strcpy(msg, applet_name);
	msg[applet_len - 2] = ':';
	msg[applet_len - 1] = ' ';
	if (strerr) {
		if (s[0]) { /* not perror_nomsg? */
			msg[used++] = ':';
			msg[used++] = ' ';
		}
		strcpy(&msg[used], strerr);
		used += strerr_len;
	}
	strcpy(&msg[used], msg_eol);

	fflush(stdout);
	full_write(1, msg, used + msgeol_len);
	free(msg);
}

static char etht_cache_device_name[64];
static eth_t *etht_cache_device = NULL;

int Strncpy(char *dest, const char *src, size_t n)
{
	strncpy(dest, src, n);

	if (dest[n - 1] == '\0')
		return 0;

	dest[n - 1] = '\0';
	return -1;
}

////////////////////////////////////////////////////
// Functions implementation for the ARP protocol
////////////////////////////////////////////////////
void set_pcap_filter(const char *device, pcap_t * pd, char *bpf, ...)
{
	va_list ap;
	char buf[128];

	struct bpf_program fcode;

	unsigned int localnet, netmask;
	char err0r[256];

	// Cast below is because OpenBSD apparently has a version that takes a
	// non-const device (hopefully they don't actually write to it).
	if (pcap_lookupnet((char *) device, &localnet, &netmask, err0r) <
	    0)
		retweet
		    ("Failed to lookup subnet/netmask for device (%s): %s",
		     device, err0r);

	va_start(ap, bpf);
	if (vsnprintf(buf, sizeof(buf), bpf, ap) >= (int) sizeof(buf))
		retweet
		    ("set_pcap_filter called with too-large filter arg");
	va_end(ap);
	//retweet( "Packet capture filter (device %s): %s", device, buf );

	if (pcap_compile(pd, &fcode, buf, 0, netmask) < 0)
		retweet("Error compiling our pcap filter: %s",
		       pcap_geterr(pd));

	if (pcap_setfilter(pd, &fcode) < 0)
		retweet("Failed to set the pcap filter: %s",
		       pcap_geterr(pd));

	pcap_freecode(&fcode);
}

pcap_t *my_pcap_open_live(const char *device, int snaplen, int promisc,
			  int to_ms)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pt = NULL;
	char pcapdev[64];

	Strncpy(pcapdev, device, sizeof(pcapdev));

	pt = pcap_open_live(device, snaplen, promisc, to_ms, errbuf);
	if (!pt) {
		retweet
		    ("Call to pcap_open_live(%s, %d, %d, %d) failed. Reported error: %s",
		     device, snaplen, promisc, to_ms, errbuf);
		return NULL;
	}

	return pt;
}

/* Call this instead of pcap_get_selectable_fd directly (or your code
won't compile on Windows).  On systems which don't seem to support
the pcap_get_selectable_fd() function properly, returns -1,
otherwise simply calls pcap_selectable_fd and returns the
results.  If you just want to test whether the function is supported,
use pcap_selectable_fd_valid() instead. */
int my_pcap_get_selectable_fd(pcap_t * p)
{
	return pcap_get_selectable_fd(p);
}

/* Attempts to read one IPv4/Ethernet ARP reply packet from the pcap
descriptor pd.  If it receives one, fills in sendermac (must pass
in 6 bytes), senderIP, and rcvdtime (can be NULL if you don't care)
and returns 1.  If it times out and reads no arp requests, returns
0.  to_usec is the timeout period in microseconds.  Use 0 to avoid
blocking to the extent possible.  Returns
-1 or exits if ther is an error. */
int read_arp_reply_pcap(pcap_t * pd,
			unsigned char *sendermac,
			struct in_addr *senderIP, long to_usec)
{
	int datalink;
	struct pcap_pkthdr head;
	unsigned char *p;
	int badcounter = 0;
	struct timeval sel_tv;
	int timedout = 0;
	int pcap_descriptor = -1;

	if (!pd) {
		retweet
		    ("NULL packet device passed to read_arp_reply_pcap(...)");
		return -1;
	}

	/* New packet capture device, need to recompute offset */
	if ((datalink = pcap_datalink(pd)) < 0) {
		retweet("Cannot obtain datalink information: %s",
		       pcap_geterr(pd));
		return -1;
	}

	if (datalink != DLT_EN10MB) {
		retweet
		    ("readarp_reply_pcap called on interfaces that is datatype %d rather than DLT_EN10MB (%d)",
		     datalink, DLT_EN10MB);
		retweet("sorry, only ethernet supported");
		return -1;
	}

	/* set timeout */
	if (to_usec < 0)
		to_usec = 0;

	do {
		pcap_descriptor = my_pcap_get_selectable_fd(pd);

		if (-1 != pcap_descriptor) {
			fd_set rfds;
			int rv = 0;

			FD_ZERO(&rfds);
			FD_SET(pcap_descriptor, &rfds);

			sel_tv.tv_sec = to_usec / 1000000;
			sel_tv.tv_usec = to_usec % 1000000;

			rv = select(pcap_descriptor + 1, &rfds, NULL, NULL,
				    &sel_tv);
			if (rv < 0) {
				retweet
				    ("my_pcap_get_selectable_fd time out, rv=%d",
				     rv);
			} else if (rv == 0) {
				timedout = 1;
			} else {
				p = NULL;
				p = (unsigned char *) pcap_next(pd, &head);
			}
		} else {
			// THIS CALL CAN BLOCK INAPPROPRIATLEY! (ie, will block until it sees another
			// packet - to_usec notwithstanding) Use the select() code if possible.
			p = NULL;
			p = (unsigned char *) pcap_next(pd, &head);
		}

		if (p && head.caplen >= 42) {
			/* >= because Ethernet padding makes 60 */
			/* frame type 0x0806 (arp), hw type eth (0x0001), 
			   prot ip (0x0800), hw size (0x06), prot size (0x04) */
			if (memcmp
			    (p + 12,
			     "\x08\x06\x00\x01\x08\x00\x06\x04\x00\x02",
			     10) == 0) {
				memcpy(sendermac, p + 22, 6);
				memcpy(&senderIP->s_addr, p + 28, 4);

#ifdef DEBUG
				unsigned char *pMAC = p + 22;
				unsigned char *pIP = p + 28;
				retweet
				    ("Get ARP reply from IP: %u.%u.%u.%u, MAC: %02X-%02X-%02X-%02X-%02X-%02X",
				     pIP[0], pIP[1], pIP[2], pIP[3],
				     pMAC[0], pMAC[1], pMAC[2], pMAC[3],
				     pMAC[4], pMAC[5]);
#endif
				break;
			}
		} else {
			/* We'll be a bit patient if we're getting actual packets back, but not indefinitely so */
			badcounter += 1;

			if (badcounter > 50)
				timedout = 1;
		}
	} while (!timedout);

	if (timedout)
		return 0;

	return 1;
}

/* A simple function that caches the eth_t from dnet for one device,
to avoid opening, closing, and re-opening it thousands of tims.  If
you give a different device, this function will close the first
one.  Thus this should never be used by programs that need to deal
with multiple devices at once.  In addition, you MUST NEVER
eth_close() A DEVICE OBTAINED FROM THIS FUNCTION.  Instead, you can
call eth_close_cached() to close whichever device (if any) is
cached.  Returns NULL if it fails to open the device. */
eth_t *eth_open_cached(const char *device)
{
	if (!device || !*device) {
		retweet("eth_open called with NULL or empty device name!");
	}

	if (0 == strcmp(device, etht_cache_device_name)) {
		/* OK, we have it cached */
		return etht_cache_device;
	}

	if (*etht_cache_device_name) {
		eth_close(etht_cache_device);
		etht_cache_device_name[0] = '\0';
		etht_cache_device = NULL;
	}

	etht_cache_device = eth_open(device);
	if (etht_cache_device) {
		Strncpy(etht_cache_device_name, device,
			sizeof(etht_cache_device_name));
	}

	return etht_cache_device;
}

/* See the description for eth_open_cached */
void eth_close_cached()
{
	if (etht_cache_device) {
		eth_close(etht_cache_device);
		etht_cache_device = NULL;
		etht_cache_device_name[0] = '\0';
	}

	return;
}

int arp(char *dev, pcap_t * pd, eth_t * ethsd, int nSpeedMode,
	unsigned long usrcip, const unsigned char *srcmac,
	unsigned long utargetip, unsigned char *targetmac)
{
	int foundit = 0;

	/* timeouts in microseconds ... the first ones are retransmit times, while 
	   the final one is when we give up */
	int timeouts[4];
	int max_sends = 3;
	int num_sends = 0;	// How many we have sent so far

	struct timeval start, now;
	int timeleft = 0;
	int listenrounds = 0;
	int rc;

	unsigned char frame[ETH_HDR_LEN + ARP_HDR_LEN + ARP_ETHIP_LEN];

	struct in_addr rcvdIP;

	bzero(timeouts, sizeof(int) * 4);

	if (nSpeedMode == 2) {
		max_sends = 2;
		timeouts[0] = 100000;
		timeouts[1] = 200000;
	} else if (nSpeedMode == 3) {
		max_sends = 3;
		timeouts[0] = 100000;
		timeouts[1] = 200000;
		timeouts[2] = 400000;
	} else if (nSpeedMode == 4) {
		max_sends = 4;
		timeouts[0] = 100000;
		timeouts[1] = 200000;
		timeouts[2] = 400000;
		timeouts[3] = 800000;
	}

	struct sockaddr_in srcip;
	bzero(&srcip, sizeof(srcip));
	srcip.sin_family = AF_INET;
	srcip.sin_addr.s_addr = htonl(usrcip);

	struct sockaddr_in targetip;
	bzero(&targetip, sizeof(targetip));
	targetip.sin_family = AF_INET;
	targetip.sin_addr.s_addr = htonl(utargetip);

	set_pcap_filter(dev, pd,
			"arp and ether dst host %02X:%02X:%02X:%02X:%02X:%02X",
			srcmac[0], srcmac[1], srcmac[2], srcmac[3],
			srcmac[4], srcmac[5]);

	eth_pack_hdr(frame, ETH_ADDR_BROADCAST, *srcmac, ETH_TYPE_ARP);
	arp_pack_hdr_ethip(frame + ETH_HDR_LEN, ARP_OP_REQUEST, *srcmac,
			   srcip.sin_addr, ETH_ADDR_BROADCAST,
			   targetip.sin_addr);

	gettimeofday(&start, NULL);

	while (!foundit && (num_sends < max_sends)) {
#ifdef DEBUG
		retweet("send the sucker...");
#endif
		/* Send the sucker */
		rc = eth_send(ethsd, frame, sizeof(frame));
#ifdef DEBUG
		if (rc != sizeof(frame)) {
			retweet
			    ("WARNING: eth_send of ARP packet returned %u rather than expected %d bytes",
			     rc, (int) sizeof(frame));
		}
#endif

		num_sends++;

		listenrounds = 0;

		while (!foundit) {
			gettimeofday(&now, NULL);
			timeleft =
			    timeouts[num_sends - 1] - TIMEVAL_SUBTRACT(now,
								       start);
			if (timeleft < 0) {
				if (listenrounds > 0)
					break;
				else
					timeleft = 25000;
			}

			listenrounds++;

			/* Now listen until we reach our next timeout or get an answer */
			rc = read_arp_reply_pcap(pd, targetmac, &rcvdIP,
						 timeleft);
			if (rc == -1) {
				retweet
				    ("Received -1 response from readarp_reply_pcap");
			} else if (rc == 1) {
				/* OK, I got one! But is it the right one? */
				if (rcvdIP.s_addr !=
				    targetip.sin_addr.s_addr)
					continue;	/* Oh, NO! */

				foundit = 1;	/* WOOHOO! */
			}
		}
	}

#ifdef DEBUG
	retweet("arp done! foundit=%d", foundit);
#endif

	return foundit;
}

/*************************************************/

#define NETWIZ_LINE_MAXBUFSIZE      32
#define PACKET_SIZE       4096
#define ERROR             0
#define SUCCESS           1

#define NODE_FLAGS_GROUP(np)	 ((np)->flags & 0x8000)
#define NODE_RECORD_SIZE    18

#ifndef TRUE
#  define TRUE  1
#  define FALSE 0
#endif

long Str2Long(const char *pBuf)
{
	long lRet = 0;
	char buf[NETWIZ_LINE_MAXBUFSIZE] = "";

	int i = 0, j = 0;
	while ('\0' != pBuf[i]) {
		if (pBuf[i] >= '0' && pBuf[i] <= '9') {
			buf[j++] = pBuf[i];
		}

		i++;
	}
	buf[j] = '\0';

	lRet = (long) atoi(buf);

	return lRet;
}

void display_nodes(machineNode *root)
{
	unsigned char ip[4];
	unsigned char targetmac[6];
	machineNode *curr = root->next;
	unsigned count = 0;

	while (curr && !IS_END_NODE(curr)) {
		memcpy(ip, curr->ip, 4);
		memcpy(targetmac, curr->mac, 6);
		retweet("stat> No=%d, IP=%u.%u.%u.%u, MAC=%02X:%02X:%02X:%02X:%02X:%02X, Ping=%d, MachineName=%s, WorkgroupName=%s, Attribute=%s, Devices=%u, Networks=%u, TxFrames=%lu, RxFrames=%lu, RxErrors=%lu",
			 count,
		     ip[0], ip[1], ip[2], ip[3], targetmac[0],
		     targetmac[1], targetmac[2], targetmac[3],
		     targetmac[4], targetmac[5], curr->ping_scaned,
		     (curr->machineName[0]=='\0'?"N/A":curr->machineName), 
			 (curr->workgroupName[0]=='\0'?"N/A":curr->workgroupName),
		     (curr->attribute[0]=='\0'?"N/A":curr->attribute), 
			 m_nDevicesFound, m_nNetworksFound,
		     m_ulTxFrames, m_ulRxFrames, m_ulRxErrors);

		count++;
		curr = curr->next;
	}
}

machineNode *AddNewHost(machineNode * tail, unsigned long ulIP,
			unsigned char *ucMacArr)
{
#ifdef DEBUG
	retweet("AddNewHost() start, ulIP=%ld", ulIP);
#endif
	if (NULL == tail)
		return NULL;

	// Insert new host into the hosts list
	m_nDevicesFound++;

	machineNode *prev = tail;
	machineNode *curr = (machineNode *) malloc(sizeof(machineNode));
	memset(curr->ip, 0, 4);
	memset(curr->mac, 0, 6);
	memcpy(curr->ip, (char *) &ulIP, 4);
	if (NULL != ucMacArr)
		memcpy(curr->mac, ucMacArr, 6);
	bzero(&curr->machineName, sizeof(curr->machineName));
	bzero(&curr->workgroupName, sizeof(curr->workgroupName));
	bzero(&curr->attribute, sizeof(curr->attribute));
	curr->snmp_scaned = 0;
	curr->ping_scaned = 0;
	curr->next = NULL;
	prev->next = curr;

	// Find a new networks ?
	if (NULL == m_pNetworkNode) {
		m_pNetworkNode =
		    (networkNode *) calloc(1, sizeof(networkNode));
		memcpy(m_pNetworkNode->ip, curr->ip, 4);
		m_pNetworkNode->next = NULL;

		m_nNetworksFound = 1;
	} else {
		networkNode *pPrevNode = NULL;

		networkNode *pNode = m_pNetworkNode;
		while (pNode) {
			if (pNode->ip[0] == curr->ip[0]
			    && pNode->ip[1] == curr->ip[1]
			    && pNode->ip[2] == curr->ip[2]) {
				break;
			}

			pPrevNode = pNode;
			pNode = pPrevNode->next;
		}

		if (NULL == pNode) {
			m_nNetworksFound++;

			networkNode *pNewNode =
			    (networkNode *) malloc(sizeof(networkNode));
			memcpy(pNewNode->ip, curr->ip, 4);
			pNewNode->next = NULL;

			pPrevNode->next = pNewNode;
		}
	}

#ifdef DEBUG
	retweet("AddNewHost() done. curr=%p", curr);
#endif
	return curr;
}

void AddEndNode(machineNode * tail)
{
	if (NULL == tail)
		return;

	machineNode *prev = tail;

	machineNode *curr = (machineNode *) malloc(sizeof(machineNode));
	memset(curr->ip, 0, 4);
	memset(curr->mac, 0, 6);
	bzero(&curr->machineName, sizeof(curr->machineName));
	bzero(&curr->workgroupName, sizeof(curr->workgroupName));
	bzero(&curr->attribute, sizeof(curr->attribute));
	curr->snmp_scaned = 2;
	curr->ping_scaned = 2;
	curr->next = NULL;

	prev->next = curr;

	return;
}

unsigned short cal_chksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up the occasional odd byte */
	if (nleft == 1) {
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);	/* add carry */
	answer = ~sum;		/* ones-complement, trunc to 16 bits */

	return answer;
}

int ping_broadcast(unsigned long ipstart, unsigned long ipstop)
{
	struct timeval timeo;
	int sockfd;
	unsigned long ulIPFound = 0;
	struct sockaddr_in addr = { htonl(INADDR_ANY) };
	struct sockaddr_in from = { htonl(INADDR_ANY) };

	struct timeval *tval;
	struct ip *iph;
	struct icmp *icmp;

	char sendpacket[PACKET_SIZE];
	char recvpacket[PACKET_SIZE];

	int n;
	pid_t pid;
	int maxfds = 0;
	fd_set readfds;

	/* create a socket to send out the icmp echo message */
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockfd < 0) {
		retweet("socket error");
		return ERROR;
	}

	/* set timeout */
	int timeout = 5000;
	timeo.tv_sec = timeout / 1000;
	timeo.tv_usec = timeout % 1000;
	if (setsockopt
	    (sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeo,
	     sizeof(timeo)) == -1) {
		retweet("setsockopt error");
		return ERROR;
	}

	/* permit sending of broadcast msgs */
	int broadcast = 1;
	if (setsockopt
	    (sockfd, SOL_SOCKET, SO_BROADCAST, (char *) &broadcast,
	     sizeof(broadcast)) == -1) {
		retweet("setsockopt error");
		return ERROR;
	}

	/* construct the icmp header */
	memset(sendpacket, 0, sizeof(sendpacket));

	pid = getpid();

	int packsize = 0;
	icmp = (struct icmp *) sendpacket;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_cksum = 0;
	icmp->icmp_seq = 0;
	//icmp->icmp_id=(short)(getpid()&0xffff);
	icmp->icmp_id = pid;
	packsize = 8 + 56;
	tval = (struct timeval *) icmp->icmp_data;
	gettimeofday(tval, NULL);
	icmp->icmp_cksum = cal_chksum((unsigned short *) icmp, packsize);

	/* Bcast address */
	inet_aton("255.255.255.255", &addr.sin_addr);

	/* send ICMP packet */
	n = sendto(sockfd, (char *) &sendpacket, packsize, 0,
		   (struct sockaddr *) &addr, sizeof(addr));
	if (n < 1) {
		retweet("sendto error");
		return ERROR;
	}

	/* receive */
	/* because other ping response may be receive, so here to use the cycle */
	while (1) {
		/* set timeout, this is the real role */
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		maxfds = sockfd + 1;
		n = select(maxfds, &readfds, NULL, NULL, &timeo);
		if (n <= 0) {
			/* timeout */
			close(sockfd);
			return ERROR;
		}

		/* receive */
		memset(recvpacket, 0, sizeof(recvpacket));
		int fromlen = sizeof(from);
		n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0,
			     (struct sockaddr *) &from,
			     (socklen_t *) & fromlen);
		if (n < 0) {
			break;
		}

		/* check response whether is my reply */
		/*
		   char *from_ip = (char *)inet_ntoa(from.sin_addr);
		   retweet("fomr ip:%s", from_ip);
		   if (strcmp(from.sin_addr, ips) != 0) {
		   retweet("ip:%s,Ip wang",ips);
		   break;
		   }
		 */

		iph = (struct ip *) recvpacket;

		icmp = (struct icmp *) (recvpacket + (iph->ip_hl << 2));

#ifdef DEBUG
		retweet("icmp->icmp_type:%d,icmp->icmp_id:%d",
			icmp->icmp_type, icmp->icmp_id);
#endif

		/* check ping reply packet status */
		if (icmp->icmp_type == ICMP_ECHOREPLY
		    && icmp->icmp_id == pid) {
			ulIPFound = (unsigned long) from.sin_addr.s_addr;
			if ((ipstart <= ulIPFound)
			    && (ulIPFound <= ipstop)) {
				/* if status is OK then exit this loop */
				break;
			}
		} else {
			/* or continue wait */
			continue;
		}
	}

	/* close socket */
	close(sockfd);

	return ulIPFound;
}

int ping(const char *targetip)
{
	struct timeval timeo;
	int sockfd;
	struct sockaddr_in addr;
	struct sockaddr_in from;

	struct timeval *tval;
	struct ip *iph;
	struct icmp *icmp;

	char sendpacket[PACKET_SIZE];
	char recvpacket[PACKET_SIZE];

	int n;
	pid_t pid;
	int maxfds = 0;
	fd_set readfds;

#ifdef DEBUG
	retweet("targetip %d.%d.%d.%d",
	       (unsigned char) targetip[0], (unsigned char) targetip[1],
	       (unsigned char) targetip[2], (unsigned char) targetip[3]);
#endif

	unsigned long uTargetIP =
	    (targetip[0] << 24) + (targetip[1] << 16) +
	    (targetip[2] << 8) + targetip[3];

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(uTargetIP);

	/* create a socket to send out the icmp echo message */
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockfd < 0) {
		retweet("socket error");
		return ERROR;
	}

	/* Wait up to five seconds. */
	timeo.tv_sec = 5;
	timeo.tv_usec = 0;

    /* bind this socket to this device */
    setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, m_localDEV, strlen(m_localDEV));

	if (setsockopt
	    (sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeo,
	     sizeof(timeo)) == -1) {
		retweet("setsockopt error");
		close(sockfd);
		return ERROR;
	}

	/* construct the icmp header */
	memset(sendpacket, 0, sizeof(sendpacket));

	pid = getpid();

	int packsize = 0;
	icmp = (struct icmp *) sendpacket;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_cksum = 0;
	icmp->icmp_seq = 0;
	//icmp->icmp_id=(short)(getpid()&0xffff);
	icmp->icmp_id = pid;
	packsize = 8 + 56;
	tval = (struct timeval *) icmp->icmp_data;
	gettimeofday(tval, NULL);
	icmp->icmp_cksum = cal_chksum((unsigned short *) icmp, packsize);

	/* send ICMP packet */
	n = sendto(sockfd, (char *) &sendpacket, packsize, 0,
		   (struct sockaddr *) &addr, sizeof(addr));
	if (n < 1) {
		retweet("sendto error");
		close(sockfd);
		return ERROR;
	}

	/* receive */
	/* because other ping response may be receive, so here to use the cycle */
	while (1) {
		/* set timeout, this is the real role */
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		maxfds = sockfd + 1;
		n = select(maxfds, &readfds, NULL, NULL, &timeo);
		if (n <= 0) {
			retweet("ping timeout");
			close(sockfd);
			return ERROR;
		}

		/* receive */
		memset(recvpacket, 0, sizeof(recvpacket));
		int fromlen = sizeof(from);
		n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0,
			     (struct sockaddr *) &from,
			     (socklen_t *) & fromlen);
		if (n < 0) {
			break;
		}

		/* check response whether is my reply */
		/*
		   char *from_ip = (char *)inet_ntoa(from.sin_addr);
		   retweet("fomr ip:%s",from_ip);
		   if (strcmp(from.sin_addr, ips) != 0) {
		   retweet("ip:%s,Ip wang",ips);
		   break;
		   }
		 */

		iph = (struct ip *) recvpacket;

		icmp = (struct icmp *) (recvpacket + (iph->ip_hl << 2));

#ifdef DEBUG
		retweet("icmp->icmp_type:%d,icmp->icmp_id:%d",
			icmp->icmp_type, icmp->icmp_id);
#endif

		/* check ping reply packet status */
		if (icmp->icmp_type == ICMP_ECHOREPLY
		    && icmp->icmp_id == pid) {
			/* if status is OK then exit this loop */
			break;
		} else {
			/* or continue wait */
			continue;
		}
	}

	/* close socket */
	close(sockfd);

	return SUCCESS;
}

#define NETWIZ_PIPE_MSGBUFSIZE     512
#define NETWIZ_LINE_MAXBUFSIZE     32

static int msg_len = 0;
static int msg_off = 0;

int ifconfig_proc(const char *msg, int len)
{
	char buf[NETWIZ_LINE_MAXBUFSIZE] = "";
	int nLen = 0;
	char *tmp1 = NULL;
	char *tmp2 = NULL;

/*
    pNetWiz->m_pSummaryRet->uDevicesFound  = pNetWiz->m_nDevicesFound;
    pNetWiz->m_pSummaryRet->uNetworksFound = pNetWiz->m_nNetworksFound;
*/

	if (NULL != (tmp1 = strstr(msg, "TX packets:"))) {
		if (NULL != (tmp2 = strstr(tmp1, "errors:"))) {
			nLen = tmp2 - (tmp1 + strlen("TX packets:"));
			if (nLen > NETWIZ_LINE_MAXBUFSIZE - 1)
				nLen = NETWIZ_LINE_MAXBUFSIZE - 1;

			memcpy(buf, tmp1 + strlen("TX packets:"), nLen);
			buf[nLen] = 0;

			//pNetWiz->m_pSummaryRet->ulTxFrames = Str2Long( buf );
#ifdef DEBUG
			retweet("ulTxFrames=%s", buf);
#endif
			m_ulTxFrames = Str2Long(buf);

			if (NULL != (tmp1 = strstr(tmp2, "dropped:"))) {
				nLen = tmp1 - (tmp2 + strlen("errors:"));
				if (nLen > NETWIZ_LINE_MAXBUFSIZE - 1)
					nLen = NETWIZ_LINE_MAXBUFSIZE - 1;

				memcpy(buf, tmp2 + strlen("errors:"),
				       nLen);
				buf[nLen] = 0;

				//pNetWiz->m_pSummaryRet->ulTxFrames += Str2Long( buf );
#ifdef DEBUG
				retweet("ulTxFrames=%s", buf);
#endif
				m_ulTxFrames += Str2Long(buf);
			}
		}
	} else if (NULL != (tmp1 = strstr(msg, "RX packets:"))) {
		if (NULL != (tmp2 = strstr(tmp1, "errors:"))) {
			nLen = tmp2 - (tmp1 + strlen("RX packets:"));
			if (nLen > NETWIZ_LINE_MAXBUFSIZE - 1)
				nLen = NETWIZ_LINE_MAXBUFSIZE - 1;

			memcpy(buf, tmp1 + strlen("RX packets:"), nLen);
			buf[nLen] = 0;

			//pNetWiz->m_pSummaryRet->ulRxFrames = Str2Long( buf );
#ifdef DEBUG
			retweet("ulRxFrames=%s", buf);
#endif
			m_ulRxFrames = Str2Long(buf);

			if (NULL != (tmp1 = strstr(tmp2, "dropped:"))) {
				nLen = tmp1 - (tmp2 + strlen("errors:"));
				if (nLen > NETWIZ_LINE_MAXBUFSIZE - 1)
					nLen = NETWIZ_LINE_MAXBUFSIZE - 1;

				memcpy(buf, tmp2 + strlen("errors:"),
				       nLen);
				buf[nLen] = 0;

				//pNetWiz->m_pSummaryRet->ulRxErrors = Str2Long( buf );
#ifdef DEBUG
				retweet("ulRxErrors=%s", buf);
#endif
				m_ulRxErrors = Str2Long(buf);
			}
		}
	}

	return 0;
}

int ProcPipe_ifconfig(FILE * pPipeHandle, unsigned char *msg_buf)
{
	int ret = 0, out_len = 0;

	if (pPipeHandle == NULL)
		return -1;

	/* Read iptools output to buffer */
	do {
		int nLen = 0;
		unsigned char *pBuf = NULL;

	      read_from_file:
		/* Move valid data in message buffer from tail to start if necessary */
		if (msg_len == NETWIZ_PIPE_MSGBUFSIZE) {
			/* Move valid data from tail to start */
			unsigned char *src = &msg_buf[msg_off],
			    *dst = &msg_buf[0],
			    *end = &msg_buf[NETWIZ_PIPE_MSGBUFSIZE];
			for (; src < end; src++, dst++)
				*dst = *src;
			/* Reposition valid data offset and length */
			msg_off = 0;
			msg_len = dst - msg_buf;
		}

		/* Read new data from file to buffer */
		if (msg_len < NETWIZ_PIPE_MSGBUFSIZE) {
			int new_len =
			    read(fileno(pPipeHandle), &msg_buf[msg_len],
				 NETWIZ_PIPE_MSGBUFSIZE - msg_len);
#ifdef DEBUG
			retweet("Read %d bytes from pipe", new_len);
#endif
			new_len = (new_len < 0 ? 0 : new_len);
			out_len += new_len;
			msg_len += new_len;
#ifdef DEBUG
			retweet
			    ("msg_off = %d, msg_len = %d, out_len = %d",
			     msg_off, msg_len, out_len);
#endif
		}

		/* Quit if no data available */
		if (msg_off == msg_len)
			break;

	      proc_next_line:
		/* Check wether there are a line of buffer, if available process it */
		nLen = 0;
		pBuf = &msg_buf[msg_off];
		for (; msg_off < msg_len; msg_off++) {
#ifdef DEBUG
			retweet("%c", msg_buf[msg_off]);
#endif
			if ((msg_buf[msg_off] != '\n')
			    && (msg_buf[msg_off] != '\r')) {
				nLen++;
			} else {
				/* Skip '\n' */
				msg_buf[msg_off] = 0;
				msg_off++;

				ret +=
				    ifconfig_proc((const char *) pBuf,
						  nLen) == 0 ? 1 : 0;
				goto proc_next_line;
			}
		}

		/* No further complete line available, reverse ses->msg_off to valid buffer start */
		msg_off = pBuf - msg_buf;

		if (msg_len < NETWIZ_PIPE_MSGBUFSIZE)
			break;

		/* Skip the whole buffer if there are no '\n' in the whole buffer */
		if (msg_off == 0)
			msg_len = 0;

		goto read_from_file;

	} while (0);

	if (0 == out_len)
		ret = -1;

	return ret;
}

/*------------------------------------------------------------------------
 * When processing a NETBIOS node status response, we receive an array of
 * name structures of this form. The name is up to 15 chars, and is sadly
 * not NUL-byte terminated -- sorry.
 *
 * NOTE: the size of the record is exactly the size of the struct members,
 * and does NOT include any padding that C provides for us automatically.
 * It is important to use the NODE_RECORD_SIZE macro when stepping through
 * the array.
 */
struct node_name_record {
	char name[15];
	char type;
	unsigned short flags;	/* in host byte order */
};

/*------------------------------------------------------------------------
 * When we get a NBTSTAT response, the tail end contains a big block of
 * statistics. These are all in network word order, and we shuffle them
 * around before storing them in the user space.
 *  
 * The definitions of the fields are taken from RFC1002.
 *
 * ===NOTE: the size of this struct must be 46 bytes and does NOT
 *  include the C padding that is normally expected. Be careful!
 */
#define NODE_STATS_SIZE 46
/*768 = struct member not referenced */
/*lint -esym(768, NODE_statistics::jumpers, NODE_statistics::test_result) */

struct NODE_statistics {
	unsigned char uniqueid[6];	/* Ethernet address */

	unsigned char jumpers;
	unsigned char test_result;

	unsigned short version_number;
	unsigned short period_of_statistics;
	unsigned short number_of_crcs;
	unsigned short number_alignment_errors;
	unsigned short number_of_collisions;
	unsigned short number_send_aborts;
	unsigned long number_good_sends;
	unsigned long number_good_receives;
	unsigned short number_retransmits;
	unsigned short number_no_resource_conditions;
	unsigned short number_free_command_blocks;
	unsigned short total_number_command_blocks;
	unsigned short max_total_number_command_blocks;
	unsigned short number_pending_sessions;
	unsigned short max_number_pending_sessions;
	unsigned short max_total_sessions_possible;
	unsigned short session_data_packet_size;
};

#define TBLSIZE(t)      (int) (sizeof(t) / sizeof((t)[0]))

/*------------------------------------------------------------------------
 * The overall packets sent and received from the other end are all of
 * the form like this. Unfortunately the "data" part of the packet is
 * variable and that takes the most work to get right. The header is
 * more or less fixed though...
 */
struct NMBpacket {
	/* HEADER */

	unsigned short tranid;	/* transaction ID */
	unsigned short flags;	/* various flags */
	unsigned short qdcount;	/* query count */
	unsigned short ancount;	/* answer count */
	unsigned short nscount;
	unsigned short arcount;

	char data[1024];
};

/*------------------------------------------------------------------------
 * When talking to the other end, we maintain this information about the
 * NETBIOS information.
 */
struct NMB_query_response {

	struct sockaddr_in remote;	/* IP address   */

	char domain[15 + 1];	/* printable    */
	char computer[15 + 1];	/* printable    */
	char ether[20];		/* printable    */
	char user[32];		/* printable    */

	int sharing;		/* sharing on?  */
	int has_IIS;		/* MS IIS?      */
	int has_Exchange;	/* MS Exchange  */
	int has_Notes;		/* Lotus notes  */
	int has_RAS;		/* Rmt Access   */
	int is_dc;		/* domain ctlr? */

	int has_unknown;	/* any unknown? */

	struct NODE_statistics nodestats;	/* full info    */

	/*----------------------------------------------------------------
	 * This is information about all the nodes that we can gather
	 * from the other end. These are taken directly from the NODE_NAME
	 * array, but >these< ones are formatted for easy printing.
	 */
	struct nodeinfo {
		char name[15 + 1];	/* NUL-terminated!   */
		char type;	/* type code         */
		unsigned short flags;	/* host byte order   */
		const char *svcname;	/* long name            */
	} nodes[100];

	int nnodes;
	int nametrunc;
};

static int timeout_secs = 2, write_sleep_msecs = 10;

void sleep_msecs(long msecs)
{
	if (msecs <= 0)
		return;
#if defined(M_XENIX)
	napms(msecs);
#else
	usleep(msecs * 1000);	/* microseconds! */
#endif
}

struct timeval *timeval_set_secs(struct timeval *tv, int secs)
{
	assert(tv != 0);

	tv->tv_sec = secs;
	tv->tv_usec = 0;

	return tv;
}

#define	FIXSHORT(x)		( (x) = ntohs(x) )
#define	FIXLONG(x)		( (x) = ntohl(x) )

void byteswap_nodestats(struct NODE_statistics *p)
{
	assert(p != 0);

	FIXSHORT(p->version_number);
	FIXSHORT(p->period_of_statistics);
	FIXSHORT(p->number_of_crcs);
	FIXSHORT(p->number_alignment_errors);
	FIXSHORT(p->number_of_collisions);
	FIXSHORT(p->number_send_aborts);
	FIXLONG(p->number_good_sends);
	FIXLONG(p->number_good_receives);
	FIXSHORT(p->number_retransmits);
	FIXSHORT(p->number_no_resource_conditions);
	FIXSHORT(p->number_free_command_blocks);
	FIXSHORT(p->total_number_command_blocks);
	FIXSHORT(p->max_total_number_command_blocks);
	FIXSHORT(p->number_pending_sessions);
	FIXSHORT(p->max_number_pending_sessions);
	FIXSHORT(p->max_total_sessions_possible);
	FIXSHORT(p->session_data_packet_size);
}
size_t nstrcpy(char *dst, const char *src)
{
	const char *dst_save = dst;

	assert(dst != 0);
	assert(src != 0);

	while ((*dst = *src++) != 0)
		dst++;

	return (size_t) (dst - dst_save);
}

char *strip(char *str)
{
	char *old = str;	/* save ptr to original string          */
	char *lnsp = 0;		/* ptr to last non-space in string      */

	assert(str != 0);

	for (; *str; str++)
		if (!isspace(*str))
			lnsp = str;
	if (lnsp)
		lnsp[1] = '\0';
	else
		*old = '\0';

	return old;
}

/*          
 * ip_to_name()
 *
 *  Given an IP address for a remote, look up its inverse name
 *  via the DNS. Return is the number of bytes in the looked-up
 *  name, or 0 if not found.
 */
int ip_to_name(unsigned long ipaddr, char *obuf, int osize)
{
	struct in_addr addr;
	struct hostent *hp;

	assert(obuf != 0);
	assert(osize > 1);

	addr.s_addr = ipaddr;

	--osize;		/* allow room for terminating NUL */

	if ((hp =
	     gethostbyaddr((char *) &addr, sizeof addr, AF_INET)) == 0)
		return 0;

	if (hp->h_name == 0)
		return 0;

	strncpy(obuf, hp->h_name, (unsigned int) osize)[osize] = '\0';

	return (int) strlen(obuf);
}

#define		UNIQUE		0x000
#define		XGROUP		0x100

const char *NETBIOS_name(const struct nodeinfo *np)
{
	int unique;
	int swvalue;

	assert(np != 0);

	unique = !!NODE_FLAGS_GROUP(np);

	swvalue = (unique << 8) | (0xFF & np->type);

	switch (swvalue) {
	case UNIQUE | 0x01:
		return "Messenger Service<1>";
	case UNIQUE | 0x03:
		return "Messenger Service<3>";
	case UNIQUE | 0x06:
		return "RAS Server Service";
	case UNIQUE | 0x1F:
		return "NetDDE Service";
	case UNIQUE | 0x1B:
		return "Domain Master Browser";
	case UNIQUE | 0x1D:
		return "Master Browser";
	case UNIQUE | 0x20:
		return "File Server Service";
	case UNIQUE | 0x21:
		return "RAS Client Service";
	case UNIQUE | 0x22:
		return "MS Exchange Interchange";
	case UNIQUE | 0x23:
		return "MS Exchange Store";
	case UNIQUE | 0x24:
		return "MS Exchange Directory";
	case UNIQUE | 0x87:
		return "MS Exchange MTA";
	case UNIQUE | 0x6A:
		return "MS Exchange IMC";
	case UNIQUE | 0xBE:
		return "Network Monitor Agent";
	case UNIQUE | 0xBF:
		return "Network Monitor Application";
	case UNIQUE | 0x30:
		return "Modem Sharing Server Service";
	case UNIQUE | 0x31:
		return "Modem Sharing Client Service";
	case UNIQUE | 0x43:
		return "SMS Clients Remote Control";
	case UNIQUE | 0x44:
		return "SMS Admin Remote Control Tool";
	case UNIQUE | 0x45:
		return "SMS Clients Remote Chat";
	case UNIQUE | 0x46:
		return "SMS Clients Remote Transfer";
	case UNIQUE | 0x52:
		return "DEC Pathworks TCP svc";

	case XGROUP | 0x00:
		return "Domain Name";
	case XGROUP | 0x01:
		return "Master Browser";
	case XGROUP | 0x1E:
		return "Browser Service Elections";


	case XGROUP | 0x42:
		if (strcmp(np->name, "MLI_GROUP_BRAD") == 0)
			return "Dr. Solomon AV Management";
		break;

	case UNIQUE | 0x42:
		if (strncmp(np->name, "MLI", 3) == 0)
			return "Dr. Solomon AV Management";
		break;

	case XGROUP | 0x1C:
		if (strcmp(np->name, "INet~Services") == 0)
			return "IIS";
		else
			return "Domain Controller";

	case UNIQUE | 0x00:
		if (strncmp(np->name, "IS~", 3) == 0)
			return "IIS";
		else
			return "Workstation Service";

	default:
		return 0;
	}

	return 0;
}
char *NETBIOS_fixname(char *buf)
{
	char *buf_save = buf;

	assert(buf != 0);

	for (; *buf; buf++) {
		if (!isprint(*buf))
			*buf = '.';
	}

	return strip(buf_save);
}

void process_response(struct NMB_query_response *rsp)
{
	int i;

	assert(rsp != 0);

	rsp->computer[0] = '\0';
	rsp->domain[0] = '\0';
	rsp->user[0] = '\0';
	rsp->has_RAS = FALSE;
	rsp->is_dc = FALSE;
	rsp->sharing = FALSE;
	rsp->has_unknown = FALSE;

	for (i = 0; i < rsp->nnodes; i++) {
		struct nodeinfo *ni = &rsp->nodes[i];
		int isgroup = NODE_FLAGS_GROUP(ni);
		int t = ni->type;

		/*--------------------------------------------------------
		 * Look up the printable NETBIOS resource name and stick
		 * it into the local node buffer. This is NULL if not
		 * known, and we mark us as having some unknown ones: this
		 * might help us research the new stuff.
		 */
		if ((ni->svcname = NETBIOS_name(ni)) == 0)
			rsp->has_unknown++;

		/*--------------------------------------------------------
		 * A GROUP node <00> is the domain name, and this is not
		 * always found if this is a workgroup environment with
		 * no domain controller.
		 */
		if (rsp->domain[0] == '\0') {
			if (isgroup && (t == 0x00)) {
				strcpy(rsp->domain, ni->name);
			}
		}

		/*--------------------------------------------------------
		 * Look for the computer name. This is always a UNIQUE name,
		 * and we think it's always first.
		 */
		if (rsp->computer[0] == '\0' && !isgroup) {
			switch (t) {
			/*------------------------------------------------
			 * Unique type <00> is either "IIS" or "Workstation
			 * Service" depending on whether we have the IS~
			 * part at the beginning.
			 */
			case 0x00:
				if (strncmp(ni->name, "IS~", 3) != 0)
					strcpy(rsp->computer, ni->name);
				break;

			case 0x06:	/* RAS Client Service           */
			case 0x01:	/* Messenger Service (uncommon) */
			case 0x1F:	/* NetDDE service               */
			case 0x20:	/* File sharing service         */
			case 0x2B:	/* Lotus Notes Server Service   */
				strcpy(rsp->computer, ni->name);
				break;

			default:
				/*nothing */
				break;
			}

		}

		/*--------------------------------------------------------
                 * Sharing is on if the File Server Service is published,
                 * and this is noticed with a unique type of <20>.
                 */
		if (!isgroup && (t == 0x20))
			rsp->sharing = TRUE;

		/*--------------------------------------------------------
		 * UNIQUE<06> seems to be RAS, which indicates modems?
		 */
		if (!isgroup && (t == 0x06)) {
			rsp->has_RAS = TRUE;
		}

		/*--------------------------------------------------------
		 * It seems that being a domain controller and running IIS
		 * are pretty similar. If the token is <1C> and the name
		 * matches the domain name, it's a domain controller.
		 */
		if (isgroup && (t == 0x1C)) {
			if (strcmp(ni->name, "INet~Services") == 0)
				rsp->has_IIS = TRUE;
			else if (strcmp(ni->name, rsp->domain) == 0)
				rsp->is_dc = TRUE;
		}

		/*--------------------------------------------------------
		 * We've observed that UNIQUE<87> and UNIQUE<6A> are MS
		 * Exchange, but we don't remember how we got that.
		 */
		if (!isgroup && (t == 0x87 || t == 0x6A)) {
			rsp->has_Exchange = TRUE;
		}

		if (!isgroup && (t == 0x2B)) {
			rsp->has_Notes = TRUE;
		}

		/*--------------------------------------------------------
		 * If this is messenger service for something other than
		 * the computer name, this is probably a user.
		 */
		if (!isgroup && (t == 0x03)) {
			if (strcmp(ni->name, rsp->computer) != 0)
				strcpy(rsp->user, ni->name);
		}
	}

	NETBIOS_fixname(rsp->domain);
	NETBIOS_fixname(rsp->computer);
}

/*
 * getshort()
 *
 *	Given a handle to a pointer to two bytes, fetch it as an unsigned short
 *	in network order and convert to host order. We advance the pointer.
 */
static unsigned short getshort(const char **p)
{
	unsigned short s;

	assert(p != 0);
	assert(*p != 0);

	memcpy(&s, *p, 2);

	*p += 2;

	return ntohs(s);
}

int NETBIOS_unpack(const char **ibuf, char *obuf, int osize)
{
	int isize;
	char *obuf_save, *obuf_max;
	const char *ibuf_save;

	assert(ibuf != 0);
	assert(*ibuf != 0);
	assert(obuf != 0);
	assert(osize > 0);

	ibuf_save = *ibuf;
	obuf_save = obuf;

	/*----------------------------------------------------------------
	 * The length in bytes of the "compressed" name must be even, as
	 * each final character is made of two input bytes. If the size
	 * is odd, it's just a bogus input.
	 *
	 * Then make sure the # of bytes will for sure fit in the output.
	 */
	isize = *(*ibuf)++;

	if ((isize % 2) != 0) {
		/* must be even length */
		return -1;
	}

	if ((isize /= 2) > osize) {
		/* output buffer not big enough */
		return -2;
	}

	obuf_max = obuf + isize;

	while (obuf < obuf_max) {
		unsigned int c1 = (unsigned int) (*(*ibuf)++ - 'A'),
		    c2 = (unsigned int) (*(*ibuf)++ - 'A');

		if (c1 > 15 || c2 > 15)
			return -3;

		*obuf++ = (char) ((c1 << 4) | c2);
	}

	*obuf = '\0';

	/* round up to even word boundary */
	if ((*ibuf - ibuf_save) % 2)
		++ * ibuf;

	return (int) (obuf - obuf_save);
}

void display_nbtstat(const struct NMB_query_response *rsp, int full)
{
	int no_inverse_lookup = FALSE;
	char reportbuf[256], *p = reportbuf;
	char computername[32];

	assert(rsp != 0);

	/*----------------------------------------------------------------
	 * The full name is DOMAIN\MACHINE, but some systems have no names
	 * at all (don't know why), so we display them in a special format.
	 * Not sure what this means...
	 */
	if (rsp->domain[0] == '\0' && rsp->computer[0] == '\0')
		sprintf(computername, "-no name-");
	else
		sprintf(computername, "%s\\%s",
			rsp->domain, rsp->computer);

	p += sprintf(p, "%-15s %-31s", inet_ntoa(rsp->remote.sin_addr),	/* IP address           */
		     computername);	/* DOMAIN\COMPUTER      */

/* delete by hong
	if ( show_mac_address && ! full )
	{
		*p++ = ' ';
		p += nstrcpy(p, rsp->ether);
	}
*/

	if (rsp->sharing)
		p += nstrcpy(p, " SHARING");
	if (rsp->is_dc)
		p += nstrcpy(p, " DC");
	if (rsp->has_IIS)
		p += nstrcpy(p, " IIS");
	if (rsp->has_Exchange)
		p += nstrcpy(p, " EXCHANGE");
	if (rsp->has_Notes)
		p += nstrcpy(p, " NOTES");
	if (rsp->has_RAS)
		p += nstrcpy(p, " RAS");
	if (rsp->has_unknown)
		p += nstrcpy(p, " ?");

	/*----------------------------------------------------------------
	 * If we have a user, display it after a U= token. But we put quotes
	 * around it if the user name contains any spaces. This is kind of
	 * a crock.
	 */
	if (rsp->user[0]) {
		const char *quote = (strchr(rsp->user, ' ') == 0)
		    ? "" : "\"";

		p += sprintf(p, " U=%s%s%s", quote, rsp->user, quote);
	}

	*p++ = '\n';
	*p = '\0';

	retweet(reportbuf);

	if (full) {
		char dnsbuf[132];
		char dispbuf[256];
#if 0
		int i;

		for (i = 0; i < rsp->nnodes; i++) {
			const struct nodeinfo *ni = &rsp->nodes[i];
			int isgroup = NODE_FLAGS_GROUP(ni);
			char namebuf[16];
			const char *svcname = ni->svcname;

			if (svcname == 0)
				svcname = "-unknown-";

			NETBIOS_fixname(strcpy(namebuf, ni->name));

			retweet(ofp, "  %-15s<%02x> %s %s\n",
				namebuf,
				0xFF & ni->type,
				isgroup ? "GROUP " : "UNIQUE", svcname);
		}
#endif

		if (no_inverse_lookup
		    || ip_to_name(rsp->remote.sin_addr.s_addr,
				  dnsbuf, sizeof dnsbuf) == 0) {
			dnsbuf[0] = '\0';
		}
		// strip trailing white from this line :-(
		sprintf(dispbuf, "  %s   ETHER  %s", rsp->ether, dnsbuf);

		strip(dispbuf);
/*
		retweet(ofp, "%s\n\n", dispbuf);
*/
	}
}

int parse_nbtstat(const struct NMBpacket *pak, int paklen,
		  struct NMB_query_response *rsp, char *errbuf)
{
	const char *p, *pmax, *nmax, *pstats;
	int rdlength, remaining, nnames;
	int qtype,		/* query type (always "NBSTAT")         */
	 qclass;		/* query class (always "IN")            */
	char tmpbuf[256];	/* random buffer                        */

	assert(pak != 0);
	assert(rsp != 0);
	assert(paklen > 0);
	assert(errbuf != 0);

	memset(rsp, 0, sizeof *rsp);

	/*----------------------------------------------------------------
	 * Set up our initial pointers into the received record. We are
	 * trying to be very careful about not running away with our
	 * memory, so we set a pointer to the very end of the valid part
	 * of the data from the other end, and we try to never look past
	 * this.
	 *
	 *   +-----------------------------------------------------------+
	 *   | headers |        response data                            |
	 *   +-----------------------------------------------------------+
	 *    ^--pak    ^--p                                         pmax-^
	 *
	 * Note that we do >nothing< with the headers, but probably should
	 * (to verify that there is actually an answer?).
	 */
	pmax = paklen + (char *) pak;
	p = pak->data;

	/*----------------------------------------------------------------
	 * The first thing we should see is the "question" section, which
	 * should simply echo what we gave them. Parse this out to skip
	 * past it. We decode it only for the benefit of the debugging
	 * code.
	 */
	NETBIOS_unpack(&p, tmpbuf, sizeof tmpbuf);

	qtype = getshort(&p);	/* question type        */
	qclass = getshort(&p);	/* question class       */

#if 0
	retweet(" QUESTION SECTION:\n");
	retweet("   name  = \"%s\"\n", tmpbuf);
#endif

	p += 4;			/* skip past TTL (always zero)  */

	/*----------------------------------------------------------------
	 * Fetch the length of the rest of this packet and make sure that
	 * we actually have this much room left. If we don't, we must have
	 * gotten a short UDP packet and won't be able to finish off this
	 * processing. The max size is ~~500 bytes or so.
	 */
	rdlength = getshort(&p);

	remaining = (int) (pmax - p);

	if (rdlength > remaining) {
		retweet(" ERROR: rdlength = %d, remaining bytes = %d",
		       rdlength, remaining);
		return -1;
	}

	/*----------------------------------------------------------------
	 * Fetch the number of names to be found in the rest of this node
	 * object. Sometimes we get >zero< and it's not clear why this is.
	 * Perhaps it means that there is no NETBIOS nameserver running
	 * but it will answer status requests. Hmmm.
	 */
	nnames = *(unsigned char *) p;
	p++;

#if 0
	retweet(" NODE COUNT = %d\n", nnames);
#endif

	if (nnames < 0) {
		sprintf(errbuf, "bad NETBIOS response (count=%d)", nnames);
		return FALSE;
	}

	pstats = p + (nnames * NODE_RECORD_SIZE);

	if (nnames > TBLSIZE(rsp->nodes)) {
		nnames = TBLSIZE(rsp->nodes);

		rsp->nametrunc = TRUE;
	}

	nmax = p + (nnames * NODE_RECORD_SIZE);

	for (; p < nmax; p += NODE_RECORD_SIZE) {
		struct node_name_record nr;
		struct nodeinfo *ni = &rsp->nodes[rsp->nnodes++];

		/* Solaris has alignment problems, gotta copy */
		memcpy(&nr, p, NODE_RECORD_SIZE);

		ni->flags = ntohs(nr.flags);
		ni->type = nr.type;

		strncpy(ni->name, nr.name, 15)[15] = '\0';

		strip(ni->name);
	}

	/*----------------------------------------------------------------
	 * Now we've finished processing the node information and gathered
	 * up everything we can find, so now look for the statistics. We
	 * ONLY try to gather these stats if there is actually any room
	 * left in our buffer.
	 */
	if ((int) (pmax - pstats) >= NODE_STATS_SIZE) {
		memcpy(&rsp->nodestats, pstats, NODE_STATS_SIZE);

		byteswap_nodestats(&rsp->nodestats);

		sprintf(rsp->ether, "%02x:%02x:%02x:%02x:%02x:%02x",
			rsp->nodestats.uniqueid[0],
			rsp->nodestats.uniqueid[1],
			rsp->nodestats.uniqueid[2],
			rsp->nodestats.uniqueid[3],
			rsp->nodestats.uniqueid[4],
			rsp->nodestats.uniqueid[5]);
	}

	/* postprocessing for good measure */
	process_response(rsp);

	return TRUE;
}

/*
 * NETBIOS_raw_pack_name()
 *
 *	Given a buffer containing a name plus a size, encode it in
 *	the usual NETBIOS way. The length is encoded as the number of
 *	output bytes (input bytes times two), and we return the total
 *	bytes placed in the output buffer.
 *
 *	We do put a NUL byte at the end of the output buffer, but
 *	this is a courtesy and it's not counted in the returned
 *	length.
 */
int NETBIOS_raw_pack_name(const char *ibuf, int isize, char *obuf)
{
	char *obuf_save = obuf;

	assert(ibuf != 0);
	assert(obuf != 0);

	*obuf++ = (char) (isize * 2);

	while (isize-- > 0) {
		unsigned int c = *(unsigned char *) ibuf;

		*obuf++ = (char) ('A' + ((c >> 4) & 0x0F));
		*obuf++ = (char) ('A' + (c & 0x0F));

		ibuf++;
	}
	*obuf = '\0';

	return (int) (obuf - obuf_save);
}

int NETBIOS_pack_name(const char *ibuf, int itype, char *obuf)
{
	char tempbuf[16 + 1];

	assert(ibuf != 0);
	assert(obuf != 0);

	/*----------------------------------------------------------------
	 * Preformat the name to be the format that we require for a
	 * normal NETBIOS name. The usual rule is 15 characters of 
	 * name (space padded) with a type code at the end. The special
	 * case of the name "*" is passed literally to the output
	 * buffer with NUL byte padding instead of spaces.
	 *
	 * +---------------------------------------------------------------+
	 * |*  | \0| \0| \0| \0| \0| \0| \0| \0| \0| \0| \0| \0| \0| \0| \0|
	 * +---------------------------------------------------------------+
	 *
	 * |                                                               |
	 * |<------------------------ 16 bytes --------------------------->|
	 * |                                                               |
	 *
	 * +---------------------------------------------------------------+
	 * |*  | S | M | B | S | E | R | V | E | R | sp| sp| sp| sp| sp| TT|
	 * +---------------------------------------------------------------+
	 *
	 * where "TT" is the type desired.
	 */
	if (ibuf[0] == '*' && ibuf[1] == '\0') {
		memset(tempbuf, 0, sizeof tempbuf);
		tempbuf[0] = '*';
	} else {
		sprintf(tempbuf, "%-15.15s%c", ibuf, itype);
	}

	return NETBIOS_raw_pack_name(tempbuf, 16, obuf);
}

/*
 * fill_namerequest()
 *
 *	HACK: this creates a hand-crafter NMB packet that requests
 *	the NBTSTAT information. This was learned by sniffing a
 *	real transactions, and though we've learned what most of this
 *	means, we've not yet gone back to generalize it properly.
 *	We probably will.
 */
static void fill_namerequest(struct NMBpacket *pak, int *len, short seq)
{
	char *pbuf;

	assert(pak != 0);
	assert(len != 0);

	*len = 50;

	memset(pak, 0, *len);

	/* POPULATE THE HEADER */

	pak->tranid = htons(seq);	/* transaction ID */
	pak->flags = 0;
	pak->qdcount = htons(1);	/* query count */
	pak->ancount = 0;
	pak->nscount = 0;
	pak->arcount = 0;

#if 0
	pak->flags |= htons(0x0010);	/* broadcast */
#endif

	/*----------------------------------------------------------------
	 * Encode the NETBIOS name, which is really just a "*" that's
	 * fully padded out. Then add the status and name class at the
	 * end.
	 */
	pbuf = pak->data;

	pbuf += NETBIOS_pack_name("*", 0, pbuf);
	*pbuf++ = 0x00;		/* length of next segment */

	*pbuf++ = 0x00;		/* NODE STATUS */
	*pbuf++ = 0x21;

	*pbuf++ = 0x00;		/* IN */
	*pbuf++ = 0x01;
}

unsigned long host2ip(char *serv)
{
	struct sockaddr_in sinn;
	struct hostent *hent;

	hent = gethostbyname(serv);
	if (hent == NULL)
		return 0;
	bzero((char *) &sinn, sizeof(sinn));
	memcpy((char *) &sinn.sin_addr, hent->h_addr, hent->h_length);
	return sinn.sin_addr.s_addr;
}

int netbios(u_long ip, char *machine, char *workgroup)
{
	struct sockaddr_in sin_src;
	int sockfd = 0;

	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd < 0) {
		retweet("ERROR: cannot create socket");
		return -1;
	}

    /* bind this socket to this device */
    setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, m_localDEV, strlen(m_localDEV));

	/*---------------------------------------------------------------
     * Bind the local endpoint to receive our responses. If we use a
     * zero, the system will pick one for us, or we can pick our own
     * if we wish to make it easier to get past our firewall.
     */
	memset(&sin_src, 0, sizeof(sin_src));

	sin_src.sin_family = AF_INET;
	sin_src.sin_addr.s_addr = htonl(INADDR_ANY);
	sin_src.sin_port = htons(0);
	if (bind(sockfd, (struct sockaddr *) &sin_src, sizeof(sin_src)) ==
	    (-1)) {
		retweet("ERROR: cannot bind to local socket");
        close(sockfd);
		return -1;
	}


	/* query names */
	int have_next_addr = FALSE;
	int npending = 0;
	struct in_addr next_addr;
	char errbuf[256];

    /*----------------------------------------------------------------
     * Figure out our starting and ending addresses to be scanning.
     * These are treated as simple long integers that are incremented
     * on each loop, and we must have at least one loop to be valid.
     */

	have_next_addr = TRUE;
	next_addr.s_addr = ip;

	while (have_next_addr ||
	       /*
	          ((have_next_addr = next_target(&next_addr)) != 0) ||
	        */
	       (npending > 0)) {
		fd_set rfds;	/* list of read descriptors */
		fd_set wfds;	/* list of write descriptors */
		fd_set *pwfds = 0;
		int n;
		struct timeval tv;

	/*--------------------------------------------------------
         * Our select is just a bit tricky. We always are waiting
         * on the read channel, but we only want to wait on the
         * write channel if there are any more addresses in our
         * list to process. After we've sent all the packets to
         * the other end, we stop writing and do only reading.
         */
		FD_ZERO(&rfds);
		FD_SET(sockfd, &rfds);

		timeval_set_secs(&tv, timeout_secs);

		if (have_next_addr) {
			wfds = rfds;
			pwfds = &wfds;
		}

		if ((n = select(sockfd + 1, &rfds, pwfds, 0, &tv)) == 0) {
			retweet("[NETBIOS] *timeout (normal end of scan)");
			break;
		} else if (n < 0) {
			retweet("[NETBIOS] ERROR select()");
			break;
		}

	/*--------------------------------------------------------
         * Has the read descriptor fired?
         */
		if (n > 0 && FD_ISSET(sockfd, &rfds)) {
			int paklen;
			struct sockaddr_in src;
			struct NMBpacket pak;
			struct NMB_query_response rsp;

			memset(&src, 0, sizeof src);
			memset(&rsp, 0, sizeof rsp);

			int fromlen = sizeof(src);
			paklen =
			    recvfrom(sockfd, &pak, sizeof(pak), 0,
				     (struct sockaddr *) &src,
				     (socklen_t *) & fromlen);
			if (paklen < 0) {
				retweet("[NETBIOS] Error on read");
			} else {
#ifdef DEBUG
				retweet("[NETBIOS] Got %d bytes from %s",
				       paklen, inet_ntoa(src.sin_addr));
#endif
			}

			if (paklen <= 0)
				continue;

			npending--;

			if (parse_nbtstat(&pak, paklen, &rsp, errbuf)) {
				rsp.remote = src;
				/*
				   if ( target_responded(&rsp.remote.sin_addr) )
				   {
				   display_nbtstat(&rsp, full_nbtstat);
				   }
				 */
				/*display_nbtstat(&rsp, FALSE); */
				// Add by hong
				strcpy(machine, rsp.computer);
				strcpy(workgroup, rsp.domain);
			} else {
				retweet
				    ("[NETBIOS] ERROR: no parse for %s -- %s",
				     inet_ntoa(src.sin_addr), errbuf);
			}
		}

	/*--------------------------------------------------------
         * If we have room to write one packet, do so here. Note
         * that we make not notice whether the write succeeds or
         * not: we don't care.
         */
		if (n > 0 && pwfds && FD_ISSET(sockfd, pwfds)) {
			struct sockaddr_in dst;
			struct NMBpacket pak;
			int sendlen;

			memset(&dst, 0, sizeof dst);

			dst.sin_family = AF_INET;
			dst.sin_addr.s_addr = next_addr.s_addr;
			dst.sin_port = htons(137);

			short seq = 1000;

			have_next_addr = FALSE;

			fill_namerequest(&pak, &sendlen, seq++);

#ifdef DEBUG
			retweet("sending to %s", inet_ntoa(dst.sin_addr));
#endif

			/* yes, ignore response! */
			sendto(sockfd, &pak, sendlen, 0,
			       (struct sockaddr *) &dst,
			       sizeof(struct sockaddr_in));

			if (write_sleep_msecs > 0)
				sleep_msecs(write_sleep_msecs);

			npending++;

			continue;
		}
	}

    close(sockfd);
	return 0;
}

int ScanSummary()
{
	int nErr = 0;
	char command[64];
	FILE *pPipeHandle = NULL;
	unsigned char msg_buf[NETWIZ_PIPE_MSGBUFSIZE];
	int timeout = 50000;
	char tmp[10] = "";

	strcpy(tmp, m_localDEV);
	bzero(&command, sizeof(command));
	sprintf(command, "/sbin/ifconfig %s", strtok(tmp, ":"));
#ifdef DEBUG
	retweet("Pipe ifconfig command: %s", command);
#endif

	if ((pPipeHandle = popen(command, "r")) != NULL) {
		bzero(&msg_buf, sizeof(msg_buf));
		msg_len = 0;
		msg_off = 0;

		int select_max;
		fd_set select_set;
		struct timeval select_to;

		select_max = 0;
		FD_ZERO(&select_set);

		int fd = (pPipeHandle == NULL ? -1 : fileno(pPipeHandle));
		select_max = (fd > select_max ? fd : select_max);
		if (0 == select_max)
			return -1;

		FD_SET(fd, &select_set);
		select_to.tv_sec = timeout / 1000000;
		select_to.tv_usec = timeout % 1000000;

		/* Process output which have output by select */
		if (select(select_max + 1, &select_set, NULL, NULL,
		     &select_to) > 0) {
			if (FD_ISSET(fd, &select_set)) {
				nErr = ProcPipe_ifconfig(pPipeHandle, msg_buf);
			}
		}

		pclose(pPipeHandle);
		pPipeHandle = NULL;

		m_ulTxFrames -= m_ulTxFrames_prev;
		m_ulRxFrames -= m_ulRxFrames_prev;
		m_ulRxErrors -= m_ulRxErrors_prev;
	} else {
#ifdef DEBUG
		retweet("NetWizard ifconfig pipe created failed!");
#endif
	}

	return nErr;
}

int TestPing(machineNode * root)
{
	machineNode *pNode = NULL;
	int ret = 0;

	retweet("ping start");
	pNode = root->next;

	retweet("ping in progress");

	while (pNode && !IS_END_NODE(pNode)) {

		if (0 == pNode->ping_scaned) {
			/*pNode->ping_scaned = -1; */
			ret = ping(pNode->ip);
			if (ret == SUCCESS) {
				pNode->ping_scaned = 1;
#ifdef DEBUG
				retweet
				    ("Machine %d.%d.%d.%d is ping alive",
				     (unsigned char) pNode->ip[0],
				     (unsigned char) pNode->ip[1],
				     (unsigned char) pNode->ip[2],
				     (unsigned char) pNode->ip[3]);
#endif
			} else {
#ifdef DEBUG
				retweet
				    ("Ping machine %d.%d.%d.%d failed!",
				     (unsigned char) pNode->ip[0],
				     (unsigned char) pNode->ip[1],
				     (unsigned char) pNode->ip[2],
				     (unsigned char) pNode->ip[3]);
#endif
			}
		}

		pNode = pNode->next;
	}

	retweet("ping done");
	return 0;
}

int TestArp(unsigned long ipstart, unsigned long ipstop,
	    machineNode * root)
{
	int curip = 0;
	machineNode *curr = root;
	pcap_t *pd = NULL;
	eth_t *ethsd;
	int ret = 0;

#ifdef DEBUG
	retweet("IP scanning range = %d", ipstop - ipstart + 1);
#endif

	/***************for debug************/
	unsigned char srcmac[6];
	unsigned int buf[6];
	sscanf(m_localMAC, "%02X:%02X:%02X:%02X:%02X:%02X", buf, buf + 1,
	       buf + 2, buf + 3, buf + 4, buf + 5);
	srcmac[0] = (unsigned char) buf[0];
	srcmac[1] = (unsigned char) buf[1];
	srcmac[2] = (unsigned char) buf[2];
	srcmac[3] = (unsigned char) buf[3];
	srcmac[4] = (unsigned char) buf[4];
	srcmac[5] = (unsigned char) buf[5];

	struct in_addr tmp_addr = { htonl(INADDR_ANY) };
	inet_aton(m_localIP, &tmp_addr);
	unsigned long lVal = ntohl(tmp_addr.s_addr);
	/***************for debug************/

	retweet("arp start");

	/* start listening */
	if (!(pd = my_pcap_open_live(m_localDEV, 50, 1, 25))) {
		return -1;
	}

	/* Prepare probe and sending stuff */
	ethsd = eth_open_cached(m_localDEV);
	if (!ethsd) {
		retweet("failed to open device %s", m_localDEV);
		pcap_close(pd);
		return -1;
	}

	unsigned char targetmac[6];

	retweet("arp in progress");

	for (curip = ipstart; curip <= ipstop; curip++) {
		memset(&targetmac, 0, 6);
		ret = arp(m_localDEV, pd, ethsd, 2, lVal, srcmac, curip,
			targetmac);
		if (ret == 1) {
			curr = AddNewHost(curr, ntohl(curip), targetmac);
		}
	}

	AddEndNode(curr);	// Identify ARP scan has been finished

	/* OK - let's close up shop ... */
	pcap_close(pd);
	eth_close_cached();

	retweet("arp done");
	return 0;
}

void TestNetBios(machineNode * root)
{
	unsigned char ip[4];
	unsigned long uTargetIP = 0;
	machineNode *curr = NULL;
	int ret = 0;

	retweet("netbios start");
	curr = root->next;

	retweet("netbios in progress");

	while (curr && !IS_END_NODE(curr)) {
		memcpy(ip, curr->ip, 4);
		uTargetIP = (ip[0] << 24) + (ip[1] << 16) + (ip[2] << 8) + ip[3];
		ret = netbios(htonl(uTargetIP), curr->machineName, curr->workgroupName);

		curr = curr->next;
	}
	retweet("netbios done");
}

void TestSNMP(machineNode * root)
{
	int nErr = 0;
	machineNode *pNode = NULL;
	SNMPliteVal_list ValList;
	unsigned char cIPArr[4];
	char szDestIP[32];
	char *pOIDStrArr[1];
	char pOIDStr[32];
	strcpy(pOIDStr, "1.3.6.1.2.1");
	pOIDStrArr[0] = pOIDStr;

	bzero(&szDestIP, sizeof(szDestIP));

	retweet("snmp start");

	pNode = root->next;

	retweet("snmp in progress");

	while (pNode && !IS_END_NODE(pNode)) {
		if (0 == pNode->snmp_scaned) {
			pNode->snmp_scaned = -1;

			memcpy(cIPArr, pNode->ip, 4);
			sprintf(szDestIP, "%u.%u.%u.%u", cIPArr[0],
				cIPArr[1], cIPArr[2], cIPArr[3]);

			bzero(&ValList, sizeof(SNMPliteVal_list));
			nErr =
			    snmplite_Get(m_localIP, m_localDEV, szDestIP, 1, "public",
					 pOIDStrArr, 1, 300000, 1,
					 &ValList);
			if (nErr == 0) {
				pNode->snmp_scaned = 1;
				if ((ValList.root != NULL)
				    && (ValList.root->value.string !=
					NULL)) {
					/*
					int nLen =
					    strlen(ValList.root->value.
						   string);
					*/
					strncpy(pNode->attribute, ValList.root->value.string, \
							sizeof(pNode->attribute));
					/*pNode->attribute[nLen] = 0;*/
				}

				snmplite_ValFree(&ValList);
			}
#ifdef DEBUG
			retweet
			    ("[SNMP] SNMP request function error! Error code = %d",
			     nErr);
#endif
		}

		pNode = pNode->next;
	}  /* end of while */

	retweet("snmp done");
}

int TestBroadcastPing(unsigned long ipstart, unsigned long ipstop,
		      machineNode * root)
{
	machineNode *pNode = NULL;
	machineNode *curr = NULL;
	unsigned long ulIP = 0;
	char ip[4];
	int ret = 0;

	retweet("ping_broadcast start");
	retweet("ping_broadcast in progress");
	ulIP = ping_broadcast(ipstart, ipstop);
	if (ulIP == ERROR) {
		retweet("ping_broadcast error");
		return -1;
	}

	memcpy(ip, &ulIP, 4);
#ifdef DEBUG
	retweet("ip: %X.%X.%X.%X", ip[0], ip[1], ip[2], ip[3]);
#endif
	curr = root;
	pNode = root->next;
	while (pNode) {
		if (pNode->ip[0] == ip[0] && pNode->ip[1] == ip[1]
		    && pNode->ip[2] == ip[2] && pNode->ip[3] == ip[3])
			break;

		pNode = pNode->next;
	}

	if (NULL == pNode) {
		unsigned char targetmac[6];
		curr = AddNewHost(curr, ulIP, NULL);
		curr->ping_scaned = 1;
		memset(targetmac, 0, 6);

		pcap_t *pd = NULL;
		eth_t *ethsd;

		unsigned char srcmac[6];
		unsigned int buf[6];
		sscanf(m_localMAC, "%02X:%02X:%02X:%02X:%02X:%02X", buf,
		       buf + 1, buf + 2, buf + 3, buf + 4, buf + 5);
		srcmac[0] = (unsigned char) buf[0];
		srcmac[1] = (unsigned char) buf[1];
		srcmac[2] = (unsigned char) buf[2];
		srcmac[3] = (unsigned char) buf[3];
		srcmac[4] = (unsigned char) buf[4];
		srcmac[5] = (unsigned char) buf[5];

		struct in_addr tmp_addr = { htonl(INADDR_ANY) };
		inet_aton(m_localIP, &tmp_addr);
		unsigned long lVal = ntohl(tmp_addr.s_addr);

		/* start listening */
		if (!(pd = my_pcap_open_live(m_localDEV, 50, 1, 25))) {
			return -1;
		}

		/* Prepare probe and sending stuff */
		ethsd = eth_open_cached(m_localDEV);
		if (!ethsd) {
			/* failed to open device */
			retweet("ping_broadcast error");
			pcap_close(pd);
			return -1;
		}

		ret =
		    arp(m_localDEV, pd, ethsd, 2, lVal, srcmac, ulIP,
			targetmac);
		if (ret == 1)
			memcpy(curr->mac, targetmac, 6);
	}

	retweet("ping_broadcast done");
	return 0;
}

typedef enum {
	ePINGBC = 0,
	eARP = 1,
	eSNMP = 2,
	ePING = 4,
	eNETBOIS = 8
} eScanOption;

machineNode *discovery(unsigned int ipstart, unsigned int ipstop,
		       unsigned short wOption, machineNode * root)
{
	machineNode *curr = NULL;

#ifdef DEBUG
	struct timeval slmtv;
	struct timezone slmtz;
	gettimeofday(&slmtv, &slmtz);
	int slmsec = slmtv.tv_sec;
	int uslmsec = slmtv.tv_usec;

	retweet("IP scanning range = %u", ipstop - ipstart + 1);
#endif

	curr = root;

	m_ulTxFrames = m_ulRxFrames = m_ulRxErrors = 0;
	m_ulTxFrames_prev = m_ulRxFrames_prev = m_ulRxErrors_prev = 0;

	ScanSummary();

	m_ulTxFrames_prev = m_ulTxFrames;
	m_ulRxFrames_prev = m_ulRxFrames;
	m_ulRxErrors_prev = m_ulRxErrors;

	if (m_ulTxFrames_prev == 0)
	{
		ScanSummary();

		m_ulTxFrames_prev = m_ulTxFrames;
		m_ulRxFrames_prev = m_ulRxFrames;
		m_ulRxErrors_prev = m_ulRxErrors;
	}

	if ((wOption & eARP) != 0)
		TestArp(ipstart, ipstop, root);
	else
		TestBroadcastPing(ipstart, ipstop, root);

	if ((wOption & eSNMP) != 0)
		TestSNMP(root);

	if ((wOption & ePING) != 0)
		TestPing(root);

	if ((wOption & eNETBOIS) != 0)
		TestNetBios(root);

	ScanSummary();

#ifdef DEBUG
	gettimeofday(&slmtv, &slmtz);
	retweet("Time cost totally: sec = %d, usec = %d",
	       slmtv.tv_sec - slmsec, slmtv.tv_usec - uslmsec);
#endif

	return root;
}

int main(int argc, char *argv[])
{
	if (getuid() != 0) {
		retweet("%s: root privelidges needed",
			*(argv + 0));
		return -1;
	}

	if (argc != 7) {
		retweet("%s [dev] [localip] [localmac] [ip1] [ip2] [opt]",
			*(argv + 0));
		return -1;
	}

	/* retweet("argv[1]=%s, argv[2]=%s, argv[3]=%s, argv[4]=%s, argv[5]=%s, argv[6]=%s\n", argv[1], argv[2], argv[3], argv[4], argv[5], argv[6]); */

	unsigned short options = 0;
	unsigned int ipstart = 0;
	unsigned int ipstop = 0;
	struct in_addr tmp_addr = { htonl(INADDR_ANY) };

	bzero(&m_localDEV, sizeof(m_localDEV));
	bzero(&m_localIP, sizeof(m_localIP));
	bzero(&m_localMAC, sizeof(m_localMAC));

	strcpy(m_localDEV, argv[1]);
	strcpy(m_localIP, argv[2]);
	strcpy(m_localMAC, argv[3]);

	inet_aton(argv[4], &tmp_addr);
	ipstart = ntohl(tmp_addr.s_addr);
	inet_aton(argv[5], &tmp_addr);
	ipstop = ntohl(tmp_addr.s_addr);

	if (argv[6] != NULL)
		options = atoi(argv[6]);
	/*
	options |= 1;
	options |= 2;
	options |= 4;
	*/

	m_pRootNode = NULL;
	m_pNetworkNode = NULL;
	m_nDevicesFound = 0;
	m_nNetworksFound = 0;

	m_pRootNode = (machineNode *) calloc(1, sizeof(machineNode));
	if (m_pRootNode == NULL)
		return 1;
	m_pRootNode->next = NULL;

	retweet("start");

	/* start NET Wiz discovery */
	discovery(ipstart, ipstop, options, m_pRootNode);

	/* print results */
	display_nodes(m_pRootNode);

	/* Destroy the network node list */
	networkNode *pNetwork = m_pNetworkNode;
	while (pNetwork) {
		m_pNetworkNode = pNetwork;
		pNetwork = m_pNetworkNode->next;
		free(m_pNetworkNode);
	}
	m_pNetworkNode = NULL;

	/* The root node is always empty */
	machineNode *pTemp = m_pRootNode->next;
	free(m_pRootNode);
	m_pRootNode = NULL;

	/* Destroy the machine node list */
	machineNode *curr = pTemp;
	while (curr) {
		if ((curr->snmp_scaned == 2) && (curr->ping_scaned == 2)) {
			free(curr);
			curr = NULL;
			break;
		}

		machineNode *next = curr->next;
		free(curr);
		curr = NULL;
		curr = next;
	}

	retweet("done");

	return 0;
}
