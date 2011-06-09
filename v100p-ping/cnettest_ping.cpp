#include "cnettest_ping.h"

#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

//#define _PING_DEBUG_

static BOOL g_exitFlag = FALSE;
static char g_devName[IFNAMSIZ] = "";
static CNetTest_Ping* g_pPingOBJ = NULL;
static void ping_timer_sighandler(int sigNum);

time_t ve_get_clock(struct timeval* tp)
{
    struct timespec clock_now;

    clock_gettime(CLOCK_MONOTONIC, &clock_now);

    if (tp != NULL)
    {
        tp->tv_sec  = clock_now.tv_sec;
        tp->tv_usec = clock_now.tv_nsec / 1000;
    }
    return (time_t)clock_now.tv_sec;
}

int u16CheckSum(const void *ptrBuff, int iSize)
{   
    unsigned int sum = 0;
    unsigned short *ptrSrc = (unsigned short *)ptrBuff;
    
    while (iSize > 1)  {
        /*  This is the inner loop */
        sum += *ptrSrc++;
        iSize -= 2;
    }   
        
    /*  Add left-over byte, if any */
    if (iSize > 0) {
        /* Make sure that the left-over byte is added correctly both
         * with little and big endian hosts */
        unsigned short tmp = 0;
        *(unsigned char *)&tmp = *(unsigned char *)ptrSrc;
        sum += tmp;
    }

    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (unsigned short)~sum;
}

int getBindDevIface()
{
    char* colon_ptr = NULL; 
    char  ifname_main[IFNAMSIZ] = "";

    strcpy(ifname_main, g_devName);
    if ((colon_ptr = strchr(ifname_main, ':')) != NULL)
        colon_ptr[0] = '\0';
    
    return if_nametoindex(ifname_main);
}

const char* getBindDevHWAddr()
{
	static unsigned char m_szBindDevHWAddr[64];
    int  ret_val = 0;
    int  sock_ctrl = -1;
    struct ifreq if_req;

	bzero((void*)m_szBindDevHWAddr, sizeof(m_szBindDevHWAddr));

    /* alloc resources for this setup */
    sock_ctrl = socket(PF_INET, SOCK_DGRAM, 0);
    ret_val = (sock_ctrl < 0) ? 11 : ret_val;
    exit_if_fail(ret_val);

    /* get mac address */
    bzero(&if_req, sizeof(if_req));
    strcpy(if_req.ifr_name, g_devName);
    if_req.ifr_addr.sa_family = AF_INET;
    ret_val = (ioctl(sock_ctrl, SIOCGIFHWADDR, &if_req) != 0) ? 21 : ret_val;
    exit_if_fail(ret_val);
    
    /* fill mac address */
    memcpy(m_szBindDevHWAddr, if_req.ifr_hwaddr.sa_data, ETH_ALEN);

lzExit:
    if (sock_ctrl > 0)
        close(sock_ctrl);
    return (const char*)m_szBindDevHWAddr;
}

int resolveIn4Addr(const char* szHostName, struct in_addr* pIn4Addr,
	               struct timeval* pStampStart, struct timeval* pStampStop)
{
	struct in_addr in4_dst;
	struct addrinfo *result = NULL;
	struct addrinfo *res = NULL;
	int error = 0, ret_val = 0;

    /* check parameters */
    ret_val = ((szHostName == NULL) || (szHostName[0] == '\0')) ? 1 : ret_val;
    exit_if_fail(ret_val);

    /* clean returning values first */
    if (pIn4Addr != NULL)
        bzero(pIn4Addr, sizeof(*pIn4Addr));
    if (pStampStart != NULL)
        bzero(pStampStart, sizeof(*pStampStart));
    if (pStampStop != NULL)
        bzero(pStampStop, sizeof(*pStampStop));
    bzero(&in4_dst, sizeof(in4_dst));

	/* try to resolve name */
	if (inet_pton(AF_INET, szHostName, &in4_dst) <= 0)
	{
		/* resolve the domain name into a list of addresses */
		ret_val = (getaddrinfo(szHostName, NULL, NULL, &result) != 0) ? 3 : ret_val;
		exit_if_fail(ret_val);
		
		/* loop over all returned results and do inverse lookup */
		for (res = result; res != NULL; res = res->ai_next)
		{   
			char hostname[NI_MAXHOST] = "";
			error = getnameinfo(res->ai_addr, res->ai_addrlen, hostname, NI_MAXHOST, NULL, 0, 0); 
			if (error != 0)
			{
				fprintf(stderr, "error in getnameinfo: %s\n", gai_strerror(error));
				continue;
			}

			if (*hostname != '\0')
			{
				#ifdef _PING_DEBUG_
				fprintf(stderr, "hostname: %s\n", hostname);
				#endif/*_PING_DEBUG_*/
				ret_val = (inet_pton(AF_INET, hostname, &in4_dst) <= 0) ? 5 : ret_val;
				exit_if_fail(ret_val);
				break;
			}
		}
	}

    ret_val = (in4_dst.s_addr == htonl(INADDR_ANY)) ? 11 : ret_val;
    exit_if_fail(ret_val);
		    
	/* fill returning values */
	if (pIn4Addr != NULL)
	{   
		memcpy(pIn4Addr, &in4_dst, sizeof(*pIn4Addr));
	}
								    
lzExit:
	if (result != NULL)
		freeaddrinfo(result);
	result = NULL;
	return (ret_val == 0) ? 0 : -1;
}

int resolveIn6Addr(const char* szHostName, struct in6_addr* pIn6Addr,
	               struct timeval* pStampStart, struct timeval* pStampStop)
{
	struct in6_addr in6_dst;
	struct addrinfo *result = NULL;
	struct addrinfo *res = NULL;
	int error = 0, ret_val = 0;

    /* check parameters */
    ret_val = ((szHostName == NULL) || (szHostName[0] == '\0')) ? 1 : ret_val;
    exit_if_fail(ret_val);

    /* clean returning values first */
    if (pIn6Addr != NULL)
        bzero(pIn6Addr, sizeof(*pIn6Addr));
    if (pStampStart != NULL)
        bzero(pStampStart, sizeof(*pStampStart));
    if (pStampStop != NULL)
        bzero(pStampStop, sizeof(*pStampStop));
    bzero(&in6_dst, sizeof(in6_dst));

	/* try to resolve name */
	if (inet_pton(AF_INET6, szHostName, &in6_dst) <= 0)
	{
		/* resolve the domain name into a list of addresses */
		ret_val = (getaddrinfo(szHostName, NULL, NULL, &result) != 0) ? 3 : ret_val;
		exit_if_fail(ret_val);
		
		/* loop over all returned results and do inverse lookup */
		for (res = result; res != NULL; res = res->ai_next)
		{   
			char hostname[NI_MAXHOST] = "";
		
			error = getnameinfo(res->ai_addr, res->ai_addrlen, hostname, NI_MAXHOST, NULL, 0, 0); 
			if (error != 0)
			{
				fprintf(stderr, "error in getnameinfo: %s\n", gai_strerror(error));
				continue;
			}

			if (*hostname != '\0')
			{
				#ifdef _PING_DEBUG_
				fprintf(stderr, "hostname: %s\n", hostname);
				#endif/*_PING_DEBUG_*/
				ret_val = (inet_pton(AF_INET6, hostname, &in6_dst) <= 0) ? 5 : ret_val;
				exit_if_fail(ret_val);
				break;
			}
		}
	}

	ret_val = (IN6_IS_ADDR_UNSPECIFIED(&in6_dst)) ? 11 : ret_val;
    exit_if_fail(ret_val);
		    
	/* fill returning values */
	if (pIn6Addr != NULL)
	{   
		memcpy(pIn6Addr, &in6_dst, sizeof(*pIn6Addr));
	}
								    
lzExit:
	if (result != NULL)
		freeaddrinfo(result);
	result = NULL;
	return (ret_val == 0) ? 0 : -1;
}

#define BUFSIZE 8192
 
struct route_info{
 u_int dstAddr;
 u_int srcAddr;
 u_int gateWay;
 char ifName[IF_NAMESIZE];
};

int readNlSock(int sockFd, char *bufPtr, int seqNum, int pId)
{
	struct nlmsghdr *nlHdr;
	int readLen = 0, msgLen = 0;

	do {
		//收到内核的应答
		if ((readLen = recv(sockFd, bufPtr, BUFSIZE - msgLen, 0)) < 0)
		{
		  perror("SOCK READ: ");
		  return -1;
		}
		
		nlHdr = (struct nlmsghdr *)bufPtr;
		
		//检查header是否有效
		if ((NLMSG_OK(nlHdr, readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR))
		{
		  perror("Error in recieved packet");
		  return -1;
		}
		
		/* Check if the its the last message */
		if(nlHdr->nlmsg_type == NLMSG_DONE)
		{
			break;
		}
		else
		{
			/* or move the pointer to buffer appropriately */
			bufPtr += readLen;
			msgLen += readLen;
		}
	
		/* Check if its a multi part message */
		if((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0)
		{
			/* return if its not */
			break;
		}
	} while((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));

	return msgLen;
}

//分析返回的路由信息
void parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo, char *gateway)
{
	int ret_val = 0;
	struct rtmsg *rtMsg;
	struct rtattr *rtAttr;
	int rtLen;
	struct in_addr dst;
	struct in_addr gate;
	
	rtMsg = (struct rtmsg *)NLMSG_DATA(nlHdr);

	// If the route is not for AF_INET or does not belong to main routing table
	//then return.
	if((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))
		return;

	/* get the rtattr field */
	rtAttr = (struct rtattr *)RTM_RTA(rtMsg);
	rtLen = RTM_PAYLOAD(nlHdr);
	for (; RTA_OK(rtAttr,rtLen); rtAttr = RTA_NEXT(rtAttr,rtLen))
	{
		switch (rtAttr->rta_type) {
			case RTA_OIF:
				if_indextoname(*(int *)RTA_DATA(rtAttr), rtInfo->ifName);
				break;
			case RTA_GATEWAY:
				rtInfo->gateWay = *(u_int *)RTA_DATA(rtAttr);
				break;
			case RTA_PREFSRC:
				rtInfo->srcAddr = *(u_int *)RTA_DATA(rtAttr);
				break;
			case RTA_DST:
				rtInfo->dstAddr = *(u_int *)RTA_DATA(rtAttr);
				break;
		}
	}

	dst.s_addr = rtInfo->dstAddr;
	if (strstr((char *)inet_ntoa(dst), "0.0.0.0"))
	{
		gate.s_addr = rtInfo->gateWay;
		strcpy(gateway, (char *)inet_ntoa(gate));
	}

	return;
}

int getGatewayAddr(char *gateway)
{
	int ret_val = 0;
	struct nlmsghdr *nlMsg = NULL;
	struct rtmsg *rtMsg = NULL;
	struct route_info *rtInfo = NULL;
	char msgBuf[BUFSIZE];
	int sock = -1, len = 0, msgSeq = 0;

    ret_val = ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) ? 1 : ret_val;
    exit_if_fail(ret_val);

	/* Initialize the buffer */
	memset(msgBuf, 0, BUFSIZE);
	
	/* point the header and the msg structure pointers into the buffer */
	nlMsg = (struct nlmsghdr *)msgBuf;
	rtMsg = (struct rtmsg *)NLMSG_DATA(nlMsg);
	
	/* Fill in the nlmsg header*/
	nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)); // Length of message.
	nlMsg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table .
	
	nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump.
	nlMsg->nlmsg_seq = msgSeq++; // Sequence of the message packet.
	nlMsg->nlmsg_pid = getpid(); // PID of process sending the request.
	
	/* Send the request */
    ret_val = (send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0) ? 3 : ret_val;
    exit_if_fail(ret_val);
	
	/* Read the response */
    ret_val = ((len = readNlSock(sock, msgBuf, msgSeq, getpid())) < 0) ? 5 : ret_val;
    exit_if_fail(ret_val);

	/* Parse and print the response */
	rtInfo = (struct route_info *)malloc(sizeof(struct route_info));
    ret_val = (rtInfo == NULL) ? 21 : ret_val;
    exit_if_fail(ret_val);
	for (; NLMSG_OK(nlMsg,len); nlMsg = NLMSG_NEXT(nlMsg,len))
	{
		memset(rtInfo, 0, sizeof(struct route_info));
		parseRoutes(nlMsg, rtInfo,gateway);
	}

lzExit:
	if (rtInfo != NULL)
		free(rtInfo);
	rtInfo = NULL;
	if (sock > 0)
		close(sock);
	return 0;
}

void readINET4Addr(const char* szAttrValue, struct in_addr* pINET4Addr)
{
    struct in_addr in4Addr;
    
    if ((szAttrValue == NULL) || (inet_pton(PF_INET, szAttrValue, &in4Addr) != 1))
        in4Addr.s_addr = htonl(INADDR_ANY);
        
    if (pINET4Addr != NULL)
        memcpy(pINET4Addr, &in4Addr, sizeof(*pINET4Addr));
}

int getINET4Info(struct in_addr* pINET4Addr, struct in_addr* pINET4Mask, struct in_addr* pINET4Gateway)
{
    int ret_val = 0;
    struct in_addr ip_addr; 
    struct in_addr ip_mask;
    struct in_addr gw_addr;
    char szConfValue[128] = "";
    int  sock_ctrl = -1;
        
    /* init returning values */
    if (pINET4Addr != NULL)
        bzero(pINET4Addr, sizeof(*pINET4Addr));
    /* init local variables */
    bzero(&ip_addr, sizeof(ip_addr));
    bzero(&ip_mask, sizeof(ip_mask));
    bzero(&gw_addr, sizeof(gw_addr));
    bzero(szConfValue, sizeof(szConfValue));

    /* alloc socket resources for this loading */
    sock_ctrl = socket(PF_INET, SOCK_DGRAM, 0);
    ret_val = (sock_ctrl < 0) ? 11 : ret_val;
    exit_if_fail(ret_val);
    /* read INET4 ip addr from socket */
    do {
        struct ifreq if_req;
        bzero(&if_req, sizeof(if_req));
        strcpy(if_req.ifr_name, g_devName);
        ret_val = (ioctl(sock_ctrl, SIOCGIFADDR, &if_req) != 0) ? 21 : ret_val;
        exit_if_fail(ret_val);
        memcpy(&ip_addr, &((struct sockaddr_in*)&if_req.ifr_addr)->sin_addr, sizeof(ip_addr));
    } while (0);

    if (pINET4Mask != NULL)
	{
        bzero(pINET4Mask, sizeof(*pINET4Mask));
		/* read INET4 ip mask from socket */
		do {
			struct ifreq if_req;
			bzero(&if_req, sizeof(if_req));
			strcpy(if_req.ifr_name, g_devName);
			ret_val = (ioctl(sock_ctrl, SIOCGIFNETMASK, &if_req) != 0) ? 22 : ret_val;
			exit_if_fail(ret_val);
			memcpy(&ip_mask, &((struct sockaddr_in*)&if_req.ifr_netmask)->sin_addr, sizeof(ip_mask));
		} while (0);
	}

    if (pINET4Gateway != NULL)
	{
        bzero(pINET4Gateway, sizeof(*pINET4Gateway));
		/* read INET4 gw addr from socket */
		getGatewayAddr(szConfValue);
		readINET4Addr(szConfValue, &gw_addr);
	}

    /* read success, fill returning values */
    if (pINET4Addr != NULL)
        memcpy(pINET4Addr, &ip_addr, sizeof(*pINET4Addr));
    if (pINET4Mask != NULL)
        memcpy(pINET4Mask, &ip_mask, sizeof(*pINET4Mask));
    if (pINET4Gateway != NULL)
        memcpy(pINET4Gateway, &gw_addr, sizeof(*pINET4Gateway));

lzExit:
    if (sock_ctrl >= 0)
        close(sock_ctrl);
    return (ret_val == 0) ? 0 : -1;
}

int openINET4Socket(int socket_type, int protocol, int bindPort)
{
    int ret_val = 0;
    const char* szBindDev = NULL;  
    int inet4_sock = -1;

    /* create INET4 socket */
    inet4_sock = socket(AF_INET, socket_type, protocol);
    ret_val = (inet4_sock < 0) ? 11 : ret_val;
    exit_if_fail(ret_val);

    /* bind this socket to this device */
    if ((szBindDev = g_devName) != NULL)
    {
        setsockopt(inet4_sock, SOL_SOCKET, SO_BINDTODEVICE, szBindDev, strlen(szBindDev));
    }

    /* enalbe reuse addr for bind */
    if (bindPort > 0)
    {
        int opt_val = 0;

        opt_val = 1;
        setsockopt(inet4_sock, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val));
    }

    /* bind this socket to name */
    if (bindPort > 0)
    {
        struct sockaddr_in localAddr;
        /* compose local address */
        bzero(&localAddr, sizeof(localAddr));
        localAddr.sin_family  = AF_INET;
        getINET4Info((struct in_addr*)&localAddr.sin_addr, NULL, NULL);
        localAddr.sin_port    = htons(bindPort);
        /* bind to local address */
        ret_val = (bind(inet4_sock,
                    (struct sockaddr*)&localAddr, sizeof(localAddr)) != 0) ? 21 : ret_val;
        exit_if_fail(ret_val);
    } while (0);

lzExit:
    if ((ret_val != 0) && (inet4_sock >= 0))
        close(inet4_sock);
	#ifdef _PING_DEBUG_
    if (ret_val != 0)
        fprintf(stderr, "create INET4 socket fail(ret=%d)!\n", ret_val);
	#endif/*_PING_DEBUG_*/
    return (ret_val == 0) ? inet4_sock : -1;
}

#define _PATH_PROCNET_IFINET6           "/proc/net/if_inet6"
int getINET6Info(struct in6_addr* pINET6Addr)
{
    int ret_val = 0;
    FILE* fIF6 = NULL;
    int  bind_iface = 0;
    BOOL bAddrFound = FALSE;
    struct in6_addr ip_addr;

    /* init returning values */
    if (pINET6Addr != NULL)
        bzero(pINET6Addr, sizeof(*pINET6Addr));

    /* init local variables */
    bzero(&ip_addr, sizeof(ip_addr));

    /* open ifinet6 config proc file */
    fIF6 = fopen(_PATH_PROCNET_IFINET6, "r");
    ret_val = (fIF6 == NULL) ? 11 : ret_val;
    exit_if_fail(ret_val);
    bind_iface = getBindDevIface();

    /* read configured inet6 address */
    while (bAddrFound == FALSE)
    {
        char line_buff[128] = "";
        char addr6p[8][8];
        int  if_idx, plen, scope, dad_status;
        char devname[IF_NAMESIZE] = "";
        char str_addr[INET6_ADDRSTRLEN] = "";
        struct in6_addr cfg_addr;

        if (fgets(line_buff, sizeof(line_buff)-1, fIF6) == NULL)
            break;

        bzero(addr6p, sizeof(addr6p));
        if_idx = 0;
        plen   = 0;
        scope  = 0;
        dad_status = 0;
        bzero(devname, sizeof(devname));
        if (sscanf(line_buff, "%4s%4s%4s%4s%4s%4s%4s%4s %08x %02x %02x %02x %20s\n",
                    addr6p[0], addr6p[1], addr6p[2], addr6p[3],
                    addr6p[4], addr6p[5], addr6p[6], addr6p[7],
                    &if_idx, &plen, &scope, &dad_status,
                    devname) != 13)
            continue;
        if (bind_iface != if_idx)
            continue;

        sprintf(str_addr, "%s:%s:%s:%s:%s:%s:%s:%s",
                addr6p[0], addr6p[1], addr6p[2], addr6p[3],
                addr6p[4], addr6p[5], addr6p[6], addr6p[7]);
        inet_pton(AF_INET6, str_addr, &cfg_addr);

        if ((!IN6_IS_ADDR_LINKLOCAL(&cfg_addr)) &&
            (!IN6_IS_ADDR_SITELOCAL(&cfg_addr)))
        {
            bAddrFound = TRUE;
            memcpy(&ip_addr, &cfg_addr, sizeof(ip_addr));
        }
    }

    /* read success, fill returning values */
    if ((pINET6Addr != NULL) && bAddrFound)
        memcpy(pINET6Addr, &ip_addr, sizeof(*pINET6Addr));

    ret_val = (bAddrFound == FALSE) ? 101 : ret_val;
    exit_if_fail(ret_val);

lzExit:
    if (fIF6 != NULL)
        fclose(fIF6);
    return (ret_val == 0) ? 0 : -1;
}

int openEthPacket(int prot, BOOL bBindLocal)
{   
    int  ret_val = 0;
    int  pack_sock = -1;
    struct sockaddr_ll local_etheraddr;
    
    /* set local address */
    bzero(&local_etheraddr, sizeof(local_etheraddr));
    local_etheraddr.sll_family   = AF_PACKET;
    local_etheraddr.sll_protocol = prot;
    local_etheraddr.sll_ifindex  = getBindDevIface();
    local_etheraddr.sll_hatype   = ARPHRD_ETHER;
    local_etheraddr.sll_pkttype  = PACKET_HOST;
    local_etheraddr.sll_halen    = ETH_ALEN;
    memcpy(local_etheraddr.sll_addr, getBindDevHWAddr(), ETH_ALEN);

    /* prepare packet socket */  
    pack_sock = socket(PF_PACKET, SOCK_DGRAM, prot);
    ret_val = (pack_sock < 0) ? 11 : ret_val;
    exit_if_fail(ret_val);
    if (bBindLocal)
    {
        ret_val = (bind(pack_sock, (struct sockaddr *)&local_etheraddr, sizeof(local_etheraddr)) != 0) ? 12 : ret_val;
        exit_if_fail(ret_val);
    }
    
lzExit: 
    if ((ret_val != 0) && (pack_sock >= 0))
        close(pack_sock);
    return (ret_val == 0) ? pack_sock : -1;
}

int openINET6Socket(int socket_type, int protocol, int bindPort)
{
    int ret_val = 0;
    const char* szBindDev = NULL;
    int inet6_sock = -1;

    /* create INET6 socket */
    inet6_sock = socket(AF_INET6, socket_type, protocol);
    ret_val = (inet6_sock < 0) ? 11 : ret_val;
    exit_if_fail(ret_val);

    /* bind this socket to this device */
    if ((szBindDev = g_devName) != NULL)
    {
        setsockopt(inet6_sock, SOL_SOCKET, SO_BINDTODEVICE, szBindDev, strlen(szBindDev));
    }

    /* enalbe reuse addr for bind */
    if (bindPort > 0)
    {
        int opt_val = 0;

        opt_val = 1;
        setsockopt(inet6_sock, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val));
    }

    /* bind this socket to name */
    if (bindPort > 0)
    {
        struct sockaddr_in6 localAddr;
        /* compose local address */
        bzero(&localAddr, sizeof(localAddr));
        localAddr.sin6_family  = AF_INET6;
        getINET6Info((struct in6_addr*)&localAddr.sin6_addr);
        localAddr.sin6_port    = htons(bindPort);
        /* bind to local address */
        ret_val = (bind(inet6_sock,
                    (struct sockaddr*)&localAddr, sizeof(localAddr)) != 0) ? 21 : ret_val;
        exit_if_fail(ret_val);
    } while (0);

lzExit:
    if ((ret_val != 0) && (inet6_sock >= 0))
        close(inet6_sock);
	#ifdef _PING_DEBUG_
    if (ret_val != 0)
        fprintf(stderr, "create INET6 socket fail(ret=%d)!\n", ret_val);
	#endif/*_PING_DEBUG_*/
    return (ret_val == 0) ? inet6_sock : -1;
}

int arpEthINET4(int iWaitUsecs, const struct in_addr* pReqIN4,
                            void* pDstMAC, struct timeval* pRepTime)
{
    int  ret_val = 0;
    BOOL bDstMACRead = FALSE;
    unsigned char bufDstMAC[8];
    int  arp_sock = -1;
    struct timeval     stamp_send;
    struct timeval     stamp_recv;
    struct timeval     arp_timeout;
    struct in_addr     local_ipaddr;
    struct sockaddr_ll remote_etheraddr;
    struct ether_arp   arp_packet;
	#ifdef _PING_DEBUG_
    fprintf(stderr, "start ...\n");
	#endif/*_PING_DEBUG_*/

    /* init returning values */
    if (pDstMAC != NULL)
        bzero(pDstMAC, ETH_ALEN);
    bzero(bufDstMAC, sizeof(bufDstMAC));
    bzero(&stamp_send, sizeof(stamp_send));
    bzero(&stamp_recv, sizeof(stamp_recv));

    /* check parameters */
    ret_val = (pReqIN4 == NULL) ? 1 : ret_val;
    exit_if_fail(ret_val);
    bzero(&arp_timeout, sizeof(arp_timeout));
    ve_get_clock(&arp_timeout);
    if (iWaitUsecs <= 0)
    {
        arp_timeout.tv_sec  = arp_timeout.tv_sec + 1;
    }
    else
    {
        struct timeval arp_waittime;
        struct timeval stamp_timeout;

        bzero(&arp_waittime, sizeof(arp_waittime));
        arp_waittime.tv_sec  = iWaitUsecs / MILLION;
        arp_waittime.tv_usec = iWaitUsecs % MILLION;
        timeradd(&arp_timeout, &arp_waittime, &stamp_timeout);

        memcpy(&arp_timeout, &stamp_timeout, sizeof(arp_timeout));
    }

    /* set arping remote address */
    bzero(&remote_etheraddr, sizeof(remote_etheraddr));
    remote_etheraddr.sll_family   = AF_PACKET;
    remote_etheraddr.sll_protocol = htons(ETHERTYPE_ARP);
    remote_etheraddr.sll_ifindex  = getBindDevIface();
    remote_etheraddr.sll_hatype   = ARPHRD_ETHER;
    remote_etheraddr.sll_pkttype  = PACKET_BROADCAST;
    remote_etheraddr.sll_halen    = ETH_ALEN;
    memcpy(remote_etheraddr.sll_addr, "\xFF\xFF\xFF\xFF\xFF\xFF", ETH_ALEN);

    /* prepare arping socket */
    arp_sock = openEthPacket(htons(ETHERTYPE_ARP), 1);
    ret_val = (arp_sock < 0) ? 11 : ret_val;
    exit_if_fail(ret_val);
    getINET4Info(&local_ipaddr, NULL, NULL);

    /* send arp request */
    bzero(&arp_packet, sizeof(arp_packet));
    arp_packet.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_packet.ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp_packet.ea_hdr.ar_hln = ETH_ALEN;
    arp_packet.ea_hdr.ar_pln = 4;
    arp_packet.ea_hdr.ar_op  = htons(ARPOP_REQUEST);
    memcpy(arp_packet.arp_sha, getBindDevHWAddr(), ETH_ALEN);
    memcpy(arp_packet.arp_spa, &local_ipaddr, sizeof(local_ipaddr));
    memcpy(arp_packet.arp_tha, "\x00\x00\x00\x00\x00\x00", ETH_ALEN);
    memcpy(arp_packet.arp_tpa, pReqIN4, 4);
    sendto(arp_sock, &arp_packet, sizeof(arp_packet), 0,
            (struct sockaddr *)&remote_etheraddr, sizeof(remote_etheraddr));
    /* record stamp of arp send */
    ve_get_clock(&stamp_send);

    /* try to receive arp reply */
    while (bDstMACRead == FALSE)
    {
        int    wait_ret = 0;
        int    read_ret = 0;
        fd_set wait_set;
        struct timeval time_now;
        struct timeval wait_timeout;

        if (g_exitFlag)
        {
			#ifdef _PING_DEBUG_
            fprintf(stderr, "arp time out!\n");
			#endif/*_PING_DEBUG_*/
            break;
        }

        /* prepare wait_set */
        FD_ZERO(&wait_set);
        FD_SET(arp_sock, &wait_set);
        /* prepare wait_timeout */
        ve_get_clock(&time_now);
        if (timercmp(&time_now, &arp_timeout, >))
        {
			#ifdef _PING_DEBUG_
            fprintf(stderr, "arp time out!\n");
			#endif/*_PING_DEBUG_*/
            break;
        }
        else
        {
            timersub(&arp_timeout, &time_now, &wait_timeout);
			#ifdef _PING_DEBUG_
			/*
            fprintf(stderr,"try listen arp(sec=%d, usec=%d) ...\n",
                    wait_timeout.tv_sec, wait_timeout.tv_usec);
			*/
			#endif/*_PING_DEBUG_*/
        }

        /* wait arp packet */
        wait_ret = select(arp_sock+1, &wait_set, NULL, NULL, &wait_timeout);
        if (wait_ret < 0)
        {
            break;
        }
        else if (!FD_ISSET(arp_sock, &wait_set))
        {
            continue;
        }

        /* read&check arp packet */
        read_ret = read(arp_sock, &arp_packet, sizeof(arp_packet));
        if (read_ret < sizeof(arp_packet))
            continue;
        if ((arp_packet.ea_hdr.ar_hrd != htons(ARPHRD_ETHER)) ||
            (arp_packet.ea_hdr.ar_pro != htons(ETHERTYPE_IP)) ||
            (arp_packet.ea_hdr.ar_op != htons(ARPOP_REPLY)) ||
            (memcmp(arp_packet.arp_spa, pReqIN4, 4) != 0))
        {
            continue;
        }

        /* do read arp response */
        memcpy(bufDstMAC, arp_packet.arp_sha, ETH_ALEN);
        bDstMACRead = TRUE;
        ve_get_clock(&stamp_recv);
    }

    /* check whether have got the arp response */
    ret_val = (bDstMACRead == FALSE) ? 51 : ret_val;
    exit_if_fail(ret_val);

    /* do fill returning values */
    if (pDstMAC != NULL)
        memcpy(pDstMAC, bufDstMAC, ETH_ALEN);
    if (pRepTime != NULL)
    {
        struct timeval arp_reptime;
        timersub(&stamp_recv, &stamp_send, &arp_reptime);
        memcpy(pRepTime, &arp_reptime, sizeof(*pRepTime));
    }

lzExit:
    if (arp_sock >= 0)
        close(arp_sock);
	#ifdef _PING_DEBUG_
    fprintf(stderr, "done!(ret=%d)\n", ret_val);
	#endif/*_PING_DEBUG_*/
    return (bDstMACRead != FALSE) ? 0 : -1;
}

int arpEthINET4Target(int iWaitUsecs, const struct in_addr* pTargetIN4,
                                struct timeval* pRepTime)
{       
    int ret_val = 0;
    BOOL bDestResp = FALSE;
    struct in_addr in4_addr;
    struct in_addr in4_mask;
    struct in_addr in4_gateway;
    
    /* check parameters */
    ret_val = (pTargetIN4 == NULL) ? 1 : ret_val;
    exit_if_fail(ret_val);
    ret_val = (pTargetIN4->s_addr == htonl(INADDR_ANY)) ? 2 : ret_val;
    exit_if_fail(ret_val);
    ret_val = (pTargetIN4->s_addr == htonl(INADDR_BROADCAST)) ? 3 : ret_val;
    exit_if_fail(ret_val);

    /* get INET4 information first */
    ret_val = (getINET4Info(&in4_addr, &in4_mask, &in4_gateway) != 0) ? 11 : ret_val;
    exit_if_fail(ret_val);

    /* try arp destination or gateway */
    if ((in4_mask.s_addr & in4_addr.s_addr) ==
        (in4_mask.s_addr & pTargetIN4->s_addr))
    {
        ret_val = (arpEthINET4(iWaitUsecs, pTargetIN4, NULL, pRepTime) != 0) ? 21 : ret_val;
        exit_if_fail(ret_val);
        bDestResp = TRUE;
    }
    else if (in4_gateway.s_addr != htonl(INADDR_ANY))
    {
        ret_val = (arpEthINET4(iWaitUsecs, &in4_gateway, NULL, pRepTime) != 0) ? 31 : ret_val;
        exit_if_fail(ret_val);
        bDestResp = TRUE;
    }
    else
    {
        bDestResp = FALSE;
    }

lzExit:
	#ifdef _PING_DEBUG_
    fprintf(stderr, "arpEthINET4Target() done!(ret=%d)\n", ret_val);
	#endif/*_PING_DEBUG_*/
    return (bDestResp) ? 0 : -1;
}


/******************************************************************************/

CNetTest_Ping::CNetTest_Ping()
{
	/* init ping test arguments */
	bzero(&m_stPingConfig, sizeof(m_stPingConfig));

	/* init ping assistant resources */
	m_bINET6Ping   = FALSE;
	m_sockICMP     = -1;
    bzero(&m_addr4ICMPSend, sizeof(m_addr4ICMPSend));
    bzero(&m_addr6ICMPSend, sizeof(m_addr6ICMPSend));
	m_sizeICMPSend = 0;
	m_buffICMPSend = NULL;
	m_sizeICMPRecv = 0;
	m_buffICMPRecv = NULL;
	m_usecPingIntv  = 0;
	m_iStatSendDiff = 0;
	m_iPingsID      = 0;
	bzero(&m_tmRecvTimeout, sizeof(m_tmRecvTimeout));

	/* init ping assistant statistics */
	m_bResolveFail  = FALSE;
	bzero(&m_tmResolvStart, sizeof(m_tmResolvStart));
	bzero(&m_tmResolvStop, sizeof(m_tmResolvStop));
	bzero(&m_tmArpResponse, sizeof(m_tmArpResponse));
	bzero(&m_tmPingStart, sizeof(m_tmPingStart));
	bzero(&m_tmPingStop, sizeof(m_tmPingStop));
	bzero(&m_tmPingStat, sizeof(m_tmPingStat));
	bzero(&m_addr4PingReply, sizeof(m_addr4PingReply));
	bzero(&m_addr6PingReply, sizeof(m_addr6PingReply));

	m_iPingsSend      = 0;
	m_iPingsReply     = 0;
	m_iPingsDuplicate = 0;
	m_iPingsIgnored   = 0;
	m_iPingsUnrech    = 0;
	m_iPingsMiss      = 0;

	timerclear(&m_tmRoundTripCur);
	timerclear(&m_tmRoundTripMin);
	timerclear(&m_tmRoundTripMax);
	m_iRoundTripSize  = 0;
	m_tmRoundTripSum  = 0;

	m_iRecSendIndex   = 0;
	m_iRecStatIndex   = 0;
	bzero(m_stPingRecords, sizeof(m_stPingRecords));

	/* install signal handler */
	g_pPingOBJ = NULL;
	signal(SIGALRM, ping_timer_sighandler);
}

CNetTest_Ping::~CNetTest_Ping()
{
}

void usage(void)              
{
	fprintf(stderr,
			"Usage: v100p-ping-app [-v IPv4/6] [-c count] [-s length] [-n ping/sec]\n"
			"                      [-I interface] [-W timeout] destination\n");
}

int CNetTest_Ping::applyTestSetting(int argc, char* argv[])
{
	int opt = 0;

	m_stPingConfig.ping_number = 3;
	m_stPingConfig.ping_speed = 1;
	m_stPingConfig.ping_echolen = 32;
	m_stPingConfig.ping_timeout = 1000;
	strcpy(g_devName, "eth0");

	/* parse command line arguments */
	while((opt = getopt(argc, argv, "v:c:s:n:I:W:")) != -1) {
		switch (opt) {
			case 'v': /* IPv4, IPv6 */
				if (atoi(optarg) == 6)
					m_stPingConfig.use_inet6 = 1;
				break;
			case 'c':
				m_stPingConfig.ping_number = atoi(optarg);
				break;
			case 's':
				m_stPingConfig.ping_echolen = atoi(optarg);
				break;
			case 'n':
				m_stPingConfig.ping_speed = atoi(optarg);
				break;
			case 'I':
				strcpy(g_devName, optarg);
				break;
			case 'W':
				m_stPingConfig.ping_timeout = atoi(optarg);
				break;
			default:
				usage();
				return -1;
		}
	}

	argc -= optind;
	argv += optind;
	if (argc == 0)
	{
		usage();
		return -1;
	}

	while (argc > 0) {
		strcpy(m_stPingConfig.dst_host, *argv);
		argc -= optind;
		argv += optind;
	}

	return 0;
}

int CNetTest_Ping::reportPingResult(BOOL bRunning)
{
	char dst_addr[128] = "";
	int  rtp_avg = 0;

    if (m_bINET6Ping == FALSE)
		inet_ntop(AF_INET, &m_addr4PingReply, dst_addr, sizeof(dst_addr));
    else
		inet_ntop(AF_INET6, &m_addr6PingReply, dst_addr, sizeof(dst_addr));

    if (m_iRoundTripSize <= 0)
        rtp_avg  = 0;
    else
        rtp_avg  = m_tmRoundTripSum / m_iRoundTripSize;

	printf("ping: stat> sent=%d, recv=%d, dup=%d, unreach=%d, miss=%d, rtrip(cur=%d, avg=%d, min=%d, max=%d), from=%s\n", 
			m_iPingsSend, m_iPingsReply, m_iPingsDuplicate, m_iPingsUnrech, m_iPingsMiss, 
			(int)(m_tmRoundTripCur.tv_sec*MILLION + m_tmRoundTripCur.tv_usec),
			rtp_avg, 
			(int)(m_tmRoundTripMin.tv_sec*MILLION + m_tmRoundTripMin.tv_usec), 
			(int)(m_tmRoundTripMax.tv_sec*MILLION + m_tmRoundTripMax.tv_usec),
			dst_addr);
	fflush(stdout);

	return 0;
}

void CNetTest_Ping::exitExec()
{
	g_exitFlag = TRUE;
}

int CNetTest_Ping::onMainLoop()
{
	#ifdef _PING_DEBUG_
	fprintf(stderr, "ping main loop start...\n");
	#endif/*_PING_DEBUG_*/

	/* exit main loop if destination is invalid */
	if (m_bResolveFail)
	{
		reportPingResult(FALSE);
		exit_no_condition();
	}

	#ifdef _PING_DEBUG_
	fprintf(stderr,
			"ping main loop entering(continous=%d, ping_number=%d) ...\n",
			m_stPingConfig.ping_continuous, m_stPingConfig.ping_number);
	#endif/*_PING_DEBUG_*/
	/* ping recv&report main loop */
	while (!g_exitFlag)
	{
		struct timeval stamp_this;
		struct timeval report_diff;
		#ifdef _PING_DEBUG_
		fprintf(stderr, "ping main loop running ...\n");
		#endif/*_PING_DEBUG_*/

		/* try to receive ping package */
		if (timerisset(&m_tmSendStamp))
		{
			recvPingPackage(&m_tmRecvTimeout);
		}

		/* report test report every second */
		ve_get_clock(&stamp_this);
		timersub(&stamp_this, &m_tmPingStat, &report_diff);
		if (report_diff.tv_sec > 0)
		{
			while ((m_iRecStatIndex + m_iStatSendDiff) < m_iRecSendIndex)
			{
				statPingRecord(m_iRecStatIndex % SIZEOF(m_stPingRecords));

				m_iRecStatIndex += 1;
			}

			//reportPingResult(TRUE);
			ve_get_clock(&m_tmPingStat);
		}
	}
	#ifdef _PING_DEBUG_
	fprintf(stderr, "ping main loop exited!\n");
	#endif/*_PING_DEBUG_*/

	/* ping recv rest packets loop */
	#ifdef _PING_DEBUG_
	fprintf(stderr, "ping rest loop entering ...\n");
	#endif/*_PING_DEBUG_*/
	while (1)
	{
		struct timeval tmStampNow;
		struct timeval tmStampOut;
		struct timeval tmRecvWait;

		if (!timerisset(&m_tmSendStamp))
			break;
		timeradd(&m_tmSendStamp, &m_tmRecvTimeout, &tmStampOut);
		ve_get_clock(&tmStampNow);
		if (timercmp(&tmStampNow, &tmStampOut, >))
			break;
		timersub(&tmStampOut, &tmStampNow, &tmRecvWait);

		#ifdef _PING_DEBUG_
		fprintf(stderr, "ping rest loop running ...\n");
		#endif/*_PING_DEBUG_*/
		/* try to receive ping package */
		recvPingPackage(&tmRecvWait);
	}
	#ifdef _PING_DEBUG_
	fprintf(stderr, "ping rest loop exited!\n");
	#endif/*_PING_DEBUG_*/

	/* statistic all uncount ping record */
	while (m_iRecStatIndex < m_iRecSendIndex)
	{
		#ifdef _PING_DEBUG_
		fprintf(stderr, "stat ping result record(stat=%u, sent=%u)\n",
			 	m_iRecStatIndex, m_iRecSendIndex);
		#endif/*_PING_DEBUG_*/
		statPingRecord(m_iRecStatIndex % SIZEOF(m_stPingRecords));
		m_iRecStatIndex += 1;
	}

	/* stop ping and report the last report */
	stopTest();

	/* do last report */
	reportPingResult(FALSE);
	ve_get_clock(&m_tmPingStat);

lzExit:
	#ifdef _PING_DEBUG_
	fprintf(stderr, "ping main loop finished!\n");
	#endif/*_PING_DEBUG_*/
	printf("over\n");
	return 0;
}

int CNetTest_Ping::onPingTimer()
{
	if (!g_exitFlag)
	{
		if ((m_stPingConfig.ping_continuous != 0) ||
			(m_iPingsSend < m_stPingConfig.ping_number))
		{
			/* send ping package */
			sendPingPackage();
		}
		else
		{
			#ifdef _PING_DEBUG_
			fprintf(stderr, "exit ping test program by timer!\n");
			#endif/*_PING_DEBUG_*/
			/* stop ping */
			g_exitFlag = TRUE;
			g_pPingOBJ = NULL;
		}
	}

	/* install next timer */
	if (!g_exitFlag)
	{
		ualarm(m_usecPingIntv, 0);
	}

	return 0;
}

int CNetTest_Ping::startTest()
{
	int ret_val = 0;
	struct in_addr  in4_dst;
	struct in6_addr in6_dst;
	struct sockaddr_in*  pIPV4Addr = NULL;
	struct sockaddr_in6* pIPV6Addr = NULL;
	#ifdef _PING_DEBUG_
	fprintf(stderr, "ping start(use_inet6=%d, ping_echolen=%d) ...\n",
					m_stPingConfig.use_inet6,
					m_stPingConfig.ping_echolen);
	#endif/*_PING_DEBUG_*/

	/* check whether able to do ping test */
	if (m_stPingConfig.use_inet6)
		m_bINET6Ping = TRUE;
	else
		m_bINET6Ping = FALSE;
	bzero(&in4_dst, sizeof(in4_dst));
	bzero(&in6_dst, sizeof(in6_dst));

	/* report at the very start */
	printf("PING %s: %d data bytes\n", m_stPingConfig.dst_host, m_stPingConfig.ping_echolen);

	/* try resolve destination */
	if (m_bINET6Ping == FALSE)
	{
		int resolv_ret = 0;

		resolv_ret = resolveIn4Addr(m_stPingConfig.dst_host, &in4_dst,
					&m_tmResolvStart, &m_tmResolvStop);

		m_bResolveFail = (resolv_ret != 0) ? TRUE : FALSE;
	}
	else
	{
		int resolv_ret = 0;

		resolv_ret = resolveIn6Addr(m_stPingConfig.dst_host, &in6_dst,
					&m_tmResolvStart, &m_tmResolvStop);

		m_bResolveFail = (resolv_ret != 0) ? TRUE : FALSE;
	}
	if (m_bResolveFail)
	{
		exit_no_condition();
	}

	/* try arp destination(gateway) */
	if (m_bINET6Ping == FALSE)
		arpEthINET4Target(2*MILLION, &in4_dst, &m_tmArpResponse);

	ve_get_clock(&m_tmPingStat);

	/* alloc ping assistant resources(create ICMP socket) */
	if (m_bINET6Ping == FALSE)
		m_sockICMP = openINET4Socket(SOCK_RAW, 1, 0);/* 1 == ICMP */
	else
		m_sockICMP = openINET6Socket(SOCK_RAW, IPPROTO_ICMPV6, 0);
	ret_val = (m_sockICMP < 0) ? 11 : ret_val;
	exit_if_fail(ret_val);
	/* bind this socket to name */
	if (m_bINET6Ping == FALSE)
	{
		struct sockaddr_in localAddr;
		/* compose local address */
		bzero(&localAddr, sizeof(localAddr));
		localAddr.sin_family  = AF_INET;
		getINET4Info((struct in_addr*)&localAddr.sin_addr, NULL, NULL);
		/* bind to local address */
		ret_val = (bind(m_sockICMP,
					(struct sockaddr*)&localAddr, sizeof(localAddr)) != 0) ? 12 : ret_val;
		exit_if_fail(ret_val);
    }
	else
	{
		struct sockaddr_in6 localAddr;
		/* compose local address */
		bzero(&localAddr, sizeof(localAddr));
		localAddr.sin6_family  = AF_INET6;
		getINET6Info((struct in6_addr*)&localAddr.sin6_addr);
		/* bind to local address */
		ret_val = (bind(m_sockICMP,
					(struct sockaddr*)&localAddr, sizeof(localAddr)) != 0) ? 13 : ret_val;
		exit_if_fail(ret_val);
    }

	/* alloc ping assistant resources(compose ICMP destination) */
    bzero(&m_addr4ICMPSend, sizeof(m_addr4ICMPSend));
    bzero(&m_addr6ICMPSend, sizeof(m_addr6ICMPSend));
	if (m_bINET6Ping == FALSE)
		pIPV4Addr = (struct sockaddr_in*)&m_addr4ICMPSend;
	else
		pIPV6Addr = (struct sockaddr_in6*)&m_addr6ICMPSend;
	if (pIPV4Addr != NULL)
	{
		pIPV4Addr->sin_family = AF_INET;
		memcpy(&pIPV4Addr->sin_addr, &in4_dst, sizeof(pIPV4Addr->sin_addr));
	}
	if (pIPV6Addr != NULL)
	{
		pIPV6Addr->sin6_family = AF_INET6;
		memcpy(&pIPV6Addr->sin6_addr, &in6_dst, sizeof(pIPV6Addr->sin6_addr));
	}
	/* alloc ping assistant resources(alloc ICMP send buffer) */
	if (m_bINET6Ping == FALSE)
	{
		m_sizeICMPSend = ICMP_MINLEN + m_stPingConfig.ping_echolen;
		m_buffICMPSend = (unsigned char*)calloc(1, m_sizeICMPSend + 4);
	}
	else
	{
		m_sizeICMPSend = sizeof(struct icmp6_hdr) + m_stPingConfig.ping_echolen;
		m_buffICMPSend = (unsigned char*)calloc(1, m_sizeICMPSend + 4);
	}
	ret_val = (m_buffICMPSend == NULL) ? 31 : ret_val;
	exit_if_fail(ret_val);
	/* init ICMP(send) payload buffer */
	do {
		unsigned char *ptr_pad = NULL, *pad_end = NULL;
		if (m_bINET6Ping == FALSE)
			ptr_pad = m_buffICMPSend + ICMP_MINLEN;
		else
			ptr_pad = m_buffICMPSend + sizeof(struct icmp6_hdr);
		pad_end = ptr_pad + m_stPingConfig.ping_echolen;
		for (; ptr_pad < pad_end; ptr_pad++)
		{
			unsigned char rand_char = rand() % 128;
			while (!isalnum(rand_char))
				rand_char = rand() % 128;
			memcpy(ptr_pad, &rand_char, sizeof(unsigned char));
		}
	} while (0);
	/* alloc ping assistant resources(alloc ICMP receive buffer) */
	if (m_bINET6Ping == FALSE)
	{
		m_sizeICMPRecv = sizeof(struct iphdr) + ICMP_MINLEN + m_stPingConfig.ping_echolen + 20;
		m_buffICMPRecv = (unsigned char*)calloc(1, m_sizeICMPRecv);
	}
	else
	{
		m_sizeICMPRecv = sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + m_stPingConfig.ping_echolen + 20;
		m_buffICMPRecv = (unsigned char*)calloc(1, m_sizeICMPRecv);
	}
	ret_val = (m_buffICMPRecv == NULL) ? 32 : ret_val;
	exit_if_fail(ret_val);
	/* alloc ping assistant resources(calcualte timer interval) */
	m_usecPingIntv  = MILLION-1;
	if ((m_stPingConfig.ping_speed > 1) && (m_stPingConfig.ping_speed < MILLION))
		m_usecPingIntv  = MILLION / m_stPingConfig.ping_speed;
	m_iStatSendDiff = MILLION / m_usecPingIntv;
	if (m_iStatSendDiff <= 0)
		m_iStatSendDiff = 1;
	/* alloc ping assistant resources(init ping ID) */
	m_iPingsID      = htons(ve_get_clock(NULL));
	if (m_stPingConfig.ping_timeout <= 0)
	{
		m_tmRecvTimeout.tv_sec  = m_usecPingIntv / MILLION;
		m_tmRecvTimeout.tv_usec = m_usecPingIntv % MILLION;
	}
	else
	{
		m_tmRecvTimeout.tv_sec  = (m_stPingConfig.ping_timeout*1000) / MILLION;
		m_tmRecvTimeout.tv_usec = (m_stPingConfig.ping_timeout*1000) % MILLION;
	}

	/* clear ping assistant statistics */
	m_bResolveFail    = FALSE;
	bzero(&m_tmPingStart, sizeof(m_tmPingStart));
	bzero(&m_tmPingStop, sizeof(m_tmPingStop));
	bzero(&m_tmPingStat, sizeof(m_tmPingStat));
	memcpy(&m_addr4PingReply, &in4_dst, sizeof(m_addr4PingReply));
	memcpy(&m_addr6PingReply, &in6_dst, sizeof(m_addr6PingReply));
	bzero(&m_tmSendStamp, sizeof(m_tmSendStamp));

	m_iPingsSend      = 0;
	m_iPingsReply     = 0;
	m_iPingsDuplicate = 0;
	m_iPingsIgnored   = 0;
	m_iPingsUnrech    = 0;
	m_iPingsMiss      = 0;

	timerclear(&m_tmRoundTripCur);
	timerclear(&m_tmRoundTripMin);
	timerclear(&m_tmRoundTripMax);
	m_iRoundTripSize  = 0;
	m_tmRoundTripSum  = 0;

	m_iRecSendIndex   = 0;
	m_iRecStatIndex   = 0;
	bzero(m_stPingRecords, sizeof(m_stPingRecords));

	/* install signal hand timer */
	g_pPingOBJ = this;

	/* install first timer */
	ualarm(1, 0);

lzExit:
	#ifdef _PING_DEBUG_
	fprintf(stderr, "ping start!(ret=%d)\n", ret_val);
	#endif/*_PING_DEBUG_*/
	return 0;
}

int CNetTest_Ping::stopTest()
{
	/* install signal hand timer */
	g_pPingOBJ = NULL;

	/* clear ping resources */
	if (m_sockICMP > 0)
		close(m_sockICMP);
	m_sockICMP = -1;
	bzero(&m_addr4ICMPSend, sizeof(m_addr4ICMPSend));
	bzero(&m_addr6ICMPSend, sizeof(m_addr6ICMPSend));
	m_sizeICMPSend = 0;
	if (m_buffICMPSend != NULL)
		free(m_buffICMPSend);
	m_buffICMPSend = NULL;
	m_sizeICMPRecv = 0;
	if (m_buffICMPRecv != NULL)
		free(m_buffICMPRecv);
	m_buffICMPRecv = NULL;
	m_usecPingIntv  = 0;
	m_iStatSendDiff = 0;
	m_iPingsID      = 0;
	bzero(&m_tmRecvTimeout, sizeof(m_tmRecvTimeout));

	/* update ping statistics */
	if (timerisset(&m_tmPingStart))
	{
		ve_get_clock(&m_tmPingStop);
	}

	return 0;
}

int CNetTest_Ping::statPingRecord(int iRecordIndex)
{
	int  ret_val = 0;
	struct timeval rtp_this;

	/* check record */
	ret_val = ((iRecordIndex < 0) || (iRecordIndex >= SIZEOF(m_stPingRecords))) ? 1 : ret_val;
	exit_if_fail(ret_val);

	if (m_stPingRecords[iRecordIndex].send_mark == 0)
		exit_no_condition();
	if (m_stPingRecords[iRecordIndex].stat_mark != 0)
		exit_no_condition();
	#ifdef _PING_DEBUG_
	fprintf(stderr, "stat ping result record(index=%d) ...\n", iRecordIndex);
	#endif/*_PING_DEBUG_*/

	/* turn record statistics mark */
	m_stPingRecords[iRecordIndex].stat_mark = 1;
	if (m_stPingRecords[iRecordIndex].recv_mark == 0)
		timerclear(&rtp_this);
	else
	{
		timersub(&m_stPingRecords[iRecordIndex].recv_stamp,
				&m_stPingRecords[iRecordIndex].send_stamp, &rtp_this);
	}

	/* update ping statistics */
	// m_iPingsSend
	if (m_stPingRecords[iRecordIndex].recv_mark)
	{
		m_iPingsReply += 1;
	}
	// m_iPingsDuplicate
	// m_iPingsIgnored
	// m_iPingsUnrech
	if (m_stPingRecords[iRecordIndex].recv_mark == 0)
	{
		m_iPingsMiss  += 1;
	}

	if (timerisset(&rtp_this))
	{
		memcpy(&m_tmRoundTripCur, &rtp_this, sizeof(m_tmRoundTripCur));
		if (!timerisset(&m_tmRoundTripMin))
			memcpy(&m_tmRoundTripMin, &rtp_this, sizeof(m_tmRoundTripMin));
		else if (timercmp(&rtp_this, &m_tmRoundTripMin, <))
			memcpy(&m_tmRoundTripMin, &rtp_this, sizeof(m_tmRoundTripMin));
		if (timercmp(&rtp_this, &m_tmRoundTripMax, >))
			memcpy(&m_tmRoundTripMax, &rtp_this, sizeof(m_tmRoundTripMax));
		m_iRoundTripSize += 1;
		m_tmRoundTripSum += rtp_this.tv_sec * MILLION + rtp_this.tv_usec;
	}

lzExit:
	return (ret_val == 0) ? 0 : -1;
}

int CNetTest_Ping::sendPingPackage()
{
	int ret_val = 0;
	int iRecordIndex = 0;
	unsigned int  send_id = 0;
	struct icmp*      send_pkt4 = NULL;
	struct icmp6_hdr* send_pkt6 = NULL;

	/* remember ping record to overall statistics */
	iRecordIndex = m_iRecSendIndex % SIZEOF(m_stPingRecords);
	statPingRecord(iRecordIndex);
	bzero(&m_stPingRecords[iRecordIndex], sizeof(m_stPingRecords[iRecordIndex]));

	/* check member status */
	ret_val = (m_buffICMPSend == NULL) ? 11 : ret_val;
	exit_if_fail(ret_val);
	ret_val = (m_sockICMP < 0) ? 12 : ret_val;
	exit_if_fail(ret_val);
	send_id = (m_iRecSendIndex+1) & 0x0000FFFF;
	ve_get_clock(&m_tmSendStamp);
	if (m_bINET6Ping == FALSE)
		send_pkt4 = (struct icmp*)m_buffICMPSend;
	else
		send_pkt6 = (struct icmp6_hdr*)m_buffICMPSend;

	/* compose ICMPv4 echo packet */
	if (send_pkt4 != NULL)
	{
		send_pkt4->icmp_type  = ICMP_ECHO;
		send_pkt4->icmp_code  = 0;
		send_pkt4->icmp_cksum = 0;
		send_pkt4->icmp_seq   = htons(send_id);
		send_pkt4->icmp_id    = m_iPingsID;
		send_pkt4->icmp_cksum = u16CheckSum(send_pkt4, m_sizeICMPSend);
	}
	/* compose ICMPv6 echo packet */
	if (send_pkt6 != NULL)
	{
		send_pkt6->icmp6_type  = ICMP6_ECHO_REQUEST;
		send_pkt6->icmp6_code  = 0;
		send_pkt6->icmp6_cksum = 0;  /* checksum field */
		send_pkt6->icmp6_id    = m_iPingsID;
		send_pkt6->icmp6_seq   = htons(send_id);
		send_pkt6->icmp6_cksum = u16CheckSum(send_pkt6, m_sizeICMPSend);
	}

	/* send ICMP echo packet */
	if (m_bINET6Ping == FALSE)
		sendto(m_sockICMP, m_buffICMPSend, m_sizeICMPSend, 0,
			(const struct sockaddr*)&m_addr4ICMPSend, sizeof(m_addr4ICMPSend));
	else
		sendto(m_sockICMP, m_buffICMPSend, m_sizeICMPSend, 0,
			(const struct sockaddr*)&m_addr6ICMPSend, sizeof(m_addr6ICMPSend));
	#ifdef _PING_DEBUG_
	fprintf(stderr, "ping packet(index=%u) sent!\n", iRecordIndex);
	#endif/*_PING_DEBUG_*/

	/* update ping record */
	m_iRecSendIndex = m_iRecSendIndex + 1;
	m_stPingRecords[iRecordIndex].send_id = send_id;
	m_stPingRecords[iRecordIndex].send_mark = 1;
	m_stPingRecords[iRecordIndex].recv_mark = 0;
	m_stPingRecords[iRecordIndex].stat_mark = 0;
	memcpy(&m_stPingRecords[iRecordIndex].send_stamp,
			&m_tmSendStamp, sizeof(m_stPingRecords[iRecordIndex].send_stamp));
	timerclear(&m_stPingRecords[iRecordIndex].recv_stamp);

	/* update ping statistics */
	if (!timerisset(&m_tmPingStart))
	{
		memcpy(&m_tmPingStart, &m_tmSendStamp, sizeof(m_tmPingStart));
	}
	m_iPingsSend += 1;

lzExit:
	return (ret_val == 0) ? 0 : -1;
}

int CNetTest_Ping::recvPingPackage(const struct timeval* ptmRecvWait)
{
	int ret_val = 0;
	fd_set read_set;
	struct timeval read_timeout;
	int        recv_size  = 0;
	struct icmp*  icmp4hdr = NULL;
	struct icmp6_hdr* icmp6hdr = NULL;
	int    newack_recv    = 0;
	struct sockaddr_in  in4_from;
	struct sockaddr_in6 in6_from;
	#ifdef _PING_DEBUG_
	fprintf(stderr, "start ...\n");
	#endif/*_PING_DEBUG_*/

	/* check member status */
	ret_val = (m_buffICMPRecv == NULL) ? 11 : ret_val;
	exit_if_fail(ret_val);
	ret_val = (m_sockICMP < 0) ? 12 : ret_val;
	exit_if_fail(ret_val);

	/* wait&read ICMP packet */
	FD_ZERO(&read_set);
	FD_SET(m_sockICMP, &read_set);
	if (timerisset(ptmRecvWait))
	{
		memcpy(&read_timeout, ptmRecvWait, sizeof(read_timeout));
	}
	else
	{
		read_timeout.tv_sec  = 0;
		read_timeout.tv_usec = 0;
	}
	if (select(m_sockICMP+1, &read_set, NULL, NULL, &read_timeout) <= 0)
	{
		exit_no_condition();
	}
	ret_val = (!FD_ISSET(m_sockICMP, &read_set)) ? 21 : ret_val;
	exit_if_fail(ret_val);
	if (m_bINET6Ping == FALSE)
	{
		socklen_t in4_from_len = sizeof(in4_from);
		bzero(&in4_from, sizeof(in4_from));
		recv_size = recvfrom(m_sockICMP, m_buffICMPRecv, m_sizeICMPRecv, 0,
			(struct sockaddr*)&in4_from, &in4_from_len);
		ret_val = (recv_size <= 0) ? 22 : ret_val;
		exit_if_fail(ret_val);
	}
	else
	{
		socklen_t in6_from_len = sizeof(in6_from);
		bzero(&in6_from, sizeof(in6_from));
		recv_size = recvfrom(m_sockICMP, m_buffICMPRecv, m_sizeICMPRecv, 0,
			(struct sockaddr*)&in6_from, &in6_from_len);
		ret_val = (recv_size <= 0) ? 23 : ret_val;
		exit_if_fail(ret_val);
	}

	/* check ICMP packet */
	if (m_bINET6Ping == FALSE)
	{
		struct iphdr *ip4hdr   = NULL;
		unsigned int  ip4hdr_len = 0;
		ret_val = (recv_size < sizeof(struct iphdr)) ? 31 : ret_val;
		exit_if_fail(ret_val);
		ip4hdr = (struct iphdr*)&m_buffICMPRecv[0];
		ip4hdr_len = ip4hdr->ihl * 4;
		ret_val = (recv_size < (ip4hdr_len + m_sizeICMPSend)) ? 32 : ret_val;
		exit_if_fail(ret_val);
		icmp4hdr = (struct icmp*)&m_buffICMPRecv[ip4hdr_len];
		#ifdef _PING_DEBUG_
		{
			char sz_src[128] = "";
			inet_ntop(AF_INET, &in4_from.sin_addr, sz_src, sizeof(sz_src));
			fprintf(stderr, "package(src=%s, recv=%d, hdr=%d, sent=%d) received!\n",
				sz_src, recv_size, ip4hdr_len, m_sizeICMPSend);
		}
		#endif/*_PING_DEBUG_*/
		ret_val = (icmp4hdr->icmp_type != ICMP_ECHOREPLY) ? 33 : ret_val;
		exit_if_fail(ret_val);
		ret_val = (icmp4hdr->icmp_id != m_iPingsID) ? 34 : ret_val;
		exit_if_fail(ret_val);
		ve_get_clock(&m_tmRecvStamp);
		#ifdef _PING_DEBUG_
		fprintf(stderr, "ICMPv4 echo reply received!\n");
		#endif/*_PING_DEBUG_*/
	}
	else
	{
		ret_val = (recv_size < m_sizeICMPSend) ? 42 : ret_val;
		exit_if_fail(ret_val);
		icmp6hdr = (struct icmp6_hdr*)&m_buffICMPRecv[0];
		#ifdef _PING_DEBUG_
		{
			char sz_src[128] = "";
			inet_ntop(AF_INET6, &in6_from.sin6_addr, sz_src, sizeof(sz_src));
			fprintf(stderr, "package(src=%s, recv=%d, sent=%d) received!\n",
				sz_src, recv_size, m_sizeICMPSend);
		}
		#endif/*_PING_DEBUG_*/
		ret_val = (icmp6hdr->icmp6_type != ICMP6_ECHO_REPLY) ? 43 : ret_val;
		exit_if_fail(ret_val);
		ret_val = (icmp6hdr->icmp6_id != m_iPingsID) ? 44 : ret_val;
		exit_if_fail(ret_val);
		ve_get_clock(&m_tmRecvStamp);
		#ifdef _PING_DEBUG_
		fprintf(stderr, "ICMPv6 echo reply received!\n");
		#endif/*_PING_DEBUG_*/
	}

	/* parse ICMP packet */
	if (m_bINET6Ping == FALSE)
	{
		int            iRecordIndex = 0;
		unsigned int   send_id = 0;
		unsigned int   round_trip = 0;

		send_id = ntohs(icmp4hdr->icmp_seq);

		iRecordIndex = (send_id-1) % SIZEOF(m_stPingRecords);
		if ((m_stPingRecords[iRecordIndex].send_id != send_id) ||
			(m_stPingRecords[iRecordIndex].send_mark == 0))
		{
			exit_no_condition();
		}
		if (m_stPingRecords[iRecordIndex].recv_mark != 0)
		{
			m_iPingsDuplicate += 1;
			exit_no_condition();
		}

		/* do not record this ping reply if timeout */
		do {
			struct timeval stamp_timeout;
			timeradd(&m_stPingRecords[iRecordIndex].send_stamp,
						&m_tmRecvTimeout, &stamp_timeout);
			if (timercmp(&m_tmRecvStamp, &stamp_timeout, >))
			{
				m_iPingsIgnored += 1;
				exit_no_condition();
			}
		} while (0);

		/* update ping record */
		// m_stPingRecords[iRecordIndex].send_id
		// m_stPingRecords[iRecordIndex].send_mark
		m_stPingRecords[iRecordIndex].recv_mark = 1;
		// m_stPingRecords[iRecordIndex].stat_mark
		// m_stPingRecords[iRecordIndex].send_stamp
		memcpy(&m_stPingRecords[iRecordIndex].recv_stamp,
						&m_tmRecvStamp, sizeof(m_stPingRecords[iRecordIndex].recv_stamp));

		memcpy(&m_addr4PingReply, &in4_from.sin_addr, sizeof(m_addr4PingReply));

		/* update ping statistics here */
		statPingRecord(iRecordIndex);
		newack_recv = 1;
	}
	else
	{
		int            iRecordIndex = 0;
		unsigned int   send_id = 0;
		unsigned int   round_trip = 0;

		send_id = ntohs(icmp6hdr->icmp6_seq);

		iRecordIndex = (send_id-1) % SIZEOF(m_stPingRecords);
		if ((m_stPingRecords[iRecordIndex].send_id != send_id) ||
			(m_stPingRecords[iRecordIndex].send_mark == 0))
		{
			exit_no_condition();
		}
		if (m_stPingRecords[iRecordIndex].recv_mark != 0)
		{
			m_iPingsDuplicate += 1;
			exit_no_condition();
		}

		/* do not record this ping reply if timeout */
		do {
			struct timeval stamp_timeout;
			timeradd(&m_stPingRecords[iRecordIndex].send_stamp,
						&m_tmRecvTimeout, &stamp_timeout);
			if (timercmp(&m_tmRecvStamp, &stamp_timeout, >))
			{
				m_iPingsIgnored += 1;
				exit_no_condition();
			}
		} while (0);

		/* update ping record */
		// m_stPingRecords[iRecordIndex].send_id
		// m_stPingRecords[iRecordIndex].send_mark
		m_stPingRecords[iRecordIndex].recv_mark = 1;
		// m_stPingRecords[iRecordIndex].stat_mark
		// m_stPingRecords[iRecordIndex].send_stamp
		memcpy(&m_stPingRecords[iRecordIndex].recv_stamp,
						&m_tmRecvStamp, sizeof(m_stPingRecords[iRecordIndex].recv_stamp));

		memcpy(&m_addr6PingReply, &in6_from.sin6_addr, sizeof(m_addr6PingReply));

		/* update ping statistics here */
		statPingRecord(iRecordIndex);
		newack_recv = 1;
	}

	/* report ping result if: low speed ping && new ping response received */
	if (newack_recv && (m_stPingConfig.ping_speed <= 1))
	{
		reportPingResult(TRUE);
		ve_get_clock(&m_tmPingStat);
	}

lzExit:
	#ifdef _PING_DEBUG_
	fprintf(stderr, "done!(ret=%d)\n", ret_val);
	#endif/*_PING_DEBUG_*/
	return (ret_val == 0) ? 0 : -1;
}

static void ping_timer_sighandler(int sigNum)
{
	if (g_pPingOBJ != NULL)
	{
		g_pPingOBJ->onPingTimer();
	}
}
