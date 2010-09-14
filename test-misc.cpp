
#include "../../include/ethcommif.h"
#include "mx300def.h"
#include "../../../include/v300ipc.h"

#include <stdio.h>
#include <time.h>
#include <sys/time.h> 
#include <stdlib.h>
#include <assert.h>

void getCurSysTime(char *pSysTime)
{
	struct timeval time;
	struct tm * p;
	
	gettimeofday( &time, NULL );
	p = gmtime((time_t *)&time);
	
	pSysTime[0] = (unsigned char)p->tm_sec;
	pSysTime[1] = (unsigned char)p->tm_min;
	pSysTime[2] = (unsigned char)p->tm_hour;
	pSysTime[3] = 0;
	pSysTime[4] = (unsigned char)p->tm_mday;
	pSysTime[5] = (unsigned char)p->tm_mon;
	pSysTime[6] = (unsigned char)p->tm_year - 70;
}

void init_list(stList* list)
{
	list->num = 0;
	list->new_node = 1;
	list->first = NULL;
}

int append_list_node(stList* list,stListNode* node)
{
	stListNode* pNode = NULL;
	if (list == NULL)
		return -1;

	pNode = list->first;
	if (pNode == NULL)
	{
		list->first = node;
		node->next = NULL;
		list->num++;
		return list->num;
	}

	while(pNode->next != NULL)
	{
		pNode = pNode->next;
	}
	pNode->next = node;
	node->next = NULL;
	list->num++;
	return list->num;
}

stListNode* get_n_node(stList* list, int index)
{
	int i;
	stListNode* pNode = NULL;
	if (list == NULL || index <= 0 || index > list->num)
		return NULL;

	pNode = list->first;
	for (i=1; i<index; i++)
	{
		pNode = pNode->next;
	}
	return pNode;
}

stListNode* del_n_node(stList* list, int index)
{
	int i;
	stListNode* pNode = NULL;
	stListNode* pPreNode = NULL;
	if (list == NULL || index <= 0 || index > list->num)
		return NULL;

	pPreNode = pNode = list->first;
	if (index == 1)
	{
		list->first = pNode->next;
		list->num--;
	}
	else
	{
		for (i=1; i<index; i++)
		{
			pNode = pPreNode->next;
			if (i == index -1)
			{
				pPreNode->next = pNode->next;
				list->num--;
				break;
			}
			else
			{
				pPreNode = pNode;
			}
		}
	}
	return pNode;
}

#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#if defined(OLD_SIOCGIFHWADDR) || (KERNEL_VERSION >= 1003038)
#define NET3
#endif

int OpenRawSocket(const char *eth_name, unsigned short netid)
{

	int s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s < 0)
	{
		perror("OpenRawSocket() socket failed:");
		return -1;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	memcpy(ifr.ifr_name, eth_name,sizeof(eth_name));
	if (ioctl(s, SIOCGIFINDEX, &ifr) == -1)
	{
		perror("OpenRawSocket() ioctl error:");
		close(s);
		return -1;
	}
	
	struct sockaddr_ll	saddr;
	memset(&saddr, 0, sizeof(saddr));
	saddr.sll_family = PF_PACKET;//AF_PACKET;
	saddr.sll_ifindex = ifr.ifr_ifindex;
	saddr.sll_protocol = htons(ETH_P_ALL);
	if (bind(s, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) 
	{
		perror("OpenRawSocket() bind failed:");
		close(s);
		return -1;
	}

	struct packet_mreq mr;
	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = ifr.ifr_ifindex;
	mr.mr_type    = PACKET_MR_PROMISC;
	if (setsockopt(s, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1) 
	{
		perror("OpenRawSocket() setsockopt failed:");
		close(s);
		return -1;
	}

	return s;
}

/*
  * Close a file handle to a raw packet type.
  */
void CloseRawSocket(int sock)
{
	close(sock);
}

/*
  *Write a packet to the network. You have to give a device to this function. 
  *This is a device name (eg 'eth0' for the first ethernet card).
  */
int WriteRawSocket(int sock, const char *device, const char *data, int len)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	memcpy(ifr.ifr_name, device,sizeof(device));
	if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1)
	{
		perror("WriteRawSocket() ioctl error:");
		return -1;
	}
	
	struct sockaddr_ll	saddr;
	memset(&saddr, 0, sizeof(saddr));
	saddr.sll_family = PF_PACKET;
	saddr.sll_ifindex = ifr.ifr_ifindex;
	saddr.sll_protocol = htons(ETH_P_ALL);

	return (sendto(sock, data, len, 0, (struct sockaddr *)&saddr, sizeof(saddr)));
}

/*
  * Read a packet from the network. The device parameter will be filled in by this routine (make it 32 bytes or more).
  * If you wish to work with one interface only you must filter yourself. 
  * Remember to make your buffer big enough for your data. Oversized packets will be truncated.
  */
int ReadRawSocket(int sock, char *data, int len)
{
	struct sockaddr sa;
	socklen_t sz = sizeof(sa);
	return (recvfrom(sock, data, len, 0, &sa, &sz));     /* Actually size of received packet */
}

/*
  * Obtain the hardware address of an interface. addr should be a buffer of 8 bytes or more.
  */
int getSocketAddress(char *device, char *addr)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq req;
	int err;
	strcpy(req.ifr_name, device);
	err = ioctl(s, SIOCGIFHWADDR, &req);
	close(s); 
	if (err == -1)
		return err;
	memcpy(addr, req.ifr_hwaddr.sa_data,8);
	return 0;
}

/*
  * Obtain the maximum packet size on an interface
  */
int GetDeviceMTU(char *device)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq req;
	int err;
	strcpy(req.ifr_name, device);
	err = ioctl(s, SIOCGIFMTU, &req);
	close(s);
	if (err == -1)
		return err;
	return req.ifr_mtu;
}

//file operation.
int getFileLength(const char *filename)
{
	int file_len = 0;
	if (filename == NULL)
		return 0;
	
	FILE* fd = fopen(filename, "rb");
	if(!fd)
	{
		printf("Open file %s failed.\n", filename);
		return -1;
	}
	fseek(fd, 0, SEEK_END);
	file_len = ftell(fd);
	fseek(fd, 0, SEEK_SET);
	fclose(fd);
	return file_len;
}

int ReadFile(const char *filename,unsigned char *pBuff, int size)
{
	int file_len = 0;
	if (filename == NULL || pBuff == NULL)
	{
		return 0;
	}
	
	FILE* fd = fopen(filename, "rb");
	if(!fd)
	{
		printf("ReadFile() Open file %s failed.\n", filename);
		return 0;
	}
	
	fseek(fd, 0, SEEK_END);
	file_len = ftell(fd);
	if (file_len > size)
	{
		printf("ReadFile() The length of file<%s> is more than size of memory, file length = %d and size of memory = %d\n",filename,file_len,size);
		fclose(fd);
		return -1;
	}
	fseek(fd, 0, SEEK_SET);
	
	if (!fread(pBuff, file_len, 1, fd))
	{
		printf("ReadFile() read file %s failed!\n",pBuff);
		fclose(fd);
		return 0;
	}
	fclose(fd);
	return file_len;
}

int WriteFile(const char *filename,unsigned char *pBuff, int size)
{
	int file_len = 0;
	if (filename == NULL || pBuff == NULL)
	{
		return 0;
	}
	
	FILE* fd = fopen(filename, "wb");
	if(!fd)
	{
		printf("WriteFile() Open file %s failed.\n", filename);
		return 0;
	}
	
	file_len = fwrite(pBuff, size, 1, fd);
	fclose(fd);
	return file_len;
}

void setSystemSrcIP(unsigned char *src_IP, int port_id)
{
	char pBuff[64];
	memset(pBuff, 0, 64);
	sprintf(pBuff,"ifconfig eth0:%d %d.%d.%d.%d",port_id+1,src_IP[0],src_IP[1],src_IP[2],src_IP[3]);
	printf("%s\n",pBuff);
	system(pBuff);
}

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int set_pktinfo_option(int socket_fd)
{
	const int	on = 1;
	if(setsockopt(socket_fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(int)) < 0)
	{
		perror("setsockopt");
		return -1;
	}
	return 0;
}

int bind2device(int socket_fd, char *devstring)
{
	if(NULL == devstring)
	{
		dbg_printf("bind2device() cancel binding to device");
		setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, " ", 0);
	}else{
		dbg_printf("bind2device() bind to devname %s", devstring);
		setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, devstring, strlen(devstring));
	}

	return 0;
}

#include <errno.h>
int udpsock_dup(int s, const char* dupdev, int dbg_verbose)
{
	int dupsock = -1;
	struct in_addr dev_addr;

	bzero(&dev_addr, sizeof(dev_addr));
	if ((dupdev != NULL) && (dupdev[0] != '\0'))
	{
		struct ifreq if_req;
		bzero(&if_req, sizeof(if_req));
		strcpy(if_req.ifr_name, dupdev);
		if_req.ifr_addr.sa_family = AF_INET;
		if (ioctl(s, SIOCGIFADDR, &if_req) == 0)
		{
			memcpy(&dev_addr, &((struct sockaddr_in*)(&if_req.ifr_addr))->sin_addr, sizeof(dev_addr));
		}
	}

	if (dev_addr.s_addr != htonl(INADDR_ANY))
	{
		int opt_on = 1;
		socklen_t addr_len = 0;
		struct sockaddr_in bind_addr;

		/* open duplicate socket */
		dupsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (setsockopt(dupsock, SOL_SOCKET, SO_REUSEADDR, &opt_on, sizeof(opt_on)) != 0)
		{
			if (dbg_verbose)
			{
				printf("set duplicate socket SO_REUSEADDR failed(%s)!\n",
					strerror(errno));
			}
		}

		/* bind it to original socket's address */
		addr_len = sizeof(bind_addr);
		bzero(&bind_addr, sizeof(bind_addr));
		if (getsockname(s, (struct sockaddr*)&bind_addr, &addr_len) == 0)
		{
			bind_addr.sin_addr.s_addr = dev_addr.s_addr;
			if (bind(dupsock, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) == 0)
			{
				if (dbg_verbose)
				{
					printf("rebind duplicate socket to %s:%u success!\n",
						inet_ntoa(bind_addr.sin_addr), ntohs(bind_addr.sin_port));
				}
			}
			else
			{
				if (dbg_verbose)
				{
					printf("rebind duplicate socket to %s:%u failed(%s)!\n",
						inet_ntoa(bind_addr.sin_addr), ntohs(bind_addr.sin_port),
						strerror(errno));
				}
			}
		}

		if (setsockopt(dupsock, SOL_SOCKET, SO_BINDTODEVICE, dupdev, strlen(dupdev)) == 0)
		{
			if (dbg_verbose)
			{
				printf("rebind duplicate socket to %s success!\n",
						dupdev);
			}
		}
		else
		{
			if (dbg_verbose)
			{
				printf("rebind duplicate socket to %s failed!\n",
						dupdev);
			}
		}
	}

	return dupsock;
}

int dupUdpsock(int socket_fd, const char* devstring)
{
	return udpsock_dup(socket_fd, devstring, 0);
}

int CreateServerSocket(unsigned short listen_port, unsigned char *IP)
{
	int socket_fd  = 0;
	char buff[32];
	
    	struct sockaddr_in listen_addr;	
	memset((char *)&listen_addr,0, sizeof(listen_addr)); 
    	listen_addr.sin_family = AF_INET;
	if (IP == NULL)
	{
		listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	}
	else
	{
		sprintf(buff,"%d.%d.%d.%d",IP[0], IP[1], IP[2],IP[3]);
		listen_addr.sin_addr.s_addr = inet_addr(buff);
	}
	listen_addr.sin_port = htons(listen_port);

    	socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    	if (socket_fd == -1)
    	{
    		printf("OpenUDPServerSocket(Listen port = %d):SOCKET() failed\n",listen_port);
		return -1;
    	}
  
 	int sockopt = 1;
    	if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR,(const char *)&sockopt, sizeof(int)) < 0) 
    	{
    		printf("OpenUDPServerSocket(Listen port = %d):setsockopt() failed\n",listen_port);
		close(socket_fd);
		return -1;
    	}
#ifdef IP_PKTINFO
	if(set_pktinfo_option(socket_fd) < 0)
	{
		close(socket_fd);
		return -1;
	}
#endif

    	if (bind(socket_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) == -1)
    	{
    		printf("OpenUDPServerSocket(Listen port = %d):bind() failed\n",listen_port);
		close(socket_fd);
        	return -1;
    	}
	return socket_fd;
}

int CreateUnicastSocket()
{
	int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
#if 0
	struct sockaddr_in listen_addr;

	bzero(&listen_addr, sizeof(listen_addr));
	listen_addr.sin_family = AF_INET;
	if (socket_fd > 0)
	{
		bind(socket_fd, (struct sockaddr*)&listen_addr, sizeof(listen_addr));
	}
#endif
#ifdef IP_PKTINFO
	if(set_pktinfo_option(socket_fd) < 0)
	{
		close(socket_fd);
		return -1;
	}
#endif
	return socket_fd;
}

int CreateBroadcastSocket()
{
	int socket_fd =  socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_fd == -1)
	{
    		printf("CreateBroadcastUDPSocket():SOCKET() failed\n");
		return -1;
	}
	int sockopt = 1;
	if (setsockopt(socket_fd, SOL_SOCKET, SO_BROADCAST, (char *) &sockopt, sizeof(sockopt)) < 0)
	{
    		printf("CreateBroadcastUDPSocket():setsockopt() failed\n");
		close(socket_fd);
		return -1;
	}
#ifdef IP_PKTINFO
	if(set_pktinfo_option(socket_fd) < 0)
	{
		close(socket_fd);
		return -1;
	}
#endif

	return socket_fd;
}

int SendPacket(int socket_fd, unsigned char *IP, unsigned short port, char *pBuff, int size)
{
	assert(pBuff != NULL && size > 0);

	struct sockaddr_in send_addr;
	char buff[32];
	
	sprintf(buff,"%d.%d.%d.%d",IP[0], IP[1], IP[2],IP[3]);
	
    	memset((char *)&(send_addr), 0,sizeof(send_addr));
	send_addr.sin_family = AF_INET;
    	send_addr.sin_addr.s_addr = inet_addr(buff);
   	send_addr.sin_port = htons(port);
	
	return sendto(socket_fd, pBuff, size,0,(struct sockaddr *)&(send_addr),sizeof(send_addr));
}

#if 0

int RecvPacket(int socket_fd, unsigned char *IP, unsigned short &port, char *pBuff, int size, bool isBlock)
{
	assert(pBuff != NULL && size > 0 && IP != NULL);
	
	int flag = 0;
	int ret = 0;
	struct sockaddr_in recv_addr;
	socklen_t addrlen = sizeof(recv_addr);
	
	if(sock_waitdata(socket_fd, 0))
	{
		ret = recvfrom(socket_fd,pBuff, size, flag,(struct sockaddr *)&recv_addr, &addrlen);
		if (ret > 0)
		{
			memcpy(IP, (unsigned char *)&(recv_addr.sin_addr.s_addr), ETH_IP_LEN);
			port = ntohs(recv_addr.sin_port);
		}
	}
	return ret;
}
int sock_waitdata(int s, int wait_usec)
{
	int flag_data = 0;
	fd_set wait_set;
	struct timeval time_out;

	FD_ZERO(&wait_set);
	FD_SET(s, &wait_set);
	time_out.tv_sec  = wait_usec / 1000000;
	time_out.tv_usec = wait_usec % 1000000;

	if (select(s+1, &wait_set, NULL, NULL, &time_out) > 0)
	{
		flag_data = FD_ISSET(s, &wait_set);
	}

	return flag_data;
}
#else

int RecvPacket(int socket_fd, unsigned char *IP, unsigned short &port, char *pBuff, int size, bool isBlock, unsigned char *DstIP)
{
	assert(pBuff != NULL && size > 0 && IP != NULL);
	
	int flag = 0;
	ssize_t				ret;
	struct msghdr			msg;
	struct cmsghdr		*cmsgptr;
	struct iovec			iov[1];
	union{
		struct cmsghdr	cmsg;
		char				control[CMSG_SPACE(sizeof(struct in_pktinfo))];
	}cmsg_un;

	struct sockaddr_in recv_addr;
	memset(&recv_addr, 0, sizeof(recv_addr));
//	socklen_t addrlen = sizeof(recv_addr);
	msg.msg_name		= &recv_addr;
	msg.msg_namelen		= sizeof(recv_addr);
	iov[0].iov_base		= pBuff;
	iov[0].iov_len			= size;
	msg.msg_iov			= iov;
	msg.msg_iovlen		= 1;
	msg.msg_control		= cmsg_un.control;
	msg.msg_controllen	= sizeof(cmsg_un.control);
	msg.msg_flags		= 0;

	if (!isBlock)
		flag = MSG_DONTWAIT;

//	int select_data = sock_waitdata(socket_fd, 0);
	if((ret = recvmsg(socket_fd, &msg, flag)) <= 0)
	{
		perror("recvmsg");
		//dbg_printf("recvmsg didnot receive any valid data select_data(%d)", select_data);
		return ret;
	}
	if((msg.msg_controllen < sizeof(struct cmsghdr)) || (msg.msg_flags & MSG_CTRUNC))
	{
		dbg_printf("received packet not correct: msg_controllen too short or MSG_CTRUNC flag is on");
		return ret;
	}
	// copy src IP and port of the packet
	memcpy(IP, (unsigned char *)&(recv_addr.sin_addr.s_addr), ETH_IP_LEN);
	port = ntohs(recv_addr.sin_port);
//	dbg_printf("received packet length = %d, from IP %s, port %d", 
//		ret, inet_ntoa(recv_addr.sin_addr), ntohs(recv_addr.sin_port));

//	dbg_printf("received packet len = %d", ret);
	if(NULL == DstIP)
	{
		return ret;
	}
	// get packet dest IP only when DstIP is not NULL
	struct in_addr		dstAddr;
	memset(&dstAddr, 0, sizeof(dstAddr));
	for(cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr; cmsgptr = CMSG_NXTHDR(&msg, cmsgptr))
	{
#ifdef IP_PKTINFO
//		dbg_printf("IP_PKTINFO defined get pkt info");
		if(cmsgptr->cmsg_level == SOL_IP && cmsgptr->cmsg_type == IP_PKTINFO)
		{
			struct in_pktinfo *in = (struct in_pktinfo *)CMSG_DATA(cmsgptr);
			memcpy(&dstAddr, &(in->ipi_addr), sizeof(struct in_addr));
		}
#endif
	}
	memcpy(DstIP, (unsigned char *)&(dstAddr.s_addr), ETH_IP_LEN);
//	dbg_printf("packet dest IP is %s", inet_ntoa(dstAddr));
	return ret;
}
#endif

void CloseSocket(int socket_fd)
{
	close(socket_fd);
}


void hex_printf(char *pBuff, int size)
{
	for (int i=0; i<size; )
	{
		printf("0x%08X   ",i);
		for (int j=0; j<16 && (i+j) < size; j++)
			printf("%02X ",pBuff[i+j]);
		printf("\n");
		i += 16;
	}
}

void printmem(char *pmemory, int size)
{
	char *pcur = pmemory;

	if(NULL == pcur)
	{
		dbg_printf("Error, NULL pointer encountered!");
		return;
	}
	
	printf("----- Print Memory Start ------");
	for( ; pcur < pmemory + size; pcur++)
	{
		if((int)(pcur - pmemory) % 32 == 0)
		{
			printf("\n%08x\t", (uint32)(pcur-pmemory));
		}
		printf("%02x ", (unsigned char)*pcur);
	}
	dbg_printf("\n----- Print Memory End ------");
}

int getMsglen()
{
	int msglen = (sizeof(stEthThrptConfig) > sizeof(stEthRfc2544Config)) ? sizeof(stEthThrptConfig) : sizeof(stEthRfc2544Config);
	if(msglen % 1024 == 0)
	{
		msglen++;
	}
	// round up to 1024, leave at least 1 byte for checksum to use
	msglen = (msglen / 1024 + 1) * 1024;
	return msglen;
}

void bert_configure_printf(const stEthBertConfig &config)
{
	printf("\n**************Bert configure:sizeof(stEthBertConfig) = %d***************\n",sizeof(stEthBertConfig));
	stEthBertConfig bert_config = config;
	printf("header: layer = %d, frmType = %d, wEthType = 0x%04X\n",bert_config.header.layer,bert_config.header.frmType,bert_config.header.wEthType);
	printf("header: SrcMAC = %02X-%02X-%02X-%02X-%02X-%02X\n",
		bert_config.header.MAC.src[0],bert_config.header.MAC.src[1],bert_config.header.MAC.src[2],bert_config.header.MAC.src[3],bert_config.header.MAC.src[4],bert_config.header.MAC.src[5]);
	printf("header: DestMAC = %02X-%02X-%02X-%02X-%02X-%02X\n",
		bert_config.header.MAC.dest[0],bert_config.header.MAC.dest[1],bert_config.header.MAC.dest[2],bert_config.header.MAC.dest[3],bert_config.header.MAC.dest[4],bert_config.header.MAC.dest[5]);
	printf("header: SrcIp = %d.%d.%d.%d\n",
		bert_config.header.ip.src[0],bert_config.header.ip.src[1],bert_config.header.ip.src[2],bert_config.header.ip.src[3]);
	printf("header: DestIp = %d.%d.%d.%d\n",
		bert_config.header.ip.dest[0],bert_config.header.ip.dest[1],bert_config.header.ip.dest[2],bert_config.header.ip.dest[3]);
	printf("header: TOSFormat = %d, ucTOS = 0x%02X\n",bert_config.header.ip.TOSFormat,bert_config.header.ip.ucTOS);
	printf("header: timeToLive = 0x%02X, protocol = 0x%02X\n",bert_config.header.ip.timeToLive,bert_config.header.ip.protocol);
	printf("header: SrcPort = %d, DestPort = %d\n",bert_config.header.port.srcPort,bert_config.header.port.detPort);
	printf("header: vlanNum = %d, mplsNum = %d\n",bert_config.header.vlan.vlanNum,bert_config.header.mpls.mplsNum);
	for (unsigned int i=0; i<bert_config.header.vlan.vlanNum; i++)
	{
		printf("header:protocol = 0x%02X,vlan id = %d, pri = %d, tunel = %d\n",
			bert_config.header.vlan.vlan[i].protocol,bert_config.header.vlan.vlan[i].vid,bert_config.header.vlan.vlan[i].pid,bert_config.header.vlan.vlan[i].tunnel);
	}
	printf("header.control: u32RxFilter = 0x%08X\n",bert_config.header.control.ucRxFilterCtr.u32RxFilter);
	printf("control: Tx_mode = %d\n",bert_config.control.Tx_mode);
	printf("traffic shape = %d\n",bert_config.traffic.shape);
	switch (bert_config.traffic.shape)
	{
	case eETH_TRAFFICSHAPE_CONST:
		printf("traffic const type = %d\n",bert_config.traffic.constant.type);
		if (bert_config.traffic.constant.type == eETH_Fixed)
		{
			printf("traffic Fix BW	= %d,framelen = %d\n",bert_config.traffic.constant.constTraf.BW,bert_config.traffic.constant.constTraf.frameLen);
			printf("traffic pattern invert = %d\n",bert_config.traffic.constant.constTraf.pattern.invert);
			printf("traffic pattern = %d\n",bert_config.traffic.constant.constTraf.pattern.pattern);
		}
		else if(bert_config.traffic.constant.type == eETH_Uniform)
		{
			printf("traffic Fix BW	= %d,framelen range [%d-%d]\n",bert_config.traffic.constant.uniformTraf.BW,
				bert_config.traffic.constant.uniformTraf.frmsizeValue[0], bert_config.traffic.constant.uniformTraf.frmsizeValue[1]);
			printf("traffic pattern invert = %d\n",bert_config.traffic.constant.uniformTraf.pattern.invert);
			printf("traffic pattern = %d\n",bert_config.traffic.constant.uniformTraf.pattern.pattern);
		}
		break;
	case eETH_TRAFFICSHAPE_RAMP:
		printf("traffic Ramp frameLen = %d,time = %d, time unit = %d(0-s,1-ms),startBW = %d,StopBw= %d,StepBW= %d\n",
			bert_config.traffic.ramp.frmLen,
			bert_config.traffic.ramp.rampTime,bert_config.traffic.ramp.rampTimeUnit,
			bert_config.traffic.ramp.startBW,bert_config.traffic.ramp.stopBW,bert_config.traffic.ramp.stepBW);
		printf("traffic pattern invert = %d\n",bert_config.traffic.ramp.pattern.invert);
		printf("traffic pattern = %d\n",bert_config.traffic.ramp.pattern.pattern);
		break;
	case eETH_TRAFFICSHAPE_BURST:
		printf("traffic burst frameLen = %d,time unit = %d(0-s,1-ms),BW1= %d,BW2=%d,time1=%d,time2=%d\n",
			bert_config.traffic.burst.frmLen,bert_config.traffic.burst.burstTimeUnit,
			bert_config.traffic.burst.BW1,bert_config.traffic.burst.BW2,
			bert_config.traffic.burst.Duration1,bert_config.traffic.burst.Duration2);
		printf("traffic pattern invert = %d\n",bert_config.traffic.burst.pattern.invert);
		printf("traffic pattern = %d\n",bert_config.traffic.burst.pattern.pattern);
		break;
	case eETH_TRAFFICSHAPE_SINGLE_BURST:
		printf("traffic singnal burst:BW = %d, frame size = %d\n",bert_config.traffic.single.BW,bert_config.traffic.single.frmLen);
		printf("traffic singnal pattern invert = %d, pattern = %d:\n",bert_config.traffic.single.pattern.invert,bert_config.traffic.single.pattern.pattern);
		if (bert_config.traffic.single.mode == eETH_FrmNum)
			printf("traffic singnal frame number = %lld\n",bert_config.traffic.single.BurstFrmNum);
		else
			printf("traffic singnal time number = %d\n",bert_config.traffic.single.BurstTime);
		break;
	default:
		printf("traffic config error:Other shape!\n");
		break;
	}

	printf("\n");
}

void thrpt_configure_printf(stEthThrptConfig &config)
{
	printf("\n**************Thrpt configure:sizeof(stEthThrptConfig) = %d***************\n",sizeof(stEthThrptConfig));
	printf("stream num = %d\n",config.stream_num);
	stEthBertConfig bert_config;
	for (unsigned int i=0; i<config.stream_num; i++)
	{
		bert_config = config.stream[i];
		printf("---------------Stream %d configure:--------------\n",i);
		printf("header: layer = %d, frmType = %d, wEthType = 0x%04X\n",bert_config.header.layer,bert_config.header.frmType,bert_config.header.wEthType);
		printf("header: SrcMAC = %02X-%02X-%02X-%02X-%02X-%02X\n",
			bert_config.header.MAC.src[0],bert_config.header.MAC.src[1],bert_config.header.MAC.src[2],bert_config.header.MAC.src[3],bert_config.header.MAC.src[4],bert_config.header.MAC.src[5]);
		printf("header: DestMAC = %02X-%02X-%02X-%02X-%02X-%02X\n",
			bert_config.header.MAC.dest[0],bert_config.header.MAC.dest[1],bert_config.header.MAC.dest[2],bert_config.header.MAC.dest[3],bert_config.header.MAC.dest[4],bert_config.header.MAC.dest[5]);
		printf("header: SrcIp = %d.%d.%d.%d\n",
			bert_config.header.ip.src[0],bert_config.header.ip.src[1],bert_config.header.ip.src[2],bert_config.header.ip.src[3]);
		printf("header: DestIp = %d.%d.%d.%d\n",
			bert_config.header.ip.dest[0],bert_config.header.ip.dest[1],bert_config.header.ip.dest[2],bert_config.header.ip.dest[3]);
		printf("header: TOSFormat = %d, ucTOS = 0x%02X\n",bert_config.header.ip.TOSFormat,bert_config.header.ip.ucTOS);
		printf("header: timeToLive = 0x%02X, protocol = 0x%02X\n",bert_config.header.ip.timeToLive,bert_config.header.ip.protocol);
		printf("header: SrcPort = %d, DestPort = %d\n",bert_config.header.port.srcPort,bert_config.header.port.detPort);
		printf("header: vlanNum = %d, mplsNum = %d\n",bert_config.header.vlan.vlanNum,bert_config.header.mpls.mplsNum);
		for (unsigned int i=0; i<bert_config.header.vlan.vlanNum; i++)
		{
			printf("header:protocol = 0x%02X,vlan id = %d, pri = %d, tunel = %d\n",
				bert_config.header.vlan.vlan[i].protocol,bert_config.header.vlan.vlan[i].vid,bert_config.header.vlan.vlan[i].pid,bert_config.header.vlan.vlan[i].tunnel);
		}
		printf("header.control: u32RxFilter = 0x%08X\n",bert_config.header.control.ucRxFilterCtr.u32RxFilter);
		printf("control: Tx_mode = %d\n",bert_config.control.Tx_mode);
		printf("traffic shape = %d\n",bert_config.traffic.shape);
		switch (bert_config.traffic.shape)
		{
		case eETH_TRAFFICSHAPE_CONST:
			printf("traffic const type = %d\n",bert_config.traffic.constant.type);
			if (bert_config.traffic.constant.type == eETH_Fixed)
			{
				printf("traffic Fix BW  = %d,framelen = %d\n",bert_config.traffic.constant.constTraf.BW,bert_config.traffic.constant.constTraf.frameLen);
				printf("traffic pattern invert = %d\n",bert_config.traffic.constant.constTraf.pattern.invert);
				printf("traffic pattern = %d\n",bert_config.traffic.constant.constTraf.pattern.pattern);
			}
			else if(bert_config.traffic.constant.type == eETH_Uniform)
			{
				printf("traffic Fix BW  = %d,framelen range [%d-%d]\n",bert_config.traffic.constant.uniformTraf.BW,
					bert_config.traffic.constant.uniformTraf.frmsizeValue[0], bert_config.traffic.constant.uniformTraf.frmsizeValue[1]);
				printf("traffic pattern invert = %d\n",bert_config.traffic.constant.uniformTraf.pattern.invert);
				printf("traffic pattern = %d\n",bert_config.traffic.constant.uniformTraf.pattern.pattern);
			}
			break;
		case eETH_TRAFFICSHAPE_RAMP:
			printf("traffic Ramp frameLen = %d,time = %d, time unit = %d(0-s,1-ms),startBW = %d,StopBw= %d,StepBW= %d\n",
				bert_config.traffic.ramp.frmLen,
				bert_config.traffic.ramp.rampTime,bert_config.traffic.ramp.rampTimeUnit,
				bert_config.traffic.ramp.startBW,bert_config.traffic.ramp.stopBW,bert_config.traffic.ramp.stepBW);
			printf("traffic pattern invert = %d\n",bert_config.traffic.ramp.pattern.invert);
			printf("traffic pattern = %d\n",bert_config.traffic.ramp.pattern.pattern);
			break;
		case eETH_TRAFFICSHAPE_BURST:
			printf("traffic burst frameLen = %d,time unit = %d(0-s,1-ms),BW1= %d,BW2=%d,time1=%d,time2=%d\n",
				bert_config.traffic.burst.frmLen,bert_config.traffic.burst.burstTimeUnit,
				bert_config.traffic.burst.BW1,bert_config.traffic.burst.BW2,
				bert_config.traffic.burst.Duration1,bert_config.traffic.burst.Duration2);
			printf("traffic pattern invert = %d\n",bert_config.traffic.burst.pattern.invert);
			printf("traffic pattern = %d\n",bert_config.traffic.burst.pattern.pattern);
			break;
		case eETH_TRAFFICSHAPE_SINGLE_BURST:
			printf("traffic singnal burst:BW = %d, frame size = %d\n",bert_config.traffic.single.BW,bert_config.traffic.single.frmLen);
			printf("traffic singnal pattern invert = %d, pattern = %d:\n",bert_config.traffic.single.pattern.invert,bert_config.traffic.single.pattern.pattern);
			if (bert_config.traffic.single.mode == eETH_FrmNum)
				printf("traffic singnal frame number = %lld\n",bert_config.traffic.single.BurstFrmNum);
			else
				printf("traffic singnal time number = %d\n",bert_config.traffic.single.BurstTime);
			break;
		default:
			printf("traffic config error:Other shape!\n");
			break;
		}
	}

	printf("\n");
}
void rfc_configure_printf(stEthRfc2544Config *pconfig)
{
	char *ptrue = "true";
	char *pfalse = "false";
	
	dbg_printf("eEthRfc2544Mode mode = %d", pconfig->mode);
	switch(pconfig->control.mode)
	{
		case eEthAsymUp:
			dbg_printf("Asymmetric Rfc2544 eEthAsymUp");
			break;
		case eEthAsymDown:
			dbg_printf("Asymmetric Rfc2544 eEthAsymDown");
			break;
		case eEthAsymUpAndDown:
			dbg_printf("Asymmetric Rfc2544 eEthAsymUpAndDown");
			break;
		case eEthManual:
			dbg_printf("Normal Rfc2544 test");
			break;
		default:
			dbg_printf("Error Rfc test mode");
			break;
	}
	// header
	dbg_printf("test layer = %d", pconfig->Header.layer);
	// frame
	dbg_printf("frame number = %d", pconfig->frame.frmNum);
	// thrpt
	dbg_printf("thrpt enable = %s", pconfig->thrpt.enable ? ptrue:pfalse);
	dbg_printf("thrpt unit = %d", pconfig->thrpt.unit);
	dbg_printf("thrpt uMaxRate = %u", pconfig->thrpt.uMaxRate);
	dbg_printf("thrpt uResolution = %u", pconfig->thrpt.uResolution);
	dbg_printf("thrpt uDuration = %u", pconfig->thrpt.uDuration);
	// background streams
	dbg_printf("background stream number = %u", pconfig->bkstream_num);
	
}

//#include "v300eprom.h"	
#include <fcntl.h>

#define	EEPROM_DEV          "/dev/i2c-0"
#define EEPROM_MAXSIZE      256
#define I2C_SLAVE	0x0703	/* Change slave address */
#define	EEPROM_I2C_ADDR	    0x51
/* smbus_access read or write markers */
#define I2C_SMBUS_READ	1
#define I2C_SMBUS_WRITE	0

#define I2C_SMBUS	0x0720	/* SMBus-level access */

int eeprom_open()
{
	int fd = 0;

	fd = open(EEPROM_DEV, O_RDWR);
	if(fd <= 0)
	{
		return -1;
	}

	// set working device
	if(ioctl(fd, I2C_SLAVE, EEPROM_I2C_ADDR) < 0)
	{
		close(fd);
		return -1;
	}

	return fd;
}

struct i2c_smbus_ioctl_data {
	char          read_write;
	unsigned char offset;
	int           len;
	unsigned char *data;
};

int eeprom_read(int fd, int offset, int len, char* buf)
{
	if(fd < 0)
	{
		dbg_printf("Invalid fd=%d", fd);
		return -1;
	}
	if((offset + len) > EEPROM_MAXSIZE)
	{
		dbg_printf("Offset=%d or len=%d Error!", offset, len);
		return -1;
	}

	struct i2c_smbus_ioctl_data args;
	unsigned char databuf[2];

	args.read_write = I2C_SMBUS_READ;
	args.offset = offset;
	args.len = 2;
	args.data = databuf;

	int ret = 0;
	char *pcur = buf;
	for(int i = 0; i < len; i ++)
	{
		ret = ioctl(fd, I2C_SMBUS, &args);
		if(ret < 0)
		{
			dbg_printf("Failed when i=%d !", i);
			return -1;
		}
		*pcur = databuf[0];
		args.offset++;
		pcur++;
	}

	return 0;	
}

const int serialno_offset = 16;
bool read_serialno(char *pbuff, int size)
{
	int i2c_fd = 0;

	// open device
	i2c_fd = eeprom_open();
	if(i2c_fd < 0)
	{
		dbg_printf("read serial No. failed! eeprom open fail");
		return false;
	}

	/* dump eprom content to iobuf */
	if(eeprom_read(i2c_fd, serialno_offset, size, pbuff) != 0)
	{
		dbg_printf("read serial No. failed! eeprom read fail");
		close(i2c_fd);
		return false;
	}
	//print serial number
//	printmem(pbuff, size);
	close(i2c_fd);
	return true;
}

bool read_mac_addr(char *pMac_addr, int size)
{
	int i2c_fd = 0;

	// open device
	i2c_fd = eeprom_open();
	if(i2c_fd < 0)
	{
		dbg_printf("read serial No. failed! eeprom open fail");
		return false;
	}

	/* dump eprom content to iobuf */
	if(eeprom_read(i2c_fd, 0, size, pMac_addr) != 0)
	{
		dbg_printf("read serial No. failed! eeprom read fail");
		close(i2c_fd);
		return false;
	}
	//print serial number
//	printmem(pbuff, size);
	close(i2c_fd);
	return true;
}

/* if a > b, return 1; if a == b, return 0; if a < b, return -1 */
int cmp_timeval(struct timeval a, struct timeval b)
{
	int ret = 0;
	if(a.tv_sec > b.tv_sec || (a.tv_sec == b.tv_sec && a.tv_usec > b.tv_usec))
	{
		ret = 1;
	}else if(a.tv_sec == b.tv_sec && a.tv_usec == b.tv_usec)
	{
		ret = 0;
	}else{
		ret = -1;
	}
	return ret;
}

/* if a > b, return the difference between a and b; else return 0 time value */
struct timeval diff_timeval(struct timeval a, struct timeval b)
{
	struct timeval ret;
	ret.tv_sec = 0;
	ret.tv_usec = 0;
	if(cmp_timeval(a, b) > 0)
	{
		if(a.tv_usec < b.tv_usec)
		{
			ret.tv_sec = a.tv_sec - b.tv_sec -1;
			ret.tv_usec = 1000000 + a.tv_usec - b.tv_usec;
		}else{
			ret.tv_sec = a.tv_sec - b.tv_sec;
			ret.tv_usec = a.tv_usec - b.tv_usec;
		}
	}
	return ret;
}
bool isZeroTimeval(struct timeval tv)
{
	if(tv.tv_sec == 0 && tv.tv_usec == 0)
	{
		return true;
	}else{
		return false;
	}
}

char rcchecksum(char *data, int size)
{
	unsigned int sum = 0;
	for(int i = 0; i < size; i++)
	{
		sum += data[i];
	}
	while(sum >> 8)
	{
		sum = (sum & 0xff) + (sum >> 8);
	}

	return (char)~sum;
}

// transform to network byte order, pconfig --> pbuff
int hton_ThrptConfig(char *pbuff, stEthThrptConfig *pconfig)
{
	memcpy(pbuff, (char*)pconfig, sizeof(stEthThrptConfig));
	return 0;
}
// transform to network byte order, pconfig --> pbuff
int hton_RfcConfig(char *pbuff, stEthRfc2544Config *pconfig)
{

	memcpy(pbuff, (char*)pconfig, sizeof(stEthRfc2544Config));
	return 0;
}

// transform to host byte order, pbuff --> pconfig
int ntoh_ThrptConfig(char *pbuff, stEthThrptConfig *pconfig)
{
	memcpy((char*)pconfig, pbuff, sizeof(stEthThrptConfig));
	
	return 0;
}
// transform to host byte order, pbuff --> pconfig
int ntoh_RfcConfig(char *pbuff, stEthRfc2544Config *pconfig)
{

	memcpy((char*)pconfig, pbuff, sizeof(stEthRfc2544Config));
	return 0;
}


