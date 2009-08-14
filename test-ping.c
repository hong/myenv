#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>

#define PACKET_SIZE       4096
#define ERROR             0
#define SUCCESS           1

void rtrim(char* str)
{
    int i = 0;
    if (str == NULL)
        return;

    for(i = strlen(str) - 1; i >= 0; i--)
        if ((str[i] != ' ') && (str[i] != '\t'))
            break;

    str[i + 1] = '\0';
}

unsigned short cal_chksum(unsigned short *addr, int len)
{
      int nleft=len;
      int sum=0;
      unsigned short *w=addr;
      unsigned short answer=0;
    
      while(nleft > 1) {
          sum += *w++;
          nleft -= 2;
      }
   
	  /* mop up the occasional odd byte */
      if( nleft == 1) {       
          *(unsigned char *)(&answer) = *(unsigned char *)w;
             sum += answer;
      }
    
      sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
      sum += (sum >> 16);                 /* add carry */
      answer = ~sum;                      /* ones-complement, trunc to 16 bits */
    
      return answer;
}

int ping(unsigned long targetip, int timeout)
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
   
	bzero(&addr,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(targetip);

	  /* create a socket to send out the icmp echo message */
      sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
      if (sockfd < 0)
      {
          fprintf(stderr,"socket error\n");
          return ERROR;
      }
    
	  /* set timeout */
      timeo.tv_sec = timeout / 1000;
      timeo.tv_usec = timeout % 1000;
    
      if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeo, sizeof(timeo)) == -1)
      {
          fprintf(stderr,"ip:%d,setsockopt error\n");
          return ERROR;
      }
    
	  /* construct the icmp header */
      memset(sendpacket, 0, sizeof(sendpacket));
    
      pid = getpid();

      int packsize = 0;
      icmp = (struct icmp*)sendpacket;
      icmp->icmp_type = ICMP_ECHO;
      icmp->icmp_code = 0;
      icmp->icmp_cksum = 0;
      icmp->icmp_seq = 0;
      //icmp->icmp_id=(short)(getpid()&0xffff);
      icmp->icmp_id = pid;
      packsize = 8 + 56;
      tval = (struct timeval *)icmp->icmp_data;
      gettimeofday(tval,NULL);
      icmp->icmp_cksum = cal_chksum((unsigned short *)icmp,packsize);

      /* send ICMP packet */ 
      n = sendto(sockfd, (char *)&sendpacket, packsize, 0, (struct sockaddr *)&addr, sizeof(addr));
      if (n < 1) {
          fprintf(stderr,"sendto error\n");
          return ERROR;
      }

	  /* receive */
	  /* because other ping response may be receive, so here to use the cycle*/
      while (1) {
		  /* set timeout, this is the real role*/
          FD_ZERO(&readfds);
          FD_SET(sockfd, &readfds);
          maxfds = sockfd + 1;
          n = select(maxfds, &readfds, NULL, NULL, &timeo);
          if (n <= 0) {
              fprintf(stderr,"time out error\n");
              close(sockfd);
              return ERROR;
          }

		  /* receive */
          memset(recvpacket, 0, sizeof(recvpacket));
          int fromlen = sizeof(from);
          n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0, (struct sockaddr *)&from, (socklen_t *)&fromlen);
          if (n < 0) {
              break;
          }
       	
          /* check response whether is my reply */
		  /*
          char *from_ip = (char *)inet_ntoa(from.sin_addr);
          fprintf(stderr,"fomr ip:%s\n",from_ip);
		  if (strcmp(from.sin_addr, ips) != 0) {
              fprintf(stderr,"ip:%s,Ip wang\n",ips);
              break;
           }
		  */
        
          iph = (struct ip *)recvpacket;
    
          icmp=(struct icmp *)(recvpacket + (iph->ip_hl<<2));

          fprintf(stderr,"icmp->icmp_type:%d,icmp->icmp_id:%d\n", icmp->icmp_type,icmp->icmp_id);

		 /* check ping reply packet status */
          if (icmp->icmp_type == ICMP_ECHOREPLY && icmp->icmp_id == pid) {
              /* if status is OK then exit this loop */
              break;
          }
          else {
              /* or continue wait */
              continue;
          }
      }
    
      /* close socket */
      close(sockfd);

      fprintf(stderr,"ip:%s, ping success!\n", inet_ntoa(addr.sin_addr));
      return SUCCESS;
}

void TestPing(unsigned long ipstart, unsigned long ipstop)
{
  u_long bha = 0;
  unsigned long NumPing = 0;

  for (NumPing = ipstart; (NumPing <= ipstop); NumPing++)
  {
    ping(NumPing, 5000);
  }
}

int main(int argc, char* argv[])
{
	int ret = 0;
	int addr1 = 0, addr2 = 0, addr3 = 0, addr4 = 0;
	unsigned char pStartIP[4];
	unsigned char pStopIP[4];

    if (getuid() != 0) {
        fprintf(stderr, "%s: root privelidges needed\n", *(argv + 0));
        return -1;
    }

	if (argc != 3) {
        fprintf(stderr, "ping [ip1] [ip2]\n");
		return -1;
	}

	printf("argv[1]=%s, argv[2]=%s\n", argv[1], argv[2]);

	if ((ret = sscanf(argv[1], "%u.%u.%u.%u", &addr1, &addr2, &addr3, &addr4)) != 4)
	{
		return -1;
	}
	pStartIP[0] = (unsigned char)addr1;
	pStartIP[1] = (unsigned char)addr2;
	pStartIP[2] = (unsigned char)addr3;
	pStartIP[3] = (unsigned char)addr4;

	if ((ret = sscanf(argv[2], "%u.%u.%u.%u", &addr1, &addr2, &addr3, &addr4)) != 4)
	{
		return -1;
	}
	pStopIP[0] = (unsigned char)addr1;
	pStopIP[1] = (unsigned char)addr2;
	pStopIP[2] = (unsigned char)addr3;
	pStopIP[3] = (unsigned char)addr4;

	printf( "NetWizard begin to scan %u:%u:%u:%u - %u:%u:%u:%u ......\n", 
			pStartIP[0], pStartIP[1], pStartIP[2], pStartIP[3],
			pStopIP[0], pStopIP[1], pStopIP[2], pStopIP[3] );

    unsigned long ipstart = (pStartIP[0] << 24) + (pStartIP[1] << 16) + (pStartIP[2] << 8) + pStartIP[3];
    unsigned long ipstop = (pStopIP[0] << 24) + (pStopIP[1] << 16) + (pStopIP[2] << 8) + pStopIP[3];

	printf( "IP scanning range = %d\n", ipstop - ipstart + 1 );

	if( ipstop - ipstart + 1 <= 0 )
		return -1;

	TestPing(ipstart, ipstop);

	return 0;
}
