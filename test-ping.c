#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <string.h>

#define PACKET_SIZE       4096
#define ERROR             0
#define SUCCESS           1

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

int ping( char *ips, int timeout)
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
    
      // 设定Ip信息
      bzero(&addr,sizeof(addr));
      addr.sin_family = AF_INET;
      addr.sin_addr.s_addr = inet_addr(ips);   

      // 取得socket
      sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
      if (sockfd < 0)
      {
          fprintf(stderr,"ip:%s,socket error\n",ips);
          return ERROR;
      }
    
      // 设定TimeOut时间
      timeo.tv_sec = timeout / 1000;
      timeo.tv_usec = timeout % 1000;
    
      if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeo, sizeof(timeo)) == -1)
      {
          fprintf(stderr,"ip:%s,setsockopt error\n",ips);
          return ERROR;
      }
    
      // 设定Ping包
      memset(sendpacket, 0, sizeof(sendpacket));
    
      // 取得PID，作为Ping的Sequence ID
      pid=getpid();
      int i,packsize;
      icmp=(struct icmp*)sendpacket;
      icmp->icmp_type=ICMP_ECHO;
      icmp->icmp_code=0;
      icmp->icmp_cksum=0;
      icmp->icmp_seq=0;
      icmp->icmp_id=pid;
      packsize=8+56;
      tval= (struct timeval *)icmp->icmp_data;
      gettimeofday(tval,NULL);
      icmp->icmp_cksum=cal_chksum((unsigned short *)icmp,packsize);

      // 发包
      n = sendto(sockfd, (char *)&sendpacket, packsize, 0, (struct sockaddr *)&addr, sizeof(addr));
      if (n < 1)
      {
          fprintf(stderr,"ip:%s,sendto error\n",ips);
          return ERROR;
      }

      // 接受
      // 由于可能接受到其他Ping的应答消息，所以这里要用循环
      while(1)
      {
          // 设定TimeOut时间，这次才是真正起作用的
          FD_ZERO(&readfds);
          FD_SET(sockfd, &readfds);
          maxfds = sockfd + 1;
          n = select(maxfds, &readfds, NULL, NULL, &timeo);
          if (n <= 0)
          {
              fprintf(stderr,"ip:%s,Time out error\n",ips);
              close(sockfd);
              return ERROR;
          }

          // 接受
          memset(recvpacket, 0, sizeof(recvpacket));
          int fromlen = sizeof(from);
          n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0, (struct sockaddr *)&from, &fromlen);
          if (n < 1) {
              break;
          }
        
          // 判断是否是自己Ping的回复
          char *from_ip = (char *)inet_ntoa(from.sin_addr);
          fprintf(stderr,"fomr ip:%s\n",from_ip);
           if (strcmp(from_ip,ips) != 0)
           {
              fprintf(stderr,"ip:%s,Ip wang\n",ips);
              break;
           }
        
          iph = (struct ip *)recvpacket;
    
          icmp=(struct icmp *)(recvpacket + (iph->ip_hl<<2));

          fprintf(stderr,"ip:%s,icmp->icmp_type:%d,icmp->icmp_id:%d\n",ips,icmp->icmp_type,icmp->icmp_id);
         // 判断Ping回复包的状态
          if (icmp->icmp_type == ICMP_ECHOREPLY && icmp->icmp_id == pid)
          {
              // 正常就退出循环
              break;
          }
          else
          {
              // 否则继续等
              continue;
          }
      }
    
      // 关闭socket
      close(sockfd);

      fprintf(stderr,"ip:%s,Success\n",ips);
      return SUCCESS;
}

int main(int argc, char* argv[])
{
    if (getuid() != 0)
    {
        fprintf(stderr, "%s: root privelidges needed\n", *(argv + 0));
        return -1;
    }

	if (argc != 2)
	{
		return -1;
	}
	printf("argv[1]=%s\n", argv[1]);
	ping(argv[1], 5000);

	return 0;
}
