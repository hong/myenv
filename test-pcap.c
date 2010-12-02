#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <stdlib.h>		/* free, exit */
#include <signal.h>
#include <string.h>		/* strdup */

#include <pthread.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/sockios.h>
#include <netpacket/packet.h>

#define RMEM_MAX "/proc/sys/net/core/rmem_max"	/* system tuning */
#define RMEM_DEF "/proc/sys/net/core/rmem_default"	/* system tuning */

#define RINGSIZE 1024*1024*5

#define THREAD_DEFAULT_PRIORITY            ( 50 )
#define THREAD_DEFAULT_STACKSIZE           ( 0x100000 )	/* 1M bytes */

/*******************************************/
int ringsize = RINGSIZE;	/* ring buffer size */
int packes_written = 0;

char *pBuffer = NULL;		/* pointer to the big malloc'd ring buffer */
char *pReadPtr = NULL;
char *pWritePtr = NULL;

FILE *fp = NULL;
char *dev = "eth5";

/*******************************************/

#define RECV_BUFF_SIZE   10485760        /* 10MB */

void *Reader(void *arg);
void *Writer(void *arg);

#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

#define PCAP_ERRBUF_SIZE 256

#define PCAP_MAGIC          0xa1b2c3d4

typedef int bpf_int32;
typedef u_int bpf_u_int32;

struct pcap_file_header {
	bpf_u_int32 magic;
	u_short version_major;
	u_short version_minor;
	bpf_int32 thiszone;	/* gmt to local correction */
	bpf_u_int32 sigfigs;	/* accuracy of timestamps */
	bpf_u_int32 snaplen;	/* max length saved portion of each pkt */
	bpf_u_int32 linktype;	/* data link type (LINKTYPE_*) */
};

struct pcap_pkthdr {
	struct timeval ts;	/* time stamp */
	bpf_u_int32 caplen;	/* length of portion present */
	bpf_u_int32 len;	/* length this packet (off wire) */
};

#define ETHHDR_SIZE     14
#define PPPHDR_SIZE     4
#define SLIPHDR_SIZE    16
#define RAWHDR_SIZE     0
#define LOOPHDR_SIZE    4

typedef struct PCAP_OBJ {
	int exitflag;		/* 0 as long as we're supposed to keep capturing */
	int savefile;		/* capture wirte file */
	int packets_captured;
	long bytes_written;
} PCAP_OBJ;

static PCAP_OBJ pcap_object;

static void sighandler(int signum)
{
	printf("exit signal(signum=%d) caught!\n", signum);
	pcap_object.exitflag = 1;

	if (fp != NULL)
		fclose(fp);
	fp = NULL;

	if (pBuffer != NULL) {
		free(pBuffer);
		pBuffer = NULL;
	}
}

//--------------------- the status of driver-------------------------//
#define CAPTURE_STATUS_IDLE 0
#define CAPTURE_STATUS_CAPTURE 1
#define CAPTURE_STATUS_TRANSFER 2

//------------------------ the ioctl command of capture driver-------//
#define CAPTURE_CMD_START 0
#define CAPTURE_CMD_STOP 1
#define CAPTURE_CMD_QUERY 2

//------------------------the ioctl control data structure----------//
typedef struct {
	int cmd;		// the cmd  CAPTURE_STOP and CAPTURE_START,CAPTURE_QUERY
	int status;		//the status of capture:start or stop
	int packets;		//the packets in the fpga pool
	long addr;		//the buffer pointer has been used by fpga capture.
} CAPTURE_IOCTL;

/*  
 * This thread copies the ring buffer to stdout in WriteSize chunks
 * or every second (or so) whichever happens first.
 */
void *Writer(void *arg)
{
	int n;
	int used;
	int writesize;
	int pushed = 0;		/* value of "push" at last write  */
	int wtid = 0;		/* Writer thread id */
	struct pcap_file_header hdr;
	fprintf(stderr, "Writer() thread start...\n");

	hdr.magic = PCAP_MAGIC;
	/* current "libpcap" format is 2.4 */
	hdr.version_major = 2;
	hdr.version_minor = 4;
	hdr.thiszone = 0;
	hdr.sigfigs = 0;
	hdr.snaplen = 65535;
	hdr.linktype = 1;

	/* write capture file header */
	if (fwrite((char *)&hdr, sizeof(hdr), 1, fp) != 1)
		pthread_exit(NULL);

	fprintf(stderr, "writing to file...\n");

	packes_written = 0;
	char buffer[2048];

	while (!pcap_object.exitflag) {
		if ((pcap_object.packets_captured > 0) &&
		    (packes_written < pcap_object.packets_captured)) {
			struct pcap_pkthdr phdr;

			memset(&buffer, 0x0, sizeof(buffer));
			memcpy((char *)&phdr, pWritePtr, sizeof(phdr));
			pWritePtr += sizeof(phdr);
			memcpy(buffer, pWritePtr, phdr.caplen);
			pWritePtr += phdr.caplen;

			(void)fwrite(&phdr, sizeof(struct pcap_pkthdr), 1, fp);
			(void)fwrite(buffer, phdr.caplen, 1, fp);

			++packes_written;
		}
	}

	fprintf(stderr, "Writer() thread exit!\n");
	pthread_exit(NULL);
}

/*
 * This thread reads stdin or the network and appends to the ring buffer
 */
void *Reader(void *arg)
{
	int num_packets = -1;	/* number of packets to capture */
	int rtid = 0;		/* reader thread id */
	int sock = -1;
	char recv_buf[2048];
	struct sockaddr_ll addr;
	fprintf(stderr, "Reader() thread start...\n");

	signal(SIGINT, sighandler);
	signal(SIGPIPE, sighandler);
	signal(SIGKILL, sighandler);

	if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		perror("socket");
		pthread_exit(NULL);
	}

	/* bind the packet socket */
	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_ifindex = if_nametoindex(dev);
	addr.sll_hatype = 0;
	addr.sll_pkttype = 0;
	addr.sll_halen = 0;
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
		close(sock);
		pthread_exit(NULL);
	}

	struct pcap_pkthdr phdr;
	int count = 0, n = 0;
	memset(&recv_buf, 0x0, sizeof(recv_buf));

	fprintf(stderr, "reading from %s...\n", dev);

	while (!pcap_object.exitflag) {
		//printf("----------\n");
		n = recvfrom(sock, recv_buf, 2048, 0, NULL, NULL);
		//printf("%d bytes read\n", n);

		/* Check to see if the packet contains at least
		 * complete Ethernet (14), IP (20) and TCP/UDP
		 * (8) headers.
		 */
		if (n < 42) {
			perror("recvfrom():");
			printf("Incomplete packet (errno is %d)\n", errno);
			close(sock);
			break;
		}
#if 0
		unsigned char *iphead, *ethhead;
		ethhead = buffer;
		printf("Destination MAC address: "
		       "%02x:%02x:%02x:%02x:%02x:%02x\n",
		       ethhead[0], ethhead[1], ethhead[2],
		       ethhead[3], ethhead[4], ethhead[5]);
		printf("Source MAC address: "
		       "%02x:%02x:%02x:%02x:%02x:%02x\n",
		       ethhead[6], ethhead[7], ethhead[8],
		       ethhead[9], ethhead[10], ethhead[11]);
#endif

		memset(&phdr, 0x0, sizeof(struct pcap_pkthdr));
		(void)gettimeofday(&phdr.ts, NULL);
		phdr.caplen = n;
		phdr.len = n;

		/*
		 * put data onto the end of global ring buffer "buf"
		 */
		memcpy(pReadPtr, (char *)&phdr, sizeof(phdr));
		pReadPtr += sizeof(phdr);
		memcpy(pReadPtr, (char *)recv_buf, phdr.caplen);
		pReadPtr += phdr.caplen;

		++pcap_object.packets_captured;

#if 0
		iphead = buffer + 14;	/* Skip Ethernet header */
		if (*iphead == 0x45) {	/* Double check for IPv4
					 * and no options present */
			printf("Source host %d.%d.%d.%d\n",
			       iphead[12], iphead[13], iphead[14], iphead[15]);
			printf("Dest host %d.%d.%d.%d\n",
			       iphead[16], iphead[17], iphead[18], iphead[19]);
			printf("Source,Dest ports %d,%d\n",
			       (iphead[20] << 8) + iphead[21],
			       (iphead[22] << 8) + iphead[23]);
			printf("Layer-4 protocol %d\n", iphead[9]);
		} else {
			/*
			   int i;
			   iphead = buffer+12;
			   for(i=0; i<n-12; i++)
			   printf(" pkt:%x, %c\n",
			   iphead[i],iphead[i]);
			 */
		}
#endif
	}

    if (sock > 0)
	    close(sock);

	/* cleanup */
	fprintf(stderr, "Reader() thread exit!\n");
	pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
	int opt = 0;

	/*
	   signal(SIGABRT, sighandler);
	   signal(SIGHUP, sighandler);
	   signal(SIGINT, sighandler);
	   signal(SIGKILL, sighandler);
	   signal(SIGQUIT, sighandler);
	   signal(SIGSEGV, sighandler);
	   signal(SIGTERM, sighandler);
	 */

	/* parse command line arguments */
	while ((opt = getopt(argc, argv, "i:")) != -1) {
		switch (opt) {
		case 'i':
			dev = optarg;
			break;
		default:
			fprintf(stderr, "Missing option: %c", opt);
			break;
		}
	}

	fprintf(stdout, "Device: %s\n", dev);

#if 0
	pcap_object.savefile =
	    open("v300-new.pcap", O_WRONLY | O_TRUNC | O_CREAT, 0600);
	if (pcap_object.savefile < 0) {
		fprintf(stderr, "Error opening output file\n");
		goto lzEXIT;
	}

	linktype = pcap_datalink(pcap_object.handler);
	file_snaplen = pcap_snapshot(pcap_object.handler);

	/* write capture file header */
	pcap_write_header(pcap_object.savefile, linktype, file_snaplen);
#endif

	pcap_object.exitflag = 0;
	pcap_object.packets_captured = 0;

	int inpkts = 0, inpkts_to_sync = 0;
	time_t upd_time, cur_time;
	int pkt_num = 0;
	pthread_t threads[2];
	int rc = 0;
	int skfd = 0;
	struct ifreq ifr;
	CAPTURE_IOCTL capture_ioctl;

#if 1
	/*
	   upd_time = time(NULL);
	   time_t end_time, begin_time;
	   begin_time = time(NULL);
	 */

	bzero(&capture_ioctl, sizeof(capture_ioctl));
	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, "eth5", sizeof(ifr.ifr_name) - 1);
	ifr.ifr_data = (char *)&capture_ioctl;
	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) == 0) {
		fprintf(stderr, "create socket error!\n");
		goto lzEXIT;
	}

	/* tell 10GE port start capture */
	capture_ioctl.cmd = CAPTURE_CMD_START;
	if (ioctl(skfd, SIOCETHTOOL, &ifr) == -1) {
		fprintf(stderr, "ioctl: CAPTURE_CMD_START error!\n");
		goto lzEXIT;
	}
	fprintf(stderr, "send CAPTURE_CMD_START to driver, start capture!\n");
#endif

	pBuffer = (char *)calloc(1, ringsize + 1);
	if (!pBuffer) {
		fprintf(stderr, "Malloc failed, exiting\n");
		goto lzEXIT;
	}

	pReadPtr = pBuffer;
	pWritePtr = pBuffer;

	fprintf(stderr, "Ring buffer size: %d\n", ringsize);

	fp = fopen("/tmp/pcap000.pcap", "w");
	if (fp == NULL) {
		fprintf(stderr, "fopen error\n");
		goto lzEXIT;
	}

	FILE *procf = NULL;
	int rmem_def = 0;
	procf = fopen(RMEM_DEF, "r");
	if (procf) {
		fscanf(procf, "%d", &rmem_def);
		fclose(procf);
	}
	if (rmem_def != RECV_BUFF_SIZE) {
		char cmd[64] = "";
		sprintf(cmd, "echo \"%d\" > %s", RECV_BUFF_SIZE, RMEM_DEF);
		system(cmd);
		sprintf(cmd, "echo \"%d\" > %s", RECV_BUFF_SIZE, RMEM_MAX);
		system(cmd);
	}
	fprintf(stderr, "%s: %d\n%s: %d\n", RMEM_DEF, RECV_BUFF_SIZE, RMEM_MAX,
		RECV_BUFF_SIZE);

	// Create the corresponding measurement thread
	struct sched_param schParam;
	pthread_attr_t ptaAttr;

	schParam.sched_priority = THREAD_DEFAULT_PRIORITY + 10;
	pthread_attr_init(&ptaAttr);
	pthread_attr_setdetachstate(&ptaAttr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setschedpolicy(&ptaAttr, SCHED_FIFO);
	pthread_attr_setschedparam(&ptaAttr, &schParam);
	//pthread_attr_setstacksize(&ptaAttr, THREAD_DEFAULT_STACKSIZE*3);
	if (0 != pthread_create(&threads[0], &ptaAttr, (void *(*)(void *))Reader, NULL))
    {
		fprintf(stderr, "pthread_create error\n");
		goto lzEXIT;
	}

	schParam.sched_priority = THREAD_DEFAULT_PRIORITY;
	pthread_attr_init(&ptaAttr);
	pthread_attr_setdetachstate(&ptaAttr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setschedpolicy(&ptaAttr, SCHED_FIFO);
	pthread_attr_setschedparam(&ptaAttr, &schParam);
	//pthread_attr_setstacksize(&ptaAttr, THREAD_DEFAULT_STACKSIZE*3);
	rc = pthread_create(&threads[1], &ptaAttr, (void *(*)(void *))Writer, NULL);
	if (rc) {
		fprintf(stderr, "pthread_create error\n");
		goto lzEXIT;
	}

	while (!pcap_object.exitflag) {
		usleep(500000);
		fprintf(stderr, "Got %ld\n", pcap_object.packets_captured);
	}

    /*
    if( 0 == (rc = pthread_cancel(threads[0])) )
    {
        pthread_join(threads[0], NULL); 
    }
    if( 0 == (rc = pthread_cancel(threads[1])) )
    {
        pthread_join(threads[1], NULL); 
    }
    */

	fprintf(stderr, "\n%ld packets captured\n",
		pcap_object.packets_captured);
	fprintf(stderr, "ring buffer use: %.1lf%% of %d MB\n",
		100.0 * (float)pcap_object.packets_captured / (float)(ringsize),
		ringsize / 1024 / 1024);

lzEXIT:
	if (skfd != 0)
		close(skfd);
	skfd = 0;

	if (pBuffer != NULL) {
		free(pBuffer);
		pBuffer = NULL;
	}

	if (fp != NULL)
		fclose(fp);
	fp = NULL;

	if (pcap_object.savefile > 0) {
		fsync(pcap_object.savefile);
		close(pcap_object.savefile);
	}
	printf("Packet capture done.\n");
	exit(0);
}
