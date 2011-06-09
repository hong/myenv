#if !defined(__VENET_NETWORK_TEST_PING_H__)
#define __VENET_NETWORK_TEST_PING_H__
#define  PINGREC_WINSIZE    (2048)

/* BOOL definitions */
#if !defined(BOOL)
#define BOOL int
#endif/*!defined(BOOL)*/
#if !defined(TRUE)
#define TRUE   1
#endif/*!defined(TRUE)*/
#if !defined(FALSE)
#define FALSE  0
#endif/*!defined(FALSE)*/

/* code regulation support */ 
#define exit_if_fail(ret_val)       \
do {                                \
    if (0 != ((int)(ret_val)))      \
        goto lzExit;                \
} while (0)
            
#define exit_no_condition()         \
do {                                \
    goto lzExit;                    \
} while (0)

                    
#if !defined(MILLION)
#define MILLION (1000000)
#endif/*!defined(MILLION)*/

#define SIZEOF(ptr) (sizeof(ptr) / sizeof(ptr[0]))

#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <signal.h>

class CNetTest_Ping
{
public:
	CNetTest_Ping ();
	virtual ~CNetTest_Ping ();

public: /* method to be implemented on actual platform */
	virtual int  applyTestSetting (int argc, char* argv[]);
	virtual int  reportPingResult (BOOL bRunning);

public:
	virtual void  exitExec ();
	virtual int  onMainLoop ();
	virtual int  onPingTimer ();

public:
	virtual int  startTest ();
	virtual int  stopTest ();

protected:
	virtual int  statPingRecord (int iRecordIndex);

protected:
	virtual int  sendPingPackage ();
	virtual int  recvPingPackage (const struct timeval* ptmRecvWait);

protected: /* ping test arguments */
	struct {
		int               use_inet6;
		char              dst_host[128];
		int               ping_continuous; /* whether ping in continuous mode, means ping_number are invalid */
		int               ping_number;     /* number of pings to send out, only valid on ping_continuous is not 0 */
		int               ping_speed;      /* ping speed, how many pings should be send in one second */
		int               ping_echolen;    /* ping payload size */
		int               ping_timeout;    /* ping recv time out, in ms */
	} m_stPingConfig;

protected: /* ping resources */
	BOOL                  m_bINET6Ping;
	int                   m_sockICMP;
    struct sockaddr_in    m_addr4ICMPSend;
    struct sockaddr_in6   m_addr6ICMPSend;
	int                   m_sizeICMPSend;
	unsigned char*        m_buffICMPSend;
	int                   m_sizeICMPRecv;
	unsigned char*        m_buffICMPRecv;
	unsigned int          m_usecPingIntv;
	unsigned int          m_iStatSendDiff;
	unsigned int          m_iPingsID;
	struct timeval        m_tmRecvTimeout;

protected:
typedef struct {
	unsigned int       send_id;
	unsigned int       send_mark;
	unsigned int       recv_mark;
	unsigned int       stat_mark;
	struct timeval     send_stamp;
	struct timeval     recv_stamp;
} ping_record;

protected: /* ping statistics */
	BOOL               m_bResolveFail;
	struct in_addr     m_addr4PingReply;
	struct in6_addr    m_addr6PingReply;

	struct timeval     m_tmResolvStart;
	struct timeval     m_tmResolvStop;
	struct timeval     m_tmArpResponse;
	struct timeval     m_tmPingStart;
	struct timeval     m_tmPingStop;
	struct timeval     m_tmPingStat;

	struct timeval     m_tmSendStamp;
	struct timeval     m_tmRecvStamp;

	unsigned int       m_iPingsSend;
	unsigned int       m_iPingsReply;
	unsigned int       m_iPingsDuplicate;
	unsigned int       m_iPingsIgnored;
	unsigned int       m_iPingsUnrech;
	unsigned int       m_iPingsMiss;

	struct timeval     m_tmRoundTripCur;
	struct timeval     m_tmRoundTripMin;
	struct timeval     m_tmRoundTripMax;
	int                m_iRoundTripSize;
	unsigned long long m_tmRoundTripSum;

	unsigned int       m_iRecSendIndex;
	unsigned int       m_iRecStatIndex;
	ping_record        m_stPingRecords[PINGREC_WINSIZE];
};

#endif/*!defined(__VENET_NETWORK_TEST_PING_H__)*/
