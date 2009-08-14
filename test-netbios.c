#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <memory.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>

#include <assert.h>

#define PACKET_SIZE       4096
#define ERROR             0
#define SUCCESS           1

#ifndef TRUE
#  define TRUE  1
#  define FALSE 0
#endif

#define NODE_FLAGS_GROUP(np)	 ((np)->flags & 0x8000)

#define NODE_RECORD_SIZE    18

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
    char        name[15];
    char        type;
    unsigned short  flags;      /* in host byte order */
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
    unsigned char       uniqueid[6];    /* Ethernet address */

    unsigned char       jumpers;
    unsigned char       test_result;

    unsigned short      version_number;
    unsigned short      period_of_statistics;
    unsigned short      number_of_crcs;
    unsigned short      number_alignment_errors;
    unsigned short      number_of_collisions;
    unsigned short      number_send_aborts;
    unsigned long       number_good_sends;
    unsigned long       number_good_receives;
    unsigned short      number_retransmits;
    unsigned short      number_no_resource_conditions;
    unsigned short      number_free_command_blocks;
    unsigned short      total_number_command_blocks;
    unsigned short      max_total_number_command_blocks;
    unsigned short      number_pending_sessions;
    unsigned short      max_number_pending_sessions;
    unsigned short      max_total_sessions_possible;
    unsigned short      session_data_packet_size;
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
            
    unsigned short  tranid;         /* transaction ID */
    unsigned short  flags;          /* various flags */
    unsigned short  qdcount;        /* query count */
    unsigned short  ancount;        /* answer count */
    unsigned short  nscount;
    unsigned short  arcount;
                
    char        data[1024];
}; 

/*------------------------------------------------------------------------
 * When talking to the other end, we maintain this information about the
 * NETBIOS information.
 */
struct NMB_query_response {

	struct sockaddr_in	remote;			/* IP address 	*/

	char			domain   [15+1];	/* printable	*/
	char			computer [15+1];	/* printable	*/
	char			ether    [20];		/* printable	*/
	char			user     [32];          /* printable    */

	int			sharing;		/* sharing on?	*/
	int			has_IIS;		/* MS IIS?	*/
	int			has_Exchange;		/* MS Exchange	*/
	int			has_Notes;		/* Lotus notes	*/
	int			has_RAS;		/* Rmt Access	*/
	int			is_dc;                  /* domain ctlr? */

	int			has_unknown;            /* any unknown? */

	struct NODE_statistics	nodestats;		/* full info	*/

	/*----------------------------------------------------------------
	 * This is information about all the nodes that we can gather
	 * from the other end. These are taken directly from the NODE_NAME
	 * array, but >these< ones are formatted for easy printing.
	 */
	struct nodeinfo {
		char		name[15+1];	   /* NUL-terminated!	*/
		char		type;		   /* type code		*/
		unsigned short	flags;	   /* host byte order	*/
		const char     *svcname;   /* long name            */
	} nodes[100];

	int			nnodes;
	int			nametrunc;
};

static int timeout_secs = 2, write_sleep_msecs = 10;

void sleep_msecs(long msecs)
{
	if (msecs <= 0) return;
#if defined(M_XENIX)
	napms(msecs);
#else
	usleep(msecs * 1000);   /* microseconds! */
#endif
}

struct timeval* timeval_set_secs(struct timeval *tv, int secs)
{
    assert(tv != 0);

    tv->tv_sec  = secs;
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
	FIXLONG (p->number_good_sends);
	FIXLONG (p->number_good_receives);
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
	const char  *dst_save = dst;

    assert(dst != 0);
    assert(src != 0);

    while ( (*dst = *src++) != 0 )
        dst++;

    return (size_t)(dst - dst_save);
}

char* strip(char *str)
{
	char    *old = str; /* save ptr to original string          */
	char    *lnsp = 0;  /* ptr to last non-space in string      */

    assert(str != 0);

    for ( ; *str; str++)
        if (!isspace(*str))
            lnsp = str;
    if ( lnsp )
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
	struct in_addr  addr;
	struct hostent  *hp;

    assert(obuf != 0);
    assert(osize > 1);
    
    addr.s_addr = ipaddr;
    
    --osize;        /* allow room for terminating NUL */
    
    if ( (hp = gethostbyaddr((char *)&addr, sizeof addr, AF_INET)) == 0 )
        return 0;
        
    if ( hp->h_name == 0 )
        return 0;
        
    strncpy(obuf, hp->h_name, (unsigned int)osize)[osize] = '\0';
    
    return (int) strlen(obuf);
} 

#define		UNIQUE		0x000
#define		XGROUP		0x100

const char *NETBIOS_name(const struct nodeinfo *np)
{
int	unique;
int	swvalue;

	assert(np != 0);

	unique = !!NODE_FLAGS_GROUP(np);

	swvalue = (unique << 8) | (0xFF & np->type);

	switch ( swvalue )
	{
	  case UNIQUE | 0x01:	return "Messenger Service<1>";
	  case UNIQUE | 0x03:	return "Messenger Service<3>";
	  case UNIQUE | 0x06:	return "RAS Server Service";
	  case UNIQUE | 0x1F:	return "NetDDE Service";
	  case UNIQUE | 0x1B:	return "Domain Master Browser";
	  case UNIQUE | 0x1D:	return "Master Browser";
	  case UNIQUE | 0x20:	return "File Server Service";
	  case UNIQUE | 0x21:	return "RAS Client Service";
	  case UNIQUE | 0x22:	return "MS Exchange Interchange";
	  case UNIQUE | 0x23:	return "MS Exchange Store";
	  case UNIQUE | 0x24:	return "MS Exchange Directory";
	  case UNIQUE | 0x87:	return "MS Exchange MTA";
	  case UNIQUE | 0x6A:	return "MS Exchange IMC";
	  case UNIQUE | 0xBE:	return "Network Monitor Agent";
	  case UNIQUE | 0xBF:	return "Network Monitor Application";
	  case UNIQUE | 0x30:	return "Modem Sharing Server Service";
	  case UNIQUE | 0x31:	return "Modem Sharing Client Service";
	  case UNIQUE | 0x43:	return "SMS Clients Remote Control";
	  case UNIQUE | 0x44:	return "SMS Admin Remote Control Tool";
	  case UNIQUE | 0x45:	return "SMS Clients Remote Chat";
	  case UNIQUE | 0x46:	return "SMS Clients Remote Transfer";
	  case UNIQUE | 0x52:	return "DEC Pathworks TCP svc";

	  case XGROUP | 0x00:	return "Domain Name";
	  case XGROUP | 0x01:	return "Master Browser";
	  case XGROUP | 0x1E:	return "Browser Service Elections";


	  case XGROUP | 0x42:
		if ( strcmp(np->name, "MLI_GROUP_BRAD") == 0)
			return "Dr. Solomon AV Management";
		break;

	  case UNIQUE | 0x42:
		if ( strncmp(np->name, "MLI", 3) == 0 )
			return "Dr. Solomon AV Management";
		break;

	  case XGROUP | 0x1C:
		if ( strcmp(np->name, "INet~Services") == 0 )
			return "IIS";
		else
			return "Domain Controller";

	  case UNIQUE | 0x00:
		if ( strncmp(np->name, "IS~", 3) == 0 )
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
	char    *buf_save = buf;

    assert(buf != 0);

    for ( ; *buf; buf++ )
    {
        if ( ! isprint(*buf) )
            *buf = '.';
    }

    return strip(buf_save);
}

void process_response(struct NMB_query_response *rsp)
{
	int	i;

	assert(rsp != 0);

	rsp->computer[0] = '\0';
	rsp->domain  [0] = '\0';
	rsp->user    [0] = '\0';
	rsp->has_RAS     = FALSE;
	rsp->is_dc       = FALSE;
	rsp->sharing     = FALSE;
	rsp->has_unknown = FALSE;

	for (i = 0; i < rsp->nnodes; i++ )
	{
	struct nodeinfo	   *ni = &rsp->nodes[i];
	int                 isgroup = NODE_FLAGS_GROUP(ni);
	int                 t = ni->type;

		/*--------------------------------------------------------
		 * Look up the printable NETBIOS resource name and stick
		 * it into the local node buffer. This is NULL if not
		 * known, and we mark us as having some unknown ones: this
		 * might help us research the new stuff.
		 */
		if ( (ni->svcname = NETBIOS_name(ni)) == 0 ) rsp->has_unknown++;

		/*--------------------------------------------------------
		 * A GROUP node <00> is the domain name, and this is not
		 * always found if this is a workgroup environment with
		 * no domain controller.
		 */
		if ( rsp->domain[0] == '\0' )
		{
			if ( isgroup  &&  (t == 0x00) )
			{
				strcpy(rsp->domain, ni->name);
			}
		}

		/*--------------------------------------------------------
		 * Look for the computer name. This is always a UNIQUE name,
		 * and we think it's always first.
		 */
		if ( rsp->computer[0] == '\0'  &&  ! isgroup )
		{
			switch ( t )
			{
			/*------------------------------------------------
			 * Unique type <00> is either "IIS" or "Workstation
			 * Service" depending on whether we have the IS~
			 * part at the beginning.
			 */
			  case 0x00:
				if ( strncmp(ni->name, "IS~", 3) != 0 )
					strcpy(rsp->computer, ni->name);
				break;

			  case 0x06:	/* RAS Client Service		*/
			  case 0x01:	/* Messenger Service (uncommon)	*/
			  case 0x1F:	/* NetDDE service		*/
			  case 0x20:	/* File sharing service		*/
			  case 0x2B:	/* Lotus Notes Server Service	*/
				strcpy(rsp->computer, ni->name);
				break;

			  default:
				/*nothing*/
				break;
			}
		
		}

                /*--------------------------------------------------------
                 * Sharing is on if the File Server Service is published,
                 * and this is noticed with a unique type of <20>.
                 */
		if ( ! isgroup  &&  (t == 0x20) )
			rsp->sharing = TRUE;

		/*--------------------------------------------------------
		 * UNIQUE<06> seems to be RAS, which indicates modems?
		 */
		if ( ! isgroup  &&  (t == 0x06) )
		{
			rsp->has_RAS = TRUE;
		}

		/*--------------------------------------------------------
		 * It seems that being a domain controller and running IIS
		 * are pretty similar. If the token is <1C> and the name
		 * matches the domain name, it's a domain controller.
		 */
		if ( isgroup && (t == 0x1C) )
		{
			if ( strcmp(ni->name, "INet~Services") == 0 )
				rsp->has_IIS = TRUE;
			else if ( strcmp(ni->name, rsp->domain) == 0 )
				rsp->is_dc = TRUE;
		}

		/*--------------------------------------------------------
		 * We've observed that UNIQUE<87> and UNIQUE<6A> are MS
		 * Exchange, but we don't remember how we got that.
		 */
		if ( ! isgroup && (t == 0x87 || t == 0x6A) )
		{
			rsp->has_Exchange = TRUE;
		}

		if ( ! isgroup && (t == 0x2B) )
		{
			rsp->has_Notes = TRUE;
		}

		/*--------------------------------------------------------
		 * If this is messenger service for something other than
		 * the computer name, this is probably a user.
		 */
		if ( ! isgroup && (t == 0x03) )
		{
			if ( strcmp(ni->name, rsp->computer) != 0 )
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
	unsigned short	s;

	assert( p != 0);
	assert(*p != 0);

	memcpy(&s, *p, 2);

	*p += 2;

	return ntohs(s);
}

int NETBIOS_unpack(const char **ibuf, char *obuf, int osize)
{
	int          isize;
	char		*obuf_save,
				*obuf_max;
	const char  *ibuf_save;

	assert(  ibuf  != 0 );
	assert( *ibuf  != 0 );
	assert(  obuf  != 0 );
	assert(  osize  > 0 );

	ibuf_save = *ibuf;
	obuf_save =  obuf;

	/*----------------------------------------------------------------
	 * The length in bytes of the "compressed" name must be even, as
	 * each final character is made of two input bytes. If the size
	 * is odd, it's just a bogus input.
	 *
	 * Then make sure the # of bytes will for sure fit in the output.
	 */
	isize = *(*ibuf)++;

	if ( (isize % 2) != 0 )
	{
		/* must be even length */
		return -1;
	}

	if ( (isize /= 2) > osize )
	{
		/* output buffer not big enough */
		return -2;
	}

	obuf_max = obuf + isize;

	while ( obuf < obuf_max )
	{
	unsigned int	c1 = (unsigned int)( *(*ibuf)++ - 'A' ),
			c2 = (unsigned int)( *(*ibuf)++ - 'A' );

		if ( c1 > 15  ||  c2 > 15 )	return -3;

		*obuf++ = (char)( (c1 << 4) | c2 );
	}

	*obuf = '\0';

	/* round up to even word boundary */
	if ( (*ibuf - ibuf_save) % 2 )
		++*ibuf;

	return (int)(obuf - obuf_save);
}

void display_nbtstat(const struct NMB_query_response *rsp, int full)
{
	int     no_inverse_lookup = FALSE;
	char	reportbuf[256],
		*p = reportbuf;
	char	computername[32];

	assert(rsp != 0);

	/*----------------------------------------------------------------
	 * The full name is DOMAIN\MACHINE, but some systems have no names
	 * at all (don't know why), so we display them in a special format.
	 * Not sure what this means...
	 */
	if (rsp->domain[0] == '\0'  &&  rsp->computer[0] == '\0' )
		sprintf(computername, "-no name-");
	else
		sprintf(computername, "%s\\%s",
			rsp->domain,
			rsp->computer );

	p += sprintf(p, "%-15s %-31s",
		inet_ntoa(rsp->remote.sin_addr),	/* IP address		*/
		computername);				/* DOMAIN\COMPUTER	*/

/* delete by hong
	if ( show_mac_address && ! full )
	{
		*p++ = ' ';
		p += nstrcpy(p, rsp->ether);
	}
*/

	if ( rsp->sharing )	p += nstrcpy(p, " SHARING"  );
	if ( rsp->is_dc)	p += nstrcpy(p, " DC"       );
	if ( rsp->has_IIS )	p += nstrcpy(p, " IIS"      );
	if ( rsp->has_Exchange)	p += nstrcpy(p, " EXCHANGE" );
	if ( rsp->has_Notes)	p += nstrcpy(p, " NOTES"    );
	if ( rsp->has_RAS )     p += nstrcpy(p, " RAS"      );
	if ( rsp->has_unknown)	p += nstrcpy(p, " ?"        );

	/*----------------------------------------------------------------
	 * If we have a user, display it after a U= token. But we put quotes
	 * around it if the user name contains any spaces. This is kind of
	 * a crock.
	 */
	if ( rsp->user[0] )
	{
		const char *quote = (strchr(rsp->user, ' ') == 0)
		                  ? ""
		                  : "\"";

		p += sprintf(p, " U=%s%s%s", quote, rsp->user, quote);
	}

	*p++ = '\n';
	*p = '\0';

	printf(reportbuf);

	if ( full )
	{
		int	i;
		char	dnsbuf[132];
		char	dispbuf[256];

		for (i = 0; i < rsp->nnodes; i++ )
		{
		const struct nodeinfo	*ni = &rsp->nodes[i];
		int			isgroup = NODE_FLAGS_GROUP(ni);
		char			namebuf[16];
		const char              *svcname = ni->svcname;

			if ( svcname == 0 ) svcname = "-unknown-";

			NETBIOS_fixname( strcpy(namebuf, ni->name) );
/*
			fprintf(ofp, "  %-15s<%02x> %s %s\n",
				namebuf,
				0xFF & ni->type,
				isgroup ? "GROUP " : "UNIQUE",
				svcname );
*/
		}

		if ( no_inverse_lookup
		 || ip_to_name(rsp->remote.sin_addr.s_addr,
				dnsbuf, sizeof dnsbuf) == 0 )
		{
			dnsbuf[0] = '\0';
		}

		// strip trailing white from this line :-(
		sprintf(dispbuf, "  %s   ETHER  %s", rsp->ether, dnsbuf);

		strip(dispbuf);
/*
		fprintf(ofp, "%s\n\n", dispbuf);
*/
	}
}

int parse_nbtstat(const struct NMBpacket *pak, int paklen,
		  struct NMB_query_response *rsp,
		  char *errbuf)
{
	const char	*p,
		*pmax,
		*nmax,
		*pstats;
	int		rdlength,
		remaining,
		nnames;
	int		qtype,		/* query type (always "NBSTAT")		*/
		   qclass;		/* query class (always "IN")		*/
	char	tmpbuf[256];	/* random buffer			*/

	assert(pak    != 0);
	assert(rsp    != 0);
	assert(paklen >  0);
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
	pmax = paklen + (char *)pak;
	p    = pak->data;

	/*----------------------------------------------------------------
	 * The first thing we should see is the "question" section, which
	 * should simply echo what we gave them. Parse this out to skip
	 * past it. We decode it only for the benefit of the debugging
	 * code.
	 */
	NETBIOS_unpack(&p, tmpbuf, sizeof tmpbuf);

	qtype  = getshort(&p);	/* question type	*/
	qclass = getshort(&p);	/* question class	*/

#if 0
	printf(" QUESTION SECTION:\n");
	printf("   name  = \"%s\"\n",	tmpbuf);
#endif

	p += 4;					/* skip past TTL (always zero)	*/

	/*----------------------------------------------------------------
	 * Fetch the length of the rest of this packet and make sure that
	 * we actually have this much room left. If we don't, we must have
	 * gotten a short UDP packet and won't be able to finish off this
	 * processing. The max size is ~~500 bytes or so.
	 */
	rdlength = getshort(&p);

	remaining = (int)(pmax - p);

	if ( rdlength > remaining )
	{
		printf(" ERROR: rdlength = %d, remaining bytes = %d\n",
		   rdlength,
		   remaining);
		return -1;
	}

	/*----------------------------------------------------------------
	 * Fetch the number of names to be found in the rest of this node
	 * object. Sometimes we get >zero< and it's not clear why this is.
	 * Perhaps it means that there is no NETBIOS nameserver running
	 * but it will answer status requests. Hmmm.
	 */
	nnames  = *(unsigned char *)p; p++;

#if 0
	printf(" NODE COUNT = %d\n", nnames);
#endif

	if ( nnames < 0 )
	{
		sprintf(errbuf, "bad NETBIOS response (count=%d)", nnames);
		return FALSE;
	}

	pstats = p + (nnames * NODE_RECORD_SIZE);

	if (nnames > TBLSIZE(rsp->nodes))
	{
		nnames = TBLSIZE(rsp->nodes);

		rsp->nametrunc = TRUE;
	}

	nmax   = p + (nnames * NODE_RECORD_SIZE);

	for ( ; p < nmax; p += NODE_RECORD_SIZE )
	{
		struct node_name_record	nr;
		struct nodeinfo		*ni = &rsp->nodes[ rsp->nnodes++ ];

		/* Solaris has alignment problems, gotta copy */
		memcpy(&nr, p, NODE_RECORD_SIZE);

		ni->flags = ntohs(nr.flags);
		ni->type  = nr.type;

		strncpy(ni->name, nr.name, 15)[15] = '\0';

		strip(ni->name);
	}

	/*----------------------------------------------------------------
	 * Now we've finished processing the node information and gathered
	 * up everything we can find, so now look for the statistics. We
	 * ONLY try to gather these stats if there is actually any room
	 * left in our buffer.
	 */
	if ( (int) (pmax - pstats) >= NODE_STATS_SIZE )
	{
		memcpy( &rsp->nodestats, pstats, NODE_STATS_SIZE );

		byteswap_nodestats( &rsp->nodestats );

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
	char	*obuf_save = obuf;

	assert( ibuf != 0 );
	assert( obuf != 0 );

	*obuf++ = (char)(isize * 2);

	while (isize-- > 0 )
	{
		unsigned int c = *(unsigned char *)ibuf;

		*obuf++ = (char)( 'A' + ( (c >> 4) & 0x0F ) );
		*obuf++ = (char)( 'A' + (  c       & 0x0F ) );

		ibuf++;
	}
	*obuf = '\0';

	return (int)(obuf - obuf_save);
}

int NETBIOS_pack_name(const char *ibuf, int itype, char *obuf)
{
	char	tempbuf[16+1];

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
	if ( ibuf[0] == '*'  &&  ibuf[1] == '\0' )
	{
		memset(tempbuf, 0, sizeof tempbuf);
		tempbuf[0] = '*';
	}
	else
	{
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
	char	*pbuf;

	assert(pak != 0);
	assert(len != 0);

	*len = 50;

	memset(pak, 0, *len);

	/* POPULATE THE HEADER */

	pak->tranid  = htons(seq);	/* transaction ID */
	pak->flags   = 0;
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
	*pbuf++ = 0x00;	/* length of next segment */

	*pbuf++ = 0x00;	/* NODE STATUS */
	*pbuf++ = 0x21;

	*pbuf++ = 0x00;	/* IN */
	*pbuf++ = 0x01;
}

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

unsigned long host2ip (char *serv)
{
  struct sockaddr_in sinn;
  struct hostent *hent;

  hent = gethostbyname (serv);
  if (hent == NULL)
    return 0;
  bzero ((char *) &sinn, sizeof (sinn));
  memcpy ((char *) &sinn.sin_addr, hent->h_addr, hent->h_length);
  return sinn.sin_addr.s_addr;
} 

int netbios(u_long ip)
{
	struct sockaddr_in sin_src,sin_dst;

	int sockfd, bha, timeout = 0;

	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd < 0)
	{
		printf("ERROR: cannot create socket\n");
		return -1;
	}

	/*---------------------------------------------------------------
     * Bind the local endpoint to receive our responses. If we use a
     * zero, the system will pick one for us, or we can pick our own
     * if we wish to make it easier to get past our firewall.
     */
	memset(&sin_src, 0, sizeof(sin_src));

	sin_src.sin_family      = AF_INET;
	sin_src.sin_addr.s_addr = htonl(INADDR_ANY);
	sin_src.sin_port        = htons(0);
	if (bind(sockfd, (struct sockaddr *)&sin_src, sizeof(sin_src))==(-1))
	{
		printf("ERROR: cannot bind to local socket\n");
		return -1;
	}


	/* query names */
	int have_next_addr = FALSE;
	int            npending = 0;
	struct in_addr next_addr;
	char           errbuf[256];

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
		   (npending > 0))
	{
		fd_set rfds;    /* list of read descriptors */
		fd_set wfds;    /* list of write descriptors */
		fd_set* pwfds = 0;
		int     n;
		struct timeval  tv;

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

		if ( have_next_addr )
		{
			wfds  = rfds;
			pwfds = &wfds;
		}

		if ( (n = select(sockfd+1, &rfds, pwfds, 0, &tv)) == 0 )
		{
			fprintf(stderr, "*timeout (normal end of scan)\n");
			break;
		}
		else if ( n < 0)
		{
			printf("ERROR select()\n");
			break;
		}

        /*--------------------------------------------------------
         * Has the read descriptor fired?
         */
        if ( n > 0  &&  FD_ISSET(sockfd, &rfds) )
		{
			int         paklen;
			struct sockaddr_in  src;
			struct NMBpacket    pak;
			struct NMB_query_response rsp;

			memset(&src, 0, sizeof src);
			memset(&rsp, 0, sizeof rsp);

			int fromlen = sizeof(src);
			paklen = recvfrom(sockfd, &pak, sizeof(pak), 0, (struct sockaddr*)&src, (socklen_t *)&fromlen);
			if ( paklen < 0 )
			{
				printf("Error on read\n");
			}
			else
			{
				printf("Got %d bytes from %s\n", paklen, inet_ntoa(src.sin_addr));
#if 0
				dump_nbtpacket(&pak, paklen, stdout);
#endif
			}
			
			if ( paklen <= 0 ) continue;

			npending--;
			
			if ( parse_nbtstat(&pak, paklen, &rsp, errbuf) )
			{
				rsp.remote = src;
				/*
				if ( target_responded(&rsp.remote.sin_addr) )
				{
					display_nbtstat(&rsp, full_nbtstat);
				}
				*/
				// Add by hong
				display_nbtstat(&rsp, FALSE);
			}
			else
			{
				printf("ERROR: no parse for %s -- %s\n",
                    inet_ntoa(src.sin_addr),
                    errbuf);
			}
		}

        /*--------------------------------------------------------
         * If we have room to write one packet, do so here. Note
         * that we make not notice whether the write succeeds or
         * not: we don't care.
         */
        if ( n > 0  &&  pwfds  && FD_ISSET(sockfd, pwfds) )
        {
			struct sockaddr_in  dst;
			struct NMBpacket    pak;
			int         sendlen;
        
            memset(&dst, 0, sizeof dst);
            
            dst.sin_family      = AF_INET;
            dst.sin_addr.s_addr = next_addr.s_addr;
            dst.sin_port        = htons(137);
           
			short            seq = 1000;

            have_next_addr = FALSE;
        
            fill_namerequest(&pak, &sendlen, seq++);
            
            printf("sending to %s\n", inet_ntoa(dst.sin_addr));
            
            /* yes, ignore response! */
			sendto(sockfd, &pak, sendlen, 0, (struct sockaddr*) &dst, sizeof(struct sockaddr_in));
 
            if ( write_sleep_msecs > 0 )
                sleep_msecs(write_sleep_msecs);
            
            npending++;
        
            continue;
        }
	}

	return 0;
}

int main(int argc, char* argv[])
{
	int ret = 0;
	u_long bha = 0;

	if (argc != 2) {
        fprintf(stderr, "netbios [ip address]\n");
		return -1;
	}

	printf("argv[1]=%s\n", argv[1]);

	bha = host2ip(argv[1]);
	if (bha == 0) {
        fprintf(stderr, "gethostbyname error!\n");
		return -1;
	}

	ret = netbios(bha);
	printf("ret=%d\n", ret);

	return 0;
}
