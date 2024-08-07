#ifndef _TYPEDEFS_H_
#define _TYPEDEFS_H_
/// @brief Helper header to define some bsd staff
///
/// This header will not be needed in QNX because
/// these definitions are present in system headers.
///
/// BSD includes:
///   net/if.h
///   net/pfvar.h

#include <cstddef>  // To include NULL
#include <cstdint>  // For definitions of std::int8_t etc
#include <sys/types.h>

/**< Re-definition of cstdint int8_t etc */
typedef std::uint8_t  u_int8_t;
typedef std::uint32_t u_int32_t;
typedef std::uint64_t u_int64_t;

#define PFI_IFLAG_SKIP		0x0100	/* skip filtering on interface */
#define PFI_IFLAG_ANY		0x0200	/* match any non-loopback interface */

/* flags for RDR options */
#define PF_DPORT_RANGE	0x01		/* Dest port uses range */
#define PF_RPORT_RANGE	0x02		/* RDR'ed port uses range */

/* Reasons code for passing/dropping a packet */
#define PFRES_MATCH	0		/* Explicit match of a rule */
#define PFRES_BADOFF	1		/* Bad offset for pull_hdr */
#define PFRES_FRAG	2		/* Dropping following fragment */
#define PFRES_SHORT	3		/* Dropping short packet */
#define PFRES_NORM	4		/* Dropping by normalizer */
#define PFRES_MEMORY	5		/* Dropped due to lacking mem */
#define PFRES_TS	6		/* Bad TCP Timestamp (RFC1323) */
#define PFRES_CONGEST	7		/* Congestion */
#define PFRES_IPOPTIONS 8		/* IP option */
#define PFRES_PROTCKSUM 9		/* Protocol checksum invalid */
#define PFRES_BADSTATE	10		/* State mismatch */
#define PFRES_STATEINS	11		/* State insertion failure */
#define PFRES_MAXSTATES	12		/* State limit */
#define PFRES_SRCLIMIT	13		/* Source node/conn limit */
#define PFRES_SYNPROXY	14		/* SYN proxy */
#define PFRES_TRANSLATE	15		/* No translation address available */
#define PFRES_NOROUTE	16		/* No route found for PBR action */
#define PFRES_MAX	17		/* total+1 */

#define PFRES_NAMES { \
	"match", \
	"bad-offset", \
	"fragment", \
	"short", \
	"normalize", \
	"memory", \
	"bad-timestamp", \
	"congestion", \
	"ip-option", \
	"proto-cksum", \
	"state-mismatch", \
	"state-insert", \
	"state-limit", \
	"src-limit", \
	"synproxy", \
	"translate", \
	"no-route", \
	NULL \
}

/* Counters for other things we want to keep track of */
#define LCNT_STATES		0	/* states */
#define LCNT_SRCSTATES		1	/* max-src-states */
#define LCNT_SRCNODES		2	/* max-src-nodes */
#define LCNT_SRCCONN		3	/* max-src-conn */
#define LCNT_SRCCONNRATE	4	/* max-src-conn-rate */
#define LCNT_OVERLOAD_TABLE	5	/* entry added to overload table */
#define LCNT_OVERLOAD_FLUSH	6	/* state entries flushed */
#define	LCNT_SYNFLOODS		7	/* synfloods detected */
#define	LCNT_SYNCOOKIES_SENT	8	/* syncookies sent */
#define	LCNT_SYNCOOKIES_VALID	9	/* syncookies validated */
#define LCNT_MAX		10	/* total+1 */

#define LCNT_NAMES { \
	"max states per rule", \
	"max-src-states", \
	"max-src-nodes", \
	"max-src-conn", \
	"max-src-conn-rate", \
	"overload table insertion", \
	"overload flush states", \
	"synfloods detected", \
	"syncookies sent", \
	"syncookies validated", \
	NULL \
}

#define FCNT_STATE_SEARCH	0
#define FCNT_STATE_INSERT	1
#define FCNT_STATE_REMOVALS	2
#define FCNT_MAX		3

#define FCNT_NAMES { \
	"searches", \
	"inserts", \
	"removals", \
	NULL \
}

struct pfctl_watermarks {
	u_int32_t	hi;
	u_int32_t	lo;
};

#define SCNT_SRC_NODE_SEARCH	0
#define SCNT_SRC_NODE_INSERT	1
#define SCNT_SRC_NODE_REMOVALS	2
#define SCNT_MAX		3

#define NCNT_FRAG_SEARCH	0
#define NCNT_FRAG_INSERT	1
#define NCNT_FRAG_REMOVALS	2
#define NCNT_MAX		3

#define	PF_MD5_DIGEST_LENGTH	16

enum	{ PF_PASS, PF_DROP, PF_SCRUB, PF_NOSCRUB, PF_NAT, PF_NONAT,
	  PF_BINAT, PF_NOBINAT, PF_RDR, PF_NORDR, PF_SYNPROXY_DROP, PF_DEFER,
	  PF_MATCH, PF_DIVERT, PF_RT, PF_AFRT };


/// Present in pfct_parser.h
#define PF_OSFP_FILE		"/etc/pf.os"

#define PF_OPT_DISABLE		0x00001
#define PF_OPT_ENABLE		0x00002
#define PF_OPT_VERBOSE		0x00004
#define PF_OPT_NOACTION		0x00008
#define PF_OPT_QUIET		0x00010
#define PF_OPT_CLRRULECTRS	0x00020
#define PF_OPT_USEDNS		0x00040
#define PF_OPT_VERBOSE2		0x00080
#define PF_OPT_DUMMYACTION	0x00100
#define PF_OPT_DEBUG		0x00200
#define PF_OPT_SHOWALL		0x00400
#define PF_OPT_OPTIMIZE		0x00800
#define PF_OPT_NODNS		0x01000
#define PF_OPT_RECURSE		0x04000
#define PF_OPT_PORTNAMES	0x08000
#define PF_OPT_IGNFAIL		0x10000
#define PF_OPT_CALLSHOW		0x20000

#define PF_TH_ALL		0xFF

#define PF_NAT_PROXY_PORT_LOW	50001
#define PF_NAT_PROXY_PORT_HIGH	65535

#define PF_OPTIMIZE_BASIC	0x0001
#define PF_OPTIMIZE_PROFILE	0x0002
////////////////////////////////////////////////////////////////////////////////

struct pf_status {
	u_int64_t	counters[PFRES_MAX];
	u_int64_t	lcounters[LCNT_MAX];	/* limit counters */
	u_int64_t	fcounters[FCNT_MAX];
	u_int64_t	scounters[SCNT_MAX];
	u_int64_t	ncounters[NCNT_MAX];
	u_int64_t	pcounters[2][2][3];
	u_int64_t	bcounters[2][2];
	u_int64_t	stateid;
	u_int64_t	syncookies_inflight[2];	/* unACKed SYNcookies */
	time_t		since;
	u_int32_t	running;
	u_int32_t	states;
	u_int32_t	states_halfopen;
	u_int32_t	src_nodes;
	u_int32_t	fragments;
	u_int32_t	debug;
	u_int32_t	hostid;
	u_int32_t	reass;			/* reassembly */
	u_int8_t	syncookies_active;
	u_int8_t	syncookies_mode;	/* never/always/adaptive */
	u_int8_t	pad[2];
	char		ifname[IFNAMSIZ];
	u_int8_t	pf_chksum[PF_MD5_DIGEST_LENGTH];
};

struct pfioc_synflwats {
	u_int32_t	hiwat;
	u_int32_t	lowat;
};

#define DIOCGETSTATUS	_IOWR('D', 21, struct pf_status)
#define DIOCGETSYNFLWATS _IOWR('D', 99, struct pfioc_synflwats)

/// Present in net/if.h
/*
 * Length of interface external name, including terminating '\0'.
 * Note: this is the same size as a generic device's external name.
 */
#define	IF_NAMESIZE	16

/* Traditional BSD name for length of interface external name. */
#define	IFNAMSIZ	IF_NAMESIZE
////////////////////////////////////////////////////////////////////////////////


#endif /* _TYPEDEFS_H_ */
