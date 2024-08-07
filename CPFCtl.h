#ifndef _PFCTL_H_
#define _PFCTL_H_

#ifdef linux
#include "typedefs.h"
#endif

#include <net/if.h>
#include <net/pfvar.h>

#define PF_OSFP_FILE          	"/etc/pf.os"

#define PF_OPT_DISABLE        	0x00001
#define PF_OPT_ENABLE         	0x00002
#define PF_OPT_VERBOSE        	0x00004
#define PF_OPT_NOACTION       	0x00008
#define PF_OPT_QUIET          	0x00010
#define PF_OPT_CLRRULECTRS    	0x00020
#define PF_OPT_USEDNS         	0x00040
#define PF_OPT_VERBOSE2       	0x00080
#define PF_OPT_DUMMYACTION    	0x00100
#define PF_OPT_DEBUG          	0x00200
#define PF_OPT_SHOWALL        	0x00400
#define PF_OPT_OPTIMIZE       	0x00800
#define PF_OPT_NODNS          	0x01000
#define PF_OPT_RECURSE        	0x04000
#define PF_OPT_PORTNAMES      	0x08000
#define PF_OPT_IGNFAIL        	0x10000
#define PF_OPT_CALLSHOW       	0x20000

#define PF_TH_ALL             	0xFF

#define PF_NAT_PROXY_PORT_LOW 	50001
#define PF_NAT_PROXY_PORT_HIGH	65535

#define PF_OPTIMIZE_BASIC     	0x0001
#define PF_OPTIMIZE_PROFILE   	0x0002

/// @brief Helper class to get pfctl data
///
class CPFCtl
{
 public:
  CPFCtl();

 private:
  int pfctlGetStates(int dev, const char* iface, int opts, long shownr);
  void print_name(struct pf_addr*, sa_family_t);
  void print_addr(struct pf_addr_wrap* addr, sa_family_t af, int verbose);
  void print_addr_str(sa_family_t af, struct pf_addr* addr);
  void print_host(struct pf_addr* addr, uint16_t port,
                  sa_family_t af, uint16_t rdom,
                  const char* proto, int opts);
  void print_seq(struct pf_state_peer* p);
  void print_state(struct pf_state* s, int opts);
  int unmask(struct pf_addr* m);

  static constexpr const char* mPFDevice = "/dev/pf";
  static constexpr const char* mIface    = "info";
  // const char	*pf_reasons[PFRES_MAX+1] = PFRES_NAMES;
  // const char	*pf_lcounters[LCNT_MAX+1] = LCNT_NAMES;
  // const char	*pf_fcounters[FCNT_MAX+1] = FCNT_NAMES;
  // const char	*pf_scounters[SCNT_MAX+1] = FCNT_NAMES;
  // const char	*pf_ncounters[NCNT_MAX+1] = FCNT_NAMES;
};

#endif /* _PFCTL_H_ */
