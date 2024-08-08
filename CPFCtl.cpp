#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/sysctl.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <libgen.h>
#include <time.h>

#include "CPFCtl.h"
#include <iostream>

const char       	*clearopt;
char 	            *rulesopt;
const char       	*showopt;
const char       	*debugopt;
char 	            *anchoropt;
const char       	*optiopt = NULL;
char 	            *ifaceopt;
char 	            *tableopt;
const char       	*tblcmdopt;
int	               src_node_killers;
char 	            *src_node_kill[2];
int	               state_killers;
char 	            *state_kill[2];

int dev         = -1;
int first_title = 1;
int labels      = 0;
int exit_val    = 0;

/// @brief constructor
///
CPFCtl::CPFCtl()
{
	dev = open(mDevice, O_RDONLY);

  if (dev >= 0)
  {
    // Debug. Remove later.
    std::cout << "Succeed opening " << mDevice << std::endl;
    //////////////////////////////////////////////////////////////////////

    GetStatus(dev);
  }
  else
  {
    std::cout << "Error opening " << mDevice << " !!!" << std::endl;
  }
}

/// @brief Get data in command "pfctl -s info"
///
/// @param dev    device name
/// @return       0 if succeed -1 if error
int CPFCtl::GetStatus(int dev)
{
  struct pf_status status;

  if (ioctl(dev, DIOCGETSTATUS, &status) == -1)
  {
		/// TODO: log the error warn("DIOCGETSTATUS");
		return (-1);
	}

  printStatus(&status);

	return (0);
}

void CPFCtl::printStatus(struct pf_status *s)
{
	char			statline[80], *running, *debug;
	time_t			runtime = 0;
	struct timespec		uptime;
	int			i;
	char			buf[PF_MD5_DIGEST_LENGTH * 2 + 1];
	static const char	hex[] = "0123456789abcdef";

  // TODO: use GetTime instead of clock_gettime
  // Perhaps it is no needed
	// if (!clock_gettime(CLOCK_BOOTTIME, &uptime))
  // {
	// 	runtime = uptime.tv_sec - s->since;
  // }

	// running = (char*)(s->running ? "Enabled" : "Disabled");

	// if (runtime)
  // {
	// 	unsigned int	sec, min, hrs;
	// 	time_t		day = runtime;

	// 	sec = day % 60;
	// 	day /= 60;
	// 	min = day % 60;
	// 	day /= 60;
	// 	hrs = day % 24;
	// 	day /= 24;
	// 	snprintf(statline, sizeof(statline),
	// 	    "Status: %s for %lld days %.2u:%.2u:%.2u",
	// 	    running, (long long)day, hrs, min, sec);
	// }
  // else
  // {
	// 	snprintf(statline, sizeof(statline), "Status: %s", running);
  // }
	// printf("%-44s", statline);
	// if (asprintf(&debug, "Debug: %s", loglevel_to_string(s->debug)) != -1) {
	// 	printf("%15s\n\n", debug);
	// 	free(debug);
	// }

	// if (opts & PF_OPT_VERBOSE) {
	// 	printf("Hostid:   0x%08x\n", ntohl(s->hostid));

	// 	for (i = 0; i < PF_MD5_DIGEST_LENGTH; i++) {
	// 		buf[i + i] = hex[s->pf_chksum[i] >> 4];
	// 		buf[i + i + 1] = hex[s->pf_chksum[i] & 0x0f];
	// 	}
	// 	buf[i + i] = '\0';
	// 	printf("Checksum: 0x%s\n\n", buf);
	// }

	if (s->ifname[0] != 0) {
		printf("Interface Stats for %-16s %5s %16s\n",
		    s->ifname, "IPv4", "IPv6");
		printf("  %-25s %14llu %16llu\n", "Bytes In",
		    (unsigned long long)s->bcounters[0][0],
		    (unsigned long long)s->bcounters[1][0]);
		printf("  %-25s %14llu %16llu\n", "Bytes Out",
		    (unsigned long long)s->bcounters[0][1],
		    (unsigned long long)s->bcounters[1][1]);
		printf("  Packets In\n");
		printf("    %-23s %14llu %16llu\n", "Passed",
		    (unsigned long long)s->pcounters[0][0][PF_PASS],
		    (unsigned long long)s->pcounters[1][0][PF_PASS]);
		printf("    %-23s %14llu %16llu\n", "Blocked",
		    (unsigned long long)s->pcounters[0][0][PF_DROP],
		    (unsigned long long)s->pcounters[1][0][PF_DROP]);
		printf("  Packets Out\n");
		printf("    %-23s %14llu %16llu\n", "Passed",
		    (unsigned long long)s->pcounters[0][1][PF_PASS],
		    (unsigned long long)s->pcounters[1][1][PF_PASS]);
		printf("    %-23s %14llu %16llu\n\n", "Blocked",
		    (unsigned long long)s->pcounters[0][1][PF_DROP],
		    (unsigned long long)s->pcounters[1][1][PF_DROP]);
	}
	printf("%-27s %14s %16s\n", "State Table", "Total", "Rate");
	printf("  %-25s %14u %14s\n", "current entries", s->states, "");
	// printf("  %-25s %14u %14s\n", "half-open tcp", s->states_halfopen, "");

  for (i = 0; i < FCNT_MAX; i++)
  {
		printf("  %-25s %14llu ", pf_fcounters[i],
			    (unsigned long long)s->fcounters[i]);
		if (runtime > 0)
			printf("%14.1f/s\n",
			    (double)s->fcounters[i] / (double)runtime);
		else
			printf("%14s\n", "");
	}
	// if (opts & PF_OPT_VERBOSE) {
	// 	printf("Source Tracking Table\n");
	// 	printf("  %-25s %14u %14s\n", "current entries",
	// 	    s->src_nodes, "");
	// 	for (i = 0; i < SCNT_MAX; i++) {
	// 		printf("  %-25s %14lld ", pf_scounters[i],
	// 			    s->scounters[i]);
	// 		if (runtime > 0)
	// 			printf("%14.1f/s\n",
	// 			    (double)s->scounters[i] / (double)runtime);
	// 		else
	// 			printf("%14s\n", "");
	// 	}
	// }
	// if (opts & PF_OPT_VERBOSE) {
	// 	printf("Fragments\n");
	// 	printf("  %-25s %14u %14s\n", "current entries",
	// 	    s->fragments, "");
	// 	for (i = 0; i < NCNT_MAX; i++) {
	// 		printf("  %-25s %14lld ", pf_ncounters[i],
	// 			    s->ncounters[i]);
	// 		if (runtime > 0)
	// 			printf("%14.1f/s\n",
	// 			    (double)s->ncounters[i] / (double)runtime);
	// 		else
	// 			printf("%14s\n", "");
	// 	}
	// }
	printf("Counters\n");
	for (i = 0; i < PFRES_MAX; i++)
  {
		printf("  %-25s %14llu ", pf_reasons[i],
		    (unsigned long long)s->counters[i]);

		if (runtime > 0)
			printf("%14.1f/s\n",
			    (double)s->counters[i] / (double)runtime);
		else
			printf("%14s\n", "");
	}
	// if (opts & PF_OPT_VERBOSE) {
	// 	printf("Limit Counters\n");
	// 	for (i = 0; i < LCNT_MAX; i++) {
	// 		printf("  %-25s %14lld ", pf_lcounters[i],
	// 			    s->lcounters[i]);
	// 		if (runtime > 0)
	// 			printf("%14.1f/s\n",
	// 			    (double)s->lcounters[i] / (double)runtime);
	// 		else
	// 			printf("%14s\n", "");
	// 	}
	// }
	// if (opts & PF_OPT_VERBOSE) {
	// 	printf("Adaptive Syncookies Watermarks\n");
	// 	printf("  %-25s %14d states\n", "start", synflwats->hi);
	// 	printf("  %-25s %14d states\n", "end", synflwats->lo);
	// }
}
