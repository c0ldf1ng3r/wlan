#include "iwutils.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <math.h>


int if_get_flags(int skfd, const char *ifname);
static inline long int freq_to_hz(const struct iw_freq *freq);
static inline void hz_to_freq(struct iw_freq *freq, long int hz);

int get_nic_index(char *pu8_nic_card_name){
    int32_t s32_sock_fd = -1;
    int32_t s32_res = -1;
    struct ifreq s_ifr;

    memset (&s_ifr, 0, sizeof(s_ifr));

    s32_sock_fd = socket (AF_INET, SOCK_DGRAM, 0);

    if( s32_sock_fd == -1 ) {
        printf("%s: socket failed: %s", __func__, strerror(errno));
        return 0;
    }

    s_ifr.ifr_addr.sa_family = AF_INET;
    strncpy(s_ifr.ifr_name, (char *) pu8_nic_card_name, IFNAMSIZ);
    s32_res = ioctl(s32_sock_fd, SIOCGIFINDEX, &s_ifr);

    if(s32_res == -1) {
        printf("%s: ioctl failed: %s", __func__, strerror(errno));
    }

    close(s32_sock_fd);
    return (s_ifr.ifr_ifru.ifru_ivalue);
}

int if_get_flags(int skfd, const char *ifname) {
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);

	if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
		printf("%s: ioctl failed: %s", __func__, strerror(errno));
	}
	return ifr.ifr_flags;
}

int if_up(const char *ifname) {
	struct ifreq ifr;
	int ret, skfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (skfd < 0) {
		printf("%s: socket failed: %s", __func__, strerror(errno));
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);

	ifr.ifr_flags = if_get_flags(skfd, ifname);
	if ( (ifr.ifr_flags & IFF_UP))  {
		return 0;
	}

	ifr.ifr_flags |= IFF_UP;
	ret = ioctl(skfd, SIOCSIFFLAGS, &ifr);
	close(skfd);
	return ret;
}

int if_down(const char *ifname) {
	struct ifreq ifr;
	int ret, skfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (skfd < 0) {
		printf("%s: socket failed: %s", __func__, strerror(errno));
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);

	ifr.ifr_flags = if_get_flags(skfd, ifname);
	if ( !(ifr.ifr_flags & IFF_UP))  {
		return 0;
	}

	ifr.ifr_flags |= IFF_UP;
	ret = ioctl(skfd, SIOCSIFFLAGS, &ifr);
	close(skfd);
	return ret;
}

int if_set_channel(const char *ifname, int channel) {
	struct iwreq iwr;
	int skfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (skfd < 0){
		syslog(LOG_NOTICE, "%s: failed", __func__);
	}

	memset(&iwr, 0, sizeof(struct iwreq));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);

	hz_to_freq(&iwr.u.freq, 2412 + 5 * (channel - 1));
	if (ioctl(skfd, SIOCSIWFREQ, &iwr) < 0) {
		printf("%s: ioctl failed: %s", __func__, strerror(errno));
	}
	return 1;
}

int if_monitor(const char *ifname) {
	struct iwreq iwr;
	int skfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (skfd < 0){
		syslog(LOG_NOTICE, "%s: failed", __func__);
	}

	memset(&iwr, 0, sizeof(struct iwreq));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);

	iwr.u.mode = IW_MODE_MONITOR;

	if (ioctl(skfd, SIOCSIWMODE, &iwr) < 0) {
		printf("%s: ioctl failed: %s", __func__, strerror(errno));
	}
	return 1;
}

static inline long int freq_to_hz(const struct iw_freq *freq){
	return freq->m * pow(10, freq->e);
}

static inline void hz_to_freq(struct iw_freq *freq, long int hz){
	freq->e = 6;
	freq->m = hz;
}
