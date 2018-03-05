#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <sys/ioctl.h>

struct ieee80211_radiotap_header {
    u_int8_t it_version;
    u_int8_t it_pad;
    u_int16_t it_len;
    u_int32_t it_present;
} __attribute__((__packed__));

struct ieee80211_hdr {   
    u_int16_t frame_control;
    u_int16_t duration_id;
    u_int8_t addr1[6];
    u_int8_t addr2[6];
    u_int8_t addr3[6];
    u_int16_t seq_ctrl;
} __attribute__((__packed__));

static const u_int8_t radiotapHeader[] = {
    0x00, 0x00, // version
    0x18, 0x00, // number of bytes
    0x0f, 0x80, 0x00, 0x00, // fields
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // timestamp
    0x10, // FCS
    0x16, // <-- rate
    0x00, 0x00, 0x00, 0x00, // <-- channel
    0x08, 0x00,
};

#define WLAN_FC_TYPE_DATA 2
#define WLAN_FC_SUBTYPE_DATA 40

#define CRC_PAD_LENGTH 4
#define PCK_HEADER_SIZE (sizeof(radiotapHeader) + sizeof(struct ieee80211_hdr))

int if_monitor(const char *ifname);
int if_up(const char *ifname);
int if_down(const char *ifname);
int if_set_channel(const char *ifname, int channel);
int get_nic_index(char *pu8_nic_card_name);
