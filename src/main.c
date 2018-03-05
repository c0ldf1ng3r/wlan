#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <syslog.h>
#include <stdarg.h>

#include <sys/socket.h>
#include <linux/sockios.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>

#include "iwutils.h"

#define PCK_MAX_SIZE 1450
#define PCK_MAX_DATA_LENGTH (PCK_MAX_SIZE - PCK_HEADER_SIZE - sizeof(struct rtx_hdr) - CRC_PAD_LENGTH - 1)

#define daemonMode

 
struct rtx_hdr {
    u_int8_t sign[2];
    u_int16_t sum;
    u_int16_t len;
} __attribute__((__packed__));

static const u_int8_t signature[] = { 0x41, 0x42 };
static const u_int8_t addr[] = { 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6 };

const int MIN_ARG_COUNT = 1;
const char * reciveFileName = "/tmp/rtx-recive";
const char * sendFileName = "/tmp/rtx-send";

static char packetHeader[PCK_HEADER_SIZE];

int32_t socket_sending_fd, socket_reciving_fd;
struct sockaddr_ll s_dest_addr;
struct sockaddr_ll s_src_addr;

unsigned char sendBuffer[PCK_MAX_SIZE];
unsigned char reciveBuffer[PCK_MAX_SIZE];

char * nicName;
int useChecksum = 1;
int channel = 5;


void usage(void);
void daemonize(void);
void run(void);

void sendLoop(void);
void reciveLoop(void);

void configure(char * nicName);

void rtx_send(const unsigned char* data, unsigned long int length);
long int rtx_recv(unsigned char* buffer, unsigned long int maxLength);

void sendPacket(const unsigned char* data, unsigned long int length);
unsigned char* recivePacket(long int *len);

unsigned short crc16(const unsigned char* data, long int length);
void preparePacketHeader(void);

void cleanup(void);
static void sighandler(int signum);

void msg(char * fmt, ...);

int main(int argc, char **argv) {

    if(argc - 1 < MIN_ARG_COUNT) {
        usage();
        exit(0);
    }

    int c;
    while ((c = getopt(argc, argv, "ac:")) != -1) {
        switch (c)
        {
            case 'a':
             useChecksum = 0;
            break;
            case 'c':
                channel = atoi(optarg);
            break;
            default:
                usage();
                exit(0);
            break;
        }
    }

    nicName = argv[optind];


    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, sighandler);
    
#ifdef daemonMode
    daemonize();
    openlog(NULL, LOG_PID, LOG_DAEMON);
#endif

    run();
    return 0;
}

void usage(void) {    
    printf("Usage: rtx -a -c <channel> <interface>\n\t -a - ignore checksum generation and validation\n\t -c use custom wifi channel; default 5\n");
}

void daemonize(void) {
    pid_t pid;

    pid = fork();
    if (pid < 0){
        exit(0);
    }

    if (pid > 0){
        exit(0);
    }

    if(setsid() < 0){
        exit(0);
    }

    pid = fork();

    if (pid < 0) {
        exit(0);
    }

    
    if (pid > 0) {
        exit(0);
    }


    umask(0);
    chdir("/");

    int x;
    for (x = sysconf(_SC_OPEN_MAX); x>=0; x--){
        close(x);
    }
}

void run(void) {

    configure(nicName);

    pid_t pid = fork();

    if (pid > 0) {
        msg("starting reciving\n");
        reciveLoop();
    }

    if (pid == 0) {
        msg("starting sending\n");
        sendLoop();
    }
}

void reciveLoop(){
	int recive_fd = 0;

    unlink(reciveFileName);

    int mkError = mkfifo(reciveFileName, 0666);
    if(mkError != 0){
        msg("failed to create fifo %s, reason: %s\n", reciveFileName, strerror(errno));
    }

    recive_fd = open(reciveFileName, O_WRONLY);
    if(recive_fd < 0) {
        msg("failed to open fifo %s, reason: %s\n", reciveFileName, strerror(errno));
        exit(1);
    }

    long int recivedLength, result;
    unsigned char *data_ptr;
    while(1){
        recivedLength = 0;
        data_ptr = recivePacket(&recivedLength);
        if(recivedLength > 0){
			result = write(recive_fd, data_ptr, recivedLength);
			if(result < 0){
				if(errno == EPIPE){
					close(recive_fd);
					recive_fd = 0;
					recive_fd = open(reciveFileName, O_WRONLY);
				}else {
					msg("write to fifo failed, reason: %s\n", strerror(errno));
				}
			}
        }
    }
}

void sendLoop(){	
	int send_fd = 0;

    unlink(sendFileName);

    int mkError = mkfifo(sendFileName, 0666);
    if(mkError != 0){
        msg("failed to fifo %s, reason: %s\n", sendFileName, strerror(errno));
    }

    send_fd = open(sendFileName, O_RDONLY);
    if(send_fd < 0) {
        msg("failed to open fifo %s, reason: %s\n", sendFileName, strerror(errno));
        exit(1);
    }

    long int sendLength;
    static unsigned char buffer[PCK_MAX_DATA_LENGTH] = {0};
    while(1){
        sendLength = 0;
        sendLength = read(send_fd, buffer, PCK_MAX_DATA_LENGTH);

		if(sendLength > 0){
        	sendPacket((const unsigned char*)buffer, sendLength);
		}else if(sendLength == 0) {
			close(send_fd);
			send_fd = 0;
			send_fd = open(sendFileName, O_RDONLY);
		}else if(sendLength < 0 ){
			msg("read from fifo failed, reason: %s\n", strerror(errno));
		}
    }
}

void configure(char * nicName) {
    // interface
    if_down(nicName);
    if_monitor(nicName);
    if_up(nicName);
    if_set_channel(nicName, channel);

    int nicIndex = get_nic_index(nicName);

    socket_sending_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    memset(&s_dest_addr, 0, sizeof(s_dest_addr));

    s_dest_addr.sll_family = AF_PACKET;
    s_dest_addr.sll_protocol = htons(ETH_P_ALL);
    s_dest_addr.sll_ifindex = nicIndex;
    s_dest_addr.sll_hatype = ARPHRD_ETHER;
    s_dest_addr.sll_pkttype = PACKET_OTHERHOST;
    s_dest_addr.sll_halen = ETH_ALEN;
    
    memcpy(s_dest_addr.sll_addr, &addr, sizeof(u_int8_t) * 6);
    s_dest_addr.sll_addr[6] = 0x00;
    s_dest_addr.sll_addr[7] = 0x00;

    // recv
    socket_reciving_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    memset(&s_src_addr, 0, sizeof (s_src_addr));

    s_src_addr.sll_family = AF_PACKET;
    s_src_addr.sll_protocol = htons(ETH_P_ALL);
    s_src_addr.sll_ifindex = nicIndex;
    s_src_addr.sll_hatype = ARPHRD_ETHER;
    s_src_addr.sll_pkttype = PACKET_HOST;
    s_src_addr.sll_halen = ETH_ALEN;

    int s32_res = bind(socket_reciving_fd,
                        (struct sockaddr *) &s_src_addr,
                        sizeof(s_src_addr));
    if(s32_res == -1){
        msg("Socket bind error");
    }

    preparePacketHeader();
}

void rtx_send(const unsigned char* data, unsigned long int length){
    int s32_res = sendto(socket_sending_fd,
                            data,
                            length,
                            MSG_DONTROUTE,
                            (struct sockaddr*)&s_dest_addr,
                            sizeof(s_dest_addr));
    if(s32_res == -1){
        msg("Socket send error: %s", strerror(errno));
    }
}

long int rtx_recv(unsigned char* buffer, unsigned long int maxLength){
     int s32_res = recvfrom(socket_reciving_fd,
                            buffer,
                            maxLength,
                            0,
                            NULL,
                            NULL);
     if(s32_res == -1){
        msg("Socket recv error: %s", strerror(errno));
        return 0;
    }

    return s32_res;
}

void sendPacket(const unsigned char* data, unsigned long int length) {
    if(length > PCK_MAX_DATA_LENGTH) {
        return;
    }

    unsigned char *pointer = sendBuffer;

    memcpy(pointer, packetHeader, PCK_HEADER_SIZE);
    pointer += PCK_HEADER_SIZE;

    struct rtx_hdr *rtxHeader = (struct rtx_hdr*)pointer;
    rtxHeader->sign[0] = signature[0];
    rtxHeader->sign[1] = signature[1];

    if(useChecksum){
        rtxHeader->sum = crc16((const unsigned char*)data, length);
    }else{
        rtxHeader->sum = 0;
    }
        
    rtxHeader->len = length;

    pointer += sizeof(struct rtx_hdr);

    memcpy(pointer, data, length);

    rtx_send(sendBuffer, PCK_HEADER_SIZE + sizeof(struct rtx_hdr) + length + CRC_PAD_LENGTH);
}

unsigned char* recivePacket(long int *len){
    rtx_recv(reciveBuffer, PCK_MAX_SIZE + PCK_HEADER_SIZE + sizeof(struct rtx_hdr) + CRC_PAD_LENGTH);

    struct ieee80211_radiotap_header *tap_header;
    struct ieee80211_hdr *iee_header;
    struct rtx_hdr *rtx_header;

    unsigned char * pointer = (unsigned char*)reciveBuffer;

    tap_header = (struct ieee80211_radiotap_header*)pointer;
    pointer += tap_header->it_len;

    iee_header = (struct ieee80211_hdr*)pointer;

    if(memcmp(iee_header->addr3, &addr, sizeof(u_int8_t) * 6) != 0){
        return 0;
    }

    pointer += sizeof(struct ieee80211_hdr);

    rtx_header = (struct rtx_hdr*)pointer;
    pointer += sizeof(struct rtx_hdr);

    if(rtx_header->sign[0] != signature[0] || rtx_header->sign[1] != signature[1]){
        msg("Invalid packet signature");
        return 0;
    }

    if(useChecksum){
        if(rtx_header->sum != crc16(pointer, rtx_header->len)){
            msg("Invalid packet crc");
            return 0;
        }
    }

    *len = rtx_header->len;
    return pointer;
}

unsigned short crc16(const unsigned char* data, long int length){
    unsigned char x;
    unsigned short crc = 0xFFFF;
    unsigned char* data_p = (unsigned char*)data;
    while (length--){
        x = crc >> 8 ^ *data_p++;
        x ^= x>>4;
        crc = (crc << 8) ^ ((unsigned short)(x << 12)) ^ ((unsigned short)(x << 5)) ^ ((unsigned short)x);
    }
    return crc;
}

void preparePacketHeader(void){
    struct ieee80211_hdr *ieeHeader = (struct ieee80211_hdr*)(packetHeader + sizeof(radiotapHeader));

    memcpy(packetHeader, radiotapHeader, sizeof(radiotapHeader));

    ieeHeader->duration_id = 0x0000;
    ieeHeader->seq_ctrl = 0;

    u_int8_t fcchunk[2] = {0};
    fcchunk[0] = 0xb4;
    fcchunk[1] = 0x02;

    memcpy(&ieeHeader->frame_control, &fcchunk[0], 2 * sizeof(u_int8_t));
    
    u_int8_t reciverAdress[] = {
        0x12, 0x34, 0x56, 0x78, 0x90, 0xff,
    };

    memcpy(&ieeHeader->addr1[0], reciverAdress, 6 * sizeof(u_int8_t));
    memcpy(&ieeHeader->addr2[0], addr, 6 * sizeof(u_int8_t));
    memcpy(&ieeHeader->addr3[0], addr, 6 * sizeof(u_int8_t));
}

void cleanup(void) {
    if(socket_sending_fd) {
        close(socket_sending_fd);
    }

    if(socket_reciving_fd) {
        close(socket_reciving_fd);
    }
}

static void sighandler(int signum){
    msg("SIGTERM recived");
    cleanup();
    exit(0);
}

void msg(char * fmt, ...){
    va_list args;
    va_start(args, fmt);
    va_end(args);

#ifdef daemonMode
    vsyslog(LOG_NOTICE, fmt, args);
#else
    vprintf(fmt, args);
#endif

}
