#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <pcap.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MSG_HEADER  0x01
#define MSG_PACKETS 0x02

#define MAX_UDP_PAYLOAD 65507

typedef struct __attribute__((packed)) {
    uint32_t magic_number;   /* 0xa1b2c3d4 */
    uint16_t version_major;  /* 2           */
    uint16_t version_minor;  /* 4           */
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_file_hdr_t;

typedef struct __attribute__((packed)) {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_rec_hdr_t;

static int sockfd;
static struct sockaddr_in servaddr;
static uint8_t send_buf[MAX_UDP_PAYLOAD];
static size_t send_buf_len = 0;   /* bytes currently in send_buf */
static pcap_t *pcap_handle  = NULL;

static void flush_buffer(void) {
    if (send_buf_len <= 1)
        return;

    if (sendto(sockfd, send_buf, send_buf_len, 0,
            (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("sendto");
    }

    send_buf[0] = MSG_PACKETS;
    send_buf_len = 1;
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data) {
    (void)user;
    size_t rec_total = sizeof(pcap_rec_hdr_t) + hdr->caplen;

    if (1 + rec_total > MAX_UDP_PAYLOAD) {
        fprintf(stderr, "Warning: packet (%zu bytes) exceeds UDP payload limit – skipped\n", rec_total);
        return;
    }

    if (send_buf_len + rec_total > MAX_UDP_PAYLOAD) {
        flush_buffer();
    }

    pcap_rec_hdr_t rec;
    rec.ts_sec = (uint32_t)hdr->ts.tv_sec;
    rec.ts_usec = (uint32_t)hdr->ts.tv_usec;
    rec.incl_len = hdr->caplen;
    rec.orig_len = hdr->len;
    memcpy(send_buf + send_buf_len, &rec, sizeof(rec));
    send_buf_len += sizeof(rec);

    memcpy(send_buf + send_buf_len, data, hdr->caplen);
    send_buf_len += hdr->caplen;
}

static void handle_signal(int sig) {
    (void)sig;
    if (pcap_handle) {
        pcap_breakloop(pcap_handle);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr,
                "Usage: %s <interface> <server_ip> <port> [bpf filter...]\n"
                "\n"
                "Example:\n"
                "  %s wifi_monitor 10.42.0.1 3456 "
                "not wlan type mgt subtype beacon\n",
                argv[0], argv[0]);
        return 1;
    }

    const char *iface = argv[1];
    const char *server_ip = argv[2];
    int port = atoi(argv[3]);
    char filter_exp[2048] = "";
    for (int i = 4; i < argc; i++) {
        if (i > 4) strncat(filter_exp, " ", sizeof(filter_exp) - strlen(filter_exp) - 1);
        strncat(filter_exp, argv[i], sizeof(filter_exp) - strlen(filter_exp) - 1);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_live(iface,
                                 65535,  // snaplen – capture full frame
                                 1,      // promiscuous mode 
                                 100,    //read timeout ms (low = lower latency, slightly more CPU) 
                                 errbuf);
    if (!pcap_handle) {
        fprintf(stderr, "pcap_open_live(%s): %s\n", iface, errbuf);
        return 1;
    }

    if (*errbuf != '\0') {
        fprintf(stderr, "pcap_open_live warning: %s\n", errbuf);
    }
    if (filter_exp[0] != '\0') {
        struct bpf_program fp;
        if (pcap_compile(pcap_handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) < 0) {
            fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(pcap_handle));
            pcap_close(pcap_handle);
            return 1;
        }
        if (pcap_setfilter(pcap_handle, &fp) < 0) {
            fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(pcap_handle));
            pcap_freecode(&fp);
            pcap_close(pcap_handle);
            return 1;
        }
        pcap_freecode(&fp);
        fprintf(stderr, "Filter: %s\n", filter_exp);
    }

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        pcap_close(pcap_handle);
        return 1;
    }
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, server_ip, &servaddr.sin_addr) != 1) {
        fprintf(stderr, "Invalid server IP: %s\n", server_ip);
        close(sockfd);
        pcap_close(pcap_handle);
        return 1;
    }

    uint8_t hdr_msg[1 + sizeof(pcap_file_hdr_t)];
    hdr_msg[0] = MSG_HEADER;

    pcap_file_hdr_t *fhdr = (pcap_file_hdr_t *)(hdr_msg + 1);
    fhdr->magic_number = 0xa1b2c3d4u;
    fhdr->version_major = 2;
    fhdr->version_minor = 4;
    fhdr->thiszone = 0;
    fhdr->sigfigs = 0;
    fhdr->snaplen = (uint32_t)pcap_snapshot(pcap_handle);
    fhdr->network = (uint32_t)pcap_datalink(pcap_handle);

    if (sendto(sockfd, hdr_msg, sizeof(hdr_msg), 0, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("sendto (header)");
        close(sockfd);
        pcap_close(pcap_handle);
        return 1;
    }

    fprintf(stderr, "Capturing on %s  →  %s:%d  (linktype=%d, snaplen=%u)\n",
        iface, server_ip, port, pcap_datalink(pcap_handle), (unsigned)fhdr->snaplen);

    send_buf[0] = MSG_PACKETS;
    send_buf_len = 1;

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    int ret = pcap_loop(pcap_handle, -1 /* infinite */, packet_handler, NULL);
    if (ret == PCAP_ERROR) {
        fprintf(stderr, "pcap_loop: %s\n", pcap_geterr(pcap_handle));
    }
    flush_buffer();

    pcap_close(pcap_handle);
    close(sockfd);
    return 0;
}
