#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_NODES  16
#define BUF_SIZE   65536

#define MSG_HEADER  0x01
#define MSG_PACKETS 0x02

typedef struct __attribute__((packed)) {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
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

typedef struct {
    struct in_addr addr;
    FILE *file;
    int slot;
    int session;
    int got_header;
    char filename[64];
} NodeSession;

static NodeSession nodes[MAX_NODES];
static int node_count = 0;

static int open_node_file(NodeSession *n) {
    snprintf(n->filename, sizeof(n->filename), "node%d_session%d.pcap", n->slot, n->session);

    if (n->file) {
        fclose(n->file);
        n->file = NULL;
    }
    n->file = fopen(n->filename, "wb");
    if (!n->file) {
        perror("fopen");
        return -1;
    }
    n->got_header = 0;
    printf("Opened %s for %s (session %d)\n", n->filename, inet_ntoa(n->addr), n->session);
    return 0;
}

static NodeSession *get_or_create_node(struct in_addr addr) {
    for (int i = 0; i < node_count; i++) {
        if (nodes[i].addr.s_addr == addr.s_addr)
            return &nodes[i];
    }
    if (node_count >= MAX_NODES) {
        fprintf(stderr, "Too many nodes (max %d)\n", MAX_NODES);
        return NULL;
    }
    NodeSession *n = &nodes[node_count];
    memset(n, 0, sizeof(*n));
    n->addr = addr;
    n->slot = node_count;
    n->session = 1;
    node_count++;

    if (open_node_file(n) < 0)
        return NULL;

    return n;
}

static void write_records(NodeSession *n, const uint8_t *payload, size_t len) {
    const uint8_t *p = payload;
    size_t rem = len;

    while (rem >= sizeof(pcap_rec_hdr_t)) {
        const pcap_rec_hdr_t *rec = (const pcap_rec_hdr_t *)p;
        size_t rec_total = sizeof(pcap_rec_hdr_t) + rec->incl_len;

        if (rec_total > rem) {
            /*
             * Incomplete record: the datagram was truncated somehow.
             * Stop processing; do not write a partial record.
             */
            fprintf(stderr,
                    "Warning: incomplete record in datagram from %s – "
                    "need %zu bytes, only %zu remain; dropping tail\n",
                    inet_ntoa(n->addr), rec_total, rem);
            break;
        }

        fwrite(p, 1, rec_total, n->file);
        p   += rec_total;
        rem -= rec_total;
    }

    fflush(n->file);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }

    int port = atoi(argv[1]);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) { perror("socket"); return 1; }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons((uint16_t)port);

    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind");
        return 1;
    }

    printf("PCAP server listening on UDP port %d  (max %d clients)\n", port, MAX_NODES);

    static uint8_t buffer[BUF_SIZE];

    while (1) {
        struct sockaddr_in cliaddr;
        socklen_t clilen = sizeof(cliaddr);

        ssize_t n = recvfrom(sockfd, buffer, BUF_SIZE, 0,
                             (struct sockaddr *)&cliaddr, &clilen);
        if (n <= 0) continue;

        if (n < 1) continue;
        uint8_t msg_type = buffer[0];

        NodeSession *node = get_or_create_node(cliaddr.sin_addr);
        if (!node) continue;

        if (msg_type == MSG_HEADER) {
            if ((size_t)n < 1 + sizeof(pcap_file_hdr_t)) {
                fprintf(stderr, "Truncated MSG_HEADER from %s – ignored\n",
                        inet_ntoa(cliaddr.sin_addr));
                continue;
            }

            if (node->got_header) {
                node->session++;
                if (open_node_file(node) < 0) continue;
                printf("Client %s restarted – new file: %s\n",
                       inet_ntoa(cliaddr.sin_addr), node->filename);
            }

            fwrite(buffer + 1, 1, sizeof(pcap_file_hdr_t), node->file);
            fflush(node->file);
            node->got_header = 1;

            const pcap_file_hdr_t *fh = (const pcap_file_hdr_t *)(buffer + 1);
            printf("  Header from %s: linktype=%u snaplen=%u\n",
                   inet_ntoa(cliaddr.sin_addr), fh->network, fh->snaplen);
            continue;
        }

        if (msg_type == MSG_PACKETS) {
            if (!node->got_header) {
                fprintf(stderr,
                        "Warning: packet data from %s before header – "
                        "waiting for header\n",
                        inet_ntoa(cliaddr.sin_addr));
                continue;
            }

            if (n < 2) continue;

            write_records(node, buffer + 1, (size_t)(n - 1));
            continue;
        }

        fprintf(stderr, "Unknown message type 0x%02x from %s – ignored\n",
                msg_type, inet_ntoa(cliaddr.sin_addr));
    }

    // Unreachable probably, but tidy up if we ever break
    for (int i = 0; i < node_count; i++) {
        if (nodes[i].file) fclose(nodes[i].file);
    }
    close(sockfd);
    return 0;
}
