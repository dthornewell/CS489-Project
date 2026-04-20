#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define MAX_CONN (10)
#define BUF_SIZE (65536)

typedef struct {
	struct in_addr addr;
	FILE *file;
	char name[32];
} NodeSession;

int main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("Usage: %s <port number>\n", argv[0]);
		return 1;
	}

	int sockfd;
	struct sockaddr_in servaddr, cliaddr;
	socklen_t len = sizeof(cliaddr);
	unsigned char buffer[BUF_SIZE];
	NodeSession nodes[MAX_CONN];
	int node_count = 0;

	memset(nodes, 0, sizeof(nodes));

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = INADDR_ANY;
	servaddr.sin_port = htons(atoi(argv[1]));

	if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
		perror("Bind failed");
		return 1;
	}

	printf("PCAP Server listening on UDP port %s...\n", argv[1]);

	while (1) {
		ssize_t n = recvfrom(sockfd, buffer, BUF_SIZE, 0, (struct sockaddr *)&cliaddr, &len);
		if (n <= 0) continue;

		// match ip to file
		int idx = -1;
		for (int i = 0; i < node_count; i++) {
			if (nodes[i].addr.s_addr == cliaddr.sin_addr.s_addr) {
				idx = i;
				break;
			}
		}

		// new node, make new file
		if (idx == -1 && node_count < MAX_CONN) {
			idx = node_count++;
			nodes[idx].addr = cliaddr.sin_addr;
			snprintf(nodes[idx].name, 32, "test%d.pcap", node_count);
			nodes[idx].file = fopen(nodes[idx].name, "wb");
			printf("Assigned %s to IP %s\n", nodes[idx].name, inet_ntoa(cliaddr.sin_addr));
		}

		if (idx != -1) {
			fwrite(buffer, 1, n, nodes[idx].file);
			fflush(nodes[idx].file);
		}
	}

	return 0;
}