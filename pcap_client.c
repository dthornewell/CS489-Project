#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUF_SIZE (65507)

int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "Usage: %s <server_ip> <port>\n", argv[0]);
    return 1;
  }

  int sockfd;
  struct sockaddr_in servaddr;
  unsigned char buffer[BUF_SIZE];
  ssize_t n;

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("Socket creation failed");
    return 1;
  }

  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(atoi(argv[2]));
  inet_pton(AF_INET, argv[1], &servaddr.sin_addr);

  fprintf(stderr, "Streaming pcap data to %s:%s...\n", argv[1], argv[2]);

  while ((n = read(STDIN_FILENO, buffer, BUF_SIZE)) > 0) {
    if (sendto(sockfd, buffer, n, 0, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
      // if interface drops this fails so we just retry :)
      usleep(100000);
    }
  }

  close(sockfd);
  return 0;
}