CC = gcc
CFLAGS = -Wall -Wextra -O3 -std=c11
LDFLAGS_CLIENT = -lpcap
LDFLAGS_SERVER =

.PHONY: all clean

all: pcap_client pcap_server

pcap_client: pcap_client.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS_CLIENT)

pcap_server: pcap_server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS_SERVER)

clean:
	rm -f pcap_client pcap_server
