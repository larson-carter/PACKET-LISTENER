#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h> // Include for struct icmphdr
#include <netinet/ip.h>      // Include for struct ip

#define ICMP_ECHO_REQUEST 8
#define MAX_TEXT_LENGTH 1024

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_hdr = (struct ip *)(packet + 14); // Assuming Ethernet header is 14 bytes

    // Ensure the packet is an ICMP packet
    if (ip_hdr->ip_p != IPPROTO_ICMP) {
        return;
    }

    // Get the ICMP header
    struct icmp *icmp = (struct icmp *)(packet + 14 + ip_hdr->ip_hl * 4); // Skip Ethernet + IP headers

    // Check if the packet is an ICMP Echo Request (type 8)
    if (icmp->icmp_type == ICMP_ECHO_REQUEST) {
        // Extract payload data
        const u_char *icmp_payload_data;
        icmp_payload_data = packet + 14 + ip_hdr->ip_hl * 4 + 8; // Skip Ethernet + IP + ICMP headers
        int data_length = header->len - (14 + ip_hdr->ip_hl * 4 + 8); // Total packet length - headers

        // Print payload data
        printf("ICMP Data: ");
        for (int i = 0; i < data_length; i++) {
            printf("%c", *(icmp_payload_data + i));
        }
        printf("\n");

        // Concatenate received text chunks
        char *received_text = (char *)args;
        strncat(received_text, (char *)icmp_payload_data, data_length);

        // Check if the received text contains "FLING-DONE"
        if (strstr(received_text, "FLING-DONE") != NULL) {
            // Stop listening
            pcap_breakloop((pcap_t *)args);
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the network device for packet capture
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    // Set filter for ICMP packets
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return 2;
    }

    // Allocate memory to store received text
    char received_text[MAX_TEXT_LENGTH] = "";

    // Start capturing packets
    printf("Listening on %s...\n", dev);
    pcap_loop(handle, -1, process_packet, (u_char *)handle);

    // Close the session
    pcap_close(handle);

    // Remove "FLING-DONE" text from received text
    char *fling_done_ptr = strstr(received_text, "FLING-DONE");
    if (fling_done_ptr != NULL) {
        *fling_done_ptr = '\0'; // Terminate the string at the "FLING-DONE" position
    }

    // Print the concatenated text without "FLING-DONE"
    printf("Received Text: %s\n", received_text);

    return 0;
}
