#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>

#define ICMP_ECHO_REQUEST 8
#define MAX_TEXT_LENGTH 1024

// Global flag variable to indicate when to stop listening
int stop_listening = 0;

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    char *received_text = (char *)args;

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
        printf("PING PONG\n");
        printf("received_text: %s\n", received_text); // Debugging output

        // Ensure received_text is properly initialized
        if (received_text == NULL) {
            // Allocate memory for received_text
            received_text = malloc(MAX_TEXT_LENGTH);
            if (received_text == NULL) {
                // Handle allocation failure
                printf("Error: Failed to allocate memory for received_text\n");
                return;
            }
            // Null terminate the string
            received_text[0] = '\0';
        }

        // Calculate remaining space in received_text buffer
        int remaining_space = MAX_TEXT_LENGTH - strlen(received_text) - 1; // -1 for null terminator
        if (remaining_space <= 0) {
            // Handle buffer overflow
            printf("Error: Insufficient space in received_text buffer\n");
            return;
        }

        // Determine how much data to copy
        int copy_length = remaining_space < data_length ? remaining_space : data_length;

        // Copy data to received_text
        strncpy(received_text + strlen(received_text), (char *)icmp_payload_data, copy_length);
        received_text[strlen(received_text) + copy_length] = '\0'; // Null terminate the string

        printf("Concatenated Text: %s\n", received_text); // Debugging output

        // Check if the received text contains "FLING-DONE"
        if (strstr(received_text, "FLING-DONE") != NULL) {
            printf("Received Text in process_packet: %s\n", received_text);
            // Set the flag to stop listening
            stop_listening = 1;
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
    char *received_text = malloc(MAX_TEXT_LENGTH);
    if (received_text == NULL) {
        fprintf(stderr, "Failed to allocate memory for received_text\n");
        pcap_close(handle);
        return 2;
    }

    // Ensure the received_text buffer is properly initialized
    received_text[0] = '\0';

    // Start capturing packets
    printf("Listening on %s...\n", dev);
    while (!stop_listening) {
        pcap_dispatch(handle, 1, process_packet, (u_char *)received_text);
    }

    // Close the session
    pcap_close(handle);

    // Print the received text from the main method
    printf("IN MAIN METHOD RECEIVED TEXT: %s\n", received_text);

    // Free the allocated memory
    free(received_text);

    return 0;
}
