#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#define MAC_ADDRESS_LEN 6
#define ETHERNET_TYPE_LEN 2
#define ETHER_ARP_TYPE 0x0806
#define ETHER_IPV4_TYPE 0x0800
#define LAYER_2_SIZE sizeof(struct ethernet_hdr)
#define IP_ADDRESS_LEN 4

#define BUFLEN 100
#define CLEAR(x) memset(&(x), 0, sizeof(x))
unsigned char EXAMPLE_PACKET[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xd4, 0x92, 0x5e, 0x7c, 0x3d, 0x2f, 0x8, 0x6, 0x0, 0x1, 0x8, 0x0, 0x6, 0x4, 0x0, 0x1, 0xd4, 0x92, 0x5e, 0x7c, 0x3d, 0x2f, 0xa, 0x0, 0x0, 0x7c, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0xd0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

void print_packet_as_hex()
{
    unsigned char *incoming_packet = EXAMPLE_PACKET;
    printf("Received packet: ");
    for (int i = 0; i < sizeof(EXAMPLE_PACKET); i++)
    {
        printf("%02x", incoming_packet[i]);
    }
    puts("\n");
}

void print_mac_address_split_by_colons(uint8_t *mac_address)
{
    printf("%02x", mac_address[0]);
    for (int i = 1; i < 6; i++)
    {
        printf(":%02x", mac_address[i]);
    }
    puts("");
}

void print_ip_address_split_by_dots(uint8_t *ip_address)
{
    printf("%d", ip_address[0]);
    for (int i = 1; i < 4; i++)
    {
        printf(".%d", ip_address[i]);
    }
    puts("");
}

struct ethernet_hdr
{
    uint8_t dst_mac[MAC_ADDRESS_LEN];
    uint8_t src_mac[MAC_ADDRESS_LEN];
    uint16_t ethernet_type;
};

char *determine_ether_type(uint16_t ethernet_type)
{
    uint16_t ethernet_type_converted = ntohs(ethernet_type);
    switch (ethernet_type_converted)
    {
    case ETHER_ARP_TYPE:
        return "ARP";
        break;
    case ETHER_IPV4_TYPE:
        return "IPv4";
        break;
    default:
        return "Unknown";
        break;
    };
}

struct arp_hdr
{
    uint16_t hw_type;
    uint16_t protocol_type;
    uint8_t hw_size;
    uint8_t protocol_size;
    uint16_t opcode;
    uint8_t sender_hw_addr[MAC_ADDRESS_LEN];
    uint8_t sender_proto_addr[IP_ADDRESS_LEN];
    uint8_t target_hw_addr[MAC_ADDRESS_LEN];
    uint8_t target_proto_addr[IP_ADDRESS_LEN];
};

void respond_to_arp(unsigned char *packet_arp_header_ptr)
{
    printf("Protocol determined to be ARP\nParsing...\n");
    struct arp_hdr *arp_header_parsed = (struct arp_hdr *)packet_arp_header_ptr;

    printf("ARP Hardware type: %d\n", ntohs(arp_header_parsed->hw_type));

    printf("ARP Protocol type: 0x%x\n", ntohs(arp_header_parsed->protocol_type));

    printf("ARP Hardware size: %d\n", (arp_header_parsed->hw_size));

    printf("ARP Protocol size: %d\n", (arp_header_parsed->protocol_size));

    printf("ARP opcode: %d\n", ntohs(arp_header_parsed->opcode));

    printf("ARP Sender Hardware Address: ");
    print_mac_address_split_by_colons(arp_header_parsed->sender_hw_addr);
    printf("ARP Sender Protocol Address: ");
    print_ip_address_split_by_dots(arp_header_parsed->sender_proto_addr);

    printf("ARP Target Hardware Address: ");
    print_mac_address_split_by_colons(arp_header_parsed->target_hw_addr);

    printf("ARP Target Protocol Address: ");
    print_ip_address_split_by_dots(arp_header_parsed->target_proto_addr);
}

int main(int argc, char *argv[])
{
    print_packet_as_hex();

    struct ethernet_hdr *eth_hdr = (struct ethernet_hdr *)EXAMPLE_PACKET;
    printf("Destination MAC: ");
    print_mac_address_split_by_colons(eth_hdr->dst_mac);

    printf("Source MAC: ");
    print_mac_address_split_by_colons(eth_hdr->src_mac);

    printf("Ethernet Type: %04x\n", ntohs(eth_hdr->ethernet_type));

    char *ether_type_name = determine_ether_type(eth_hdr->ethernet_type);
    printf("Ethernet Type: %s\n", ether_type_name);

    switch (ntohs(eth_hdr->ethernet_type))
    {
    case ETHER_ARP_TYPE:
        respond_to_arp(&(EXAMPLE_PACKET[LAYER_2_SIZE]));
        break;
    case ETHER_IPV4_TYPE:
        // code
        break;
    default:
        // Unknown type
        return 1;
        break;
    }

    return 0;
}