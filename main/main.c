#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#define MAC_ADDRESS_LEN 6
#define ETHERNET_TYPE_LEN 2
#define ETHER_ARP_TYPE 0x0806
#define ETHER_IPV4_TYPE 0x0800

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

int main(int argc, char *argv[])
{
    char *packet_current_position_ptr;
    print_packet_as_hex();

    struct ethernet_hdr *eth_hdr = (struct ethernet_hdr *)EXAMPLE_PACKET;
    printf("Destination MAC: ");
    print_mac_address_split_by_colons(eth_hdr->dst_mac);
    puts("\n");

    printf("Source MAC: ");
    print_mac_address_split_by_colons(eth_hdr->src_mac);
    puts("\n");

    printf("Ethernet Type: %04x\n", ntohs(eth_hdr->ethernet_type));

    char *ether_type_name = determine_ether_type(eth_hdr->ethernet_type);
    printf("Ethernet Type: %s\n", ether_type_name);

    switch (ntohs(eth_hdr->ethernet_type))
    {
    case ETHER_ARP_TYPE:
        /* code */
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