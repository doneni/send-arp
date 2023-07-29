#include <cstdio>
#include <cstdlib>
#include <pcap.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

bool getMyInfo(const char* dev, Mac& my_mac, Ip& my_ip) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return false;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    // Get MAC address
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR");
        close(sockfd);
        return false;
    }

    my_mac = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));

    // Get IP address
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFADDR");
        close(sockfd);
        return false;
    }

    my_ip = Ip(inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));

    close(sockfd);
    return true;
}

int sendArpPacket(int method, pcap_t* handle, const Mac& eth_smac, const char* eth_dmac,
                  const Mac& arp_smac, const Ip& arp_sip, const Mac& arp_tmac, const Ip& arp_tip)
{
    EthArpPacket packet;

    packet.eth_.smac_ = eth_smac;
    packet.eth_.dmac_ = Mac(eth_dmac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    if (method == 0) {
        packet.arp_.op_ = htons(ArpHdr::Request);
    } else if (method == 1) {
        packet.arp_.op_ = htons(ArpHdr::Reply);
    }
    packet.arp_.smac_ = arp_smac;
    packet.arp_.sip_ = htonl(arp_sip);
    packet.arp_.tmac_ = arp_tmac;
    packet.arp_.tip_ = htonl(arp_tip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    return res;
}

void receiveArpReply(pcap_t* handle, const Mac& my_mac, const Ip& target_ip, Mac& sender_mac) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;

    // Receive ARP reply packets until we find the one from the target IP
    while (true) {
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 1 && header->caplen >= sizeof(EthHdr) + sizeof(ArpHdr)) {
            EthArpPacket* arp_packet = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(packet));
            if (arp_packet->eth_.type() == htons(EthHdr::Arp) &&
                arp_packet->arp_.hrd() == ArpHdr::ETHER &&
                arp_packet->arp_.pro() == EthHdr::Ip4 &&
                arp_packet->arp_.op() == htons(ArpHdr::Reply)
//              && arp_packet->arp_.sip() == htonl(target_ip
		) {
                sender_mac = arp_packet->arp_.smac(); // sender (sip) MAC address
                break;
            }
        } else if (res == 0) {
            // Timeout (optional handling, you can add break; here to stop waiting)
        } else {
            fprintf(stderr, "Error reading packet: %s\n", pcap_geterr(handle));
            break;
        }
    }
}

int main(int argc, char* argv[]) {
    // Checking the arguments
    if (argc < 4 || (argc % 2 != 0)) {
        usage();
        return -1;
    }
    int iter = (argc - 2) / 2;

    // Get Host Information
    Mac my_mac;
    Ip my_ip;
    if (getMyInfo(argv[1], my_mac, my_ip)) {
        printf("interface: %s\n", argv[1]);
        printf("my MAC: %s\n", std::string(my_mac).c_str());
        printf("my IP: %s\n", std::string(my_ip).c_str());
    } else {
        fprintf(stderr, "cant get host info.\n");
        return -1;
    }

    for (int i = 1; i <= iter; i++) {
        Ip sender_ip = Ip(argv[i * 2]);
        Ip target_ip = Ip(argv[i * 2 + 1]);
        printf("sender ip: %s\n", std::string(sender_ip).c_str());
        printf("target ip: %s\n", std::string(target_ip).c_str());

        // Open the pcap handle
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
            fprintf(stderr, "couldn't open device %s(%s)\n", argv[1], errbuf);
            continue;
        }

        // Send ARP Request
        sendArpPacket(0, handle, my_mac, "ff:ff:ff:ff:ff:ff", my_mac, my_ip, Mac("00:00:00:00:00:00"), sender_ip);

        // Receive ARP Reply
        Mac sender_mac;
        receiveArpReply(handle, my_mac, target_ip, sender_mac);
        printf("Received ARP Reply\n");
        printf("Sender MAC address: %s\n", std::string(sender_mac).c_str());

        pcap_close(handle);
    }

    return 0;
}

