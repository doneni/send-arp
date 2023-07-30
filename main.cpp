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

bool sendArp(pcap_t* handle, char* op, Mac eth_dmac, Mac eth_smac, Mac arp_smac, Mac arp_tmac, Ip arp_sip, Ip arp_tip)
{
	EthArpPacket packet;
	
	packet.eth_.dmac_ = eth_dmac;
	packet.eth_.smac_ = eth_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);


	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	if (op == "request")
		packet.arp_.op_ = htons(ArpHdr::Request);
	else if (op == "reply")
		packet.arp_.op_ = htons(ArpHdr::Reply);
	else
		printf("request or reply?\n");
	packet.arp_.smac_ = arp_smac;
	packet.arp_.tmac_ = arp_tmac;
	packet.arp_.sip_ = htonl(arp_sip);
	packet.arp_.tip_ = htonl(arp_tip);
	
	printf("sending arp target:  %s\n", std::string(arp_tip).c_str());
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle))    ;
		return false;
	}
	return true;
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

	// Open pcap
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	for (int i = 1; i <= iter; i++)
	{
		// Handling argument
        Ip sender_ip = Ip(argv[i * 2]);
        Ip target_ip = Ip(argv[i * 2 + 1]);
        printf("======================\n");
		printf("sender ip: %s\n", std::string(sender_ip).c_str());
        printf("target ip: %s\n", std::string(target_ip).c_str());

		// Send normal arp packet to get sender mac addr
		while(true)
		{
			sendArp(handle, "request", Mac("ff:ff:ff:ff:ff:ff"), my_mac, my_mac, Mac("00:00:00:00:00:00"), my_ip, sender_ip);		
			// and parse...
			struct pcap_pkthdr* header;
			EthArpPacket reqPacket, resPacket;
			const u_char* packet_data;
			int res = pcap_next_ex(pcap, &header, &packet_data);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
			{
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
				break;
			}
			
			if (header->caplen < sizeof(EthArpPacket))
				continue;

			// [todo] memory copy overhead -> 'parsing' w/index
		
			
	}

	pcap_close(handle);
    return 0;
}

