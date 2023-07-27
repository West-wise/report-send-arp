#include <iostream>
#include <string>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#define MAC_ADDR_LEN
#pragma pack(push,1)
struct EthArpPacket final{
	EthHdr eth_;
	ArpHdr arp_;
};

#pragma pack(pop)

void getSMAC(const std::string& sip, const std::string& interfaceName, const std::string& myMacAddress, const std::string& gatewayIp) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interfaceName.c_str(), BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", interfaceName.c_str(), errbuf);
        return;
    }

    EthArpPacket normal_packet;

    normal_packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF"); // 브로드캐스트 주소로 ARP 요청을 보냅니다.
    normal_packet.eth_.smac_ = Mac(myMacAddress); // 자신의 MAC 주소를 설정합니다.
    normal_packet.eth_.type_ = htons(EthHdr::Arp);

    normal_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    normal_packet.arp_.pro_ = htons(EthHdr::Ip4);
    normal_packet.arp_.hln_ = Mac::SIZE;
    normal_packet.arp_.pln_ = Ip::SIZE;
    normal_packet.arp_.op_ = htons(ArpHdr::Request);
    normal_packet.arp_.smac_ = Mac(myMacAddress);
    normal_packet.arp_.sip_ = htonl(Ip(gatewayIp)); // 게이트웨이 IP를 사용하여 ARP 요청을 보냅니다.
    normal_packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // 타겟 MAC 주소를 0으로 설정합니다.
    normal_packet.arp_.tip_ = htonl(Ip(sip)); // 요청할 IP 주소를 설정합니다.

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&normal_packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    } else {
        // ARP 응답 패킷을 받아옵니다. (예시이므로 실제로는 timeout 등을 고려해야 합니다.)
        struct pcap_pkthdr* header;
        const u_char* packet;
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 1) {
            // 패킷 수신에 성공한 경우, ARP 응답 패킷에서 해당 IP 주소의 MAC 주소를 출력합니다.
            EthArpPacket* arpResponsePacket = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(packet));
            std::cout << "IP 주소 " << sip << "에 대한 MAC 주소: " << std::string(arpResponsePacket->arp_.smac_) << std::endl;
        } else {
            std::cout << "MAC 주소를 찾을 수 없습니다." << std::endl;
        }
    }

    pcap_close(handle);
}

int main() {
    // 와이파이 인터페이스 이름
    std::string interfaceName = "wlan0";

    // 게이트웨이 IP 주소
    std::string gatewayIp = "192.168.43.1"; // 게이트웨이 IP 주소 예시

    // 자신의 MAC 주소
    std::string myMacAddress = "00:0c:29:50:5e:11";

    // 특정 IP 주소
    std::string targetIp = "192.168.43.174"; // 타겟 IP 주소 예시

    // 특정 IP 주소에 대한 MAC 주소 알아내기
    getSMAC(targetIp, interfaceName, myMacAddress, gatewayIp);

    return 0;
}

