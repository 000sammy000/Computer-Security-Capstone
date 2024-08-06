#include "session.h"

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <span>
#include <utility>

#include <arpa/inet.h> 

extern bool running;

uint32_t convertIPv4Address(const std::string& ipAddressStr) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ipAddressStr.c_str(), &addr) != 1) {
        // Error handling
        std::cerr << "Invalid IP address: " << ipAddressStr << std::endl;
        return 0;
    }
    return addr.s_addr;
}

Session::Session(const std::string& iface, ESPConfig&& cfg)
    : sock{0}, recvBuffer{}, sendBuffer{}, config{std::move(cfg)}, state{} {
  checkError(sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL)), "Create socket failed");
  // TODO: Setup sockaddr_ll
  sockaddr_ll addr_ll{};
  addr_ll.sll_family = AF_PACKET;
  addr_ll.sll_protocol = htons(ETH_P_ALL); 
  addr_ll.sll_ifindex = if_nametoindex(iface.c_str()); 
  checkError(bind(sock, reinterpret_cast<sockaddr*>(&addr_ll), sizeof(sockaddr_ll)), "Bind failed");
}

Session::~Session() {
  shutdown(sock, SHUT_RDWR);
  close(sock);
}
void Session::run() {
  epoll_event triggeredEvent[2];
  epoll_event event;
  Epoll ep;

  event.events = EPOLLIN;
  event.data.fd = 0;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, 0, &event), "Failed to add stdin to epoll");
  event.data.fd = sock;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, sock, &event), "Failed to add sock to epoll");

  std::string secret;
  std::cout << "You can start to send the message...\n";
  while (running) {
    int cnt = epoll_wait(ep.fd, triggeredEvent, 2, 500);
    for (int i = 0; i < cnt; i++) {
      if (triggeredEvent[i].data.fd == 0) {
        std::getline(std::cin, secret);
      } else {
        ssize_t readCount = recvfrom(sock, recvBuffer, sizeof(recvBuffer), 0,
                                     reinterpret_cast<sockaddr*>(&addr), &addrLen);
        checkError(readCount, "Failed to read sock");
        state.sendAck = false;
        dissect(readCount);
        if (state.sendAck) encapsulate("");
        if (!secret.empty() && state.recvPacket) {
          encapsulate(secret);
          secret.clear();
        }
      }
    }
  }
}
void Session::dissect(ssize_t rdcnt) {
  auto payload = std::span{recvBuffer, recvBuffer + rdcnt};
  // TODO: NOTE
  // In following packet dissection code, we should set parameters if we are
  // receiving packets from remote
  dissectIPv4(payload);
}

void Session::dissectIPv4(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  // TODO:
  // Set `recvPacket = true` if we are receiving packet from remote
  state.recvPacket = (hdr.saddr != htonl(INADDR_LOOPBACK)); 
  // Call dissectESP(payload) if next protocol is ESP
  in_addr_t remoteAddr;
  if(inet_pton(AF_INET,config.remote.c_str(),&remoteAddr)<=0){
    std::cerr<<"Error: Invalid IP address for config.remote:"<<config.remote<<std::endl;
    state.recvPacket=false;
    return; 

  } 
  state.recvPacket=(hdr.saddr==remoteAddr);
  if(state.recvPacket==0)
    state.ipId=ntohs(hdr.id);
  
  auto payload = buffer.subspan(sizeof(iphdr));
  if(hdr.protocol==IPPROTO_ESP){
    dissectESP(payload);
  }
}
void Session::dissectESP(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  int hashLength = config.aalg->hashLength();
  // Strip hash
  buffer = buffer.subspan(sizeof(ESPHeader), buffer.size() - sizeof(ESPHeader) - hashLength);
  
  std::vector<uint8_t> data;
  // Decrypt payload
  if (!config.ealg->empty()) {
    data = config.ealg->decrypt(buffer);
    buffer = std::span{data.data(), data.size()};
  }

  // TODO:
  // Track ESP sequence number
  //   state.espseq = ;
   
  if(!state.recvPacket)
    state.espseq =htonl(ntohl(hdr.seq) + 1);

  auto trailer = buffer.last(sizeof(ESPTrailer));
  uint8_t paddingLength = trailer[0];
  uint8_t nextProtocol = trailer[1];
  if (nextProtocol == IPPROTO_TCP) {
    auto payload = buffer.first(buffer.size() - paddingLength-sizeof(ESPTrailer));
    dissectTCP(payload);
  }
}
int lastPayloadLen;

void Session::dissectTCP(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  auto length = hdr.doff << 2;
  auto payload = buffer.last(buffer.size() - length);
  
  //TODO
  state.tcpseq = ntohl(hdr.seq);
  state.tcpackseq = ntohl(hdr.ack_seq);
  state.srcPort = ntohs(hdr.source);
  state.dstPort = ntohs(hdr.dest);
  lastPayloadLen=payload.size();
  // Is ACK message?
  if (payload.empty()) return;
  // We only got non ACK when we receive secret, then we need to send ACK
  if (state.recvPacket) {
    std::cout << "Secret: " << std::string(payload.begin(), payload.end()) << std::endl;
    state.sendAck = true;
  }
}
uint16_t calculateChecksum(const uint16_t* data, size_t length) {
    uint32_t sum = 0;

    // Sum up 16-bit words
    while (length > 1) {
        sum += *data++;
        length -= 2;
    }

    // Add any remaining byte
    if (length > 0) {
        sum += *reinterpret_cast<const uint8_t*>(data);
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Take one's complement
    return static_cast<uint16_t>(~sum);
}
void Session::encapsulate(const std::string& payload) {
  //std::cout<<"encapsulate:"<<payload<<std::endl;
  auto buffer = std::span{sendBuffer};
  std::fill(buffer.begin(), buffer.end(), 0);
  int totalLength = encapsulateIPv4(buffer, payload);
  //std::cout<<"encapsulate:"<<payload<<std::endl;
  sendto(sock, sendBuffer, totalLength, 0, reinterpret_cast<sockaddr*>(&addr), addrLen);
}

uint16_t calculateIpv4Checksum(const iphdr* header) {
    return calculateChecksum(reinterpret_cast<const uint16_t*>(header), sizeof(iphdr));
} 
int Session::encapsulateIPv4(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  // TODO: Fill IP header
 
  hdr.version = 4; // Assuming IPv4
  hdr.ihl = sizeof(iphdr) / 4; // Header length in 32-bit words
  hdr.ttl = 64; // Time to Live
  hdr.id = htons(state.ipId+1); 
  hdr.protocol = IPPROTO_ESP; // Protocol - assuming ESP for encapsulation
  hdr.frag_off = 0x0040; // Fragmentation offset
  in_addr_t remoteAddr;
  if(inet_pton(AF_INET,config.remote.c_str(),&remoteAddr)<=0){
    std::cerr<<"Error: Invalid IP address for config.remote:"<<config.remote<<std::endl;
    state.recvPacket=false;
    return 0; 
  } 
  in_addr_t localAddr;
  if(inet_pton(AF_INET,config.local.c_str(),&localAddr)<=0){
    std::cerr<<"Error: Invalid IP address for config.remote:"<<config.remote<<std::endl;
    state.recvPacket=false;
    return 0; 
  } 

  hdr.saddr = localAddr; // Source IP address - convert to network byte order
  hdr.daddr = remoteAddr; // Destination IP address - convert to network byte order
  
  auto nextBuffer = buffer.last(buffer.size() - sizeof(iphdr));
  int payloadLength = encapsulateESP(nextBuffer, payload);
  //std::cout<<"encapsulateIPv4:"<<payload<<std::endl;
  payloadLength += sizeof(iphdr);
  hdr.tot_len = htons(payloadLength); // Total length of IP packet - convert to network byte order
  hdr.check = calculateIpv4Checksum(&hdr);

  return payloadLength;
}
int Session::encapsulateESP(std::span<uint8_t> buffer, const std::string& payload) {
  //std::cout<<"encapsulateESP:"<<payload<<std::endl;
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  auto nextBuffer = buffer.last(buffer.size() - sizeof(ESPHeader));
  // TODO: Fill ESP header
  hdr.spi =htonl(config.spi); 
  hdr.seq =state.espseq;
  int payloadLength = encapsulateTCP(nextBuffer, payload);
  //std::cout<<"encapsulateESP:"<<payload<<std::endl;

  auto endBuffer = nextBuffer.last(nextBuffer.size() - payloadLength);

  
  // TODO: Calculate padding size and do padding in `endBuffer`
  int padSize=4-(payloadLength%4)+2;
  if(payloadLength%4==0)padSize=2;
  payloadLength += padSize;
  
  //std::cout<<"padSize:"<<padSize<<std::endl;
  // ESP trailer
  std::fill(endBuffer.begin(), endBuffer.begin() + padSize, 0);
  
  endBuffer[padSize] = padSize;
  endBuffer[padSize+1] = IPPROTO_TCP; 
  payloadLength += sizeof(ESPTrailer);
  
  std::vector<uint8_t> allData;
  allData.insert(allData.end(),reinterpret_cast<uint8_t*>(&hdr),
                reinterpret_cast<uint8_t*>(&hdr)+sizeof(ESPHeader));
  allData.insert(allData.end(),nextBuffer.begin(),nextBuffer.begin()+payloadLength);

  // Do encryption
  if (!config.ealg->empty()) {
    auto result = config.ealg->encrypt(nextBuffer.first(payloadLength));
    std::copy(result.begin(), result.end(), nextBuffer.begin());
    payloadLength += result.size();
  }
   payloadLength += sizeof(ESPHeader);
  if (!config.aalg->empty()) {
    // TODO: Fill in config.aalg->hash()'s parameter
    auto result = config.aalg->hash(allData);
    std::copy(result.begin(), result.end(), buffer.begin() + payloadLength);
    payloadLength += result.size();
  }

  return payloadLength;

}
struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};
int Session::encapsulateTCP(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  //std::cout<<"encapsulateTCP:"<<payload<<std::endl;
  if (!payload.empty()) hdr.psh = 1;
  // TODO: Fill TCP header
  
  hdr.ack = 1; // Assuming this is not an acknowledgment packet
  hdr.doff = sizeof(tcphdr) / 4; // TCP header length in 32-bit words
  hdr.dest = htons(state.srcPort); // Destination port (converted to network byte order)
  hdr.source = htons(state.dstPort); // Source port (converted to network byte order)
  hdr.ack_seq = htonl(state.tcpseq+lastPayloadLen); // Acknowledgment sequence number (converted to >
  hdr.seq = htonl(state.tcpackseq); // Sequence number (converted to network byte order)
  hdr.window = 0xf601; //
  
  
  auto nextBuffer = buffer.last(buffer.size() - sizeof(tcphdr));
  int payloadLength = 0;
  if (!payload.empty()) {
    std::copy(payload.begin(), payload.end(), nextBuffer.begin());
    payloadLength += payload.size();
  }
  // TODO: Update TCP sequence number
  state.tcpseq+=payloadLength;
  payloadLength += sizeof(tcphdr);
   hdr.check = 0;
  pseudo_header psh;
  psh.source_address = convertIPv4Address(config.local);
  psh.dest_address = convertIPv4Address(config.remote);
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(payloadLength);
    
  size_t psh_len = sizeof(pseudo_header) + sizeof(tcphdr) + payloadLength;
  uint16_t* buffer_for_checksum = new uint16_t[psh_len / 2]; // Using uint16_t for checksum calculat>
  uint8_t* pseudogram = reinterpret_cast<uint8_t*>(&psh);
  std::copy(pseudogram, pseudogram + sizeof(pseudo_header), reinterpret_cast<uint8_t*>(buffer_for_checksum));
  std::copy(buffer.data(), buffer.data() + sizeof(tcphdr) + payloadLength, reinterpret_cast<uint8_t*>(buffer_for_checksum) + sizeof(pseudo_header));

  hdr.check = calculateChecksum(buffer_for_checksum, psh_len);

  delete[] buffer_for_checksum;
  

  return payloadLength;
}
