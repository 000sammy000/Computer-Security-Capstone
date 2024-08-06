#include "sadb.h"

#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <iomanip>
#include <iostream>
#include <vector>

std::optional<ESPConfig> getConfigFromSADB() {
  // Allocate buffer
  std::vector<uint8_t> message(65536);
  sadb_msg msg{};
  // TODO: Fill sadb_msg
  msg.sadb_msg_version = PF_KEY_V2;
  msg.sadb_msg_type = SADB_DUMP;
  msg.sadb_msg_satype = SADB_SATYPE_ESP;
  msg.sadb_msg_len = sizeof(sadb_msg)/8;
  msg.sadb_msg_pid = getpid();

  // TODO: Create a PF_KEY_V2 socket and write msg to it
  // Then read from socket to get SADB information
  int sockfd = socket(AF_KEY, SOCK_RAW, PF_KEY_V2);
  if (sockfd < 0) {
    std::cerr << "Error creating socket." << std::endl;
    return std::nullopt;
  }
  if (send(sockfd, &msg, sizeof(msg), 0) < 0) {
    std::cerr << "Error sending message." << std::endl;
    close(sockfd);
    return std::nullopt;
  }
  
  ssize_t bytes_read = recv(sockfd, message.data(), message.size(), 0);
  if (bytes_read < 0) {
    std::cerr << "Error receiving message." << std::endl;
    close(sockfd);
    return std::nullopt;
  }

  if (send(sockfd, &msg, sizeof(msg), 0) < 0) {
    std::cerr << "Error sending message." << std::endl;
    close(sockfd);
    return std::nullopt;
  }
  
  bytes_read = recv(sockfd, message.data(), message.size(), 0);
  if (bytes_read < 0) {
    std::cerr << "Error receiving message." << std::endl;
    close(sockfd);
    return std::nullopt;
  }

  // TODO: Set size to number of bytes in response message
  int size = bytes_read;

  sadb_sa *msgp=reinterpret_cast<sadb_sa*>(message.data());
  if (size != sizeof(sadb_msg)) {
    ESPConfig config{};
    // TODO: Parse SADB message
    // If no encryption algorithm is specified, set ealg to nullptr or an appropriate default value
  
    // Parse extensions
    sadb_msg* rcv_message = reinterpret_cast<sadb_msg*>(message.data());
    char * ext_ptr = reinterpret_cast<char*>(msgp+1);
    struct sadb_sa *ext_sa = (struct sadb_sa *)ext_ptr;
    uint32_t spi_little_endian = ntohl(ext_sa->sadb_sa_spi); // Convert to host byte order
    config.spi = spi_little_endian;
    uint8_t auth_algorithm_id = ext_sa->sadb_sa_auth;
    uint8_t encrypt_algorithm_id = ext_sa->sadb_sa_encrypt;
    int find_aalg=0,find_ealg=0;
    while (ext_ptr < reinterpret_cast<char*>(message.data()) + size) {
        sadb_ext* ext = reinterpret_cast<sadb_ext*>(ext_ptr);

        if (ext->sadb_ext_type == SADB_EXT_KEY_AUTH) {
            find_aalg=1;
            sadb_key* key_ext = reinterpret_cast<sadb_key*>(ext);

            //std::cout << "Key data (hex): ";
            int bits;
            uint8_t *p; 
            uint8_t *uint8_array = (uint8_t*)malloc(key_ext->sadb_key_len / 8); 
            int index = 0;
            for (p = (uint8_t *)(key_ext+1), bits = key_ext->sadb_key_bits;
              bits > 0; p++, bits -= 8){
              //printf("%02x", *p);
              uint8_array[index++] = *p;
            }
            //printf("\n");
            std::span<uint8_t> key_data(uint8_array ,index); 
            /*std::cout<<"span data: ";
            for (uint8_t byte :key_data) {
                std::cout << std::hex << std::setw(2) << std::setfill('0')<< static_cast<int>(byte) << " ";
            }
            std::cout << std::endl;*/
            config.aalg = std::make_unique<ESP_AALG>(auth_algorithm_id , key_data);
        }
        if(ext->sadb_ext_type == SADB_EXT_ADDRESS_SRC){

            sadb_address* addr_ext = reinterpret_cast<sadb_address*>(ext);
            struct sockaddr_in* sa;
            sa = reinterpret_cast<struct sockaddr_in*>(addr_ext + 1);
            char addr_str[INET_ADDRSTRLEN];     
            if (inet_ntop(AF_INET, &(sa->sin_addr), addr_str, INET_ADDRSTRLEN) != nullptr) {
                config.local=addr_str;
            } else {
                perror("inet_ntop");
             }

        }else if(ext->sadb_ext_type == SADB_EXT_ADDRESS_DST){
            sadb_address* addr_ext = reinterpret_cast<sadb_address*>(ext);
            struct sockaddr_in* sa;
            sa = reinterpret_cast<struct sockaddr_in*>(addr_ext + 1);
            char addr_str[INET_ADDRSTRLEN];     
            if (inet_ntop(AF_INET, &(sa->sin_addr), addr_str, INET_ADDRSTRLEN) != nullptr) {
                config.remote=addr_str;
            } else {
                  perror("inet_ntop");
            }       
        }else if(ext->sadb_ext_type ==SADB_EXT_KEY_ENCRYPT){
             find_ealg=1;
             sadb_key* key_ext = reinterpret_cast<sadb_key*>(ext);
            // Assuming the key is stored as raw bytes, you might need to convert it to the appropri>
             std::span<uint8_t> key_data(reinterpret_cast<uint8_t*>(key_ext->sadb_key_bits)
                                                               , key_ext->sadb_key_len/8);
             config.ealg = std::make_unique<ESP_EALG>(encrypt_algorithm_id , key_data);   
        }
        ext_ptr += ext->sadb_ext_len * sizeof(uint64_t); // Move to the next extension
    }
    if(find_aalg==0){
        config.aalg=std::make_unique<ESP_AALG>(SADB_AALG_NONE, std::span<uint8_t>{});
    }
    if(find_ealg==0){
        config.ealg=std::make_unique<ESP_EALG>(SADB_EALG_NONE, std::span<uint8_t>{});
    }

    return config;
  }
    
  std::cerr << "SADB entry not found." << std::endl;
  return std::nullopt;
}

std::ostream &operator<<(std::ostream &os, const ESPConfig &config) {
  os << "------------------------------------------------------------" << std::endl;
  os << "AALG  : ";
  if (!config.aalg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.aalg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "EALG  : ";
  if (!config.ealg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.ealg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "Local : " << config.local << std::endl;
  os << "Remote: " << config.remote << std::endl;
  os << "------------------------------------------------------------";
  return os;
}
