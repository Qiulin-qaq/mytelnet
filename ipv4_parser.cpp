#include "ipv4_parser.h"
#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <netinet/in.h>
#include <arpa/inet.h>








constexpr size_t IPV4_HEADER_MIN_LEN = 20;




Ipv4Parser::Ipv4Parser(const uint8_t* data, size_t length)
    : ProtocolLayer(data, length) {
    parse();
}

void Ipv4Parser::parse() {
    if (data_length_ < sizeof(IpHeader_new)) {
        throw std::runtime_error("IPv4 packet too short");
    }

    const IpHeader_new* header = reinterpret_cast<const IpHeader_new*>(raw_data_);
    
    // 计算IP头部长度
    size_t header_length = (header->version_ihl & 0x0F) * 4;
    if (data_length_ < header_length) {
        throw std::runtime_error("IPv4 packet shorter than header length");
    }

    // 验证 IP 校验和
    uint16_t calculated_checksum = calculate_ip_checksum(header);
    uint16_t packet_checksum = ntohs(header->check);
    //std::cout << "Calculated checksum: 0x" << std::hex << calculated_checksum 
             // << ", Packet checksum: 0x" << packet_checksum << std::dec << std::endl;
    if (calculated_checksum != packet_checksum) {
        throw std::runtime_error("Invalid IP checksum");
    }

    // 设置负载指针和长度
    payload_ptr_ = raw_data_ + header_length;
    payload_len_ = ntohs(header->total_len) - header_length;
}











ProtocolType Ipv4Parser::type() const noexcept {
    return ProtocolType::IPv4;
}

std::string Ipv4Parser::summary() const noexcept {
    std::ostringstream oss;
    const IpHeader_new* header = reinterpret_cast<const IpHeader_new*>(raw_data_);
    
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &header->saddr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &header->daddr, dst_ip, INET_ADDRSTRLEN);
    
    oss << "IPv4 " << src_ip << " -> " << dst_ip
        << " Protocol: " << static_cast<int>(header->protocol)
        << " TTL: " << static_cast<int>(header->ttl)
        << " Length: " << ntohs(header->total_len);
    
    return oss.str();
}

uint8_t Ipv4Parser::protocol() const noexcept {
    const IpHeader_new* header = reinterpret_cast<const IpHeader_new*>(raw_data_);
    return header->protocol;
}

uint32_t Ipv4Parser::source_ip() const noexcept {
    const IpHeader_new* header = reinterpret_cast<const IpHeader_new*>(raw_data_);
    return ntohl(header->saddr);
}

uint32_t Ipv4Parser::dest_ip() const noexcept {
    const IpHeader_new* header = reinterpret_cast<const IpHeader_new*>(raw_data_);
    return ntohl(header->daddr);
}

uint16_t Ipv4Parser::total_length() const noexcept {
    const IpHeader_new* header = reinterpret_cast<const IpHeader_new*>(raw_data_);
    return ntohs(header->total_len);
}

uint8_t Ipv4Parser::version() const noexcept {
    const IpHeader_new* header = reinterpret_cast<const IpHeader_new*>(raw_data_);
    return (header->version_ihl >> 4) & 0x0F;
}

uint8_t Ipv4Parser::ihl() const noexcept {
    const IpHeader_new* header = reinterpret_cast<const IpHeader_new*>(raw_data_);
    return header->version_ihl & 0x0F;
}

uint16_t Ipv4Parser::identification() const noexcept {
    const IpHeader_new* header = reinterpret_cast<const IpHeader_new*>(raw_data_);
    return ntohs(header->id);
}

uint16_t Ipv4Parser::fragment_offset() const noexcept {
    const IpHeader_new* header = reinterpret_cast<const IpHeader_new*>(raw_data_);
    return ntohs(header->frag_off);
}

uint8_t Ipv4Parser::ttl() const noexcept {
    const IpHeader_new* header = reinterpret_cast<const IpHeader_new*>(raw_data_);
    return header->ttl;
}

uint16_t Ipv4Parser::checksum() const noexcept {
    const IpHeader_new* header = reinterpret_cast<const IpHeader_new*>(raw_data_);
    return ntohs(header->check);
}

const uint8_t* Ipv4Parser::payload() const noexcept {
    return payload_ptr_;
}

size_t Ipv4Parser::payload_length() const noexcept {
    return payload_len_;
}    
