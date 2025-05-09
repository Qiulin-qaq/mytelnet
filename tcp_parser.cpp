#include "tcp_parser.h"
#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <netinet/in.h>

TcpParser::TcpParser(const uint8_t* data, size_t length)
    : ProtocolLayer(data, length) {
    parse();
}

void TcpParser::parse() {
    if (data_length_ < sizeof(TcpHeader_new)) {
        throw std::runtime_error("TCP header too short");
    }

    const TcpHeader_new* header = reinterpret_cast<const TcpHeader_new*>(raw_data_);
    
    // 计算TCP头部长度 (data offset)
    uint8_t header_length = (ntohs(header->flags) >> 12) * 4;
    if (data_length_ < header_length) {
        throw std::runtime_error("TCP packet shorter than header length");
    }

    // 设置负载指针和长度
    payload_ptr_ = raw_data_ + header_length;
    payload_len_ = data_length_ - header_length;
}

ProtocolType TcpParser::type() const noexcept {
    return ProtocolType::TCP;
}

std::string TcpParser::summary() const noexcept {
    std::ostringstream oss;
    const TcpHeader_new* header = reinterpret_cast<const TcpHeader_new*>(raw_data_);
    
    oss << "TCP " << ntohs(header->source) << " -> " << ntohs(header->dest)
        << " [";
    
    uint16_t flags = ntohs(header->flags) & 0x3F;
    
    if (flags & TCP_SYN) oss << "SYN ";
    if (flags & TCP_FIN) oss << "FIN ";
    if (flags & TCP_RST) oss << "RST ";
    if (flags & TCP_PSH) oss << "PSH ";
    if (flags & TCP_ACK) oss << "ACK ";
    if (flags & TCP_URG) oss << "URG ";
    
    oss << "] Seq=" << ntohl(header->seq)
        << " Ack=" << ntohl(header->ack_seq)
        << " Win=" << ntohs(header->window);
    
    return oss.str();
}

uint16_t TcpParser::source_port() const noexcept {
    const TcpHeader_new* header = reinterpret_cast<const TcpHeader_new*>(raw_data_);
    return ntohs(header->source);
}

uint16_t TcpParser::dest_port() const noexcept {
    const TcpHeader_new* header = reinterpret_cast<const TcpHeader_new*>(raw_data_);
    return ntohs(header->dest);
}

uint32_t TcpParser::sequence_number() const noexcept {
    const TcpHeader_new* header = reinterpret_cast<const TcpHeader_new*>(raw_data_);
    return ntohl(header->seq);
}

uint32_t TcpParser::ack_number() const noexcept {
    const TcpHeader_new* header = reinterpret_cast<const TcpHeader_new*>(raw_data_);
    return ntohl(header->ack_seq);
}

uint8_t TcpParser::data_offset() const noexcept {
    const TcpHeader_new* header = reinterpret_cast<const TcpHeader_new*>(raw_data_);
    return (ntohs(header->flags) >> 12) & 0x0F;
}

uint16_t TcpParser::flags() const noexcept {
    const TcpHeader_new* header = reinterpret_cast<const TcpHeader_new*>(raw_data_);
    return ntohs(header->flags) & 0x3F;
}

uint16_t TcpParser::window_size() const noexcept {
    const TcpHeader_new* header = reinterpret_cast<const TcpHeader_new*>(raw_data_);
    return ntohs(header->window);
}

uint16_t TcpParser::checksum() const noexcept {
    const TcpHeader_new* header = reinterpret_cast<const TcpHeader_new*>(raw_data_);
    return ntohs(header->check);
}

uint16_t TcpParser::urgent_pointer() const noexcept {
    const TcpHeader_new* header = reinterpret_cast<const TcpHeader_new*>(raw_data_);
    return ntohs(header->urg_ptr);
}

bool TcpParser::is_syn() const noexcept {
    return (flags() & TCP_SYN) != 0;
}

bool TcpParser::is_ack() const noexcept {
    return (flags() & TCP_ACK) != 0;
}

bool TcpParser::is_fin() const noexcept {
    return (flags() & TCP_FIN) != 0;
}

bool TcpParser::is_rst() const noexcept {
    return (flags() & TCP_RST) != 0;
}

bool TcpParser::is_psh() const noexcept {
    return (flags() & TCP_PSH) != 0;
}

bool TcpParser::is_urg() const noexcept {
    return (flags() & TCP_URG) != 0;
}

const uint8_t* TcpParser::payload() const noexcept {
    return payload_ptr_;
}

size_t TcpParser::payload_length() const noexcept {
    return payload_len_;
} 
