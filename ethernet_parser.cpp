#include "ethernet_parser.h"
#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <netinet/in.h>



EthernetParser::EthernetParser(const uint8_t* data, size_t length)
    : ProtocolLayer(data, length) {
    std::cout << "Entering EthernetParser constructor. data pointer: " 
              << static_cast<const void*>(data)
              << ", length: " << length << std::endl;
    if (data == nullptr) {
        throw std::invalid_argument("Input data pointer for EthernetParser is null");
    }
    try {
        parse();
    } catch (const std::exception& e) {
        std::cerr << "Error in EthernetParser: " << e.what() << std::endl;
        throw; // 重新抛出异常，让上层处理
    }
}

void EthernetParser::parse() {
    std::cout << "Entering parse function. data_length_: " << data_length_ << std::endl;
    // 参数校验
    if (data_length_ < ETHERNET_HEADER_LEN) {
        std::cerr << "Error: Ethernet header too short. data_length_: " << data_length_ << std::endl;
        throw std::runtime_error("Ethernet header too short");
    }

    // 解析MAC地址
    std::copy(raw_data_, raw_data_ + 6, dst_mac_.bytes);
    std::copy(raw_data_ + 6, raw_data_ + 12, src_mac_.bytes);

    // 解析以太类型
    ether_type_ = ntohs(*reinterpret_cast<const uint16_t*>(raw_data_ + 12));

    // 设置payload
    payload_ptr_ = raw_data_ + ETHERNET_HEADER_LEN;
    payload_len_ = data_length_ - ETHERNET_HEADER_LEN;

    // 支持更多的以太网类型
    switch (ether_type_) {
        case ETHERTYPE_IP:    // IPv4
        case ETHERTYPE_IPV6:  // IPv6
        case ETHERTYPE_ARP:   // ARP
        case ETHERTYPE_VLAN:  // VLAN
        case ETHERTYPE_REVARP: // Reverse ARP
        case ETHERTYPE_AT:    // AppleTalk
        case ETHERTYPE_AARP:  // AppleTalk ARP
        case ETHERTYPE_IPX:   // IPX
            break;
        default:
            std::cerr << "Warning: Unknown EtherType: 0x" 
                      << std::hex << ether_type_ << std::dec << std::endl;
            break;
    }
}

std::string EthernetParser::summary() const noexcept {
    auto mac_to_str = [](const MacAddress_new& mac) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (size_t i = 0; i < 6; ++i) {
            if (i != 0) oss << ":";
            oss << std::setw(2) << static_cast<int>(mac.bytes[i]);
        }
        return oss.str();
    };

    std::string type_str;
    switch (ether_type_) {
        case ETHERTYPE_IP:    type_str = "IPv4"; break;
        case ETHERTYPE_IPV6:  type_str = "IPv6"; break;
        case ETHERTYPE_ARP:   type_str = "ARP"; break;
        case ETHERTYPE_VLAN:  type_str = "VLAN"; break;
        case ETHERTYPE_REVARP:type_str = "RARP"; break;
        case ETHERTYPE_AT:    type_str = "AppleTalk"; break;
        case ETHERTYPE_AARP:  type_str = "AppleTalk ARP"; break;
        case ETHERTYPE_IPX:   type_str = "IPX"; break;
        default:     type_str = "0x" + std::to_string(ether_type_);
    }

    return "Ethernet [Dst: " + mac_to_str(dst_mac_) +
           ", Src: " + mac_to_str(src_mac_) +
           ", Type: " + type_str + "]";
}    
