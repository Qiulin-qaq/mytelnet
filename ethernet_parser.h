#pragma once
#include "protocol_layer.h"
#include <string>


constexpr size_t ETHERNET_HEADER_LEN = 14;
constexpr uint16_t ETHERTYPE_IP = 0x0800;     // IPv4
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;   // IPv6
constexpr uint16_t ETHERTYPE_ARP = 0x0806;    // ARP
constexpr uint16_t ETHERTYPE_VLAN = 0x8100;   // VLAN
constexpr uint16_t ETHERTYPE_REVARP = 0x8035; // Reverse ARP
constexpr uint16_t ETHERTYPE_AT = 0x809B;     // AppleTalk
constexpr uint16_t ETHERTYPE_AARP = 0x80F3;   // AppleTalk ARP
constexpr uint16_t ETHERTYPE_IPX = 0x8137;    // IPX


class EthernetParser : public ProtocolLayer {
public:
    explicit EthernetParser(const uint8_t* data, size_t length);

    // ProtocolLayer 接口实现
    ProtocolType type() const noexcept override {
        return ProtocolType::ETHERNET;
    }
    std::string summary() const noexcept override;

    const uint8_t* payload() const noexcept override {
        return payload_ptr_;
    }

    size_t payload_length() const noexcept override {
        return payload_len_;
    }

    // 以太网特有方法
    const MacAddress_new& source_mac() const noexcept {
        return src_mac_;
    }
    const MacAddress_new& destination_mac() const noexcept {
        return dst_mac_;
    }
    uint16_t ether_type() const noexcept {
        return ether_type_;
    }

private:
    void parse();

    MacAddress_new src_mac_;
    MacAddress_new dst_mac_;
    uint16_t ether_type_;
};    
