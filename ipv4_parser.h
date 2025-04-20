#pragma once
#include "protocol_layer.h"
#include <iostream>

class Ipv4Parser : public ProtocolLayer {
public:
    Ipv4Parser(const uint8_t* data, size_t length);
    virtual ~Ipv4Parser() = default;

    virtual ProtocolType type() const noexcept override;
    virtual std::string summary() const noexcept override;
    virtual const uint8_t* payload() const noexcept override;
    virtual size_t payload_length() const noexcept override;

    // IPv4鐗规湁鐨勬柟娉�
    uint8_t protocol() const noexcept;
    uint32_t source_ip() const noexcept;
    uint32_t dest_ip() const noexcept;
    uint16_t total_length() const noexcept;
    uint8_t version() const noexcept;
    uint8_t ihl() const noexcept;
    uint16_t identification() const noexcept;
    uint16_t fragment_offset() const noexcept;
    uint8_t ttl() const noexcept;
    uint16_t checksum() const noexcept;

private:
    void parse();
};    


// 閫氱敤鏍￠獙鍜岃绠楀嚱鏁帮紝鍙敤浜嶪P/TCP/UDP
inline uint16_t calculate_checksum_new(const uint8_t* data, size_t length) {
    uint32_t sum = 0;
    for (size_t i = 0; i < length; i += 2) {
        uint16_t word = (data[i] << 8) + (i + 1 < length ? data[i + 1] : 0);
        sum += word;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

// IP澶翠笓鐢ㄦ牎楠屽拰灏佽
inline uint16_t calculate_ip_checksum(const IpHeader_new* ip_header) {
    size_t header_length = (ip_header->version_ihl & 0x0F) * 4;
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(ip_header);
    std::vector<uint8_t> copy(bytes, bytes + header_length);
    copy[10] = 0;
    copy[11] = 0;
    return calculate_checksum_new(copy.data(), header_length);
}
