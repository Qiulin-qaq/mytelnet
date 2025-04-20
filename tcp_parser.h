#pragma once
#include "protocol_layer.h"
#include <string>
#include <vector>
#include <cstdint>
#include <netinet/in.h>
#include <arpa/inet.h>

class TcpParser : public ProtocolLayer {
public:
    TcpParser(const uint8_t* data, size_t length);
    virtual ~TcpParser() = default;

    virtual ProtocolType type() const noexcept override;
    virtual std::string summary() const noexcept override;
    virtual const uint8_t* payload() const noexcept override;
    virtual size_t payload_length() const noexcept override;

    // TCP特有方法
    uint16_t source_port() const noexcept;
    uint16_t dest_port() const noexcept;
    uint32_t sequence_number() const noexcept;
    uint32_t ack_number() const noexcept;
    uint8_t data_offset() const noexcept;
    uint16_t flags() const noexcept;
    uint16_t window_size() const noexcept;
    uint16_t checksum() const noexcept;
    uint16_t urgent_pointer() const noexcept;

    // 检查TCP标志位
    bool is_syn() const noexcept;
    bool is_ack() const noexcept;
    bool is_fin() const noexcept;
    bool is_rst() const noexcept;
    bool is_psh() const noexcept;
    bool is_urg() const noexcept;

private:
    void parse();
};

// TCP校验和计算函数
inline uint16_t calculate_tcp_checksum(
    const uint32_t src_ip, 
    const uint32_t dst_ip, 
    const TcpHeader_new* tcp_header, 
    const uint8_t* payload, 
    size_t payload_len) {
    
    // 创建伪头部结构体
    struct {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint8_t zero;
        uint8_t protocol;
        uint16_t tcp_len;
    } pseudo_header;
    
    // 填充伪头部 - 确保网络字节序
    pseudo_header.src_ip = htonl(src_ip);
    pseudo_header.dst_ip = htonl(dst_ip);
    pseudo_header.zero = 0;
    pseudo_header.protocol = 6; // TCP协议号
    
    // 获取TCP头部长度 (4位，以32位字为单位)
    uint8_t header_len = ((ntohs(tcp_header->flags) >> 12) & 0xF) * 4;
    if (header_len < 20) {
        header_len = 20; // 确保最小TCP头部长度
    }
    
    // TCP总长度（头部 + 负载）
    pseudo_header.tcp_len = htons(header_len + payload_len);
    
    // 计算校验和（一字节和）
    uint32_t sum = 0;
    
    // 1. 伪头部的和
    uint16_t* ptr = (uint16_t*)&pseudo_header;
    for (size_t i = 0; i < sizeof(pseudo_header) / 2; i++) {
        sum += ntohs(ptr[i]);
    }
    
    // 2. TCP头部的和 (临时将校验和字段清零)
    uint16_t orig_checksum = tcp_header->check;
    const_cast<TcpHeader_new*>(tcp_header)->check = 0;
    
    ptr = (uint16_t*)tcp_header;
    for (size_t i = 0; i < header_len / 2; i++) {
        sum += ntohs(ptr[i]);
    }
    
    // 恢复原始校验和
    const_cast<TcpHeader_new*>(tcp_header)->check = orig_checksum;
    
    // 3. 负载的和
    if (payload && payload_len > 0) {
        ptr = (uint16_t*)payload;
        for (size_t i = 0; i < payload_len / 2; i++) {
            sum += ntohs(ptr[i]);
        }
        
        // 如果负载长度为奇数，处理最后一个字节
        if (payload_len & 1) {
            sum += ((uint16_t)(payload[payload_len - 1])) << 8;
        }
    }
    
    // 进位相加
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // 取反
    return htons(~sum);
} 
