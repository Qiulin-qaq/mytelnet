#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <pcap.h>
#include <memory>
#include <functional>
#include <map>
#include <random>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <queue>

#include "packet.h"
#include "ethernet_parser.h"
#include "ipv4_parser.h"
#include "tcp_parser.h"

// TCP连接状态
enum class TcpState {
    CLOSED,
    SYN_SENT,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    LAST_ACK,
    TIME_WAIT,
    CLOSING
};

// TCP连接信息
struct TcpConnection {
    uint32_t local_ip;
    uint16_t local_port;
    uint32_t remote_ip;
    uint16_t remote_port;
    
    uint32_t seq_num;        // 本地序列号
    uint32_t ack_num;        // 确认号
    uint32_t remote_seq_num; // 远程序列号
    
    uint16_t window_size;
    TcpState state;
    
    std::vector<uint8_t> rx_buffer; // 接收缓冲区
    std::vector<uint8_t> tx_buffer; // 发送缓冲区
    
    std::chrono::time_point<std::chrono::steady_clock> last_activity;
    
    // 连接标识符
    std::string get_id() const {
        return std::to_string(local_ip) + ":" + 
               std::to_string(local_port) + "-" + 
               std::to_string(remote_ip) + ":" + 
               std::to_string(remote_port);
    }
};

using PacketHandler = std::function<void(const Packet& packet)>;
using TcpEventHandler = std::function<void(TcpConnection& conn, const std::vector<uint8_t>& data)>;

class TcpStack {
public:
    TcpStack();
    ~TcpStack();
    
    // 初始化
    bool initialize(const std::string& interface_name);
    
    // 连接到远程主机
    bool connect(const std::string& remote_ip, uint16_t remote_port);
    
    // 发送数据
    bool send_data(const std::vector<uint8_t>& data);
    
    // 关闭连接
    bool close_connection();
    
    // 等待连接建立
    bool wait_for_connection(int timeout_ms = 10000);
    
    // 等待数据
    bool wait_for_data(std::vector<uint8_t>& data, int timeout_ms = 10000);
    
    // 获取连接状态
    TcpState get_connection_state() const;
    
    // 设置回调
    void set_on_connected(TcpEventHandler handler) { on_connected_ = handler; }
    void set_on_data_received(TcpEventHandler handler) { on_data_received_ = handler; }
    void set_on_connection_closed(TcpEventHandler handler) { on_connection_closed_ = handler; }
    
private:
    // 捕获线程函数
    void capture_thread_func();
    
    // 数据包处理
    void process_packet(const Packet& packet);
    
    // 构造并发送以太网+IP+TCP数据包
    bool send_tcp_packet(uint16_t flags, const uint8_t* payload = nullptr, size_t payload_len = 0);
    
    // 构造各层头部
    std::vector<uint8_t> build_ethernet_header(const MacAddress_new& dst_mac, const MacAddress_new& src_mac, uint16_t ether_type);
    std::vector<uint8_t> build_ip_header(uint32_t src_ip, uint32_t dst_ip, uint16_t total_len, uint8_t protocol);
    std::vector<uint8_t> build_tcp_header(uint16_t src_port, uint16_t dst_port, uint32_t seq_num, 
                                         uint32_t ack_num, uint16_t flags, uint16_t window_size);
    
    // TCP包过滤条件
    bool is_packet_for_connection(const Packet& packet);
    
    // 获取本机MAC和IP
    bool get_local_mac_and_ip(const std::string& interface_name);
    
    // 获取网关MAC
    bool get_gateway_mac();
    
    // 数据包捕获相关
    pcap_t* pcap_handle_;
    std::thread capture_thread_;
    bool should_stop_;
    
    // 连接相关
    std::shared_ptr<TcpConnection> current_connection_;
    
    // 本机网络信息
    MacAddress_new local_mac_;
    uint32_t local_ip_;
    MacAddress_new gateway_mac_;
    
    // 随机数生成器
    std::mt19937 rng_;
    
    // 同步相关
    std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<std::vector<uint8_t>> data_queue_;
    
    // 事件处理器
    TcpEventHandler on_connected_;
    TcpEventHandler on_data_received_;
    TcpEventHandler on_connection_closed_;
    
    // 超时重传管理
    // TODO: 实现重传机制
}; 
