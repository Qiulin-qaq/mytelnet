#include "tcp_stack.h"
#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <algorithm>

// 匿名命名空间中的辅助函数
namespace {
    // 打印MAC地址
    std::string mac_to_string(const MacAddress_new& mac) {
        char buf[18];
        snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                mac.bytes[0], mac.bytes[1], mac.bytes[2],
                mac.bytes[3], mac.bytes[4], mac.bytes[5]);
        return std::string(buf);
    }
    
    // IP地址转换为字符串
    std::string ip_to_string(uint32_t ip) {
        struct in_addr addr;
        addr.s_addr = htonl(ip);
        return std::string(inet_ntoa(addr));
    }
    
    // 字符串转换为IP地址
    uint32_t string_to_ip(const std::string& ip_str) {
        struct in_addr addr;
        inet_aton(ip_str.c_str(), &addr);
        return ntohl(addr.s_addr);
    }
    
    // 生成随机端口号 (1024-65535)
    uint16_t generate_random_port(std::mt19937& rng) {
        std::uniform_int_distribution<uint16_t> dist(1024, 65535);
        return dist(rng);
    }
    
    // 生成随机序列号
    uint32_t generate_random_seq(std::mt19937& rng) {
        std::uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);
        return dist(rng);
    }
}

TcpStack::TcpStack() 
    : pcap_handle_(nullptr), 
      should_stop_(false), 
      local_ip_(0),
      rng_(std::random_device()()) {
    // 初始化MAC地址为0
    memset(&local_mac_, 0, sizeof(local_mac_));
    memset(&gateway_mac_, 0, sizeof(gateway_mac_));
}

TcpStack::~TcpStack() {
    // 关闭连接
    close_connection();
    
    // 停止捕获线程
    should_stop_ = true;
    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }
    
    // 关闭pcap句柄
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
}

bool TcpStack::initialize(const std::string& interface_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // 打开网络接口 - 启用混杂模式(参数2设为1)，延长超时(参数3设为1000ms)
    pcap_handle_ = pcap_open_live(interface_name.c_str(), 65536, 1, 1000, errbuf);
    if (!pcap_handle_) {
        std::cerr << "Failed to open network interface: " << errbuf << std::endl;
        return false;
    }
    
    // 设置非阻塞模式
    if (pcap_setnonblock(pcap_handle_, 1, errbuf) == -1) {
        std::cerr << "Failed to set non-blocking mode: " << errbuf << std::endl;
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }
    
    // 检查是否支持PACKET_TX_RING发送功能（可选，用于调试）
    int dlt = pcap_datalink(pcap_handle_);
    std::cout << "Interface datalink type: " << dlt << " (" 
              << pcap_datalink_val_to_name(dlt) << ")" << std::endl;
    
    // 获取本机MAC和IP
    if (!get_local_mac_and_ip(interface_name)) {
        std::cerr << "Failed to get local MAC and IP address" << std::endl;
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }
    
    // 获取网关MAC地址
    if (!get_gateway_mac()) {
        std::cerr << "Warning: Failed to get gateway MAC address, using broadcast address" << std::endl;
        // 设置广播MAC地址
        memset(&gateway_mac_, 0xFF, sizeof(gateway_mac_));
    }

    // 设置一个广泛的BPF过滤器，后续会在连接时更新为具体的过滤规则
    std::string filter = "tcp";
    struct bpf_program fp;
    if (pcap_compile(pcap_handle_, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Failed to compile filter: " << pcap_geterr(pcap_handle_) << std::endl;
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }
    if (pcap_setfilter(pcap_handle_, &fp) == -1) {
        std::cerr << "Failed to apply filter: " << pcap_geterr(pcap_handle_) << std::endl;
        pcap_freecode(&fp);
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }
    pcap_freecode(&fp);
    
    // 启动捕获线程
    should_stop_ = false;
    capture_thread_ = std::thread(&TcpStack::capture_thread_func, this);
    
    std::cout << "TCP stack initialized, Local IP: " << ip_to_string(local_ip_) 
              << ", MAC: " << mac_to_string(local_mac_) 
              << ", Gateway MAC: " << mac_to_string(gateway_mac_) << std::endl;
    
    return true;
}

bool TcpStack::get_local_mac_and_ip(const std::string& interface_name) {
    // 使用libpcap获取网络接口信息，而不使用socket
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // 获取所有可用的网络接口
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Failed to get network interfaces: " << errbuf << std::endl;
        return false;
    }
    
    bool found = false;
    
    // 遍历所有网络接口
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        if (dev->name && interface_name == dev->name) {
            // 找到指定的网络接口
            
            // 尝试获取IP地址
            for (pcap_addr_t* addr = dev->addresses; addr != nullptr; addr = addr->next) {
                if (addr->addr && addr->addr->sa_family == AF_INET) {
                    // 获取IPv4地址
                    struct sockaddr_in* ipv4 = (struct sockaddr_in*)addr->addr;
                    local_ip_ = ntohl(ipv4->sin_addr.s_addr);
                    found = true;
                    break;
                }
            }
            
            if (found) {
                break;
            }
        }
    }
    
    // 释放设备列表
    pcap_freealldevs(alldevs);
    
    if (!found) {
        std::cerr << "Could not find IP address for interface: " << interface_name << std::endl;
        return false;
    }
    
    // 为了获取MAC地址，我们需要打开设备并进行一些额外操作
    // 由于没有很好的直接方法通过libpcap获取MAC地址，我们可以：
    // 1. 生成一个随机MAC地址进行测试
    // 或者
    // 2. 使用ARP请求自己的IP地址获取MAC地址
    
    // 为简化，这里使用选项1：生成一个随机的MAC地址
    uint8_t mac[6];
    for (int i = 0; i < 6; i++) {
        mac[i] = static_cast<uint8_t>(rand() % 256);
    }
    
    // 确保这是一个合法的单播地址
    mac[0] &= 0xFE; // 清除第一个字节的最低位，使其成为单播地址
    
    // 复制MAC地址
    memcpy(local_mac_.bytes, mac, 6);
    
    std::cout << "Using IP: " << ip_to_string(local_ip_)
              << " and MAC: " << mac_to_string(local_mac_) << std::endl;
    
    return true;
}

bool TcpStack::get_gateway_mac() {
    // 这个功能在没有使用socket的情况下比较复杂
    // 我们可以通过捕获ARP或读取/proc文件系统来获取网关MAC
    // 为简化实现，我们直接使用指定的MAC地址
    
    // 使用虚拟机环境中的网关MAC地址
    gateway_mac_.bytes[0] = 0x00;
    gateway_mac_.bytes[1] = 0x50;
    gateway_mac_.bytes[2] = 0x56;
    gateway_mac_.bytes[3] = 0xe7;
    gateway_mac_.bytes[4] = 0xfb;
    gateway_mac_.bytes[5] = 0x1b;
    
    std::cout << "Using gateway MAC: " << mac_to_string(gateway_mac_) << std::endl;
    
    return true;
}

void TcpStack::capture_thread_func() {
    struct pcap_pkthdr* header;
    const u_char* packet_data;
    
    std::cout << "Packet capture thread started..." << std::endl;
    
    // 设置更频繁的捕获轮询
    const int max_packets_per_loop = 10;  // 每次循环处理的最大数据包数
    
    while (!should_stop_) {
        int packets_processed = 0;
        
        // 尝试处理多个数据包，提高效率
        while (packets_processed < max_packets_per_loop) {
            int res = pcap_next_ex(pcap_handle_, &header, &packet_data);
            if (res == 0) {
                // 超时，没有数据包可处理
                break;
            } else if (res == -1) {
                // 错误
                std::cerr << "pcap_next_ex error: " << pcap_geterr(pcap_handle_) << std::endl;
                should_stop_ = true;
                break;
            } else if (res == -2) {
                // 读到文件结尾
                should_stop_ = true;
                break;
            } else if (res == 1) {
                // 成功捕获数据包
                packets_processed++;
                
                // 处理数据包
                try {
                    // 打印基本信息以便调试
                    std::cout << "Captured packet: " << header->len << " bytes at time " 
                              << header->ts.tv_sec << "." << header->ts.tv_usec << std::endl;
                    
                    // 创建数据包对象
                    Packet packet(header->ts);
                    
                    // 解析以太网层
                    auto eth_layer = std::make_unique<EthernetParser>(packet_data, header->caplen);
                    packet.add_layer(std::move(eth_layer));
                    
                    // 如果以太网层的负载是IPv4
                    const EthernetParser* eth = packet.find_layer<EthernetParser>();
                    if (eth && eth->ether_type() == ETHERTYPE_IP) {
                        // 打印MAC地址
                        std::cout << "Ethernet: " << mac_to_string(eth->source_mac()) << " -> " 
                                  << mac_to_string(eth->destination_mac()) << std::endl;
                        
                        // 解析IPv4层
                        auto ip_layer = std::make_unique<Ipv4Parser>(eth->payload(), eth->payload_length());
                        packet.add_layer(std::move(ip_layer));
                        
                        const Ipv4Parser* ip = packet.find_layer<Ipv4Parser>();
                        if (ip) {
                            std::cout << "IP packet: " << ip_to_string(ip->source_ip()) 
                                      << " -> " << ip_to_string(ip->dest_ip())
                                      << " Protocol: " << static_cast<int>(ip->protocol()) 
                                      << " Length: " << ip->total_length() << std::endl;
                        
                            // 如果IPv4层的负载是TCP
                            if (ip->protocol() == 6) { // TCP协议号为6
                                // 解析TCP层
                                auto tcp_layer = std::make_unique<TcpParser>(ip->payload(), ip->payload_length());
                                packet.add_layer(std::move(tcp_layer));
                                
                                const TcpParser* tcp = packet.find_layer<TcpParser>();
                                if (tcp) {
                                    std::cout << "TCP packet: " << tcp->source_port() 
                                             << " -> " << tcp->dest_port() 
                                             << " Seq: " << tcp->sequence_number()
                                             << " Ack: " << tcp->ack_number()
                                             << " Flags: " 
                                             << (tcp->is_syn() ? "S" : "") 
                                             << (tcp->is_ack() ? "A" : "") 
                                             << (tcp->is_fin() ? "F" : "") 
                                             << (tcp->is_rst() ? "R" : "") 
                                             << (tcp->is_psh() ? "P" : "") 
                                             << " Window: " << tcp->window_size()
                                             << " Data Offset: " << static_cast<int>(tcp->data_offset())
                                             << " Data Length: " << tcp->payload_length()
                                             << std::endl;
                                    
                                    // 打印数据包负载
                                    if (tcp->payload_length() > 0) {
                                        std::cout << "Payload (" << tcp->payload_length() << " bytes):" << std::endl;
                                        
                                        // 打印16进制和ASCII形式
                                        const uint8_t* payload = tcp->payload();
                                        for (size_t i = 0; i < tcp->payload_length(); i += 16) {
                                            // 打印偏移量
                                            printf("%04zx: ", i);
                                            
                                            // 打印十六进制
                                            for (size_t j = 0; j < 16; j++) {
                                                if (i + j < tcp->payload_length()) {
                                                    printf("%02x ", payload[i + j]);
                                                } else {
                                                    printf("   ");
                                                }
                                                
                                                // 在中间添加额外空格
                                                if (j == 7) {
                                                    printf(" ");
                                                }
                                            }
                                            
                                            // 打印ASCII
                                            printf(" |");
                                            for (size_t j = 0; j < 16; j++) {
                                                if (i + j < tcp->payload_length()) {
                                                    char c = payload[i + j];
                                                    // 只打印可打印字符
                                                    printf("%c", (c >= 32 && c <= 126) ? c : '.');
                                                } else {
                                                    printf(" ");
                                                }
                                            }
                                            printf("|\n");
                                        }
                                        std::cout << std::endl;
                                    }
                                }
                                
                                // 处理数据包
                                process_packet(packet);
                            }
                        }
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Packet processing exception: " << e.what() << std::endl;
                }
            }
        }
        
        // 如果没有处理任何数据包，短暂休眠以减少CPU占用
        if (packets_processed == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    
    std::cout << "Packet capture thread terminated." << std::endl;
}

bool TcpStack::connect(const std::string& remote_ip, uint16_t remote_port) {
    if (!pcap_handle_) {
        std::cerr << "TCP stack not initialized" << std::endl;
        return false;
    }
    
    // 创建新的TCP连接对象
    std::shared_ptr<TcpConnection> conn = std::make_shared<TcpConnection>();
    conn->local_ip = local_ip_;
    conn->local_port = generate_random_port(rng_);
    conn->remote_ip = string_to_ip(remote_ip);
    conn->remote_port = remote_port;
    conn->seq_num = generate_random_seq(rng_);
    conn->ack_num = 0;
    conn->remote_seq_num = 0;
    conn->window_size = 8192;
    conn->state = TcpState::CLOSED;
    conn->last_activity = std::chrono::steady_clock::now();
    
    // 更新BPF过滤器以匹配当前连接
    std::string filter = "host " + remote_ip + " and tcp and (port " + 
                         std::to_string(remote_port) + " or port " + 
                         std::to_string(conn->local_port) + ")";
    
    std::cout << "Setting BPF filter: " << filter << std::endl;
    
    struct bpf_program fp;
    if (pcap_compile(pcap_handle_, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Failed to compile connection filter: " << pcap_geterr(pcap_handle_) << std::endl;
        return false;
    }
    if (pcap_setfilter(pcap_handle_, &fp) == -1) {
        std::cerr << "Failed to apply connection filter: " << pcap_geterr(pcap_handle_) << std::endl;
        pcap_freecode(&fp);
        return false;
    }
    pcap_freecode(&fp);
    
    // 设置当前连接
    std::lock_guard<std::mutex> lock(mutex_);
    current_connection_ = conn;
    
    // 发送SYN包
    std::cout << "Sending SYN packet, connecting to " << remote_ip << ":" << remote_port << std::endl;
    if (!send_tcp_packet(TCP_SYN)) {
        std::cerr << "Failed to send SYN packet" << std::endl;
        current_connection_ = nullptr;
        return false;
    }
    
    // 更新状态
    current_connection_->state = TcpState::SYN_SENT;
    
    return true;
}

bool TcpStack::wait_for_connection(int timeout_ms) {
    auto start_time = std::chrono::steady_clock::now();
    
    // 增加默认超时时间到30秒
    if (timeout_ms <= 0) {
        timeout_ms = 30000;
    }
    
    std::cout << "Waiting for connection establishment (timeout: " << timeout_ms << "ms)..." << std::endl;
    
    // 添加SYN包重传逻辑
    int syn_retries = 0;
    const int max_syn_retries = 3;
    const int syn_retry_interval_ms = 3000; // 3秒重传一次
    auto last_syn_time = start_time;
    
    while (true) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (current_connection_ && current_connection_->state == TcpState::ESTABLISHED) {
                std::cout << "Connection established successfully!" << std::endl;
                return true;
            }
            
            // 检查是否需要重传SYN包
            auto now = std::chrono::steady_clock::now();
            auto elapsed_since_last_syn = std::chrono::duration_cast<std::chrono::milliseconds>
                                         (now - last_syn_time).count();
            
            if (current_connection_ && 
                current_connection_->state == TcpState::SYN_SENT && 
                elapsed_since_last_syn >= syn_retry_interval_ms && 
                syn_retries < max_syn_retries) {
                
                std::cout << "Retransmitting SYN packet (retry " << (syn_retries + 1) 
                          << " of " << max_syn_retries << ")..." << std::endl;
                
                // 重新发送SYN包
                if (send_tcp_packet(TCP_SYN)) {
                    syn_retries++;
                    last_syn_time = now;
                }
            }
        }
        
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
        
        // 每5秒输出一次等待状态
        if (elapsed % 5000 < 100 && elapsed > 0) {
            std::cout << "Still waiting for connection... " << elapsed/1000 << " seconds elapsed" << std::endl;
            
            // 检查连接状态
            std::lock_guard<std::mutex> lock(mutex_);
            if (current_connection_) {
                std::cout << "Current connection state: " ;
                switch (current_connection_->state) {
                    case TcpState::CLOSED: std::cout << "CLOSED"; break;
                    case TcpState::SYN_SENT: std::cout << "SYN_SENT"; break;
                    case TcpState::ESTABLISHED: std::cout << "ESTABLISHED"; break;
                    case TcpState::FIN_WAIT_1: std::cout << "FIN_WAIT_1"; break;
                    case TcpState::FIN_WAIT_2: std::cout << "FIN_WAIT_2"; break;
                    case TcpState::CLOSE_WAIT: std::cout << "CLOSE_WAIT"; break;
                    case TcpState::LAST_ACK: std::cout << "LAST_ACK"; break;
                    case TcpState::TIME_WAIT: std::cout << "TIME_WAIT"; break;
                    case TcpState::CLOSING: std::cout << "CLOSING"; break;
                    default: std::cout << "UNKNOWN"; break;
                }
                std::cout << std::endl;
            }
        }
        
        if (elapsed >= timeout_ms) {
            std::cerr << "Connection timeout after " << timeout_ms << "ms" << std::endl;
            std::cerr << "Failed to receive SYN-ACK from the server. Possible causes:" << std::endl;
            std::cerr << "  - Server is not reachable" << std::endl;
            std::cerr << "  - Server is not accepting connections on specified port" << std::endl;
            std::cerr << "  - Firewall is blocking the connection" << std::endl;
            std::cerr << "  - Packet capture filter is incorrect" << std::endl;
            
            // 打印更多调试信息
            std::cerr << "Debug info:" << std::endl;
            std::cerr << "  - Local IP: " << ip_to_string(local_ip_) << std::endl; 
            std::cerr << "  - Local MAC: " << mac_to_string(local_mac_) << std::endl;
            std::cerr << "  - Gateway MAC: " << mac_to_string(gateway_mac_) << std::endl;
            
            if (current_connection_) {
                std::cerr << "  - Local Port: " << current_connection_->local_port << std::endl;
                std::cerr << "  - Remote IP: " << ip_to_string(current_connection_->remote_ip) << std::endl;
                std::cerr << "  - Remote Port: " << current_connection_->remote_port << std::endl;
                std::cerr << "  - SYN Retries: " << syn_retries << std::endl;
            }
            
            return false;
        }
        
        // 等待一小段时间
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

bool TcpStack::send_data(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!current_connection_ || current_connection_->state != TcpState::ESTABLISHED) {
        std::cerr << "TCP connection not established, cannot send data" << std::endl;
        return false;
    }
    
    // 发送数据包
    std::cout << "Sending data packet, length: " << data.size() << " bytes" << std::endl;
    if (!send_tcp_packet(TCP_PSH | TCP_ACK, data.data(), data.size())) {
        std::cerr << "Failed to send data" << std::endl;
        return false;
    }
    
    return true;
}

bool TcpStack::wait_for_data(std::vector<uint8_t>& data, int timeout_ms) {
    auto start_time = std::chrono::steady_clock::now();
    
    while (true) {
        // 检查数据队列
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!data_queue_.empty()) {
                data = std::move(data_queue_.front());
                data_queue_.pop();
                return true;
            }
        }
        
        // 检查超时
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
        if (elapsed >= timeout_ms) {
            return false;
        }
        
        // 等待一小段时间
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

bool TcpStack::close_connection() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!current_connection_ || current_connection_->state == TcpState::CLOSED) {
        // 已经关闭
        return true;
    }
    
    // 只有在连接已建立的情况下才发送FIN包
    if (current_connection_->state == TcpState::ESTABLISHED) {
        std::cout << "Sending FIN packet, closing connection" << std::endl;
        if (!send_tcp_packet(TCP_FIN | TCP_ACK)) {
            std::cerr << "Failed to send FIN packet" << std::endl;
            return false;
        }
        
        // 更新状态
        current_connection_->state = TcpState::FIN_WAIT_1;
    } else {
        // 直接关闭连接
        current_connection_->state = TcpState::CLOSED;
    }
    
    return true;
}

TcpState TcpStack::get_connection_state() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
    if (current_connection_) {
        return current_connection_->state;
    }
    return TcpState::CLOSED;
}

void TcpStack::process_packet(const Packet& packet) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!current_connection_) {
        return;
    }
    
    // 检查是否属于当前连接
    if (!is_packet_for_connection(packet)) {
        return;
    }
    
    const TcpParser* tcp = packet.find_layer<TcpParser>();
    const Ipv4Parser* ip = packet.find_layer<Ipv4Parser>();
    
    if (!tcp || !ip) {
        return;
    }
    
    // 更新最后活动时间
    current_connection_->last_activity = std::chrono::steady_clock::now();
    
    // 根据当前状态和接收到的包类型，执行相应的操作
    switch (current_connection_->state) {
        case TcpState::SYN_SENT:
            // 等待SYN+ACK
            if (tcp->is_syn() && tcp->is_ack()) {
                std::cout << "Received SYN+ACK, sending ACK" << std::endl;
                
                // 如果源端口与我们预期的不同，更新连接信息
                if (tcp->source_port() != current_connection_->remote_port) {
                    std::cout << "Updating remote port from " << current_connection_->remote_port 
                              << " to " << tcp->source_port() << std::endl;
                    current_connection_->remote_port = tcp->source_port();
                }
                
                // 保存远程序列号
                current_connection_->remote_seq_num = tcp->sequence_number();
                
                // 设置确认号为远程序列号+1
                current_connection_->ack_num = tcp->sequence_number() + 1;
                
                // 发送ACK
                if (send_tcp_packet(TCP_ACK)) {
                    // 连接已建立
                    current_connection_->state = TcpState::ESTABLISHED;
                    
                    // 调用连接成功回调
                    if (on_connected_) {
                        on_connected_(*current_connection_, {});
                    }
                }
            }
            break;
            
        case TcpState::ESTABLISHED:
            // 处理数据包
            if (tcp->is_psh() && tcp->is_ack()) {
                // 数据包，提取负载
                if (tcp->payload_length() > 0) {
                    std::cout << "Received data packet, length: " << tcp->payload_length() << " bytes" << std::endl;
                    
                    // 复制数据
                    std::vector<uint8_t> payload_data(tcp->payload(), tcp->payload() + tcp->payload_length());
                    
                    // 更新序列号和确认号
                    current_connection_->ack_num = tcp->sequence_number() + tcp->payload_length();
                    
                    // 发送ACK确认数据
                    send_tcp_packet(TCP_ACK);
                    
                    // 将数据加入队列
                    data_queue_.push(std::move(payload_data));
                    
                    // 调用数据接收回调
                    if (on_data_received_ && !data_queue_.empty()) {
                        on_data_received_(*current_connection_, data_queue_.back());
                    }
                }
            } else if (tcp->is_fin() && tcp->is_ack()) {
                // 服务器要求关闭连接
                std::cout << "Received FIN+ACK, sending ACK" << std::endl;
                
                // 更新确认号
                current_connection_->ack_num = tcp->sequence_number() + 1;
                
                // 发送ACK
                send_tcp_packet(TCP_ACK);
                
                // 更新状态
                current_connection_->state = TcpState::CLOSE_WAIT;
                
                // 发送FIN+ACK
                std::cout << "Sending FIN+ACK" << std::endl;
                send_tcp_packet(TCP_FIN | TCP_ACK);
                
                // 更新状态
                current_connection_->state = TcpState::LAST_ACK;
            }
            break;
            
        case TcpState::FIN_WAIT_1:
            // 等待ACK
            if (tcp->is_ack() && !tcp->is_fin()) {
                std::cout << "Received ACK, waiting for FIN" << std::endl;
                current_connection_->state = TcpState::FIN_WAIT_2;
            } else if (tcp->is_fin() && tcp->is_ack()) {
                // 同时收到FIN+ACK
                std::cout << "Received FIN+ACK, sending ACK" << std::endl;
                
                // 更新确认号
                current_connection_->ack_num = tcp->sequence_number() + 1;
                
                // 发送ACK
                send_tcp_packet(TCP_ACK);
                
                // 更新状态
                current_connection_->state = TcpState::TIME_WAIT;
                
                // 在实际应用中，这里应该启动定时器，等待2MSL
                // 为简化，直接关闭连接
                current_connection_->state = TcpState::CLOSED;
                
                // 调用连接关闭回调
                if (on_connection_closed_) {
                    on_connection_closed_(*current_connection_, {});
                }
            }
            break;
            
        case TcpState::FIN_WAIT_2:
            // 等待FIN
            if (tcp->is_fin()) {
                std::cout << "Received FIN, sending ACK" << std::endl;
                
                // 更新确认号
                current_connection_->ack_num = tcp->sequence_number() + 1;
                
                // 发送ACK
                send_tcp_packet(TCP_ACK);
                
                // 更新状态
                current_connection_->state = TcpState::TIME_WAIT;
                
                // 在实际应用中，这里应该启动定时器，等待2MSL
                // 为简化，直接关闭连接
                current_connection_->state = TcpState::CLOSED;
                
                // 调用连接关闭回调
                if (on_connection_closed_) {
                    on_connection_closed_(*current_connection_, {});
                }
            }
            break;
            
        case TcpState::LAST_ACK:
            // 等待最后的ACK
            if (tcp->is_ack()) {
                std::cout << "Received final ACK, connection closed" << std::endl;
                current_connection_->state = TcpState::CLOSED;
                
                // 调用连接关闭回调
                if (on_connection_closed_) {
                    on_connection_closed_(*current_connection_, {});
                }
            }
            break;
            
        default:
            break;
    }
}

bool TcpStack::is_packet_for_connection(const Packet& packet) {
    const Ipv4Parser* ip = packet.find_layer<Ipv4Parser>();
    const TcpParser* tcp = packet.find_layer<TcpParser>();
    
    if (!ip || !tcp || !current_connection_) {
        return false;
    }
    
    // 打印完整的匹配信息用于调试
    std::cout << "Matching packet: " 
              << ip_to_string(ip->source_ip()) << ":" << tcp->source_port() 
              << " -> "
              << ip_to_string(ip->dest_ip()) << ":" << tcp->dest_port()
              << " against connection: "
              << ip_to_string(current_connection_->remote_ip) << ":" << current_connection_->remote_port
              << " -> "
              << ip_to_string(current_connection_->local_ip) << ":" << current_connection_->local_port
              << std::endl;
    
    // 首先，检查是否能匹配到当前连接的正常方向
    bool normal_direction = (ip->source_ip() == current_connection_->remote_ip &&
                            ip->dest_ip() == current_connection_->local_ip &&
                            tcp->source_port() == current_connection_->remote_port &&
                            tcp->dest_port() == current_connection_->local_port);
    
    if (normal_direction) {
        std::cout << "Packet matches normal direction" << std::endl;
        return true;
    }
    
    // 特别检查SYN-ACK响应，可能端口不完全匹配但IP正确
    bool syn_ack_response = (ip->source_ip() == current_connection_->remote_ip &&
                           ip->dest_ip() == current_connection_->local_ip &&
                           tcp->is_syn() && tcp->is_ack());
                           
    if (syn_ack_response) {
        std::cout << "Received SYN-ACK from server - possible response to our connection attempt" << std::endl;
        return true;
    }
    
    // 然后，检查是否能匹配到RST响应
    bool rst_packet = (ip->dest_ip() == current_connection_->local_ip &&
                     tcp->dest_port() == current_connection_->local_port &&
                     tcp->is_rst());
    
    if (rst_packet) {
        std::cout << "Received RST packet for our connection" << std::endl;
        return true;
    }
    
    // 其它情况，不匹配
    std::cout << "Packet does not match current connection" << std::endl;
    return false;
}

std::vector<uint8_t> TcpStack::build_ethernet_header(const MacAddress_new& dst_mac, 
                                                 const MacAddress_new& src_mac, 
                                                 uint16_t ether_type) {
    std::vector<uint8_t> header(ETHERNET_HEADER_LEN);
    
    // 填充目标MAC
    std::copy(dst_mac.bytes, dst_mac.bytes + 6, header.begin());
    
    // 填充源MAC
    std::copy(src_mac.bytes, src_mac.bytes + 6, header.begin() + 6);
    
    // 填充以太类型
    header[12] = static_cast<uint8_t>(ether_type >> 8);
    header[13] = static_cast<uint8_t>(ether_type & 0xFF);
    
    return header;
}

std::vector<uint8_t> TcpStack::build_ip_header(uint32_t src_ip, uint32_t dst_ip, 
                                           uint16_t total_len, uint8_t protocol) {
    std::vector<uint8_t> header(sizeof(IpHeader_new));
    
    // 创建IP头部
    IpHeader_new ip_header;
    memset(&ip_header, 0, sizeof(ip_header));
    
    // 版本(4位) + 头部长度(4位)
    ip_header.version_ihl = (4 << 4) | 5; // IPv4, 5个32位字(20字节)
    
    // 服务类型
    ip_header.tos = 0;
    
    // 总长度(IP头 + 数据)
    ip_header.total_len = htons(total_len);
    
    // 标识符
    static uint16_t id = 0;
    ip_header.id = htons(++id);
    
    // 分片标志和偏移 - 允许分片 (DF位设为0)
    ip_header.frag_off = 0;  // 不禁止分片
    
    // 生存时间
    ip_header.ttl = 64;
    
    // 协议
    ip_header.protocol = protocol;
    
    // 校验和(先设为0)
    ip_header.check = 0;
    
    // 源IP和目标IP (需要转换为网络字节序)
    ip_header.saddr = htonl(src_ip);
    ip_header.daddr = htonl(dst_ip);
    
    // 计算校验和
    ip_header.check = htons(calculate_ip_checksum(&ip_header));
    
    // 复制到header向量
    std::memcpy(header.data(), &ip_header, sizeof(ip_header));
    
    return header;
}

std::vector<uint8_t> TcpStack::build_tcp_header(uint16_t src_port, uint16_t dst_port,
                                            uint32_t seq_num, uint32_t ack_num,
                                            uint16_t flags, uint16_t window_size) {
    std::vector<uint8_t> header(sizeof(TcpHeader_new));
    
    // 创建TCP头部
    TcpHeader_new tcp_header;
    memset(&tcp_header, 0, sizeof(tcp_header));
    
    // 源端口和目标端口
    tcp_header.source = htons(src_port);
    tcp_header.dest = htons(dst_port);
    
    // 序列号和确认号
    tcp_header.seq = htonl(seq_num);
    tcp_header.ack_seq = htonl(ack_num);
    
    // 数据偏移(4位) + 保留(6位) + 标志位(6位)
    // 数据偏移: 5个32位字(20字节)
    // 注意：TCP头部的flags字段包含了数据偏移和标志位
    uint16_t offset_flags = (5 << 12) | (flags & 0x3F);
    tcp_header.flags = htons(offset_flags);
    
    // 窗口大小
    tcp_header.window = htons(window_size);
    
    // 校验和(稍后计算)
    tcp_header.check = 0;
    
    // 紧急指针
    tcp_header.urg_ptr = 0;
    
    // 复制到header向量
    std::memcpy(header.data(), &tcp_header, sizeof(tcp_header));
    
    return header;
}

bool TcpStack::send_tcp_packet(uint16_t flags, const uint8_t* payload, size_t payload_len) {
    if (!pcap_handle_ || !current_connection_) {
        std::cerr << "Error: pcap_handle_ or current_connection_ is nullptr" << std::endl;
        return false;
    }
    
    // 计算各层长度
    size_t eth_len = ETHERNET_HEADER_LEN;
    size_t ip_len = sizeof(IpHeader_new);
    size_t tcp_len = sizeof(TcpHeader_new);
    size_t total_len = eth_len + ip_len + tcp_len + payload_len;
    
    // 创建数据包缓冲区
    std::vector<uint8_t> packet(total_len);
    
    // 构建以太网头部 - 目标MAC是网关MAC，源MAC是本机MAC
    auto eth_header = build_ethernet_header(gateway_mac_, local_mac_, ETHERTYPE_IP);
    
    // 打印以太网头部信息
    std::cout << "Ethernet header: SRC=" << mac_to_string(local_mac_) 
              << " DST=" << mac_to_string(gateway_mac_) << std::endl;
              
    std::copy(eth_header.begin(), eth_header.end(), packet.begin());
    
    // 构建IP头部 - IP总长度是IP头部+TCP头部+负载长度
    auto ip_header = build_ip_header(current_connection_->local_ip, 
                                   current_connection_->remote_ip, 
                                   ip_len + tcp_len + payload_len, 
                                   6); // 6是TCP协议号
    std::copy(ip_header.begin(), ip_header.end(), packet.begin() + eth_len);
    
    // 构建TCP头部
    auto tcp_header = build_tcp_header(current_connection_->local_port, 
                                     current_connection_->remote_port, 
                                     current_connection_->seq_num, 
                                     current_connection_->ack_num, 
                                     flags, 
                                     current_connection_->window_size);
    std::copy(tcp_header.begin(), tcp_header.end(), packet.begin() + eth_len + ip_len);
    
    // 如果有负载，复制负载数据
    if (payload && payload_len > 0) {
        std::copy(payload, payload + payload_len, packet.begin() + eth_len + ip_len + tcp_len);
    }
    
    // 计算TCP校验和
    TcpHeader_new* tcp = reinterpret_cast<TcpHeader_new*>(packet.data() + eth_len + ip_len);
    IpHeader_new* ip = reinterpret_cast<IpHeader_new*>(packet.data() + eth_len);
    
    // 将校验和字段清零
    tcp->check = 0;
    
    // 使用正确的源IP和目标IP（主机字节序）
    uint32_t src_ip = ntohl(ip->saddr);
    uint32_t dst_ip = ntohl(ip->daddr);
    
    // 计算并设置TCP校验和
    uint16_t tcp_csum = calculate_tcp_checksum(
        src_ip,
        dst_ip,
        tcp,
        payload_len > 0 ? packet.data() + eth_len + ip_len + tcp_len : nullptr,
        payload_len
    );
    tcp->check = tcp_csum; // 已经是网络字节序
    
    // 打印发送的数据包信息
    std::cout << "Sending TCP packet: " 
              << current_connection_->local_port << " -> " << current_connection_->remote_port 
              << " Flags: " 
              << ((flags & TCP_SYN) ? "S" : "")
              << ((flags & TCP_ACK) ? "A" : "")
              << ((flags & TCP_FIN) ? "F" : "")
              << ((flags & TCP_RST) ? "R" : "")
              << ((flags & TCP_PSH) ? "P" : "")
              << " Seq: " << current_connection_->seq_num
              << " Ack: " << current_connection_->ack_num
              << " Len: " << payload_len 
              << " Total packet size: " << packet.size() << " bytes"
              << std::endl;
    
    // 打印完整的TCP头部信息
    std::cout << "TCP Header: Data Offset=" << ((ntohs(tcp->flags) >> 12) & 0xF)
              << " Window=" << ntohs(tcp->window)
              << " Checksum=0x" << std::hex << ntohs(tcp->check) << std::dec
              << " URG_ptr=" << ntohs(tcp->urg_ptr)
              << std::endl;
    
    // 发送数据包
    int sent_bytes = pcap_inject(pcap_handle_, packet.data(), packet.size());
    if (sent_bytes == -1) {
        std::cerr << "Failed to send packet: " << pcap_geterr(pcap_handle_) << std::endl;
        return false;
    } else if (static_cast<size_t>(sent_bytes) != packet.size()) {
        std::cerr << "Warning: Sent only " << sent_bytes << " of " << packet.size() << " bytes" << std::endl;
    } else {
        std::cout << "Successfully sent " << sent_bytes << " bytes" << std::endl;
    }
    
    // 更新序列号
    if (flags & TCP_SYN || flags & TCP_FIN) {
        // SYN和FIN消耗1个序列号
        current_connection_->seq_num++;
    }
    if (payload_len > 0) {
        // 数据消耗相应的序列号
        current_connection_->seq_num += payload_len;
    }
    
    return true;
} 
