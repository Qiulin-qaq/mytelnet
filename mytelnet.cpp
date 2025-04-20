#include <iostream>
#include <string>
#include <cstring>
#include <filesystem>
#include <pcap.h>

#include "http_client.h"

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options] <server_ip> <port> [file path]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -i <interface>  Network interface to use (default: auto-detect)" << std::endl;
    std::cout << "Parameters:" << std::endl;
    std::cout << "  server_ip    - Server IP address" << std::endl;
    std::cout << "  port         - Server port, usually 80" << std::endl;
    std::cout << "  file path    - Path of the file to retrieve, default is /" << std::endl;
    std::cout << std::endl;
    std::cout << "Example: " << program_name << " 155.138.142.54 80 /index.html" << std::endl;
}

// 获取活跃的网络接口
std::string get_default_interface() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Failed to find network interfaces: " << errbuf << std::endl;
        return "eth0"; // 默认值
    }
    
    std::string interface_name = "";
    
    // 尝试找到一个活跃的接口
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        if (dev->flags & PCAP_IF_UP && dev->flags & PCAP_IF_RUNNING && !(dev->flags & PCAP_IF_LOOPBACK)) {
            interface_name = dev->name;
            break;
        }
    }
    
    if (interface_name.empty() && alldevs) {
        interface_name = alldevs->name; // 取第一个作为默认
    }
    
    pcap_freealldevs(alldevs);
    
    if (interface_name.empty()) {
        return "eth0"; // 如果找不到，使用默认值
    }
    
    return interface_name;
}

int main(int argc, char* argv[]) {
    // 定义参数变量
    std::string interface_name = "";
    std::string server_ip = ""; // 需要从命令行参数获取
    uint16_t server_port = 80; // 默认端口80
    std::string file_path = "/"; // 默认路径"/"
    
    // 记录非选项参数数量
    int non_option_args = 0;
    
    // 解析命令行参数
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-i" && i + 1 < argc) {
            interface_name = argv[++i];
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else {
            // 解析非选项参数
            non_option_args++;
            
            // 第一个非选项参数是IP地址
            if (non_option_args == 1) {
                server_ip = arg;
            }
            // 第二个非选项参数是端口
            else if (non_option_args == 2) {
                try {
                    server_port = static_cast<uint16_t>(std::stoi(arg));
                } catch (const std::exception& e) {
                    std::cerr << "Invalid port number: " << arg << std::endl;
                    print_usage(argv[0]);
                    return 1;
                }
            }
            // 第三个非选项参数是文件路径
            else if (non_option_args == 3) {
                file_path = arg;
                if (!file_path.empty() && file_path[0] != '/') {
                    file_path = "/" + file_path;
                }
            }
        }
    }
    
    // 检查必需参数
    if (server_ip.empty()) {
        std::cerr << "Error: Server IP address is required" << std::endl;
        print_usage(argv[0]);
        return 1;
    }
    
    // 如果没有指定网络接口，尝试自动检测
    if (interface_name.empty()) {
        interface_name = get_default_interface();
        std::cout << "Using auto-detected network interface: " << interface_name << std::endl;
    }
    
    // 设置本地保存的文件名
    std::string local_filename;
    if (file_path == "/") {
        local_filename = "index.html";
    } else {
        // 获取文件路径的最后一部分作为本地文件名
        size_t last_slash = file_path.find_last_of('/');
        if (last_slash != std::string::npos && last_slash < file_path.length() - 1) {
            local_filename = file_path.substr(last_slash + 1);
        } else {
            local_filename = "download.dat";
        }
    }
    
    std::cout << "mytelnet - Custom TCP Stack HTTP Client" << std::endl;
    std::cout << "Downloading from " << server_ip << ":" << server_port 
              << " file: " << file_path << std::endl;
    std::cout << "Saving as: " << local_filename << std::endl;
    std::cout << "Using network interface: " << interface_name << std::endl;
    
    // 创建HTTP客户端
    HttpClient client;
    
    // 初始化HTTP客户端
    std::cout << "Initializing network..." << std::endl;
    if (!client.initialize(interface_name)) {
        std::cerr << "Failed to initialize network!" << std::endl;
        return 1;
    }
    
    // 下载文件
    std::cout << "Starting download..." << std::endl;
    bool success = client.download_file(server_ip, server_port, file_path, local_filename);
    
    if (success) {
        std::cout << "Download complete! File saved as: " << local_filename << std::endl;
        
        // 获取文件大小
        std::filesystem::path file_path_obj(local_filename);
        if (std::filesystem::exists(file_path_obj)) {
            auto file_size = std::filesystem::file_size(file_path_obj);
            std::cout << "File size: " << file_size << " bytes" << std::endl;
        }
    } else {
        std::cerr << "Download failed!" << std::endl;
        return 1;
    }
    
    // 关闭客户端
    client.close();
    
    return 0;
} 
