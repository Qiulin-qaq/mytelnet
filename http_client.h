#pragma once
#include "tcp_stack.h"
#include <string>
#include <map>
#include <vector>
#include <functional>
#include <fstream>

// HTTP响应回调
using HttpResponseCallback = std::function<void(
    int status_code, 
    const std::string& status_message, 
    const std::map<std::string, std::string>& headers, 
    const std::vector<uint8_t>& body)>;

// HTTP客户端类
class HttpClient {
public:
    HttpClient();
    ~HttpClient();
    
    // 初始化
    bool initialize(const std::string& interface_name);
    
    // 发送HTTP GET请求
    bool get(const std::string& host, uint16_t port, const std::string& path, 
             HttpResponseCallback callback = nullptr);
    
    // 下载文件
    bool download_file(const std::string& host, uint16_t port, const std::string& path,
                      const std::string& local_file);
    
    // 关闭连接
    void close();
    
private:
    // 构建HTTP请求
    std::string build_http_request(const std::string& method, const std::string& host, 
                                  const std::string& path, 
                                  const std::map<std::string, std::string>& headers = {});
    
    // 解析HTTP响应
    bool parse_http_response(const std::vector<uint8_t>& data, 
                           int& status_code, 
                           std::string& status_message, 
                           std::map<std::string, std::string>& headers, 
                           std::vector<uint8_t>& body);
    
    // TCP栈
    TcpStack tcp_stack_;
    
    // 响应数据缓冲区
    std::vector<uint8_t> response_buffer_;
    
    // 当前回调
    HttpResponseCallback current_callback_;
}; 
