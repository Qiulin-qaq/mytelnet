#include "http_client.h"
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cctype>

HttpClient::HttpClient() {
}

HttpClient::~HttpClient() {
    close();
}

bool HttpClient::initialize(const std::string& interface_name) {
    return tcp_stack_.initialize(interface_name);
}

bool HttpClient::get(const std::string& host, uint16_t port, const std::string& path,
                   HttpResponseCallback callback) {
    // 保存回调
    current_callback_ = callback;
    
    // 清空响应缓冲区
    response_buffer_.clear();
    
    // 连接到服务器
    if (!tcp_stack_.connect(host, port)) {
        std::cerr << "Failed to connect to server: " << host << ":" << port << std::endl;
        return false;
    }
    
    // 等待连接建立
    if (!tcp_stack_.wait_for_connection()) {
        std::cerr << "Connection to server timed out" << std::endl;
        return false;
    }
    
    // 构建HTTP GET请求
    std::string request = build_http_request("GET", host, path);
    
    // 发送请求
    std::vector<uint8_t> request_data(request.begin(), request.end());
    if (!tcp_stack_.send_data(request_data)) {
        std::cerr << "Failed to send HTTP request" << std::endl;
        return false;
    }
    
    // 接收响应
    std::vector<uint8_t> response_chunk;
    bool received_complete = false;
    
    while (!received_complete) {
        // 等待数据
        if (!tcp_stack_.wait_for_data(response_chunk, 5000)) {
            // 超时
            std::cerr << "Receiving HTTP response timed out" << std::endl;
            break;
        }
        
        // 追加到响应缓冲区
        response_buffer_.insert(response_buffer_.end(), response_chunk.begin(), response_chunk.end());
        
        // 解析响应
        int status_code;
        std::string status_message;
        std::map<std::string, std::string> headers;
        std::vector<uint8_t> body;
        
        if (parse_http_response(response_buffer_, status_code, status_message, headers, body)) {
            // 响应解析成功
            received_complete = true;
            
            // 输出响应信息
            std::cout << "Received HTTP response: " << status_code << " " << status_message << std::endl;
            std::cout << "Response headers: " << std::endl;
            for (const auto& header : headers) {
                std::cout << "  " << header.first << ": " << header.second << std::endl;
            }
            std::cout << "Response body size: " << body.size() << " bytes" << std::endl;
            
            // 调用回调
            if (current_callback_) {
                current_callback_(status_code, status_message, headers, body);
            }
        }
    }
    
    // 关闭连接
    tcp_stack_.close_connection();
    
    return received_complete;
}

bool HttpClient::download_file(const std::string& host, uint16_t port, const std::string& path,
                             const std::string& local_file) {
    // 创建文件流
    std::shared_ptr<std::ofstream> file_ptr = std::make_shared<std::ofstream>(local_file, std::ios::binary);
    if (!file_ptr->is_open()) {
        std::cerr << "Failed to create local file: " << local_file << std::endl;
        return false;
    }
    
    // 为lambda表达式创建一个复制的文件名
    std::string filename_copy = local_file;
    
    // 设置回调函数来保存文件
    auto file_callback = [file_ptr, filename_copy](int status_code, const std::string& status_message,
                              const std::map<std::string, std::string>& headers,
                              const std::vector<uint8_t>& body) {
        if (status_code == 200) {
            // 写入文件
            file_ptr->write(reinterpret_cast<const char*>(body.data()), body.size());
            
            std::cout << "File downloaded successfully, saved as: " << filename_copy << std::endl;
        } else {
            std::cerr << "File download failed, status code: " << status_code << " " << status_message << std::endl;
        }
    };
    
    // 发送GET请求
    bool result = get(host, port, path, file_callback);
    
    // 关闭文件
    file_ptr->close();
    
    return result;
}

void HttpClient::close() {
    tcp_stack_.close_connection();
}

std::string HttpClient::build_http_request(const std::string& method, const std::string& host,
                                        const std::string& path,
                                        const std::map<std::string, std::string>& headers) {
    std::ostringstream request;
    
    // 请求行
    request << method << " " << (path.empty() ? "/" : path) << " HTTP/1.1\r\n";
    
    // 请求头
    request << "Host: " << host << "\r\n";
    request << "Connection: close\r\n";
    request << "User-Agent: MyTelnet/1.0\r\n";
    
    // 添加用户提供的头
    for (const auto& header : headers) {
        request << header.first << ": " << header.second << "\r\n";
    }
    
    // 头部结束
    request << "\r\n";
    
    return request.str();
}

bool HttpClient::parse_http_response(const std::vector<uint8_t>& data,
                                  int& status_code,
                                  std::string& status_message,
                                  std::map<std::string, std::string>& headers,
                                  std::vector<uint8_t>& body) {
    // 检查数据是否包含完整的HTTP头部
    std::string response_str(data.begin(), data.end());
    size_t header_end = response_str.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        // 头部不完整
        return false;
    }
    
    // 提取头部
    std::string headers_str = response_str.substr(0, header_end);
    
    // 解析状态行
    size_t line_end = headers_str.find("\r\n");
    std::string status_line = headers_str.substr(0, line_end);
    
    // HTTP/1.1 200 OK
    size_t version_end = status_line.find(" ");
    size_t status_code_end = status_line.find(" ", version_end + 1);
    
    if (version_end == std::string::npos || status_code_end == std::string::npos) {
        return false;
    }
    
    // 解析状态码
    std::string status_code_str = status_line.substr(version_end + 1, status_code_end - version_end - 1);
    status_code = std::stoi(status_code_str);
    
    // 解析状态消息
    status_message = status_line.substr(status_code_end + 1);
    
    // 解析头部字段
    headers.clear();
    size_t pos = line_end + 2; // 跳过第一行的\r\n
    
    while (pos < header_end) {
        size_t line_end = headers_str.find("\r\n", pos);
        if (line_end == std::string::npos) {
            break;
        }
        
        std::string line = headers_str.substr(pos, line_end - pos);
        size_t colon = line.find(":");
        
        if (colon != std::string::npos) {
            std::string name = line.substr(0, colon);
            std::string value = line.substr(colon + 1);
            
            // 去除前后空格
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            
            // 转换头部名称为小写
            std::transform(name.begin(), name.end(), name.begin(), 
                          [](unsigned char c) { return std::tolower(c); });
            
            headers[name] = value;
        }
        
        pos = line_end + 2; // 跳过\r\n
    }
    
    // 提取响应体
    body.clear();
    body.insert(body.begin(), data.begin() + header_end + 4, data.end()); // +4跳过\r\n\r\n
    
    return true;
} 
