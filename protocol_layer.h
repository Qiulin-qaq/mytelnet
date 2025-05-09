#pragma once

#include <memory>
#include <vector>
#include <string>
#include <cstdint>

// 鍗忚绫诲瀷鏋氫妇
enum class ProtocolType {
	ETHERNET,
	IPv4,
	UDP,
	DNS,
	UNKNOWN,
	TCP
};

// MAC鍦板潃缁撴瀯 - 6瀛楄妭
struct MacAddress_new {
	uint8_t bytes[6];
};

// IPv4鍦板潃缁撴瀯 - 4瀛楄妭
struct IPv4Address_new {
	uint8_t bytes[4];
};

// 浠ュお缃戝ご閮ㄧ粨鏋� - 14瀛楄妭
struct EthernetHeader_new {
	uint8_t dest_mac[6];    // 鐩爣MAC鍦板潃
	uint8_t src_mac[6];     // 婧怣AC鍦板潃
	uint16_t ether_type;    // 鍗忚绫诲瀷
};

// IP澶撮儴缁撴瀯 - 20瀛楄妭
// 寮哄埗1瀛楄妭瀵归綈锛岄槻姝㈢粨鏋勪綋琛ラ綈瀵艰嚧IP澶翠笉鏄�20瀛楄妭
struct __attribute__((packed)) IpHeader_new {
	uint8_t version_ihl;    // 鐗堟湰鍙�(4浣�)鍜岄閮ㄩ暱搴�(4浣�)
	uint8_t tos;           // 鏈嶅姟绫诲瀷
	uint16_t total_len;    // 鎬婚暱搴�
	uint16_t id;           // 鏍囪瘑
	uint16_t frag_off;     // 鍒嗙墖鍋忕Щ
	uint8_t ttl;           // 鐢熷瓨鏃堕棿
	uint8_t protocol;      // 鍗忚绫诲瀷
	uint16_t check;        // 鏍￠獙鍜�
	uint32_t saddr;        // 婧怚P鍦板潃
	uint32_t daddr;        // 鐩爣IP鍦板潃
};

// TCP澶撮儴缁撴瀯 - 20瀛楄妭
struct TcpHeader_new {
	uint16_t source;       // 婧愮鍙�
	uint16_t dest;         // 鐩爣绔彛
	uint32_t seq;          // 搴忓垪鍙�
	uint32_t ack_seq;      // 纭鍙�
	uint16_t flags;        // 鏁版嵁鍋忕Щ(4浣�)銆佷繚鐣�(6浣�)鍜屾爣蹇椾綅(6浣�)
	uint16_t window;       // 绐楀彛澶у皬
	uint16_t check;        // 鏍￠獙鍜�
	uint16_t urg_ptr;      // 绱ф€ユ寚閽�
};

// TCP鏍囧織浣嶅畾涔�
constexpr uint16_t TCP_FIN = 0x0001;
constexpr uint16_t TCP_SYN = 0x0002;
constexpr uint16_t TCP_RST = 0x0004;
constexpr uint16_t TCP_PSH = 0x0008;
constexpr uint16_t TCP_ACK = 0x0010;
constexpr uint16_t TCP_URG = 0x0020;
constexpr uint16_t TCP_ECE = 0x0040;
constexpr uint16_t TCP_CWR = 0x0080;

// TCP浼ご閮ㄧ粨鏋勶紙鐢ㄤ簬鏍￠獙鍜岃绠楋級
struct TcpPseudoHeader {
	uint32_t saddr;        // 婧怚P鍦板潃
	uint32_t daddr;        // 鐩爣IP鍦板潃
	uint8_t zero;          // 淇濈暀瀛楁
	uint8_t protocol;      // 鍗忚绫诲瀷
	uint16_t tcp_len;      // TCP闀垮害
};

class ProtocolLayer {
public:
	ProtocolLayer(const uint8_t* data, size_t length)
		: raw_data_(data),
		data_length_(length),
		payload_ptr_(nullptr),
		payload_len_(0) {}

	virtual ~ProtocolLayer() = default;

	virtual ProtocolType type() const noexcept = 0;

	virtual std::string summary() const noexcept = 0;

	virtual const uint8_t* payload() const noexcept = 0;

	virtual size_t payload_length() const noexcept = 0;

	const uint8_t* raw_data() const noexcept {
		return raw_data_;
	}
	size_t data_length() const noexcept {
		return data_length_;
	}

protected:
	const uint8_t* raw_data_;      // 鍘熷鏁版嵁鎸囬拡
	size_t data_length_;           // 鏁版嵁鎬婚暱搴�
	const uint8_t* payload_ptr_;
	size_t payload_len_;
};
