#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "packet_parser.h"
#include "rule_manager.h"
#include "sni_extractor.h"
#include "types.h"

namespace {

void testAppClassification() {
    assert(DPI::sniToAppType("www.youtube.com") == DPI::AppType::YOUTUBE);
    assert(DPI::sniToAppType("api.github.com") == DPI::AppType::GITHUB);
    assert(DPI::sniToAppType("unknown.example") == DPI::AppType::HTTPS);
    assert(DPI::appTypeToString(DPI::AppType::TIKTOK) == "TikTok");
}

void testHTTPHostExtraction() {
    const std::string request =
        "GET /watch HTTP/1.1\r\n"
        "Host: www.youtube.com:443\r\n"
        "User-Agent: unit-test\r\n"
        "\r\n";

    auto host = DPI::HTTPHostExtractor::extract(
        reinterpret_cast<const uint8_t*>(request.data()), request.size());

    assert(host.has_value());
    assert(*host == "www.youtube.com");
}

void testDNSQueryExtraction() {
    const std::vector<uint8_t> query = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'w', 'w',
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01
    };

    auto domain = DPI::DNSExtractor::extractQuery(query.data(), query.size());

    assert(domain.has_value());
    assert(*domain == "www.example.com");
}

void testRuleManager() {
    DPI::RuleManager rules;
    rules.blockIP("192.168.1.10");
    rules.blockApp(DPI::AppType::YOUTUBE);
    rules.blockDomain("*.facebook.com");
    rules.blockPort(53);

    assert(rules.isIPBlocked(0x0A01A8C0));
    assert(rules.isAppBlocked(DPI::AppType::YOUTUBE));
    assert(rules.isDomainBlocked("video.facebook.com"));
    assert(rules.isDomainBlocked("facebook.com"));
    assert(rules.isPortBlocked(53));

    auto reason = rules.shouldBlock(0x0A01A8C0, 443, DPI::AppType::HTTPS, "");
    assert(reason.has_value());
    assert(reason->type == DPI::RuleManager::BlockReason::IP);
}

void testPacketParserTCP() {
    PacketAnalyzer::RawPacket raw{};
    raw.header.incl_len = 54;
    raw.header.orig_len = 54;
    raw.data.resize(54, 0);

    auto& data = raw.data;

    data[0] = 0xaa; data[1] = 0xbb; data[2] = 0xcc;
    data[3] = 0xdd; data[4] = 0xee; data[5] = 0xff;
    data[6] = 0x00; data[7] = 0x11; data[8] = 0x22;
    data[9] = 0x33; data[10] = 0x44; data[11] = 0x55;
    data[12] = 0x08; data[13] = 0x00;

    data[14] = 0x45;
    data[16] = 0x00; data[17] = 0x28;
    data[22] = 64;
    data[23] = PacketAnalyzer::Protocol::TCP;
    data[26] = 192; data[27] = 168; data[28] = 1; data[29] = 10;
    data[30] = 93; data[31] = 184; data[32] = 216; data[33] = 34;

    data[34] = 0x30; data[35] = 0x39;
    data[36] = 0x01; data[37] = 0xbb;
    data[46] = 0x50;
    data[47] = PacketAnalyzer::TCPFlags::SYN;

    PacketAnalyzer::ParsedPacket parsed{};
    assert(PacketAnalyzer::PacketParser::parse(raw, parsed));
    assert(parsed.has_ip);
    assert(parsed.has_tcp);
    assert(parsed.src_ip == "192.168.1.10");
    assert(parsed.dest_ip == "93.184.216.34");
    assert(parsed.src_port == 12345);
    assert(parsed.dest_port == 443);
    assert(parsed.tcp_flags == PacketAnalyzer::TCPFlags::SYN);
}

} // namespace

int main() {
    testAppClassification();
    testHTTPHostExtraction();
    testDNSQueryExtraction();
    testRuleManager();
    testPacketParserTCP();

    std::cout << "All packet component tests passed\n";
    return 0;
}
