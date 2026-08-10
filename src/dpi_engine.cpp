#include "dpi_engine.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr size_t kContentWidth = 68;

std::string fitLine(const std::string& text) {
    if (text.size() >= kContentWidth) {
        return text.substr(0, kContentWidth);
    }
    return text + std::string(kContentWidth - text.size(), ' ');
}

std::string border() {
    return "+" + std::string(kContentWidth + 2, '-') + "+\n";
}

std::string row(const std::string& text) {
    return "| " + fitLine(text) + " |\n";
}

std::string centered(const std::string& text) {
    if (text.size() >= kContentWidth) {
        return row(text);
    }

    const size_t left = (kContentWidth - text.size()) / 2;
    const size_t right = kContentWidth - text.size() - left;
    return "| " + std::string(left, ' ') + text + std::string(right, ' ') + " |\n";
}

std::string section(const std::string& title) {
    return border() + centered(title) + border();
}

std::string jsonEscape(const std::string& value) {
    std::ostringstream escaped;
    for (char ch : value) {
        switch (ch) {
            case '"': escaped << "\\\""; break;
            case '\\': escaped << "\\\\"; break;
            case '\b': escaped << "\\b"; break;
            case '\f': escaped << "\\f"; break;
            case '\n': escaped << "\\n"; break;
            case '\r': escaped << "\\r"; break;
            case '\t': escaped << "\\t"; break;
            default:
                if (static_cast<unsigned char>(ch) < 0x20) {
                    escaped << "\\u"
                            << std::hex << std::setw(4) << std::setfill('0')
                            << static_cast<int>(static_cast<unsigned char>(ch))
                            << std::dec << std::setfill(' ');
                } else {
                    escaped << ch;
                }
        }
    }
    return escaped.str();
}

std::string jsonString(const std::string& value) {
    return "\"" + jsonEscape(value) + "\"";
}

template <typename T>
std::string metric(const std::string& label, const T& value) {
    std::ostringstream line;
    line << "  " << std::left << std::setw(24) << label << " : " << value;
    return row(line.str());
}

} // namespace

namespace DPI {

// ============================================================================
// DPIEngine Implementation
// ============================================================================

DPIEngine::DPIEngine(const Config& config)
    : config_(config), output_queue_(10000) {
    
    std::cout << "\n";
    std::cout << border();
    std::cout << centered("DPI ENGINE v1.0");
    std::cout << centered("Deep Packet Inspection System");
    std::cout << border();
    std::cout << metric("Load Balancers", config.num_load_balancers);
    std::cout << metric("FPs per LB", config.fps_per_lb);
    std::cout << metric("Total FP Threads", config.num_load_balancers * config.fps_per_lb);
    std::cout << border();
}

DPIEngine::~DPIEngine() {
    stop();
}

bool DPIEngine::initialize() {
    // Create rule manager
    rule_manager_ = std::make_unique<RuleManager>();
    
    // Load rules if specified
    if (!config_.rules_file.empty()) {
        rule_manager_->loadRules(config_.rules_file);
    }
    
    // Create output callback
    auto output_cb = [this](const PacketJob& job, PacketAction action) {
        handleOutput(job, action);
    };
    
    // Create FP manager (creates FP threads and their queues)
    int total_fps = config_.num_load_balancers * config_.fps_per_lb;
    fp_manager_ = std::make_unique<FPManager>(total_fps, rule_manager_.get(), output_cb);
    
    // Create LB manager (creates LB threads, connects to FP queues)
    lb_manager_ = std::make_unique<LBManager>(
        config_.num_load_balancers,
        config_.fps_per_lb,
        fp_manager_->getQueuePtrs()
    );
    
    // Create global connection table
    global_conn_table_ = std::make_unique<GlobalConnectionTable>(total_fps);
    for (int i = 0; i < total_fps; i++) {
        global_conn_table_->registerTracker(i, &fp_manager_->getFP(i).getConnectionTracker());
    }
    
    std::cout << "[DPIEngine] Initialized successfully\n";
    return true;
}

void DPIEngine::start() {
    if (running_) return;
    
    running_ = true;
    processing_complete_ = false;
    
    // Start output thread
    output_thread_ = std::thread(&DPIEngine::outputThreadFunc, this);
    
    // Start FP threads
    fp_manager_->startAll();
    
    // Start LB threads
    lb_manager_->startAll();
    
    std::cout << "[DPIEngine] All threads started\n";
}

void DPIEngine::stop() {
    if (!running_) return;
    
    running_ = false;
    
    // Stop LB threads first (they feed FPs)
    if (lb_manager_) {
        lb_manager_->stopAll();
    }
    
    // Stop FP threads
    if (fp_manager_) {
        fp_manager_->stopAll();
    }
    
    // Stop output thread
    output_queue_.shutdown();
    if (output_thread_.joinable()) {
        output_thread_.join();
    }
    
    std::cout << "[DPIEngine] All threads stopped\n";
}

void DPIEngine::waitForCompletion() {
    // Wait for reader to finish
    if (reader_thread_.joinable()) {
        reader_thread_.join();
    }
    
    // Signal completion
    processing_complete_ = true;
}

bool DPIEngine::processFile(const std::string& input_file,
                            const std::string& output_file) {
    
    std::cout << "\n[DPIEngine] Processing: " << input_file << "\n";
    std::cout << "[DPIEngine] Output to:  " << output_file << "\n\n";
    
    // Initialize if not already done
    if (!rule_manager_) {
        if (!initialize()) {
            return false;
        }
    }
    
    // Open output file
    output_file_.open(output_file, std::ios::binary);
    if (!output_file_.is_open()) {
        std::cerr << "[DPIEngine] Error: Cannot open output file\n";
        return false;
    }
    
    // Start processing threads
    start();
    
    // Start reader thread
    reader_thread_ = std::thread(&DPIEngine::readerThreadFunc, this, input_file);
    
    // Wait for completion
    waitForCompletion();
    
    // Stop all threads after the reader is done; each stage drains its queue.
    stop();
    
    // Close output file
    if (output_file_.is_open()) {
        output_file_.close();
    }
    
    // Print final report
    std::cout << generateReport();
    std::cout << fp_manager_->generateClassificationReport();
    
    return true;
}

void DPIEngine::readerThreadFunc(const std::string& input_file) {
    PacketAnalyzer::PcapReader reader;
    
    if (!reader.open(input_file)) {
        std::cerr << "[Reader] Error: Cannot open input file\n";
        return;
    }
    
    // Write PCAP header to output
    writeOutputHeader(reader.getGlobalHeader());
    
    PacketAnalyzer::RawPacket raw;
    PacketAnalyzer::ParsedPacket parsed;
    uint32_t packet_id = 0;
    
    std::cout << "[Reader] Starting packet processing...\n";
    
    while (reader.readNextPacket(raw)) {
        // Parse the packet
        if (!PacketAnalyzer::PacketParser::parse(raw, parsed)) {
            continue;  // Skip unparseable packets
        }
        
        // Only process IP packets with TCP/UDP
        if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) {
            continue;
        }
        
        // Create packet job
        PacketJob job = createPacketJob(raw, parsed, packet_id++);
        
        // Update global stats
        stats_.total_packets++;
        stats_.total_bytes += raw.data.size();
        
        if (parsed.has_tcp) {
            stats_.tcp_packets++;
        } else if (parsed.has_udp) {
            stats_.udp_packets++;
        }
        
        // Send to appropriate LB based on hash
        LoadBalancer& lb = lb_manager_->getLBForPacket(job.tuple);
        lb.getInputQueue().push(std::move(job));
    }
    
    std::cout << "[Reader] Finished reading " << packet_id << " packets\n";
    reader.close();
}

PacketJob DPIEngine::createPacketJob(const PacketAnalyzer::RawPacket& raw,
                                      const PacketAnalyzer::ParsedPacket& parsed,
                                      uint32_t packet_id) {
    PacketJob job;
    job.packet_id = packet_id;
    job.ts_sec = raw.header.ts_sec;
    job.ts_usec = raw.header.ts_usec;
    
    // Set five-tuple - parse IP addresses from string back to uint32
    auto parseIP = [](const std::string& ip) -> uint32_t {
        uint32_t result = 0;
        int octet = 0;
        int shift = 0;
        for (char c : ip) {
            if (c == '.') {
                result |= (octet << shift);
                shift += 8;
                octet = 0;
            } else if (c >= '0' && c <= '9') {
                octet = octet * 10 + (c - '0');
            }
        }
        result |= (octet << shift);
        return result;
    };
    
    job.tuple.src_ip = parseIP(parsed.src_ip);
    job.tuple.dst_ip = parseIP(parsed.dest_ip);
    job.tuple.src_port = parsed.src_port;
    job.tuple.dst_port = parsed.dest_port;
    job.tuple.protocol = parsed.protocol;
    
    // TCP flags
    job.tcp_flags = parsed.tcp_flags;
    
    // Copy packet data
    job.data = raw.data;
    
    // Calculate offsets
    job.eth_offset = 0;
    job.ip_offset = 14;  // Ethernet header is 14 bytes
    
    // IP header length
    if (job.data.size() > 14) {
        uint8_t ip_ihl = job.data[14] & 0x0F;
        size_t ip_header_len = ip_ihl * 4;
        job.transport_offset = 14 + ip_header_len;
        
        // Transport header length
        if (parsed.has_tcp && job.data.size() >= job.transport_offset + 13) {
            uint8_t tcp_data_offset = (job.data[job.transport_offset + 12] >> 4) & 0x0F;
            size_t tcp_header_len = tcp_data_offset * 4;
            job.payload_offset = job.transport_offset + tcp_header_len;
        } else if (parsed.has_udp && job.data.size() >= job.transport_offset + 8) {
            job.payload_offset = job.transport_offset + 8;  // UDP header is 8 bytes
        }
        
        if (job.payload_offset < job.data.size()) {
            job.payload_length = job.data.size() - job.payload_offset;
            job.payload_data = job.data.data() + job.payload_offset;
        }
    }
    
    return job;
}

void DPIEngine::outputThreadFunc() {
    while (true) {
        auto job_opt = output_queue_.popWithTimeout(std::chrono::milliseconds(100));
        
        if (job_opt) {
            writeOutputPacket(*job_opt);
            continue;
        }

        if (output_queue_.isShutdown()) {
            break;
        }
    }
}

void DPIEngine::handleOutput(const PacketJob& job, PacketAction action) {
    if (action == PacketAction::DROP) {
        stats_.dropped_packets++;
        return;
    }
    
    stats_.forwarded_packets++;
    output_queue_.push(job);
}

bool DPIEngine::writeOutputHeader(const PacketAnalyzer::PcapGlobalHeader& header) {
    std::lock_guard<std::mutex> lock(output_mutex_);
    
    if (!output_file_.is_open()) return false;
    
    output_file_.write(reinterpret_cast<const char*>(&header), sizeof(header));
    return output_file_.good();
}

void DPIEngine::writeOutputPacket(const PacketJob& job) {
    std::lock_guard<std::mutex> lock(output_mutex_);
    
    if (!output_file_.is_open()) return;
    
    // Write packet header
    PacketAnalyzer::PcapPacketHeader pkt_header;
    pkt_header.ts_sec = job.ts_sec;
    pkt_header.ts_usec = job.ts_usec;
    pkt_header.incl_len = job.data.size();
    pkt_header.orig_len = job.data.size();
    
    output_file_.write(reinterpret_cast<const char*>(&pkt_header), sizeof(pkt_header));
    output_file_.write(reinterpret_cast<const char*>(job.data.data()), job.data.size());
}

// ============================================================================
// Rule Management API
// ============================================================================

void DPIEngine::blockIP(const std::string& ip) {
    if (rule_manager_) {
        rule_manager_->blockIP(ip);
    }
}

void DPIEngine::unblockIP(const std::string& ip) {
    if (rule_manager_) {
        rule_manager_->unblockIP(ip);
    }
}

void DPIEngine::blockApp(AppType app) {
    if (rule_manager_) {
        rule_manager_->blockApp(app);
    }
}

void DPIEngine::blockApp(const std::string& app_name) {
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
        if (appTypeToString(static_cast<AppType>(i)) == app_name) {
            blockApp(static_cast<AppType>(i));
            return;
        }
    }
    std::cerr << "[DPIEngine] Unknown app: " << app_name << "\n";
}

void DPIEngine::unblockApp(AppType app) {
    if (rule_manager_) {
        rule_manager_->unblockApp(app);
    }
}

void DPIEngine::unblockApp(const std::string& app_name) {
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
        if (appTypeToString(static_cast<AppType>(i)) == app_name) {
            unblockApp(static_cast<AppType>(i));
            return;
        }
    }
}

void DPIEngine::blockDomain(const std::string& domain) {
    if (rule_manager_) {
        rule_manager_->blockDomain(domain);
    }
}

void DPIEngine::unblockDomain(const std::string& domain) {
    if (rule_manager_) {
        rule_manager_->unblockDomain(domain);
    }
}

bool DPIEngine::loadRules(const std::string& filename) {
    if (rule_manager_) {
        return rule_manager_->loadRules(filename);
    }
    return false;
}

bool DPIEngine::saveRules(const std::string& filename) {
    if (rule_manager_) {
        return rule_manager_->saveRules(filename);
    }
    return false;
}

// ============================================================================
// Reporting
// ============================================================================

std::string DPIEngine::generateReport() const {
    std::ostringstream ss;
    
    ss << "\n" << section("DPI ENGINE STATISTICS");

    ss << centered("PACKET STATISTICS");
    ss << metric("Total Packets", stats_.total_packets.load());
    ss << metric("Total Bytes", stats_.total_bytes.load());
    ss << metric("TCP Packets", stats_.tcp_packets.load());
    ss << metric("UDP Packets", stats_.udp_packets.load());

    ss << section("FILTERING STATISTICS");
    ss << metric("Forwarded", stats_.forwarded_packets.load());
    ss << metric("Dropped/Blocked", stats_.dropped_packets.load());
    
    if (stats_.total_packets > 0) {
        double drop_rate = 100.0 * stats_.dropped_packets.load() / stats_.total_packets.load();
        std::ostringstream value;
        value << std::fixed << std::setprecision(2) << drop_rate << "%";
        ss << metric("Drop Rate", value.str());
    }
    
    if (lb_manager_) {
        auto lb_stats = lb_manager_->getAggregatedStats();
        ss << section("LOAD BALANCER STATISTICS");
        ss << metric("LB Received", lb_stats.total_received);
        ss << metric("LB Dispatched", lb_stats.total_dispatched);
    }
    
    if (fp_manager_) {
        auto fp_stats = fp_manager_->getAggregatedStats();
        ss << section("FAST PATH STATISTICS");
        ss << metric("FP Processed", fp_stats.total_processed);
        ss << metric("FP Forwarded", fp_stats.total_forwarded);
        ss << metric("FP Dropped", fp_stats.total_dropped);
        ss << metric("Active Connections", fp_stats.total_connections);
    }
    
    if (rule_manager_) {
        auto rule_stats = rule_manager_->getStats();
        ss << section("BLOCKING RULES");
        ss << metric("Blocked IPs", rule_stats.blocked_ips);
        ss << metric("Blocked Apps", rule_stats.blocked_apps);
        ss << metric("Blocked Domains", rule_stats.blocked_domains);
        ss << metric("Blocked Ports", rule_stats.blocked_ports);
    }
    
    ss << border();
    
    return ss.str();
}

std::string DPIEngine::generateClassificationReport() const {
    if (fp_manager_) {
        return fp_manager_->generateClassificationReport();
    }
    return "";
}

bool DPIEngine::saveJsonReport(const std::string& filename,
                               const std::string& input_file,
                               const std::string& output_file) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }

    const uint64_t total_packets = stats_.total_packets.load();
    const uint64_t dropped_packets = stats_.dropped_packets.load();
    const double drop_rate = total_packets > 0
        ? (100.0 * static_cast<double>(dropped_packets) / static_cast<double>(total_packets))
        : 0.0;

    LBManager::AggregatedStats lb_stats{0, 0};
    if (lb_manager_) {
        lb_stats = lb_manager_->getAggregatedStats();
    }

    FPManager::AggregatedStats fp_stats{0, 0, 0, 0};
    FPManager::ClassificationSummary classification{0, 0, 0, {}};
    if (fp_manager_) {
        fp_stats = fp_manager_->getAggregatedStats();
        classification = fp_manager_->getClassificationSummary();
    }

    RuleManager::RuleStats rule_stats{0, 0, 0, 0};
    std::vector<std::string> blocked_ips;
    std::vector<std::string> blocked_domains;
    std::vector<std::string> blocked_apps;
    std::vector<uint16_t> blocked_ports;

    if (rule_manager_) {
        rule_stats = rule_manager_->getStats();
        blocked_ips = rule_manager_->getBlockedIPs();
        blocked_domains = rule_manager_->getBlockedDomains();
        blocked_ports = rule_manager_->getBlockedPorts();

        for (AppType app : rule_manager_->getBlockedApps()) {
            blocked_apps.push_back(appTypeToString(app));
        }
    }

    file << std::fixed << std::setprecision(2);
    file << "{\n";
    file << "  \"project\": \"DPI Engine\",\n";
    file << "  \"version\": \"1.0\",\n";
    file << "  \"input_file\": " << jsonString(input_file) << ",\n";
    file << "  \"output_file\": " << jsonString(output_file) << ",\n";
    file << "  \"configuration\": {\n";
    file << "    \"load_balancers\": " << config_.num_load_balancers << ",\n";
    file << "    \"fast_paths_per_load_balancer\": " << config_.fps_per_lb << ",\n";
    file << "    \"total_fast_path_threads\": " << (config_.num_load_balancers * config_.fps_per_lb) << "\n";
    file << "  },\n";
    file << "  \"packet_statistics\": {\n";
    file << "    \"total_packets\": " << total_packets << ",\n";
    file << "    \"total_bytes\": " << stats_.total_bytes.load() << ",\n";
    file << "    \"tcp_packets\": " << stats_.tcp_packets.load() << ",\n";
    file << "    \"udp_packets\": " << stats_.udp_packets.load() << ",\n";
    file << "    \"other_packets\": " << stats_.other_packets.load() << "\n";
    file << "  },\n";
    file << "  \"filtering_statistics\": {\n";
    file << "    \"forwarded_packets\": " << stats_.forwarded_packets.load() << ",\n";
    file << "    \"dropped_packets\": " << dropped_packets << ",\n";
    file << "    \"drop_rate_percent\": " << drop_rate << "\n";
    file << "  },\n";
    file << "  \"thread_statistics\": {\n";
    file << "    \"load_balancer_received\": " << lb_stats.total_received << ",\n";
    file << "    \"load_balancer_dispatched\": " << lb_stats.total_dispatched << ",\n";
    file << "    \"fast_path_processed\": " << fp_stats.total_processed << ",\n";
    file << "    \"fast_path_forwarded\": " << fp_stats.total_forwarded << ",\n";
    file << "    \"fast_path_dropped\": " << fp_stats.total_dropped << ",\n";
    file << "    \"active_connections\": " << fp_stats.total_connections << "\n";
    file << "  },\n";
    file << "  \"classification\": {\n";
    file << "    \"total_connections\": " << classification.total_connections << ",\n";
    file << "    \"classified_connections\": " << classification.classified_connections << ",\n";
    file << "    \"unidentified_connections\": " << classification.unidentified_connections << ",\n";
    file << "    \"app_distribution\": [\n";
    for (size_t i = 0; i < classification.app_distribution.size(); ++i) {
        const auto& entry = classification.app_distribution[i];
        const double pct = classification.total_connections > 0
            ? (100.0 * static_cast<double>(entry.second) / static_cast<double>(classification.total_connections))
            : 0.0;
        file << "      {\"app\": " << jsonString(appTypeToString(entry.first))
             << ", \"count\": " << entry.second
             << ", \"percentage\": " << pct << "}";
        file << (i + 1 < classification.app_distribution.size() ? "," : "") << "\n";
    }
    file << "    ]\n";
    file << "  },\n";
    file << "  \"blocking_rules\": {\n";
    file << "    \"counts\": {\n";
    file << "      \"blocked_ips\": " << rule_stats.blocked_ips << ",\n";
    file << "      \"blocked_apps\": " << rule_stats.blocked_apps << ",\n";
    file << "      \"blocked_domains\": " << rule_stats.blocked_domains << ",\n";
    file << "      \"blocked_ports\": " << rule_stats.blocked_ports << "\n";
    file << "    },\n";
    file << "    \"ips\": [";
    for (size_t i = 0; i < blocked_ips.size(); ++i) {
        file << (i > 0 ? ", " : "") << jsonString(blocked_ips[i]);
    }
    file << "],\n";
    file << "    \"apps\": [";
    for (size_t i = 0; i < blocked_apps.size(); ++i) {
        file << (i > 0 ? ", " : "") << jsonString(blocked_apps[i]);
    }
    file << "],\n";
    file << "    \"domains\": [";
    for (size_t i = 0; i < blocked_domains.size(); ++i) {
        file << (i > 0 ? ", " : "") << jsonString(blocked_domains[i]);
    }
    file << "],\n";
    file << "    \"ports\": [";
    for (size_t i = 0; i < blocked_ports.size(); ++i) {
        file << (i > 0 ? ", " : "") << blocked_ports[i];
    }
    file << "]\n";
    file << "  }\n";
    file << "}\n";

    return file.good();
}

const DPIStats& DPIEngine::getStats() const {
    return stats_;
}

void DPIEngine::printStatus() const {
    std::cout << "\n--- Live Status ---\n";
    std::cout << "Packets: " << stats_.total_packets.load()
              << " | Forwarded: " << stats_.forwarded_packets.load()
              << " | Dropped: " << stats_.dropped_packets.load() << "\n";
    
    if (fp_manager_) {
        auto fp_stats = fp_manager_->getAggregatedStats();
        std::cout << "Connections: " << fp_stats.total_connections << "\n";
    }
}

} // namespace DPI
