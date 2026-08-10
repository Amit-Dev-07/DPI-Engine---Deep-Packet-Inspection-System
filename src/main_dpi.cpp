#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "dpi_engine.h"

using namespace DPI;

namespace {

void printUsage(const char* program) {
    std::cout << R"(
DPI ENGINE v1.0
Deep Packet Inspection System

Usage: )" << program << R"( <input.pcap> <output.pcap> [options]

Arguments:
  input.pcap     Input PCAP file containing captured traffic
  output.pcap    Output PCAP file for forwarded traffic

Options:
  --block-ip <ip>        Block packets from source IP
  --block-app <app>      Block application, e.g. YouTube or Facebook
  --block-domain <dom>   Block domain; supports simple wildcards like *.facebook.com
  --rules <file>         Load blocking rules from file
  --json-report <file>   Write dashboard-ready JSON report
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              Fast path threads per load balancer (default: 2)
  --verbose              Enable verbose output
  --help, -h             Show this help

Examples:
  )" << program << R"( capture.pcap filtered.pcap
  )" << program << R"( capture.pcap filtered.pcap --block-app YouTube
  )" << program << R"( capture.pcap filtered.pcap --json-report frontend/dashboard/report.json
  )" << program << R"( capture.pcap filtered.pcap --block-ip 192.168.1.50 --block-domain *.tiktok.com
  )" << program << R"( capture.pcap filtered.pcap --rules blocking_rules.txt

Supported apps for blocking:
  Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon,
  Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub

Pipeline:
  PCAP Reader -> Load Balancers -> Fast Path Workers -> Output Writer

)";
}

bool requireValue(int index, int argc, const std::string& option) {
    if (index + 1 < argc) {
        return true;
    }

    std::cerr << "Missing value for option: " << option << "\n";
    return false;
}

int parsePositiveInt(const char* value, const std::string& option) {
    int parsed = std::stoi(value);
    if (parsed <= 0) {
        throw std::invalid_argument(option + " must be greater than zero");
    }
    return parsed;
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    if (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") {
        printUsage(argv[0]);
        return 0;
    }

    if (argc < 3) {
        printUsage(argv[0]);
        return 1;
    }

    std::string input_file = argv[1];
    std::string output_file = argv[2];

    DPIEngine::Config config;
    std::vector<std::string> block_ips;
    std::vector<std::string> block_apps;
    std::vector<std::string> block_domains;
    std::string rules_file;
    std::string json_report_file;

    try {
        for (int i = 3; i < argc; i++) {
            std::string arg = argv[i];

            if (arg == "--block-ip") {
                if (!requireValue(i, argc, arg)) return 1;
                block_ips.push_back(argv[++i]);
            } else if (arg == "--block-app") {
                if (!requireValue(i, argc, arg)) return 1;
                block_apps.push_back(argv[++i]);
            } else if (arg == "--block-domain") {
                if (!requireValue(i, argc, arg)) return 1;
                block_domains.push_back(argv[++i]);
            } else if (arg == "--rules") {
                if (!requireValue(i, argc, arg)) return 1;
                rules_file = argv[++i];
            } else if (arg == "--json-report") {
                if (!requireValue(i, argc, arg)) return 1;
                json_report_file = argv[++i];
            } else if (arg == "--lbs") {
                if (!requireValue(i, argc, arg)) return 1;
                config.num_load_balancers = parsePositiveInt(argv[++i], arg);
            } else if (arg == "--fps") {
                if (!requireValue(i, argc, arg)) return 1;
                config.fps_per_lb = parsePositiveInt(argv[++i], arg);
            } else if (arg == "--verbose") {
                config.verbose = true;
            } else if (arg == "--help" || arg == "-h") {
                printUsage(argv[0]);
                return 0;
            } else {
                std::cerr << "Unknown option: " << arg << "\n";
                printUsage(argv[0]);
                return 1;
            }
        }
    } catch (const std::exception& ex) {
        std::cerr << "Invalid command-line option: " << ex.what() << "\n";
        return 1;
    }

    DPIEngine engine(config);

    if (!engine.initialize()) {
        std::cerr << "Failed to initialize DPI engine\n";
        return 1;
    }

    if (!rules_file.empty() && !engine.loadRules(rules_file)) {
        std::cerr << "Failed to load rules file: " << rules_file << "\n";
        return 1;
    }

    for (const auto& ip : block_ips) {
        engine.blockIP(ip);
    }

    for (const auto& app : block_apps) {
        engine.blockApp(app);
    }

    for (const auto& domain : block_domains) {
        engine.blockDomain(domain);
    }

    if (!engine.processFile(input_file, output_file)) {
        std::cerr << "Failed to process file\n";
        return 1;
    }

    if (!json_report_file.empty()) {
        if (!engine.saveJsonReport(json_report_file, input_file, output_file)) {
            std::cerr << "Failed to write JSON report: " << json_report_file << "\n";
            return 1;
        }
        std::cout << "JSON report written to: " << json_report_file << "\n";
    }

    std::cout << "\nProcessing complete!\n";
    std::cout << "Output written to: " << output_file << "\n";

    return 0;
}
