#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <cstdint>
#include <iomanip>
#include <algorithm>
#include <optional>

// --- Color definitions for output (no OS-specific headers needed) ---
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_CYAN    "\033[36m"
#define BOLD_TEXT     "\033[1m"


// --- Self-implemented IP Address conversion functions ---

// Parses a string like "192.168.1.1" into a 32-bit integer.
// Returns std::nullopt if the string is not a valid IP address.
std::optional<uint32_t> stringToIp(const std::string& ip_str) {
    std::stringstream ss(ip_str);
    std::string segment;
    uint32_t ip_value = 0;
    int segment_count = 0;

    while (std::getline(ss, segment, '.')) {
        // Check for non-numeric characters or empty segments (e.g., "192..1.1")
        if (segment.empty() || !std::all_of(segment.begin(), segment.end(), ::isdigit)) {
            return std::nullopt;
        }

        int octet_val;
        try {
            octet_val = std::stoi(segment);
        } catch (const std::out_of_range&) {
            // Value too large to be an integer
            return std::nullopt;
        }

        // Check if the octet is in the valid 0-255 range.
        if (octet_val < 0 || octet_val > 255) {
            return std::nullopt;
        }

        ip_value = (ip_value << 8) | octet_val;
        segment_count++;
    }

    // A valid IP must have exactly 4 segments.
    // We also check if the stringstream has leftover characters after the last segment,
    // which would mean an invalid format like "1.2.3.4."
    if (segment_count != 4 || !ss.eof()) {
        return std::nullopt;
    }

    return ip_value;
}

// Converts a 32-bit integer back to a string like "192.168.1.1".
std::string ipToString(uint32_t ip_value) {
    std::stringstream ss;
    ss << ((ip_value >> 24) & 0xFF) << "."
       << ((ip_value >> 16) & 0xFF) << "."
       << ((ip_value >> 8) & 0xFF)  << "."
       << (ip_value & 0xFF);
    return ss.str();
}


// --- Helper struct for IP Address operations (now using our functions) ---
struct IPAddress {
    uint32_t value = 0;

    IPAddress() = default;

    IPAddress(uint32_t val) : value(val) {}

    // Convert from string to IPAddress. Returns false on failure.
    bool fromString(const std::string& ip_str) {
        std::optional<uint32_t> result = stringToIp(ip_str);
        if (result.has_value()) {
            value = result.value();
            return true;
        }
        return false;
    }

    // Convert from IPAddress to string.
    std::string toString() const {
        return ipToString(value);
    }

    // Operator for range comparisons
    bool operator<=(const IPAddress& other) const {
        return value <= other.value;
    }
    bool operator>=(const IPAddress& other) const {
        return value >= other.value;
    }
};

// --- Helper Functions ---

void print_usage() {
    std::cerr << BOLD_TEXT << "Usage:" << COLOR_RESET << " ip_calculator <ip>[/<length>] [mask|length] [-w wildcard] [--capacity N] [--range <from> <to>]" << std::endl;
    std::cerr << "       Mask can be specified in 4 ways (only one is allowed):" << std::endl;
    std::cerr << "         1. CIDR notation: 192.168.1.1/24" << std::endl;
    std::cerr << "         2. Mask length:   192.168.1.1 24" << std::endl;
    std::cerr << "         3. Dotted mask:   192.168.1.1 255.255.255.0" << std::endl;
    std::cerr << "         4. Wildcard mask: 192.168.1.1 -w 0.0.0.255" << std::endl;
}

void print_error(const std::string& msg) {
    std::cerr << BOLD_TEXT << COLOR_RED << "[ERROR] " << COLOR_RESET << msg << std::endl;
}

// --- Main Program Logic (Unchanged) ---

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::vector<std::string> args(argv + 1, argv + argc);

    IPAddress input_ip, range_from, range_to;
    std::optional<int> mask_len;
    std::optional<IPAddress> netmask;
    std::optional<IPAddress> wildcard;
    std::optional<long long> capacity_req;
    bool mask_from_cidr = false;
    bool mask_provided = false;
    bool is_classful_default = false;


    // --- 1. Argument Parsing ---
    try {
        // First argument is always IP, potentially with CIDR
        std::string first_arg = args[0];
        size_t slash_pos = first_arg.find('/');
        if (slash_pos != std::string::npos) {
            if (!input_ip.fromString(first_arg.substr(0, slash_pos))) {
                print_error("Invalid IP address format in CIDR: " + first_arg.substr(0, slash_pos));
                return 1;
            }
            mask_len = std::stoi(first_arg.substr(slash_pos + 1));
            mask_provided = true;
            mask_from_cidr = true;
        } else {
            if (!input_ip.fromString(first_arg)) {
                print_error("Invalid IP address format: " + first_arg);
                return 1;
            }
        }

        // Parse remaining arguments
        for (size_t i = 1; i < args.size(); ++i) {
            if (args[i] == "-w") {
                if (mask_provided) { print_error("Multiple mask definitions provided."); return 1; }
                if (++i >= args.size()) { print_error("-w requires a wildcard mask argument."); return 1; }
                IPAddress w;
                if (!w.fromString(args[i])) { print_error("Invalid wildcard mask format: " + args[i]); return 1; }
                wildcard = w;
                mask_provided = true;
            } else if (args[i] == "--capacity") {
                if (++i >= args.size()) { print_error("--capacity requires a numeric argument."); return 1; }
                capacity_req = std::stoll(args[i]);
                if (capacity_req.value() <= 0) { print_error("Capacity must be a positive number."); return 1; }
            } else if (args[i] == "--range") {
                if (i + 2 >= args.size()) { print_error("--range requires two IP addresses (from and to)."); return 1; }
                if (!range_from.fromString(args[++i])) { print_error("Invalid 'from' IP in range: " + args[i]); return 1; }
                if (!range_to.fromString(args[++i])) { print_error("Invalid 'to' IP in range: " + args[i]); return 1; }
                if (range_to.value < range_from.value) { print_error("'to' IP cannot be smaller than 'from' IP in range."); return 1;}
            } else { // Assume it's a mask or length
                if (mask_provided) { print_error("Multiple mask definitions provided."); return 1; }
                // Is it a length?
                try {
                    int len = std::stoi(args[i]);
                    if (args[i].find('.') == std::string::npos) { // ensure it's not a misparsed IP
                         mask_len = len;
                         mask_provided = true;
                         continue;
                    }
                } catch(...) { /* Not a simple integer */ }

                // Is it a dotted-decimal mask?
                IPAddress m;
                if (m.fromString(args[i])) {
                    netmask = m;
                    mask_provided = true;
                } else {
                    print_error("Unrecognized argument: " + args[i]);
                    return 1;
                }
            }
        }
    } catch (const std::exception& e) {
        print_error("Invalid numeric argument provided. " + std::string(e.what()));
        return 1;
    }

    // --- 2. Validation and Mask Calculation ---
    uint32_t final_mask_val;

    if (mask_len.has_value()) {
        if (mask_len.value() < 0 || mask_len.value() > 32) {
            print_error("Mask length must be between 0 and 32.");
            return 1;
        }
        if (mask_len.value() == 0) final_mask_val = 0x0;
        else final_mask_val = (0xFFFFFFFF << (32 - mask_len.value()));
    } else if (netmask.has_value()) {
        final_mask_val = netmask.value().value;
        // Validate mask format (contiguous 1s then 0s)
        uint32_t temp = ~final_mask_val;
        if ((temp & (temp + 1)) != 0 && final_mask_val != 0xFFFFFFFF) {
            print_error("Invalid netmask: bits must be contiguous ones followed by zeros.");
            return 1;
        }
    } else if (wildcard.has_value()) {
        final_mask_val = ~wildcard.value().value;
         // Validate wildcard format (contiguous 0s then 1s) by checking its inverse mask
        uint32_t temp = ~(~final_mask_val);
        if ((temp & (temp + 1)) != 0 && (~final_mask_val) != 0xFFFFFFFF) {
            print_error("Invalid wildcard mask: bits must be contiguous zeros followed by ones.");
            return 1;
        }
    } else {
        // No mask provided, determine from class
        is_classful_default = true;
        uint8_t first_octet = (input_ip.value >> 24) & 0xFF;
        if (first_octet >= 0 && first_octet <= 127) final_mask_val = 0xFF000000;       // Class A
        else if (first_octet >= 128 && first_octet <= 191) final_mask_val = 0xFFFF0000; // Class B
        else if (first_octet >= 192 && first_octet <= 223) final_mask_val = 0xFFFFFF00; // Class C
        else {
            print_error("Cannot determine default classful mask for IP " + input_ip.toString() + ". Please provide a mask.");
            return 1;
        }
    }

    // --- 3. Final Calculations ---
    IPAddress final_mask(final_mask_val);
    int final_len = 0;
    for(int i=0; i<32; ++i) if((final_mask.value >> i) & 1) final_len++;

    IPAddress network_addr(input_ip.value & final_mask.value);
    IPAddress final_wildcard(~final_mask.value);
    IPAddress broadcast_addr(network_addr.value | final_wildcard.value);
    
    // Total IPs in the subnet. Using unsigned long long to avoid overflow for /0.
    unsigned long long total_ips = (unsigned long long)final_wildcard.value + 1;

    IPAddress first_host, last_host;
    if (final_len <= 30) {
        first_host.value = network_addr.value + 1;
        last_host.value = broadcast_addr.value - 1;
    } else { // For /31 and /32, first/last host is not applicable in the traditional sense
        first_host = network_addr;
        last_host = broadcast_addr;
    }


    // --- 4. Output Results ---
    // std::cout << std::string(40, '-') << std::endl;
    // std::cout << BOLD_TEXT << COLOR_CYAN << "IP Network Analysis" << COLOR_RESET << std::endl;
    // std::cout << std::string(40, '-') << std::endl;

    if (is_classful_default) {
        std::cout << "Mask was not provided. Using default Classful Mask " << COLOR_YELLOW << final_len << COLOR_RESET << std::endl;
    }

    std::cout << std::left << std::setw(18) << "Network Address:" << BOLD_TEXT << network_addr.toString() << "/" << final_len << COLOR_RESET << std::endl;
    std::cout << std::left << std::setw(18) << "Netmask:" << final_mask.toString() << std::endl;
    std::cout << std::left << std::setw(18) << "Wildcard Mask:" << final_wildcard.toString() << std::endl;
    std::cout << std::left << std::setw(18) << "Broadcast:" << broadcast_addr.toString() << std::endl;
    if (final_len < 31) {
        std::cout << std::left << std::setw(18) << "First Host IP:" << first_host.toString() << std::endl;
        std::cout << std::left << std::setw(18) << "Last Host IP:" << last_host.toString() << std::endl;
    } else if (final_len == 31) {
        std::cout << std::left << std::setw(18) << "Host IPs:" << "N/A (Point-to-Point Link)" << std::endl;
    } else { // final_len == 32
        std::cout << std::left << std::setw(18) << "Host IPs:" << "N/A (Host Route)" << std::endl;
    }
    std::cout << std::left << std::setw(18) << "Total IPs:" << total_ips << std::endl;


    // Capacity Check
    if (capacity_req.has_value()) {
        // std::cout << std::string(40, '-') << std::endl;
        bool satisfied = (total_ips >= (unsigned long long)capacity_req.value());
        // std::cout << BOLD_TEXT << "Capacity Check" << COLOR_RESET << std::endl;
        std::cout << "Capacity Required: " << capacity_req.value() << ", Network Provides: " << total_ips << ", ";
        if (satisfied) {
            std::cout << COLOR_GREEN << "Requirement satisfied." << COLOR_RESET << std::endl;
        } else {
            std::cout << COLOR_RED << "Requirement NOT satisfied." << COLOR_RESET << std::endl;
        }
    }

    // Range Check
    if (range_from.value != 0 || range_to.value != 0) { // Check if range was provided
         // std::cout << std::string(40, '-') << std::endl;
        bool in_range = (range_from >= network_addr && range_to <= broadcast_addr);
        // std::cout << BOLD_TEXT << "Range Check" << COLOR_RESET << std::endl;
        // std::cout << "Checking if " << range_from.toString() << " - " << range_to.toString() << " is within the network." << std::endl;
        //  if (in_range) {
        //     std::cout << COLOR_GREEN << "-> The entire specified range is within this network." << COLOR_RESET << std::endl;
        // } else {
        //     std::cout << COLOR_RED << "-> The specified range is NOT entirely within this network." << COLOR_RESET << std::endl;
        // }
        if (in_range) {
           std::cout << COLOR_GREEN << "Specified range (" << range_from.toString() << " - " << range_to.toString() << ") is within this network." << COLOR_RESET << std::endl; 
        } else {
            std::cout << COLOR_RED << "Specified range (" << range_from.toString() << " - " << range_to.toString() << ") is NOT entirely within this network." << COLOR_RESET << std::endl; 
        }
    }

    // std::cout << std::string(40, '-') << std::endl;

    return 0;
}