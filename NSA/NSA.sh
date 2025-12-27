#!/bin/bash

# Colors for UI
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if file argument is provided
if [ -z "$1" ]; then
    echo -e "${RED}Usage: $0 <target_file.txt>${NC}"
    exit 1
fi

TARGET_FILE=$1

# Arrays to store results
VULN_LIST=()
SAFE_LIST=()

print_header() {
    clear
    echo -e "${CYAN}========================================"
    echo -e "      Network Security Auditor v1.2"
    echo -e "========================================${NC}"
}

run_scan() {
    local choice=$1
    local total_ips=$(wc -l < "$TARGET_FILE")
    local count=0

    echo -e "\n${YELLOW}Running Scan... Please wait.${NC}"

    while read -r line; do
        [[ -z "$line" ]] && continue 
        
        ip=$(echo "$line" | awk '{print $1}')
        port=$(echo "$line" | awk '{print $3}')
        ((count++))

        # Progress bar
        echo -ne "Progress: [${count}/${total_ips}] Scanning $ip...\r"

        case $choice in
            1) # NTP Monlist
                output=$(nmap -sU -p 123 -n -Pn --script ntp-monlist "$ip" 2>/dev/null)
                if [[ $output == *"ntp-monlist:"* ]]; then VULN_LIST+=("$ip Port $port"); else SAFE_LIST+=("$ip Port $port"); fi
                ;;
            2) # NTP Mode 6
                output=$(nmap -sU -p 123 --script ntp-info "$ip" 2>/dev/null)
                if [[ $output == *"ntp-info:"* ]]; then VULN_LIST+=("$ip Port $port"); else SAFE_LIST+=("$ip Port $port"); fi
                ;;
            3) # SNMP Public
                output=$(snmp-check "$ip" -c public 2>/dev/null)
                if [[ $output == *"System information"* || $output == *"Network interfaces"* || $output == *"Network IP"* || $output == *"Software components"* || $output == *"Storage information"* || $output == *"Processes"* || $output == *"Device information"* ]]; then
                    VULN_LIST+=("$ip Port $port")
                else
                    SAFE_LIST+=("$ip Port $port")
                fi
                ;;
            4) # SMB Signing
                output=$(nmap --script smb-security-mode.nse -p 445 "$ip" 2>/dev/null)
                if [[ $output == *"message_signing: disabled"* ]]; then VULN_LIST+=("$ip Port $port"); else SAFE_LIST+=("$ip Port $port"); fi
                ;;
            5) # AMQP Cleartext
                output=$(nmap --script amqp-info -p 5672 "$ip" 2>/dev/null)
                if [[ $output == *"amqp-info:"* ]]; then VULN_LIST+=("$ip Port $port"); else SAFE_LIST+=("$ip Port $port"); fi
                ;;
            6) # Redis Vuln Checker (Unauthenticated Access)
                # Using your logic: if 'INFO' command returns data, it's unauthenticated/vulnerable
                if timeout 3 redis-cli -h "$ip" -p 6379 INFO &>/dev/null; then
                    VULN_LIST+=("$ip Port 6379")
                else
                    SAFE_LIST+=("$ip Port 6379")
                fi
                ;;
        esac
    done < "$TARGET_FILE"
    
    echo -e "\n\n${GREEN}Scan Complete!${NC}"
    display_results
}

display_results() {
    echo -e "----------------------------------------"
    echo -e "${RED}Vulnerable IPs:${NC}"
    if [ ${#VULN_LIST[@]} -eq 0 ]; then echo "  None"; else
        for i in "${VULN_LIST[@]}"; do echo -e "  $i"; done
    fi

    echo -e "\n${GREEN}Not Vulnerable IPs:${NC}"
    if [ ${#SAFE_LIST[@]} -eq 0 ]; then echo "  None"; else
        for i in "${SAFE_LIST[@]}"; do echo -e "  $i"; done
    fi

    echo -e "\n${BLUE}Stats:${NC}"
    echo "Total IPs inputted: $(( ${#VULN_LIST[@]} + ${#SAFE_LIST[@]} ))"
    echo -e "Total ${RED}vulnerable${NC} IP: ${#VULN_LIST[@]}"
    echo -e "Total ${GREEN}non vulnerable${NC} IP: ${#SAFE_LIST[@]}"
    echo -e "----------------------------------------"
}

# Main Menu
print_header
echo "1. NTP monlist (DoS)"
echo "2. NTP Mode 6 Scanner"
echo "3. SNMP Default Community (public)"
echo "4. SMB Signing Not Required"
echo "5. AMQP Cleartext Authentication"
echo "6. Redis Vuln Checker (Unauthenticated Access)"
echo -ne "\nSelect an option [1-6]: "
read choice

if [[ "$choice" -ge 1 && "$choice" -le 6 ]]; then
    run_scan "$choice"
else
    echo -e "${RED}Invalid option selected.${NC}"
fi
