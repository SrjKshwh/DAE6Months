#!/bin/bash

# Volatility Setup Script for Parrot OS
# This script installs and configures Volatility framework for memory analysis

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

success() {
    echo -e "${GREEN}✓ $1${NC}"
}

error() {
    echo -e "${RED}✗ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Function to install Volatility
install_volatility() {
    log "Installing Volatility framework..."

    # Update package list
    sudo apt update

    # Install Volatility and dependencies
    sudo apt install -y volatility volatility-tools python3-volatility

    # Install additional Python dependencies
    sudo apt install -y python3-pip python3-dev build-essential

    # Install Python packages for enhanced functionality
    pip3 install --user --upgrade pip
    pip3 install --user openpyxl pycrypto yara-python distorm3

    # Install Volatility 3 (latest version)
    if [ ! -d "~/volatility3" ]; then
        git clone https://github.com/volatilityfoundation/volatility3.git ~/volatility3
        cd ~/volatility3
        sudo python3 setup.py install
        cd -
    fi

    success "Volatility installed successfully"
}

# Function to create memory analysis scripts
create_analysis_scripts() {
    log "Creating memory analysis scripts..."

    # Create analysis directory
    mkdir -p ~/volatility_analysis
    mkdir -p ~/volatility_analysis/dumps
    mkdir -p ~/volatility_analysis/reports

    # Profile detection script
    cat > ~/volatility_analysis/detect_profile.sh << 'EOF'
#!/bin/bash

MEMORY_IMAGE=$1

if [ -z "$MEMORY_IMAGE" ]; then
    echo "Usage: $0 <memory_image>"
    echo "Supported formats: .raw, .dmp, .vmem, .mem"
    exit 1
fi

if [ ! -f "$MEMORY_IMAGE" ]; then
    echo "Error: Memory image file not found: $MEMORY_IMAGE"
    exit 1
fi

echo "Detecting profile for memory image: $MEMORY_IMAGE"
echo "================================================="

# Try Volatility 3 first
echo "Trying Volatility 3..."
if command -v vol >/dev/null 2>&1; then
    echo "Available Volatility 3 plugins:"
    vol --help | grep -A 50 "Available plugins:" | head -20

    echo ""
    echo "Attempting automatic profile detection..."
    if vol -f "$MEMORY_IMAGE" windows.info >/dev/null 2>&1; then
        echo "Windows profile detected. Use: vol -f $MEMORY_IMAGE windows.info"
        vol -f "$MEMORY_IMAGE" windows.info | grep "Kernel"
    elif vol -f "$MEMORY_IMAGE" linux.info >/dev/null 2>&1; then
        echo "Linux profile detected. Use: vol -f $MEMORY_IMAGE linux.info"
        vol -f "$MEMORY_IMAGE" linux.info | grep "Kernel"
    else
        echo "Could not auto-detect profile with Volatility 3"
    fi
else
    echo "Volatility 3 not found"
fi

echo ""
echo "Trying Volatility 2..."
if command -v volatility >/dev/null 2>&1; then
    echo "Attempting profile detection with Volatility 2..."
    volatility -f "$MEMORY_IMAGE" imageinfo 2>/dev/null || echo "Profile detection failed"
else
    echo "Volatility 2 not found"
fi

echo ""
echo "Manual profile detection hints:"
echo "- For Windows: Win7SP1x64, Win10x64, etc."
echo "- For Linux: Linux kernel version specific profiles"
echo "- Check Volatility documentation for supported profiles"
EOF

    chmod +x ~/volatility_analysis/detect_profile.sh

    # Process analysis script
    cat > ~/volatility_analysis/process_analysis.sh << 'EOF'
#!/bin/bash

MEMORY_IMAGE=$1
PROFILE=$2

if [ -z "$MEMORY_IMAGE" ] || [ -z "$PROFILE" ]; then
    echo "Usage: $0 <memory_image> <profile>"
    echo "Example: $0 memory.dmp Win10x64_19041"
    exit 1
fi

if [ ! -f "$MEMORY_IMAGE" ]; then
    echo "Error: Memory image file not found: $MEMORY_IMAGE"
    exit 1
fi

echo "Performing process analysis on: $MEMORY_IMAGE"
echo "Using profile: $PROFILE"
echo "==========================================="

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="~/volatility_analysis/reports/process_analysis_$TIMESTAMP.txt"

echo "Process Analysis Report - $TIMESTAMP" > "$REPORT_FILE"
echo "Memory Image: $MEMORY_IMAGE" >> "$REPORT_FILE"
echo "Profile: $PROFILE" >> "$REPORT_FILE"
echo "=====================================" >> "$REPORT_FILE"

# Try Volatility 3 first
if command -v vol >/dev/null 2>&1; then
    echo "Using Volatility 3..."

    echo "=== Running Processes ==="
    vol -f "$MEMORY_IMAGE" --profile="$PROFILE" windows.pslist 2>/dev/null || vol -f "$MEMORY_IMAGE" windows.pslist
    vol -f "$MEMORY_IMAGE" --profile="$PROFILE" windows.pslist 2>/dev/null >> "$REPORT_FILE" || vol -f "$MEMORY_IMAGE" windows.pslist >> "$REPORT_FILE"

    echo ""
    echo "=== Process Tree ==="
    vol -f "$MEMORY_IMAGE" --profile="$PROFILE" windows.pstree 2>/dev/null || vol -f "$MEMORY_IMAGE" windows.pstree
    vol -f "$MEMORY_IMAGE" --profile="$PROFILE" windows.pstree 2>/dev/null >> "$REPORT_FILE" || vol -f "$MEMORY_IMAGE" windows.pstree >> "$REPORT_FILE"

    echo ""
    echo "=== Suspicious Processes ==="
    echo "Processes with suspicious names:"
    vol -f "$MEMORY_IMAGE" --profile="$PROFILE" windows.pslist 2>/dev/null | grep -i "suspicious\|malware\|unknown\|cmd\|powershell" || vol -f "$MEMORY_IMAGE" windows.pslist | grep -i "suspicious\|malware\|unknown\|cmd\|powershell"

    echo ""
    echo "=== Network Connections ==="
    vol -f "$MEMORY_IMAGE" --profile="$PROFILE" windows.netscan 2>/dev/null || vol -f "$MEMORY_IMAGE" windows.netscan
    vol -f "$MEMORY_IMAGE" --profile="$PROFILE" windows.netscan 2>/dev/null >> "$REPORT_FILE" || vol -f "$MEMORY_IMAGE" windows.netscan >> "$REPORT_FILE"

    echo ""
    echo "=== DLL Analysis ==="
    vol -f "$MEMORY_IMAGE" --profile="$PROFILE" windows.dlllist 2>/dev/null | head -20 || vol -f "$MEMORY_IMAGE" windows.dlllist | head -20

else
    echo "Volatility 3 not found, trying Volatility 2..."

    # Fallback to Volatility 2
    if command -v volatility >/dev/null 2>&1; then
        echo "=== Running Processes ==="
        volatility -f "$MEMORY_IMAGE" --profile="$PROFILE" pslist
        volatility -f "$MEMORY_IMAGE" --profile="$PROFILE" pslist >> "$REPORT_FILE"

        echo ""
        echo "=== Process Tree ==="
        volatility -f "$MEMORY_IMAGE" --profile="$PROFILE" pstree
        volatility -f "$MEMORY_IMAGE" --profile="$PROFILE" pstree >> "$REPORT_FILE"

        echo ""
        echo "=== Network Connections ==="
        volatility -f "$MEMORY_IMAGE" --profile="$PROFILE" netscan
        volatility -f "$MEMORY_IMAGE" --profile="$PROFILE" netscan >> "$REPORT_FILE"

        echo ""
        echo "=== DLL Analysis ==="
        volatility -f "$MEMORY_IMAGE" --profile="$PROFILE" dlllist | head -20
    else
        echo "Neither Volatility 2 nor 3 found!"
        exit 1
    fi
fi

echo ""
echo "=== Analysis Summary ==="
echo "Report saved to: $REPORT_FILE"
echo "Memory image size: $(du -h "$MEMORY_IMAGE" | cut -f1)"
echo "Analysis completed at: $(date)"

success "Process analysis completed. Check report: $REPORT_FILE"
EOF

    chmod +x ~/volatility_analysis/process_analysis.sh

    # Memory forensics script
    cat > ~/volatility_analysis/memory_forensics.sh << 'EOF'
#!/bin/bash

MEMORY_IMAGE=$1
PROFILE=$2

if [ -z "$MEMORY_IMAGE" ] || [ -z "$PROFILE" ]; then
    echo "Usage: $0 <memory_image> <profile>"
    echo "Example: $0 memory.dmp Win10x64_19041"
    exit 1
fi

if [ ! -f "$MEMORY_IMAGE" ]; then
    echo "Error: Memory image file not found: $MEMORY_IMAGE"
    exit 1
fi

echo "Performing memory forensics on: $MEMORY_IMAGE"
echo "Using profile: $PROFILE"
echo "==========================================="

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="~/volatility_analysis/reports/forensics_$TIMESTAMP.txt"
DUMP_DIR="~/volatility_analysis/dumps/$TIMESTAMP"

mkdir -p "$DUMP_DIR"

echo "Memory Forensics Report - $TIMESTAMP" > "$REPORT_FILE"
echo "Memory Image: $MEMORY_IMAGE" >> "$REPORT_FILE"
echo "Profile: $PROFILE" >> "$REPORT_FILE"
echo "Dump Directory: $DUMP_DIR" >> "$REPORT_FILE"
echo "=====================================" >> "$REPORT_FILE"

# Try Volatility 3 first
if command -v vol >/dev/null 2>&1; then
    echo "Using Volatility 3..."

    echo "=== System Information ==="
    vol -f "$MEMORY_IMAGE" --profile="$PROFILE" windows.info 2>/dev/null || vol -f "$MEMORY_IMAGE" windows.info
    vol -f "$MEMORY_IMAGE" --profile="$PROFILE" windows.info 2>/dev/null >> "$REPORT_FILE" || vol -f "$MEMORY_IMAGE" windows.info >> "$REPORT_FILE"

    echo ""
    echo "=== Registry Analysis ==="
    echo "Registry hives:"
    vol -f "$MEMORY_IMAGE" --profile="$PROFILE" windows.registry.hivelist 2>/dev/null || vol -f "$MEMORY_IMAGE" windows.registry.hivelist
    vol -f "$MEMORY_IMAGE" --profile="$PROFILE" windows.registry.hivelist 2>/dev/null >> "$REPORT_FILE" || vol -f "$MEMORY_IMAGE" windows.registry.hivelist >> "$REPORT_FILE"

    echo ""
    echo "=== Dumping Suspicious Processes ==="
    # Get suspicious process PIDs and dump them
    vol -f "$MEMORY_IMAGE" --profile="$PROFILE" windows.pslist 2>/dev/null | \
    grep -i "cmd\|powershell\|suspicious\|unknown" | \
    awk '{print $3}' | \
    while read pid; do
        if [ ! -z "$pid" ] && [ "$pid" != "PID" ]; then
            echo "Dumping process PID: $pid"
            vol -f "$MEMORY_IMAGE" --profile="$PROFILE" windows.pslist.PsList.pid="$pid" 2>/dev/null || echo "Could not dump PID $pid"
        fi
    done

    echo ""
    echo "=== Malware Detection ==="
    echo "Checking for rootkits..."
    vol -f "$MEMORY_IMAGE" --profile="$PROFILE" windows.ssdt 2>/dev/null || vol -f "$MEMORY_IMAGE" windows.ssdt
    vol -f "$MEMORY_IMAGE" --profile="$PROFILE" windows.ssdt 2>/dev/null >> "$REPORT_FILE" || vol -f "$MEMORY_IMAGE" windows.ssdt >> "$REPORT_FILE"

    echo ""
    echo "=== File Analysis ==="
    echo "Recent file activity:"
    vol -f "$MEMORY_IMAGE" --profile="$PROFILE" windows.filescan 2>/dev/null | head -20 || vol -f "$MEMORY_IMAGE" windows.filescan | head -20

    echo ""
    echo "=== Command Line Analysis ==="
    vol -f "$MEMORY_IMAGE" --profile="$PROFILE" windows.cmdline 2>/dev/null || vol -f "$MEMORY_IMAGE" windows.cmdline
    vol -f "$MEMORY_IMAGE" --profile="$PROFILE" windows.cmdline 2>/dev/null >> "$REPORT_FILE" || vol -f "$MEMORY_IMAGE" windows.cmdline >> "$REPORT_FILE"

else
    echo "Volatility 3 not found, trying Volatility 2..."

    # Fallback to Volatility 2
    if command -v volatility >/dev/null 2>&1; then
        echo "=== System Information ==="
        volatility -f "$MEMORY_IMAGE" --profile="$PROFILE" imageinfo
        volatility -f "$MEMORY_IMAGE" --profile="$PROFILE" imageinfo >> "$REPORT_FILE"

        echo ""
        echo "=== Dumping Suspicious Processes ==="
        volatility -f "$MEMORY_IMAGE" --profile="$PROFILE" pslist | \
        grep -i "cmd\|powershell\|suspicious" | \
        awk '{print $3}' | \
        while read pid; do
            if [ ! -z "$pid" ] && [ "$pid" != "PID" ]; then
                echo "Dumping process PID: $pid"
                volatility -f "$MEMORY_IMAGE" --profile="$PROFILE" procdump -p $pid -D "$DUMP_DIR/"
            fi
        done

        echo ""
        echo "=== Registry Analysis ==="
        volatility -f "$MEMORY_IMAGE" --profile="$PROFILE" hivelist
        volatility -f "$MEMORY_IMAGE" --profile="$PROFILE" hivelist >> "$REPORT_FILE"

        echo ""
        echo "=== Command Line Analysis ==="
        volatility -f "$MEMORY_IMAGE" --profile="$PROFILE" cmdline
        volatility -f "$MEMORY_IMAGE" --profile="$PROFILE" cmdline >> "$REPORT_FILE"
    else
        echo "Neither Volatility 2 nor 3 found!"
        exit 1
    fi
fi

echo ""
echo "=== Forensics Summary ==="
echo "Report saved to: $REPORT_FILE"
echo "Process dumps saved to: $DUMP_DIR"
echo "Memory image size: $(du -h "$MEMORY_IMAGE" | cut -f1)"
echo "Analysis completed at: $(date)"

success "Memory forensics completed. Check report: $REPORT_FILE and dumps: $DUMP_DIR"
EOF

    chmod +x ~/volatility_analysis/memory_forensics.sh

    # Quick triage script
    cat > ~/volatility_analysis/triage.sh << 'EOF'
#!/bin/bash

MEMORY_IMAGE=$1

if [ -z "$MEMORY_IMAGE" ]; then
    echo "Usage: $0 <memory_image>"
    echo "Performs quick triage analysis on memory image"
    exit 1
fi

echo "Performing quick triage on: $MEMORY_IMAGE"
echo "========================================"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TRIAGE_FILE="~/volatility_analysis/reports/triage_$TIMESTAMP.txt"

echo "Memory Triage Report - $TIMESTAMP" > "$TRIAGE_FILE"
echo "Memory Image: $MEMORY_IMAGE" >> "$TRIAGE_FILE"
echo "=================================" >> "$TRIAGE_FILE"

# Detect profile first
echo "Detecting profile..."
PROFILE=""
if command -v vol >/dev/null 2>&1; then
    if vol -f "$MEMORY_IMAGE" windows.info >/dev/null 2>&1; then
        PROFILE="windows"
        echo "Profile: Windows (Volatility 3)" | tee -a "$TRIAGE_FILE"
    elif vol -f "$MEMORY_IMAGE" linux.info >/dev/null 2>&1; then
        PROFILE="linux"
        echo "Profile: Linux (Volatility 3)" | tee -a "$TRIAGE_FILE"
    fi
elif command -v volatility >/dev/null 2>&1; then
    # Try common profiles for Volatility 2
    for prof in Win7SP1x64 Win10x64 Linux; do
        if volatility -f "$MEMORY_IMAGE" --profile="$prof" pslist >/dev/null 2>&1; then
            PROFILE="$prof"
            echo "Profile: $prof (Volatility 2)" | tee -a "$TRIAGE_FILE"
            break
        fi
    done
fi

if [ -z "$PROFILE" ]; then
    echo "Could not determine profile automatically" | tee -a "$TRIAGE_FILE"
    echo "Run: ~/volatility_analysis/detect_profile.sh $MEMORY_IMAGE" | tee -a "$TRIAGE_FILE"
    exit 1
fi

echo "" | tee -a "$TRIAGE_FILE"
echo "=== Quick Analysis Results ===" | tee -a "$TRIAGE_FILE"

# Run appropriate analysis based on profile
if [ "$PROFILE" = "windows" ]; then
    if command -v vol >/dev/null 2>&1; then
        echo "Running processes:" | tee -a "$TRIAGE_FILE"
        vol -f "$MEMORY_IMAGE" windows.pslist 2>/dev/null | wc -l | xargs echo "Total processes:" | tee -a "$TRIAGE_FILE"

        echo "Network connections:" | tee -a "$TRIAGE_FILE"
        vol -f "$MEMORY_IMAGE" windows.netscan 2>/dev/null | grep -c "TCP\|UDP" | xargs echo "Active connections:" | tee -a "$TRIAGE_FILE"

        echo "Suspicious processes:" | tee -a "$TRIAGE_FILE"
        vol -f "$MEMORY_IMAGE" windows.pslist 2>/dev/null | grep -i -c "cmd\|powershell\|suspicious" | xargs echo "Potentially suspicious:" | tee -a "$TRIAGE_FILE"
    fi
elif [ "$PROFILE" = "linux" ]; then
    if command -v vol >/dev/null 2>&1; then
        echo "Running processes:" | tee -a "$TRIAGE_FILE"
        vol -f "$MEMORY_IMAGE" linux.pslist 2>/dev/null | wc -l | xargs echo "Total processes:" | tee -a "$TRIAGE_FILE"

        echo "Network connections:" | tee -a "$TRIAGE_FILE"
        vol -f "$MEMORY_IMAGE" linux.netstat 2>/dev/null | grep -c "TCP\|UDP" | xargs echo "Active connections:" | tee -a "$TRIAGE_FILE"
    fi
else
    # Volatility 2 analysis
    echo "Running processes:" | tee -a "$TRIAGE_FILE"
    volatility -f "$MEMORY_IMAGE" --profile="$PROFILE" pslist 2>/dev/null | wc -l | xargs echo "Total processes:" | tee -a "$TRIAGE_FILE"

    echo "Network connections:" | tee -a "$TRIAGE_FILE"
    volatility -f "$MEMORY_IMAGE" --profile="$PROFILE" netscan 2>/dev/null | grep -c "TCP\|UDP" | xargs echo "Active connections:" | tee -a "$TRIAGE_FILE"

    echo "Suspicious processes:" | tee -a "$TRIAGE_FILE"
    volatility -f "$MEMORY_IMAGE" --profile="$PROFILE" pslist 2>/dev/null | grep -i -c "cmd\|powershell\|suspicious" | xargs echo "Potentially suspicious:" | tee -a "$TRIAGE_FILE"
fi

echo "" | tee -a "$TRIAGE_FILE"
echo "Triage completed. Full report: $TRIAGE_FILE" | tee -a "$TRIAGE_FILE"
echo "For detailed analysis, run:" | tee -a "$TRIAGE_FILE"
echo "  ~/volatility_analysis/process_analysis.sh $MEMORY_IMAGE $PROFILE" | tee -a "$TRIAGE_FILE"
echo "  ~/volatility_analysis/memory_forensics.sh $MEMORY_IMAGE $PROFILE" | tee -a "$TRIAGE_FILE"
EOF

    chmod +x ~/volatility_analysis/triage.sh

    success "Analysis scripts created"
}

# Function to create sample memory images for testing
create_sample_data() {
    log "Creating sample data and documentation..."

    # Create README for analysis scripts
    cat > ~/volatility_analysis/README.md << 'EOF'
# Volatility Memory Analysis Scripts

This directory contains scripts for memory forensics analysis using Volatility.

## Scripts Overview

### detect_profile.sh
Detects the appropriate Volatility profile for a memory image.
```bash
./detect_profile.sh <memory_image>
```

### process_analysis.sh
Performs comprehensive process analysis on a memory image.
```bash
./process_analysis.sh <memory_image> <profile>
```

### memory_forensics.sh
Conducts full memory forensics investigation.
```bash
./memory_forensics.sh <memory_image> <profile>
```

### triage.sh
Quick triage analysis for rapid assessment.
```bash
./triage.sh <memory_image>
```

## Directory Structure

- `dumps/` - Process memory dumps
- `reports/` - Analysis reports
- `scripts/` - Custom analysis scripts

## Usage Examples

### Windows Memory Analysis
```bash
# Detect profile
./detect_profile.sh windows_memory.dmp

# Full analysis
./process_analysis.sh windows_memory.dmp Win10x64_19041
./memory_forensics.sh windows_memory.dmp Win10x64_19041

# Quick triage
./triage.sh windows_memory.dmp
```

### Linux Memory Analysis
```bash
# Detect profile
./detect_profile.sh linux_memory.mem

# Full analysis
./process_analysis.sh linux_memory.mem Linux
./memory_forensics.sh linux_memory.mem Linux
```

## Common Profiles

### Windows
- Win7SP1x64
- Win10x64_19041
- Win2012R2x64
- Win2016x64

### Linux
- Linux (generic)
- Ubuntu profiles based on kernel version

## Memory Image Acquisition

### Windows
```bash
# Using DumpIt
DumpIt.exe /Q /O memory.dmp

# Using WinPMEM
winpmem.exe memory.raw
```

### Linux
```bash
# Using LiME
sudo insmod lime.ko "path=/tmp/mem.lime format=lime"

# Using /dev/mem (if available)
sudo dd if=/dev/mem of=/tmp/memory.img bs=1M
```

## Troubleshooting

1. **Profile not found**: Run detect_profile.sh to identify correct profile
2. **Permission denied**: Ensure Volatility is run with appropriate permissions
3. **Memory image corrupted**: Verify image integrity with file command
4. **Plugin not available**: Check Volatility version and install missing plugins

## Security Notes

- Memory analysis should be performed in isolated environment
- Handle memory images as sensitive forensic evidence
- Document chain of custody for legal proceedings
- Use read-only mounts when possible
EOF

    # Create sample test script
    cat > ~/volatility_analysis/test_installation.sh << 'EOF'
#!/bin/bash

echo "Testing Volatility Installation"
echo "=============================="

# Test Volatility 3
echo "Testing Volatility 3..."
if command -v vol >/dev/null 2>&1; then
    echo "✓ Volatility 3 found: $(vol --version 2>/dev/null || echo 'version check failed')"
    echo "Available plugins:"
    vol --help | grep -c "Available plugins" | xargs echo "Plugins available:"
else
    echo "✗ Volatility 3 not found"
fi

echo ""

# Test Volatility 2
echo "Testing Volatility 2..."
if command -v volatility >/dev/null 2>&1; then
    echo "✓ Volatility 2 found: $(volatility --version 2>/dev/null || echo 'version check failed')"
    echo "Available plugins:"
    volatility --help 2>/dev/null | grep -c "Supported plugin commands" | xargs echo "Plugins available:"
else
    echo "✗ Volatility 2 not found"
fi

echo ""

# Test Python dependencies
echo "Testing Python dependencies..."
python3 -c "import openpyxl; print('✓ openpyxl available')" 2>/dev/null || echo "✗ openpyxl not available"
python3 -c "import Crypto; print('✓ pycrypto available')" 2>/dev/null || echo "✗ pycrypto not available"
python3 -c "import yara; print('✓ yara-python available')" 2>/dev/null || echo "✗ yara-python not available"

echo ""

# Test scripts
echo "Testing analysis scripts..."
for script in detect_profile.sh process_analysis.sh memory_forensics.sh triage.sh; do
    if [ -x "~/volatility_analysis/$script" ]; then
        echo "✓ $script is executable"
    else
        echo "✗ $script not found or not executable"
    fi
done

echo ""
echo "Test completed. Check above for any missing components."
EOF

    chmod +x ~/volatility_analysis/test_installation.sh

    success "Sample data and documentation created"
}

# Function to verify installation
verify_installation() {
    log "Verifying Volatility installation..."

    # Check Volatility installations
    local vol3_found=false
    local vol2_found=false

    if command -v vol >/dev/null 2>&1; then
        success "Volatility 3 found: $(vol --version 2>/dev/null | head -1 || echo 'version unknown')"
        vol3_found=true
    else
        warning "Volatility 3 not found"
    fi

    if command -v volatility >/dev/null 2>&1; then
        success "Volatility 2 found: $(volatility --version 2>/dev/null | head -1 || echo 'version unknown')"
        vol2_found=true
    else
        warning "Volatility 2 not found"
    fi

    if [[ "$vol3_found" == false && "$vol2_found" == false ]]; then
        error "No Volatility installation found"
        return 1
    fi

    # Check Python dependencies
    if python3 -c "import openpyxl" 2>/dev/null; then
        success "Python openpyxl available"
    else
        warning "Python openpyxl not available (optional)"
    fi

    if python3 -c "import Crypto" 2>/dev/null; then
        success "Python pycrypto available"
    else
        warning "Python pycrypto not available (optional)"
    fi

    # Check analysis scripts
    if [ -d ~/volatility_analysis ]; then
        success "Analysis directory created"
        local script_count=$(find ~/volatility_analysis -name "*.sh" -executable | wc -l)
        success "Executable scripts created: $script_count"
    else
        error "Analysis directory not found"
        return 1
    fi

    # Check directories
    for dir in dumps reports; do
        if [ -d ~/volatility_analysis/$dir ]; then
            success "Directory $dir created"
        else
            warning "Directory $dir not found"
        fi
    done

    success "Volatility installation verification completed"
}

# Function to display usage information
show_usage() {
    echo "Volatility Setup Script for Parrot OS"
    echo "===================================="
    echo ""
    echo "This script installs and configures Volatility framework for memory analysis."
    echo ""
    echo "Usage:"
    echo "  $0 [options]"
    echo ""
    echo "Options:"
    echo "  --help          Show this help message"
    echo "  --no-samples    Skip creation of sample data"
    echo ""
    echo "After installation:"
    echo "  1. Test installation: ~/volatility_analysis/test_installation.sh"
    echo "  2. Detect profile: ~/volatility_analysis/detect_profile.sh <memory_image>"
    echo "  3. Quick triage: ~/volatility_analysis/triage.sh <memory_image>"
    echo "  4. Full analysis: ~/volatility_analysis/process_analysis.sh <memory_image> <profile>"
    echo ""
    echo "Analysis files are located in ~/volatility_analysis/"
    echo "Reports are saved in ~/volatility_analysis/reports/"
    echo "Memory dumps are saved in ~/volatility_analysis/dumps/"
}

# Main function
main() {
    local skip_samples=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help)
                show_usage
                exit 0
                ;;
            --no-samples)
                skip_samples=true
                shift
                ;;
            *)
                error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    echo "Volatility Setup Script for Parrot OS"
    echo "===================================="

    install_volatility
    create_analysis_scripts

    if [[ "$skip_samples" != true ]]; then
        create_sample_data
    fi

    verify_installation

    success "Volatility setup completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Test installation: ~/volatility_analysis/test_installation.sh"
    echo "2. Read documentation: cat ~/volatility_analysis/README.md"
    echo "3. Run triage on memory image: ~/volatility_analysis/triage.sh <image>"
    echo "4. For Windows analysis, common profiles: Win7SP1x64, Win10x64_19041"
    echo "5. For Linux analysis, use profile: Linux"
}

# Run main function
main "$@"