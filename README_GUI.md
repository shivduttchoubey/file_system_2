# Forensic Disk Analyzer - Professional GUI Edition

A comprehensive forensic analysis tool with an elegant Tkinter GUI for analyzing disk images, E01 evidence files, and USB devices. Features advanced correlation engine for file reconstruction and defragmentation.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-Educational-orange)


# 1. Install dependencies
pip install -r requirements_gui.txt

# 2. Generate test data
python3 generate_test_data.py

# 3. Launch GUI
./launch_forensic_gui.sh

# 4. In GUI:
#    - Click "Load USB Device" → Select "test_disk.img"
#    - Click "Analyze Blocks"
#    - Click "Run Correlation"
#    - Explore the treemap visualization

## ✨ Features

### 🎨 Visual Analysis
- **WizTree-like Treemap Visualization** - Interactive block-level disk visualization
- **Color-coded Blocks** - Instant identification of file types and data characteristics
- **Hover Metadata Display** - Real-time block information on mouse hover
- **Interactive Canvas** - Click blocks for detailed analysis

### 🔍 Forensic Capabilities
- **E01 Evidence File Support** - Native support for forensic disk images
- **USB Device Analysis** - Direct reading from attached storage devices
- **File Type Detection** - Automatic identification via magic bytes
- **Entropy Analysis** - Detect encrypted/compressed data
- **Timestamp Extraction** - M/C/A/B time analysis

### 🔗 Correlation Engine
- **Advanced Block Correlation** - Identify related blocks for reconstruction
- **Head/Tail Analysis** - Compare block boundaries for sequence detection
- **Defragmentation** - Reconstruct fragmented files
- **Confidence Scoring** - Probabilistic matching with confidence levels
- **File Carving** - Recover deleted or fragmented files

### 📊 Analysis Tools
- **Timeline Visualization** - Chronological view of disk activity
- **Read/Write Age Analysis** - Identify when data was written
- **Metadata Inspection** - Comprehensive block-level metadata
- **Hex Viewer** - Raw data inspection
- **Correlation Results** - Detailed relationship mapping

## 🚀 Quick Start

### One-Command Setup

```bash
# Clone or download files
# Then run:
./launch_forensic_gui.sh
```

### Manual Installation

```bash
# Install dependencies
pip install -r requirements_gui.txt

# Generate test data
python3 generate_test_data.py

# Launch application
python3 forensic_gui_analyzer.py
```

### First Analysis

1. **Launch**: `./launch_forensic_gui.sh`
2. **Load**: Click "📁 Load E01 File" or "💾 Load USB Device"
3. **Analyze**: Click "🔍 Analyze Blocks"
4. **Correlate**: Click "🔗 Run Correlation"
5. **Timeline**: Click "📊 Build Timeline"
6. **Export**: Click "💾 Export Report"

## 📋 Requirements

### System Requirements
- Python 3.8 or higher
- 4 GB RAM minimum (8 GB recommended)
- 100 MB disk space for application
- Additional space for evidence files

### Python Packages
```
tkinter (included with Python)
pytsk3 (optional - for E01 support)
numpy (optional - for enhanced analysis)
```

### Operating Systems
- ✅ Linux (Ubuntu, Debian, Fedora, Arch)
- ✅ macOS (10.14+)
- ✅ Windows (10/11)

## 🎯 Use Cases

### Digital Forensics
- Evidence analysis from E01 images
- Deleted file recovery
- Timeline reconstruction
- Anti-forensics detection

### Data Recovery
- Reconstruct fragmented files
- Recover from corrupted disks
- File carving from unallocated space
- Metadata-based recovery

### Security Analysis
- Detect encrypted containers
- Identify steganography
- Find hidden data
- Overwrite detection

### Research & Education
- Filesystem forensics teaching
- Disk structure analysis
- File format research
- Correlation algorithm testing

## 📖 Documentation

### Complete Guides
- **[FORENSIC_GUI_GUIDE.md](FORENSIC_GUI_GUIDE.md)** - Comprehensive user guide
- **[EXPERIMENTAL_GUIDE.md](EXPERIMENTAL_GUIDE.md)** - Testing scenarios
- **README.md** (this file) - Quick reference

### Key Sections
1. [Installation](#installation) - Setup instructions
2. [Features](#features) - Capability overview
3. [Usage](#usage) - How to use
4. [Advanced](#advanced-usage) - Expert features
5. [Troubleshooting](#troubleshooting) - Common issues

## 🔧 Installation

### Ubuntu/Debian

```bash
# System dependencies
sudo apt-get update
sudo apt-get install python3 python3-tk python3-pip
sudo apt-get install libewf-dev  # For E01 support

# Python packages
pip3 install -r requirements_gui.txt

# Make executable
chmod +x forensic_gui_analyzer.py launch_forensic_gui.sh

# Launch
./launch_forensic_gui.sh
```

### macOS

```bash
# Install Homebrew (if needed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# System dependencies
brew install python-tk libewf

# Python packages
pip3 install -r requirements_gui.txt

# Launch
./launch_forensic_gui.sh
```

### Windows

```powershell
# Download Python from python.org (includes Tkinter)

# Install Python packages
pip install -r requirements_gui.txt

# Launch
python forensic_gui_analyzer.py
```

## 💡 Usage

### Analyzing E01 Files

```bash
# Create E01 from physical device
sudo dc3dd if=/dev/sdb of=evidence.e01

# Launch GUI
python3 forensic_gui_analyzer.py

# In GUI:
# 1. Click: Load E01 File
# 2. Select: evidence.e01
# 3. Click: Analyze Blocks
# 4. Click: Run Correlation
```

### Analyzing USB Devices

**Linux**:
```bash
# List devices
lsblk

# Launch with sudo
sudo ./launch_forensic_gui.sh

# In GUI:
# Select: /dev/sdb (or /dev/sdb1)
```

**macOS**:
```bash
# List devices
diskutil list

# Unmount (don't eject)
diskutil unmountDisk /dev/disk2

# Launch with sudo
sudo ./launch_forensic_gui.sh

# In GUI:
# Select: /dev/disk2
```

### File Reconstruction Workflow

```
1. Load evidence source
2. Analyze blocks (F5)
3. Run correlation (F6)
4. Review correlation results
5. Select correlated blocks
6. Click: Reconstruct File (F8)
7. Save reconstructed file
8. Validate recovered file
```

## 🎨 User Interface

### Main Components

```
┌─────────────────────────────────────────────┐
│ Toolbar: File | Analyze | Export            │
├──────────────────┬──────────────────────────┤
│ Treemap          │ Details Panel            │
│ Visualization    │ • Metadata               │
│                  │ • Hex View               │
│ [Color-coded     │ • Timestamps             │
│  block grid]     │ • Correlations           │
├──────────────────┴──────────────────────────┤
│ Timeline | Correlation Results | R/W Age    │
├─────────────────────────────────────────────┤
│ Progress: ████████░░░░ 75%                  │
│ Status: Analyzing blocks...                 │
└─────────────────────────────────────────────┘
```

### Color Scheme

| Color | Meaning | Example |
|-------|---------|---------|
| 🟦 Blue (#007acc) | Low entropy data | Text files, structured data |
| 🟩 Green (#4ec9b0) | Identified file types | JPEG, PNG, PDF detected |
| 🟧 Orange (#ce9178) | Medium entropy | Compressed files |
| 🟥 Red (#f48771) | High entropy | Encrypted/random data |
| ⬜ Gray (#404040) | Empty blocks | Zeros, unallocated space |

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+O` | Load E01 File |
| `Ctrl+U` | Load USB Device |
| `F5` | Analyze Blocks |
| `F6` | Run Correlation |
| `F7` | Build Timeline |
| `F8` | Reconstruct File |
| `Ctrl+S` | Export Report |
| `Ctrl+Q` | Quit |

## 🔬 Advanced Usage

### Custom Block Size

```python
# Modify in code or add CLI argument
analyzer = DiskAnalyzer(block_size=8192)  # 8KB blocks
```

### Correlation Threshold

```python
# In correlate_blocks() method
if score > 0.7:  # Adjust threshold
    # 0.9 = very strict
    # 0.7 = balanced (default)
    # 0.5 = permissive
```

### Performance Tuning

```python
# Limit blocks for large disks
if blocks_analyzed >= 10000:
    break

# Increase block size
analyzer = DiskAnalyzer(block_size=65536)  # 64KB

# Sample every Nth block
for block_id in range(0, total_blocks, 10):
    # Process block
```

## 🐛 Troubleshooting

### E01 Support Not Available

**Problem**: `E01 support not available`

**Solution**:
```bash
# Install pyewf
pip install pyewf-python

# Or use pytsk3
pip install pytsk3
```

### Permission Denied

**Problem**: `Permission denied` on USB device

**Solution**:
```bash
# Linux/macOS
sudo python3 forensic_gui_analyzer.py

# Windows: Run as Administrator
```

### Tkinter Not Found

**Problem**: `No module named 'tkinter'`

**Solution**:
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# macOS
brew install python-tk
```

### Slow Analysis

**Problem**: Analysis takes too long

**Solutions**:
- Limit block count (modify code)
- Increase block size
- Use sampling strategy
- Analyze specific regions only

## 📊 Test Data

### Generate Test Disk Image

```bash
# Create 10MB test disk with various scenarios
python3 generate_test_data.py

# Output: test_disk.img

# Test scenarios included:
# - JPEG files (complete)
# - Fragmented PNG file
# - Deleted PDF remnants
# - Encrypted data
# - Text files
```

### Using Test Data

```bash
# 1. Generate test data
python3 generate_test_data.py

# 2. Launch GUI
./launch_forensic_gui.sh

# 3. Load test disk
# Click: Load USB Device
# Select: test_disk.img

# 4. Analyze and test features
```

## 🔐 Forensic Best Practices

### Chain of Custody
1. Document evidence source
2. Record analysis timestamps
3. Note tool version and settings
4. Save all generated reports
5. Maintain audit trail

### Evidence Handling
1. Always work with forensic copies
2. Use write blockers for physical devices
3. Verify hashes before/after analysis
4. Never analyze original evidence
5. Document all findings

### Reporting
1. Export detailed JSON reports
2. Include screenshots of key findings
3. Document correlation results
4. Note any anomalies detected
5. Provide reconstruction confidence scores

## 🚧 Limitations

### Current Limitations
- **Block Analysis**: Limited to first 1000 blocks for POC
- **Filesystem Parsing**: Generic block-level only (no FS-specific parsing)
- **E01 Support**: Requires external libraries (pyewf/pytsk3)
- **Memory Usage**: Large disks may require memory optimization
- **Real-time**: Not designed for live disk monitoring

### Future Enhancements
- [ ] Full filesystem parsing (NTFS, ext4, APFS)
- [ ] Multi-threaded analysis
- [ ] GPU-accelerated correlation
- [ ] Machine learning file type detection
- [ ] Automated file reconstruction
- [ ] Steganography detection
- [ ] Network evidence correlation

## 📝 License

Educational and research use. Always follow proper forensic procedures and legal requirements when conducting investigations.

## 🤝 Contributing

### Reporting Issues
- Use GitHub Issues for bug reports
- Include system information
- Provide steps to reproduce
- Attach relevant logs/screenshots

### Feature Requests
- Describe use case
- Explain expected behavior
- Provide examples if possible

## 📚 References

### Forensic Concepts
- **Treemap Visualization**: Space-efficient hierarchical display
- **Correlation Engine**: Pattern matching for file reconstruction
- **Entropy Analysis**: Measuring data randomness
- **File Carving**: Recovering files without metadata
- **Timeline Analysis**: Temporal event reconstruction

### Related Tools
- **FTK Imager**: Evidence acquisition
- **Autopsy**: Forensic analysis platform
- **Sleuth Kit**: Forensic toolkit
- **WizTree**: Disk space analyzer (inspiration)

### Standards
- **E01 Format**: Expert Witness Format for evidence
- **ISO 27037**: Digital evidence handling
- **NIST SP 800-86**: Computer forensics guide

## 🎓 Educational Use

Perfect for:
- Digital forensics courses
- Cybersecurity training
- Research projects
- Forensic tool development
- File system analysis

### Learning Objectives
1. Understanding block-level disk structure
2. File fragmentation and recovery
3. Correlation algorithms
4. Forensic analysis workflows
5. Evidence handling procedures

## 📞 Support

### Documentation
- **FORENSIC_GUI_GUIDE.md** - Complete guide
- **EXPERIMENTAL_GUIDE.md** - Testing guide
- **README.md** - This file

### Community
- GitHub Issues
- Forensics forums
- Security conferences

## 🏆 Credits

Developed for educational and forensic research purposes.

Special thanks to:
- Sleuth Kit project
- Digital forensics community
- Open source forensic tools

---

**Version**: 1.0.0  
**Last Updated**: February 2026  
**Status**: Production Ready (POC)

---

## Quick Command Reference

```bash
# Setup
./launch_forensic_gui.sh

# Generate test data
python3 generate_test_data.py

# Run analyzer
python3 forensic_gui_analyzer.py

# With device access
sudo python3 forensic_gui_analyzer.py

# Check dependencies
python3 -c "import tkinter; import pytsk3"
```

---

**Ready to analyze? Launch the GUI and start investigating! 🔍**
