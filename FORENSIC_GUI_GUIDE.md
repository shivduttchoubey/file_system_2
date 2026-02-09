# Forensic Disk Analyzer - Complete User Guide

## Overview

A professional-grade forensic analysis tool with an elegant Tkinter GUI that provides comprehensive disk analysis capabilities including:

- **WizTree-like Treemap Visualization** - Visual representation of disk blocks
- **E01 Evidence File Support** - Full support for forensic evidence files
- **USB Device Analysis** - Direct reading from attached storage
- **Correlation Engine** - Advanced file defragmentation and reconstruction
- **Timeline Analysis** - Temporal visualization of disk activity
- **Metadata Inspection** - Detailed block-level metadata on hover
- **Read/Write Age Analysis** - Identify when data was written
- **File Carving** - Reconstruct fragmented files

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Features in Detail](#features-in-detail)
4. [User Interface Guide](#user-interface-guide)
5. [Advanced Usage](#advanced-usage)
6. [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

**Required:**
- Python 3.8 or higher
- Tkinter (usually included with Python)

**Optional but Recommended:**
- libewf (for E01 support)
- Root/Administrator privileges (for USB device access)

### Installation Steps

#### Linux (Ubuntu/Debian)

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install python3 python3-tk python3-pip
sudo apt-get install libewf-dev  # For E01 support

# Install Python dependencies
pip install -r requirements_gui.txt

# Make executable
chmod +x forensic_gui_analyzer.py
```

#### macOS

```bash
# Install Homebrew if not installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python-tk libewf

# Install Python packages
pip3 install -r requirements_gui.txt
```

#### Windows

```powershell
# Install Python from python.org (includes Tkinter)
# Download libewf from: https://github.com/libyal/libewf/releases

# Install Python packages
pip install -r requirements_gui.txt
```

---

## Quick Start

### Basic Workflow

```bash
# 1. Launch the application
python3 forensic_gui_analyzer.py

# 2. Load evidence source (E01 or USB device)
#    Click: "📁 Load E01 File" or "💾 Load USB Device"

# 3. Analyze blocks
#    Click: "🔍 Analyze Blocks"

# 4. Run correlation engine
#    Click: "🔗 Run Correlation"

# 5. Build timeline
#    Click: "📊 Build Timeline"

# 6. Export results
#    Click: "💾 Export Report"
```

---

## Features in Detail

### Feature 1: Treemap Visualization (WizTree-like)

**Purpose**: Visual representation of disk space allocation using treemap layout

**How it Works**:
1. Each rectangle represents a disk block (4KB default)
2. Colors indicate block characteristics:
   - **Gray (#404040)**: Empty/zero blocks
   - **Green (#4ec9b0)**: Identified file types (PNG, JPEG, PDF, etc.)
   - **Red (#f48771)**: High entropy (encrypted/compressed data)
   - **Orange (#ce9178)**: Medium entropy
   - **Blue (#007acc)**: Low entropy (text/structured data)

**Interaction**:
- **Hover**: Displays tooltip with block metadata
  - Block ID and offset
  - Size
  - File type (if detected)
  - Entropy value
  - Timestamps (M/C/A/B times)
- **Click**: Shows detailed information in right panel

**Metadata on Hover**:
```
Block ID: 42
Offset: 0x0002a000
Size: 4096 bytes
Type: JPEG
Entropy: 7.85
Modified: 2026-02-09 14:23:45
Created: 2026-02-09 14:23:45
```

---

### Feature 2: Completeness Analysis & Head/Tail Correlation

**Purpose**: Identify fragmented blocks and assess file completeness

**Components**:

#### A. Block Completeness Table

Each block maintains:
- **Head Data**: First 512 bytes (signature/header)
- **Tail Data**: Last 512 bytes (footer/trailer)
- **Completeness Score**: Based on magic bytes and structure integrity

**Table Structure**:
```
Block ID | Offset    | Size | Head Hash | Tail Hash | Complete | Type
---------|-----------|------|-----------|-----------|----------|------
0x0042   | 0x00A8000 | 4096 | a3f2d... | 9c1e8...  | Yes      | JPEG
0x0043   | 0x00A9000 | 4096 | 7b4a3... | incomplete| No       | Unknown
```

#### B. Correlation Engine

**Algorithm**:
```python
For each block B1:
    For each subsequent block B2:
        # Compare tail of B1 with head of B2
        similarity = compare_bytes(B1.tail, B2.head)
        
        # Calculate correlation score
        score = (
            byte_similarity * 0.5 +
            pattern_match * 0.3 +
            entropy_similarity * 0.2
        )
        
        if score > 0.7:  # High correlation threshold
            # These blocks likely sequential
            mark_as_related(B1, B2)
```

**Correlation Scoring**:
- **0.9-1.0**: Very high confidence - blocks are sequential
- **0.7-0.9**: High confidence - likely related
- **0.5-0.7**: Medium confidence - possibly related
- **<0.5**: Low confidence - likely unrelated

#### C. File Reconstruction

**Process**:
1. Identify correlated block sequences
2. Extract head/tail signatures
3. Build reconstruction chain
4. Validate against known file structures
5. Reconstruct complete file

**Example**:
```
Fragmented JPEG detected:
Block 0x0042: Head=FFD8FFE0 (JPEG header), Tail=incomplete
Block 0x0078: Head=matches_0x0042_tail, Tail=incomplete
Block 0x00A3: Head=matches_0x0078_tail, Tail=FFD9 (JPEG EOF)

Reconstruction Chain: 0x0042 → 0x0078 → 0x00A3
Confidence: 94%
Action: Click "🔧 Reconstruct File"
```

---

### Feature 3: Read/Write Age Analysis

**Purpose**: Identify when data was written to disk using metadata

**Visualization**:
- Heat map in bottom panel showing disk age
- Color gradient: Dark (old) → Light (new)

**Analysis Components**:

#### A. Timestamp Extraction
```
For each block:
    - Modified Time (mtime): When content was last changed
    - Created Time (ctime): When inode was created
    - Accessed Time (atime): When last read
    - Birth Time (btime): Original creation (if available)
```

#### B. Age Calculation
```python
current_time = now()
write_age = current_time - mtime
read_age = current_time - atime

if write_age < 1_hour:
    category = "Very Recent"
elif write_age < 1_day:
    category = "Recent"
elif write_age < 1_week:
    category = "This Week"
else:
    category = "Older"
```

#### C. Overwrite Detection
```
Indicators of Recent Overwrites:
- mtime very recent on old inode (ctime >> mtime)
- Spatial clustering of recent writes in old disk area
- Entropy changes (encrypted data → zeros)
```

**Use Cases**:
- Identify recently modified evidence
- Detect anti-forensic wiping attempts
- Timeline reconstruction
- Data recovery prioritization

---

### Feature 4: Timeline Visualization

**Purpose**: Chronological view of disk activity

**Timeline Events**:
- File creation
- File modification
- File deletion
- Block overwrites
- Metadata changes

**Timeline Table**:
```
Timestamp           | Block  | Event Type      | Details
--------------------|--------|-----------------|---------------------------
2026-02-09 14:23:45 | 0x0042 | file_creation   | File type: JPEG
2026-02-09 14:25:12 | 0x0078 | file_modification | Size changed: +2048 bytes
2026-02-09 14:26:33 | 0x00A3 | block_overwrite | Previous: zeros
```

**Filtering Options**:
- By date range
- By event type
- By block range
- By file type

---

## User Interface Guide

### Main Window Layout

```
┌─────────────────────────────────────────────────────────────┐
│ Toolbar: [Load E01] [Load USB] | [Analyze] [Correlate]     │
├──────────────────────┬──────────────────────────────────────┤
│                      │                                      │
│   Treemap            │   Details Panel                      │
│   Visualization      │   ┌──────────────────────────────┐  │
│   (Canvas)           │   │ Tabs:                        │  │
│                      │   │ - Metadata                   │  │
│   [Block Grid]       │   │ - Hex View                   │  │
│                      │   │ - Timestamps                 │  │
│                      │   │ - Correlations               │  │
│                      │   └──────────────────────────────┘  │
├──────────────────────┴──────────────────────────────────────┤
│ Bottom Panel:                                               │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Tabs: [Timeline] [Correlation Results] [Read/Write Age] │ │
│ └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ Progress Bar: [████████████████░░░░░░░░] 75%              │
│ Status: Analyzing blocks... 750/1000                        │
└─────────────────────────────────────────────────────────────┘
```

### Toolbar Buttons

| Button | Function | Shortcut |
|--------|----------|----------|
| 📁 Load E01 File | Open E01 evidence file | Ctrl+O |
| 💾 Load USB Device | Select USB device | Ctrl+U |
| 🔍 Analyze Blocks | Start block analysis | F5 |
| 🔗 Run Correlation | Execute correlation engine | F6 |
| 📊 Build Timeline | Generate timeline | F7 |
| 💾 Export Report | Export results to JSON | Ctrl+S |
| 🔧 Reconstruct File | Reconstruct fragmented file | F8 |

### Right-Click Context Menu

On block:
- Show Details
- Export Block Data
- Mark for Reconstruction
- Add to Timeline Filter

---

## Advanced Usage

### Analyzing E01 Evidence Files

```bash
# 1. Create E01 from physical device (using FTK Imager or dc3dd)
sudo dc3dd if=/dev/sdb of=evidence.e01 hash=md5 hash=sha256

# 2. Load in analyzer
python3 forensic_gui_analyzer.py
# Click: Load E01 File → Select evidence.e01

# 3. Analyze
# The tool will:
# - Read E01 container
# - Extract block metadata
# - Calculate entropy
# - Detect file signatures
# - Build correlation map
```

### Analyzing USB Devices Directly

**Linux**:
```bash
# List devices
lsblk

# Run analyzer with sudo
sudo python3 forensic_gui_analyzer.py

# Select device: /dev/sdb (or /dev/sdb1 for partition)
```

**macOS**:
```bash
# List devices
diskutil list

# Unmount (don't eject)
diskutil unmountDisk /dev/disk2

# Run analyzer with sudo
sudo python3 forensic_gui_analyzer.py

# Select device: /dev/disk2
```

**Windows**:
```powershell
# Run PowerShell as Administrator
# List devices
wmic diskdrive list brief

# Run analyzer
python forensic_gui_analyzer.py

# Select: \\.\PhysicalDrive1
```

### File Carving Workflow

**Scenario**: Recover deleted JPEG images

```
1. Load Evidence
   → Load E01 or USB device

2. Analyze Blocks
   → Click "Analyze Blocks"
   → Wait for completion

3. Filter for JPEG Blocks
   → In treemap, identify green blocks
   → Check metadata for "JPEG" magic

4. Run Correlation
   → Click "Run Correlation"
   → Review Correlation Results tab

5. Identify Sequences
   → Look for blocks with correlation > 0.8
   → Check sequence order (e.g., 0x42 → 0x78 → 0xA3)

6. Reconstruct
   → Select first block in sequence
   → Click "Reconstruct File"
   → Save reconstructed file

7. Validate
   → Open reconstructed JPEG
   → Verify image integrity
```

### Custom Correlation Thresholds

Modify in code:
```python
# In correlate_blocks() method
if score > 0.7:  # Change threshold here
    # Lower = more results (less precise)
    # Higher = fewer results (more precise)
```

**Recommended Thresholds**:
- **0.9**: Very strict - only highly confident matches
- **0.7**: Balanced - good precision/recall
- **0.5**: Permissive - more potential matches (may include false positives)

---

## Troubleshooting

### Issue: E01 Support Not Available

**Error**: `E01 support not available. Install pyewf-python.`

**Solution**:
```bash
# Ubuntu/Debian
sudo apt-get install libewf-dev
pip install pyewf-python

# macOS
brew install libewf
pip install pyewf-python

# If still fails, use pytsk3 as alternative
pip install pytsk3
```

### Issue: Permission Denied on USB Device

**Error**: `Permission denied. Run as administrator/root.`

**Solution**:
```bash
# Linux/macOS
sudo python3 forensic_gui_analyzer.py

# Windows
# Right-click → Run as Administrator
```

### Issue: Tkinter Not Found

**Error**: `ModuleNotFoundError: No module named 'tkinter'`

**Solution**:
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# macOS (should be included)
brew install python-tk

# Windows
# Reinstall Python with Tkinter option checked
```

### Issue: Analysis Takes Too Long

**Problem**: Analyzing large disk (>100GB) takes hours

**Solutions**:

**Option 1: Limit Block Count**
```python
# In analyze_blocks() method
if blocks_analyzed >= 10000:  # Analyze first 10k blocks
    break
```

**Option 2: Increase Block Size**
```python
analyzer = DiskAnalyzer(block_size=65536)  # 64KB blocks instead of 4KB
```

**Option 3: Sample Strategy**
```python
# Analyze every 10th block
for block_id in range(0, total_blocks, 10):
    # Process block
```

### Issue: Out of Memory

**Error**: `MemoryError`

**Solution**:
```python
# Process blocks in batches
BATCH_SIZE = 1000

for batch_start in range(0, total_blocks, BATCH_SIZE):
    # Process batch
    # Clear processed blocks from memory
    # Write to temporary file
```

---

## Performance Optimization

### Recommended Settings by Disk Size

| Disk Size | Block Size | Max Blocks | Expected Time |
|-----------|------------|------------|---------------|
| <1 GB | 4 KB | All | 1-2 min |
| 1-10 GB | 4 KB | 10,000 | 5-10 min |
| 10-100 GB | 16 KB | 10,000 | 10-15 min |
| 100+ GB | 64 KB | 5,000 | 15-20 min |

### Multi-threading

Enable parallel analysis:
```python
# In DiskAnalyzer class
import concurrent.futures

def analyze_blocks_parallel(self):
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        # Process blocks in parallel
        futures = []
        # ... implementation
```

---

## Export Formats

### JSON Report Structure

```json
{
  "timestamp": "2026-02-09T14:30:00",
  "evidence_source": "evidence.e01",
  "total_blocks": 1000,
  "blocks_analyzed": 1000,
  "correlations_found": 42,
  "timeline_events": 128,
  "blocks": [
    {
      "block_id": 42,
      "offset": "0x0002a000",
      "size": 4096,
      "metadata": {
        "is_zero": false,
        "entropy": 7.85,
        "has_magic": "JPEG",
        "printable_ratio": 0.12
      },
      "timestamps": {
        "mtime": "2026-02-09T14:23:45",
        "ctime": "2026-02-09T14:23:45"
      }
    }
  ],
  "correlations": [
    {
      "block1": 42,
      "block2": 78,
      "score": 0.94,
      "sequence": "42 → 78",
      "confidence": 0.94
    }
  ]
}
```

---

## Best Practices

### Chain of Custody

1. **Document Everything**
   - Evidence source
   - Analysis start/end times
   - Tool version
   - Operator name

2. **Use Read-Only Mode**
   - Always work with forensic copies (E01)
   - Never analyze original evidence directly

3. **Hash Verification**
   - Verify E01 hash before/after analysis
   - Document any hash mismatches

### Forensic Soundness

1. **Write Blocking**
   - Use hardware write blocker for USB devices
   - Mount E01 files read-only

2. **Logging**
   - Enable verbose logging
   - Capture all analysis steps

3. **Reproducibility**
   - Document all settings
   - Save configuration files
   - Record tool versions

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+O | Load E01 File |
| Ctrl+U | Load USB Device |
| F5 | Analyze Blocks |
| F6 | Run Correlation |
| F7 | Build Timeline |
| F8 | Reconstruct File |
| Ctrl+S | Export Report |
| Ctrl+F | Find Block |
| Ctrl+Q | Quit |
| F1 | Help |

---

## Future Enhancements

### Planned Features

- [ ] Multi-threaded analysis
- [ ] GPU-accelerated correlation
- [ ] Machine learning file type detection
- [ ] Automatic JPEG/PNG reconstruction
- [ ] NTFS/ext4 filesystem parsing
- [ ] Deleted file recovery
- [ ] Email carving (PST/MBOX)
- [ ] Database reconstruction (SQLite/MySQL)
- [ ] Encrypted container detection
- [ ] Steganography analysis

---

## Support & Resources

### Documentation
- README.md - Quick start guide
- EXPERIMENTAL_GUIDE.md - Testing scenarios
- This file - Complete user guide

### Community
- GitHub Issues - Bug reports and feature requests
- Forensics Forums - Community discussions

### Citation

If using this tool in research:
```
Forensic Disk Analyzer - Professional Edition (2026)
Comprehensive disk forensics with correlation engine
```

---

## License

Educational and research use. Follow proper forensic procedures and legal requirements.

---

**End of User Guide**
