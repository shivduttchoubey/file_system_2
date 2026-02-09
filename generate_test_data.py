#!/usr/bin/env python3
"""
Test Data Generator for Forensic GUI Analyzer
Creates sample disk images with various forensic scenarios
"""

import os
import struct
import random
from pathlib import Path

class ForensicTestDataGenerator:
    """Generate test disk images with forensic scenarios"""
    
    def __init__(self, output_path, size_mb=10):
        self.output_path = Path(output_path)
        self.size_bytes = size_mb * 1024 * 1024
        self.block_size = 4096
        
    def generate(self):
        """Generate complete test disk image"""
        print(f"[*] Creating test disk image: {self.output_path}")
        print(f"[*] Size: {self.size_bytes / (1024*1024):.1f} MB")
        
        with open(self.output_path, 'wb') as f:
            # Scenario 1: Normal files (JPEG images)
            self._write_jpeg_files(f, count=5)
            
            # Scenario 2: Fragmented file
            self._write_fragmented_file(f)
            
            # Scenario 3: Deleted file (zeros with remnants)
            self._write_deleted_file_remnants(f)
            
            # Scenario 4: Encrypted/compressed data
            self._write_encrypted_data(f)
            
            # Scenario 5: Text files
            self._write_text_files(f, count=3)
            
            # Fill remaining with zeros
            current_pos = f.tell()
            remaining = self.size_bytes - current_pos
            if remaining > 0:
                f.write(b'\x00' * remaining)
        
        print(f"[+] Test disk image created successfully!")
        print(f"[+] Location: {self.output_path.absolute()}")
        print(f"\n[*] Use this file with:")
        print(f"    python forensic_gui_analyzer.py")
        print(f"    Then: Load USB Device → Select: {self.output_path}")
    
    def _write_jpeg_files(self, f, count=5):
        """Write sample JPEG files"""
        print(f"[*] Writing {count} JPEG files...")
        
        for i in range(count):
            # JPEG header
            jpeg_header = b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
            
            # Random image data
            size = random.randint(8192, 32768)
            image_data = os.urandom(size - len(jpeg_header) - 2)
            
            # JPEG footer
            jpeg_footer = b'\xFF\xD9'
            
            # Write complete JPEG
            f.write(jpeg_header)
            f.write(image_data)
            f.write(jpeg_footer)
            
            # Pad to block boundary
            current_pos = f.tell()
            padding = (self.block_size - (current_pos % self.block_size)) % self.block_size
            if padding > 0:
                f.write(b'\x00' * padding)
    
    def _write_fragmented_file(self, f):
        """Write a fragmented file (parts separated)"""
        print("[*] Writing fragmented file...")
        
        # Part 1: PNG header and beginning
        png_header = b'\x89PNG\r\n\x1a\n'
        part1_data = os.urandom(self.block_size - len(png_header))
        
        f.write(png_header)
        f.write(part1_data)
        
        # Gap (zeros simulating other data)
        gap_blocks = 10
        f.write(b'\x00' * (gap_blocks * self.block_size))
        
        # Part 2: Middle of PNG
        part2_data = os.urandom(self.block_size)
        f.write(part2_data)
        
        # Another gap
        f.write(b'\x00' * (gap_blocks * self.block_size))
        
        # Part 3: End of PNG
        png_footer = b'IEND\xaeB`\x82'
        part3_data = os.urandom(self.block_size - len(png_footer))
        f.write(part3_data)
        f.write(png_footer)
        
        # Pad to block boundary
        current_pos = f.tell()
        padding = (self.block_size - (current_pos % self.block_size)) % self.block_size
        if padding > 0:
            f.write(b'\x00' * padding)
    
    def _write_deleted_file_remnants(self, f):
        """Write remnants of deleted file"""
        print("[*] Writing deleted file remnants...")
        
        # First part: File header (partially overwritten)
        pdf_header = b'%PDF-1.4\n'
        partial_data = os.urandom(2048)
        
        # Write header and partial data
        f.write(pdf_header)
        f.write(partial_data)
        
        # Zeros (file "deleted")
        f.write(b'\x00' * self.block_size)
        
        # Remnant: tail of file still present
        remnant_data = b'%%EOF\n'
        f.write(os.urandom(4096 - len(remnant_data)))
        f.write(remnant_data)
        
        # Pad to block boundary
        current_pos = f.tell()
        padding = (self.block_size - (current_pos % self.block_size)) % self.block_size
        if padding > 0:
            f.write(b'\x00' * padding)
    
    def _write_encrypted_data(self, f):
        """Write encrypted/random data (high entropy)"""
        print("[*] Writing encrypted data...")
        
        # Simulated encrypted container
        # Header
        header = b'ENCRYPTED\x00\x00\x00\x00\x00\x00\x00'
        
        # High-entropy data (simulated encryption)
        encrypted_size = 16384
        encrypted_data = os.urandom(encrypted_size)
        
        f.write(header)
        f.write(encrypted_data)
        
        # Pad to block boundary
        current_pos = f.tell()
        padding = (self.block_size - (current_pos % self.block_size)) % self.block_size
        if padding > 0:
            f.write(b'\x00' * padding)
    
    def _write_text_files(self, f, count=3):
        """Write sample text files"""
        print(f"[*] Writing {count} text files...")
        
        sample_texts = [
            b"This is a sample text file for forensic analysis.\n" * 100,
            b"Important document content here.\nConfidential information.\n" * 80,
            b"Log file entry: 2026-02-09 14:30:00 - System started\n" * 60
        ]
        
        for i in range(min(count, len(sample_texts))):
            text_data = sample_texts[i]
            
            # Write text
            f.write(text_data)
            
            # Pad to block boundary
            current_pos = f.tell()
            padding = (self.block_size - (current_pos % self.block_size)) % self.block_size
            if padding > 0:
                f.write(b'\x00' * padding)


def main():
    """Generate test data"""
    print("=" * 60)
    print("  Forensic Test Data Generator")
    print("=" * 60)
    print("")
    
    # Generate test disk image
    generator = ForensicTestDataGenerator('test_disk.img', size_mb=10)
    generator.generate()
    
    print("\n" + "=" * 60)
    print("  Test Scenarios Included")
    print("=" * 60)
    print("")
    print("1. JPEG Files (5 files)")
    print("   - Complete files with proper headers/footers")
    print("   - Should appear as green blocks in treemap")
    print("")
    print("2. Fragmented PNG File")
    print("   - Header, middle, and footer separated by gaps")
    print("   - Correlation engine should identify relationship")
    print("   - Test reconstruction feature")
    print("")
    print("3. Deleted PDF Remnants")
    print("   - Partial header and footer remain")
    print("   - Middle overwritten with zeros")
    print("   - Demonstrates file carving capability")
    print("")
    print("4. Encrypted Data")
    print("   - High entropy content")
    print("   - Should appear as red blocks")
    print("   - Entropy: ~8.0")
    print("")
    print("5. Text Files (3 files)")
    print("   - Low entropy readable text")
    print("   - Should appear as blue blocks")
    print("   - Entropy: ~4.0-5.0")
    print("")
    print("=" * 60)
    print("  Testing Instructions")
    print("=" * 60)
    print("")
    print("1. Launch GUI:")
    print("   ./launch_forensic_gui.sh")
    print("")
    print("2. Load test disk:")
    print("   Click: Load USB Device")
    print("   Select: test_disk.img")
    print("")
    print("3. Analyze:")
    print("   Click: Analyze Blocks")
    print("   Wait for completion")
    print("")
    print("4. Run correlation:")
    print("   Click: Run Correlation")
    print("   Check Correlation Results tab")
    print("")
    print("5. View timeline:")
    print("   Click: Build Timeline")
    print("   Examine Timeline tab")
    print("")
    print("6. Test reconstruction:")
    print("   Select fragmented PNG blocks")
    print("   Click: Reconstruct File")
    print("")


if __name__ == '__main__':
    main()
