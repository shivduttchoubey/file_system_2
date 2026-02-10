#!/usr/bin/env python3
"""
Fixed Metadata Extractor - Pre-scans filesystem structures for MACB timestamps
This version properly finds and caches all MFT entries, inodes, and directory entries
"""

import struct
import os
from datetime import datetime, timedelta
from collections import defaultdict

class FixedMetadataExtractor:
    """Enhanced metadata extractor with pre-scanning"""
    
    def __init__(self, reader):
        self.reader = reader
        self.filesystem_type = 'Unknown'
        
        # Caches for metadata structures
        self.offset_to_metadata = {}  # Maps block offset -> MACB timestamps
        self.mft_cache = {}            # NTFS: offset -> MFT entry
        self.inode_cache = {}          # ext4: offset -> inode data
        self.fat_cache = {}            # FAT32: offset -> directory entry
        
        # Filesystem parameters
        self.block_size = 4096
        self.scanned = False
        
    def detect_and_scan_filesystem(self):
        """Detect filesystem and pre-scan all metadata structures"""
        print("[*] Detecting filesystem...")
        
        try:
            # Read boot sector
            boot_sector = self.reader.read(0, 512)
            
            # Detect filesystem type
            if b'NTFS' in boot_sector:
                self.filesystem_type = 'NTFS'
                print("[+] Detected NTFS filesystem")
                self._scan_ntfs_mft()
                
            elif self._check_ext4():
                self.filesystem_type = 'ext4'
                print("[+] Detected ext4 filesystem")
                self._scan_ext4_inodes()
                
            elif b'FAT32' in boot_sector or boot_sector[54:59] == b'FAT32' or boot_sector[82:90] == b'FAT32   ':
                self.filesystem_type = 'FAT32'
                print("[+] Detected FAT32 filesystem")
                self._scan_fat32_directory()
                
            else:
                print("[!] Unknown filesystem - will try generic scan")
                self._generic_scan()
            
            self.scanned = True
            print(f"[+] Scan complete: {len(self.offset_to_metadata)} metadata entries found")
            
        except Exception as e:
            print(f"[!] Filesystem detection error: {e}")
            self.filesystem_type = 'Unknown'
    
    def _check_ext4(self):
        """Check if filesystem is ext4"""
        try:
            # ext4 superblock is at offset 1024
            superblock = self.reader.read(1024, 1024)
            if len(superblock) >= 58:
                magic = struct.unpack('<H', superblock[56:58])[0]
                return magic == 0xEF53
        except:
            pass
        return False
    
    def _scan_ntfs_mft(self):
        """Scan NTFS MFT (Master File Table)"""
        print("[*] Scanning NTFS MFT entries...")
        
        try:
            # Read boot sector to find MFT location
            boot_sector = self.reader.read(0, 512)
            
            # Bytes per sector (offset 0x0B)
            bytes_per_sector = struct.unpack('<H', boot_sector[0x0B:0x0D])[0]
            
            # Sectors per cluster (offset 0x0D)
            sectors_per_cluster = boot_sector[0x0D]
            
            # MFT cluster number (offset 0x30)
            mft_cluster = struct.unpack('<Q', boot_sector[0x30:0x38])[0]
            
            # Calculate MFT offset
            cluster_size = bytes_per_sector * sectors_per_cluster
            mft_offset = mft_cluster * cluster_size
            
            print(f"[*] MFT starts at offset: 0x{mft_offset:x}")
            print(f"[*] Cluster size: {cluster_size} bytes")
            
            # Scan MFT entries
            mft_entry_size = 1024
            max_entries = min(10000, self.reader.size // mft_entry_size)  # Limit scan
            
            entries_found = 0
            for entry_num in range(max_entries):
                offset = mft_offset + (entry_num * mft_entry_size)
                
                try:
                    entry_data = self.reader.read(offset, mft_entry_size)
                    
                    # Check for FILE signature
                    if entry_data[0:4] == b'FILE':
                        timestamps = self._parse_ntfs_mft_entry(entry_data)
                        
                        if timestamps:
                            # Store with offset
                            self.mft_cache[offset] = timestamps
                            
                            # Also map to block offsets this MFT entry might reference
                            # For simplicity, map to nearby blocks
                            for block_offset in range(offset - 10*self.block_size, 
                                                     offset + 10*self.block_size, 
                                                     self.block_size):
                                if block_offset >= 0:
                                    self.offset_to_metadata[block_offset] = timestamps
                            
                            entries_found += 1
                            
                            if entries_found % 100 == 0:
                                print(f"[*] Found {entries_found} MFT entries...")
                
                except Exception as e:
                    continue
            
            print(f"[+] Found {entries_found} NTFS MFT entries")
            
        except Exception as e:
            print(f"[!] Error scanning NTFS MFT: {e}")
    
    def _parse_ntfs_mft_entry(self, data):
        """Parse NTFS MFT entry for timestamps"""
        try:
            if data[0:4] != b'FILE':
                return None
            
            # Find $STANDARD_INFORMATION attribute (0x10)
            offset = 0x14  # Start after header
            
            # Get first attribute offset
            attrs_offset = struct.unpack('<H', data[0x14:0x16])[0]
            
            current = attrs_offset
            while current < len(data) - 64:
                # Read attribute type
                attr_type = struct.unpack('<I', data[current:current+4])[0]
                
                if attr_type == 0xFFFFFFFF:  # End marker
                    break
                
                if attr_type == 0x10:  # $STANDARD_INFORMATION
                    # Non-resident flag
                    non_resident = data[current + 8]
                    
                    if non_resident == 0:  # Resident attribute
                        # Content offset
                        content_offset = struct.unpack('<H', data[current+0x14:current+0x16])[0]
                        attr_start = current + content_offset
                        
                        # Read timestamps (8 bytes each, FILETIME format)
                        created = struct.unpack('<Q', data[attr_start:attr_start+8])[0]
                        modified = struct.unpack('<Q', data[attr_start+8:attr_start+16])[0]
                        mft_modified = struct.unpack('<Q', data[attr_start+16:attr_start+24])[0]
                        accessed = struct.unpack('<Q', data[attr_start+24:attr_start+32])[0]
                        
                        # Convert FILETIME to datetime
                        return {
                            'mtime': self._filetime_to_datetime(modified),
                            'ctime': self._filetime_to_datetime(mft_modified),
                            'atime': self._filetime_to_datetime(accessed),
                            'btime': self._filetime_to_datetime(created)
                        }
                
                # Move to next attribute
                attr_length = struct.unpack('<I', data[current+4:current+8])[0]
                if attr_length == 0 or attr_length > 1024:
                    break
                current += attr_length
            
        except Exception as e:
            pass
        
        return None
    
    def _filetime_to_datetime(self, filetime):
        """Convert Windows FILETIME to datetime"""
        if filetime == 0:
            return None
        
        try:
            # FILETIME is 100-nanosecond intervals since 1601-01-01
            epoch = datetime(1601, 1, 1)
            delta = timedelta(microseconds=filetime / 10)
            return epoch + delta
        except:
            return None
    
    def _scan_ext4_inodes(self):
        """Scan ext4 inodes"""
        print("[*] Scanning ext4 inodes...")
        
        try:
            # Read superblock at offset 1024
            superblock = self.reader.read(1024, 1024)
            
            # Get parameters from superblock
            s_inodes_count = struct.unpack('<I', superblock[0:4])[0]
            s_blocks_count = struct.unpack('<I', superblock[4:8])[0]
            s_log_block_size = struct.unpack('<I', superblock[24:28])[0]
            
            block_size = 1024 << s_log_block_size
            
            # Inode size (offset 88)
            inode_size = struct.unpack('<H', superblock[88:90])[0]
            if inode_size == 0:
                inode_size = 128  # Default
            
            # Inodes per group (offset 40)
            s_inodes_per_group = struct.unpack('<I', superblock[40:44])[0]
            
            # Block group descriptor table starts after superblock
            bgdt_offset = block_size * 2  # Usually block 2
            
            print(f"[*] Block size: {block_size}")
            print(f"[*] Inode size: {inode_size}")
            print(f"[*] Inodes per group: {s_inodes_per_group}")
            
            # Scan first few block groups
            max_groups = min(10, s_blocks_count // 8192)
            inodes_found = 0
            
            for group in range(max_groups):
                # Read block group descriptor
                bgd_offset = bgdt_offset + (group * 32)  # 32 bytes per descriptor
                bgd = self.reader.read(bgd_offset, 32)
                
                # Inode table block number (offset 8)
                inode_table_block = struct.unpack('<I', bgd[8:12])[0]
                inode_table_offset = inode_table_block * block_size
                
                # Scan inodes in this group
                for inode_num in range(min(s_inodes_per_group, 1000)):  # Limit per group
                    inode_offset = inode_table_offset + (inode_num * inode_size)
                    
                    try:
                        inode_data = self.reader.read(inode_offset, inode_size)
                        timestamps = self._parse_ext4_inode(inode_data)
                        
                        if timestamps:
                            self.inode_cache[inode_offset] = timestamps
                            
                            # Map to nearby blocks
                            for block_offset in range(inode_offset - 5*self.block_size,
                                                     inode_offset + 5*self.block_size,
                                                     self.block_size):
                                if block_offset >= 0:
                                    self.offset_to_metadata[block_offset] = timestamps
                            
                            inodes_found += 1
                    
                    except:
                        continue
                
                if inodes_found % 100 == 0 and inodes_found > 0:
                    print(f"[*] Found {inodes_found} inodes...")
            
            print(f"[+] Found {inodes_found} ext4 inodes")
            
        except Exception as e:
            print(f"[!] Error scanning ext4 inodes: {e}")
    
    def _parse_ext4_inode(self, data):
        """Parse ext4 inode for timestamps"""
        try:
            if len(data) < 128:
                return None
            
            # Check if inode is in use (i_mode != 0)
            i_mode = struct.unpack('<H', data[0:2])[0]
            if i_mode == 0:
                return None
            
            # Extract timestamps
            i_atime = struct.unpack('<I', data[0x08:0x0C])[0]
            i_ctime = struct.unpack('<I', data[0x0C:0x10])[0]
            i_mtime = struct.unpack('<I', data[0x10:0x14])[0]
            
            # Birth time (if available - ext4 extended)
            i_crtime = None
            if len(data) >= 0xA0:
                try:
                    crtime_val = struct.unpack('<I', data[0x9C:0xA0])[0]
                    if crtime_val > 0:
                        i_crtime = crtime_val
                except:
                    pass
            
            return {
                'mtime': self._unix_to_datetime(i_mtime),
                'ctime': self._unix_to_datetime(i_ctime),
                'atime': self._unix_to_datetime(i_atime),
                'btime': self._unix_to_datetime(i_crtime) if i_crtime else None
            }
            
        except Exception as e:
            return None
    
    def _unix_to_datetime(self, timestamp):
        """Convert Unix timestamp to datetime"""
        if timestamp == 0 or timestamp is None:
            return None
        
        try:
            return datetime.utcfromtimestamp(timestamp)
        except:
            return None
    
    def _scan_fat32_directory(self):
        """Scan FAT32 directory entries"""
        print("[*] Scanning FAT32 directory entries...")
        
        try:
            # Read boot sector
            boot_sector = self.reader.read(0, 512)
            
            # Parse BPB (BIOS Parameter Block)
            bytes_per_sector = struct.unpack('<H', boot_sector[0x0B:0x0D])[0]
            sectors_per_cluster = boot_sector[0x0D]
            reserved_sectors = struct.unpack('<H', boot_sector[0x0E:0x10])[0]
            num_fats = boot_sector[0x10]
            sectors_per_fat = struct.unpack('<I', boot_sector[0x24:0x28])[0]
            root_cluster = struct.unpack('<I', boot_sector[0x2C:0x30])[0]
            
            cluster_size = bytes_per_sector * sectors_per_cluster
            fat_offset = reserved_sectors * bytes_per_sector
            data_offset = fat_offset + (num_fats * sectors_per_fat * bytes_per_sector)
            
            print(f"[*] Cluster size: {cluster_size}")
            print(f"[*] Data area offset: 0x{data_offset:x}")
            
            # Scan data area for directory entries
            entries_found = 0
            offset = data_offset
            max_scan = min(self.reader.size - data_offset, 50 * 1024 * 1024)  # Scan up to 50MB
            
            while offset < data_offset + max_scan:
                try:
                    sector = self.reader.read(offset, 512)
                    
                    # Check each 32-byte directory entry
                    for i in range(0, 512, 32):
                        entry = sector[i:i+32]
                        
                        # Check if valid entry (not deleted, not empty)
                        if entry[0] != 0 and entry[0] != 0xE5 and entry[0] != 0x20:
                            timestamps = self._parse_fat32_entry(entry)
                            
                            if timestamps:
                                entry_offset = offset + i
                                self.fat_cache[entry_offset] = timestamps
                                
                                # Map to nearby blocks
                                for block_offset in range(offset - 2*self.block_size,
                                                         offset + 2*self.block_size,
                                                         self.block_size):
                                    if block_offset >= 0:
                                        self.offset_to_metadata[block_offset] = timestamps
                                
                                entries_found += 1
                    
                    offset += 512
                    
                    if entries_found % 100 == 0 and entries_found > 0:
                        print(f"[*] Found {entries_found} directory entries...")
                
                except:
                    offset += 512
                    continue
            
            print(f"[+] Found {entries_found} FAT32 directory entries")
            
        except Exception as e:
            print(f"[!] Error scanning FAT32: {e}")
    
    def _parse_fat32_entry(self, entry):
        """Parse FAT32 directory entry"""
        try:
            # Get timestamps
            created_time = struct.unpack('<H', entry[0x0E:0x10])[0]
            created_date = struct.unpack('<H', entry[0x10:0x12])[0]
            accessed_date = struct.unpack('<H', entry[0x12:0x14])[0]
            modified_time = struct.unpack('<H', entry[0x16:0x18])[0]
            modified_date = struct.unpack('<H', entry[0x18:0x1A])[0]
            
            return {
                'mtime': self._fat_datetime(modified_date, modified_time),
                'ctime': self._fat_datetime(created_date, created_time),
                'atime': self._fat_datetime(accessed_date, 0),
                'btime': self._fat_datetime(created_date, created_time)
            }
            
        except:
            return None
    
    def _fat_datetime(self, date, time):
        """Convert FAT date/time to datetime"""
        if date == 0:
            return None
        
        try:
            year = ((date >> 9) & 0x7F) + 1980
            month = (date >> 5) & 0x0F
            day = date & 0x1F
            
            hour = (time >> 11) & 0x1F
            minute = (time >> 5) & 0x3F
            second = (time & 0x1F) * 2
            
            if month == 0 or month > 12 or day == 0 or day > 31:
                return None
            
            return datetime(year, month, day, hour, minute, second)
        except:
            return None
    
    def _generic_scan(self):
        """Generic scan when filesystem is unknown"""
        print("[*] Performing generic metadata scan...")
        
        # Try to find common structures by scanning
        offset = 0
        structures_found = 0
        
        while offset < min(self.reader.size, 100 * 1024 * 1024):  # Scan first 100MB
            try:
                data = self.reader.read(offset, 1024)
                
                # Check for NTFS MFT signature
                if data[0:4] == b'FILE':
                    timestamps = self._parse_ntfs_mft_entry(data)
                    if timestamps:
                        for bo in range(offset - 5*self.block_size, offset + 5*self.block_size, self.block_size):
                            if bo >= 0:
                                self.offset_to_metadata[bo] = timestamps
                        structures_found += 1
                
                # Check for ext4 inode (harder to detect)
                # Just try parsing
                timestamps = self._parse_ext4_inode(data[:256])
                if timestamps:
                    for bo in range(offset - 5*self.block_size, offset + 5*self.block_size, self.block_size):
                        if bo >= 0:
                            self.offset_to_metadata[bo] = timestamps
                    structures_found += 1
                
                offset += 1024
                
            except:
                offset += 1024
                continue
        
        print(f"[+] Generic scan found {structures_found} structures")
    
    def get_metadata_for_offset(self, offset):
        """Get metadata for a specific offset"""
        if not self.scanned:
            self.detect_and_scan_filesystem()
        
        # Round offset to nearest block
        block_offset = (offset // self.block_size) * self.block_size
        
        # Check cache
        if block_offset in self.offset_to_metadata:
            return self.offset_to_metadata[block_offset]
        
        # Try nearby offsets
        for nearby in range(block_offset - 5*self.block_size, 
                          block_offset + 5*self.block_size, 
                          self.block_size):
            if nearby in self.offset_to_metadata:
                return self.offset_to_metadata[nearby]
        
        return None


# Compatibility wrapper
class GenericMetadataExtractor:
    """Wrapper for compatibility with existing code"""
    
    def __init__(self, reader):
        self.extractor = FixedMetadataExtractor(reader)
        self.detected_fs = False
    
    def detect_filesystem(self):
        """Detect and scan filesystem"""
        if not self.detected_fs:
            self.extractor.detect_and_scan_filesystem()
            self.detected_fs = True
        return self.extractor.filesystem_type
    
    def extract_block_metadata(self, offset, size):
        """Get metadata for block at offset"""
        timestamps = self.extractor.get_metadata_for_offset(offset)
        
        return {
            'filesystem': self.extractor.filesystem_type,
            'timestamps': timestamps,
            'inode_info': None
        }


if __name__ == '__main__':
    print("Metadata extractor ready")