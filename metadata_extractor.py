#!/usr/bin/env python3
"""
Enhanced Metadata Extractor for Forensic Analysis
Extracts real MACB timestamps from filesystem structures (NTFS, ext4, FAT32, etc.)
"""

import struct
import os
from datetime import datetime, timedelta
from collections import namedtuple

# Metadata structures
MACBTimestamps = namedtuple('MACBTimestamps', [
    'mtime',  # Modified
    'ctime',  # Changed/Created
    'atime',  # Accessed
    'btime'   # Birth/Created
])

InodeMetadata = namedtuple('InodeMetadata', [
    'inode_number',
    'file_size',
    'timestamps',
    'uid',
    'gid',
    'mode',
    'links_count'
])


class NTFSMetadataExtractor:
    """Extract metadata from NTFS filesystem"""
    
    # NTFS epoch: January 1, 1601
    NTFS_EPOCH = datetime(1601, 1, 1)
    
    @staticmethod
    def parse_mft_entry(mft_data):
        """Parse MFT entry to extract timestamps"""
        if len(mft_data) < 1024:
            return None
        
        try:
            # MFT entry signature
            signature = mft_data[0:4]
            if signature != b'FILE':
                return None
            
            # Standard Information attribute ($STANDARD_INFORMATION = 0x10)
            # Located at offset 0x38 typically
            offset = 0x38
            
            # Find $STANDARD_INFORMATION attribute
            while offset < len(mft_data) - 64:
                attr_type = struct.unpack('<I', mft_data[offset:offset+4])[0]
                
                if attr_type == 0x10:  # $STANDARD_INFORMATION
                    # Skip to attribute content
                    content_offset = offset + 24
                    
                    # Extract MACB timestamps (8 bytes each, FILETIME format)
                    created_raw = struct.unpack('<Q', mft_data[content_offset:content_offset+8])[0]
                    modified_raw = struct.unpack('<Q', mft_data[content_offset+8:content_offset+16])[0]
                    mft_changed_raw = struct.unpack('<Q', mft_data[content_offset+16:content_offset+24])[0]
                    accessed_raw = struct.unpack('<Q', mft_data[content_offset+24:content_offset+32])[0]
                    
                    # Convert FILETIME to datetime
                    created = NTFSMetadataExtractor._filetime_to_datetime(created_raw)
                    modified = NTFSMetadataExtractor._filetime_to_datetime(modified_raw)
                    mft_changed = NTFSMetadataExtractor._filetime_to_datetime(mft_changed_raw)
                    accessed = NTFSMetadataExtractor._filetime_to_datetime(accessed_raw)
                    
                    return MACBTimestamps(
                        mtime=modified,
                        ctime=mft_changed,
                        atime=accessed,
                        btime=created
                    )
                
                # Move to next attribute
                attr_length = struct.unpack('<I', mft_data[offset+4:offset+8])[0]
                if attr_length == 0:
                    break
                offset += attr_length
            
        except Exception as e:
            print(f"[!] Error parsing NTFS MFT entry: {e}")
        
        return None
    
    @staticmethod
    def _filetime_to_datetime(filetime):
        """Convert Windows FILETIME to Python datetime"""
        if filetime == 0:
            return None
        
        try:
            # FILETIME is in 100-nanosecond intervals since 1601-01-01
            microseconds = filetime / 10
            return NTFSMetadataExtractor.NTFS_EPOCH + timedelta(microseconds=microseconds)
        except:
            return None


class Ext4MetadataExtractor:
    """Extract metadata from ext4 filesystem"""
    
    # ext4 epoch: January 1, 1970
    UNIX_EPOCH = datetime(1970, 1, 1)
    
    @staticmethod
    def parse_inode(inode_data):
        """Parse ext4 inode structure"""
        if len(inode_data) < 256:  # ext4 inode is at least 256 bytes
            return None
        
        try:
            # ext4 inode structure (simplified)
            # Offset 0x00: i_mode (2 bytes)
            # Offset 0x02: i_uid (2 bytes)
            # Offset 0x04: i_size_lo (4 bytes)
            # Offset 0x08: i_atime (4 bytes)
            # Offset 0x0C: i_ctime (4 bytes)
            # Offset 0x10: i_mtime (4 bytes)
            # Offset 0x14: i_dtime (4 bytes) - deletion time
            # Offset 0x16: i_gid (2 bytes)
            # Offset 0x1A: i_links_count (2 bytes)
            
            i_mode = struct.unpack('<H', inode_data[0x00:0x02])[0]
            i_uid = struct.unpack('<H', inode_data[0x02:0x04])[0]
            i_size = struct.unpack('<I', inode_data[0x04:0x08])[0]
            i_atime = struct.unpack('<I', inode_data[0x08:0x0C])[0]
            i_ctime = struct.unpack('<I', inode_data[0x0C:0x10])[0]
            i_mtime = struct.unpack('<I', inode_data[0x10:0x14])[0]
            i_dtime = struct.unpack('<I', inode_data[0x14:0x18])[0]
            i_gid = struct.unpack('<H', inode_data[0x16:0x18])[0]
            i_links_count = struct.unpack('<H', inode_data[0x1A:0x1C])[0]
            
            # ext4 also has nanosecond precision in extended fields
            # Offset 0x90: i_atime_extra (4 bytes - upper bits)
            # Offset 0x94: i_mtime_extra (4 bytes - upper bits)
            # Offset 0x98: i_ctime_extra (4 bytes - upper bits)
            # Offset 0x9C: i_crtime (4 bytes - creation time)
            
            btime = None
            if len(inode_data) >= 0xA0:
                try:
                    i_crtime = struct.unpack('<I', inode_data[0x9C:0xA0])[0]
                    if i_crtime > 0:
                        btime = Ext4MetadataExtractor._unix_to_datetime(i_crtime)
                except:
                    pass
            
            timestamps = MACBTimestamps(
                mtime=Ext4MetadataExtractor._unix_to_datetime(i_mtime),
                ctime=Ext4MetadataExtractor._unix_to_datetime(i_ctime),
                atime=Ext4MetadataExtractor._unix_to_datetime(i_atime),
                btime=btime
            )
            
            metadata = InodeMetadata(
                inode_number=0,  # Would need to track from filesystem
                file_size=i_size,
                timestamps=timestamps,
                uid=i_uid,
                gid=i_gid,
                mode=i_mode,
                links_count=i_links_count
            )
            
            return metadata
            
        except Exception as e:
            print(f"[!] Error parsing ext4 inode: {e}")
        
        return None
    
    @staticmethod
    def _unix_to_datetime(timestamp):
        """Convert Unix timestamp to datetime"""
        if timestamp == 0:
            return None
        
        try:
            return Ext4MetadataExtractor.UNIX_EPOCH + timedelta(seconds=timestamp)
        except:
            return None


class FAT32MetadataExtractor:
    """Extract metadata from FAT32 filesystem"""
    
    # FAT epoch: January 1, 1980
    FAT_EPOCH = datetime(1980, 1, 1)
    
    @staticmethod
    def parse_directory_entry(dir_entry):
        """Parse FAT32 directory entry"""
        if len(dir_entry) < 32:
            return None
        
        try:
            # FAT32 directory entry structure
            # Offset 0x00: Filename (8 bytes)
            # Offset 0x08: Extension (3 bytes)
            # Offset 0x0B: Attributes (1 byte)
            # Offset 0x0E: Created time (2 bytes)
            # Offset 0x10: Created date (2 bytes)
            # Offset 0x12: Last access date (2 bytes)
            # Offset 0x16: Last modified time (2 bytes)
            # Offset 0x18: Last modified date (2 bytes)
            # Offset 0x1C: File size (4 bytes)
            
            created_time = struct.unpack('<H', dir_entry[0x0E:0x10])[0]
            created_date = struct.unpack('<H', dir_entry[0x10:0x12])[0]
            accessed_date = struct.unpack('<H', dir_entry[0x12:0x14])[0]
            modified_time = struct.unpack('<H', dir_entry[0x16:0x18])[0]
            modified_date = struct.unpack('<H', dir_entry[0x18:0x1A])[0]
            file_size = struct.unpack('<I', dir_entry[0x1C:0x20])[0]
            
            # Convert FAT date/time to datetime
            created = FAT32MetadataExtractor._fat_datetime(created_date, created_time)
            modified = FAT32MetadataExtractor._fat_datetime(modified_date, modified_time)
            accessed = FAT32MetadataExtractor._fat_datetime(accessed_date, 0)
            
            return MACBTimestamps(
                mtime=modified,
                ctime=created,  # FAT doesn't have separate ctime
                atime=accessed,
                btime=created   # Birth time = creation time
            )
            
        except Exception as e:
            print(f"[!] Error parsing FAT32 entry: {e}")
        
        return None
    
    @staticmethod
    def _fat_datetime(date_val, time_val):
        """Convert FAT date/time format to datetime"""
        if date_val == 0:
            return None
        
        try:
            # Extract date components
            year = ((date_val >> 9) & 0x7F) + 1980
            month = (date_val >> 5) & 0x0F
            day = date_val & 0x1F
            
            # Extract time components
            hour = (time_val >> 11) & 0x1F
            minute = (time_val >> 5) & 0x3F
            second = (time_val & 0x1F) * 2
            
            return datetime(year, month, day, hour, minute, second)
        except:
            return None


class GenericMetadataExtractor:
    """Generic metadata extractor - attempts to identify filesystem and extract"""
    
    def __init__(self, reader):
        self.reader = reader
        self.filesystem_type = None
        self.detected_fs = False
        
    def detect_filesystem(self):
        """Detect filesystem type from boot sector"""
        try:
            # Read first sector (boot sector)
            boot_sector = self.reader.read(0, 512)
            
            # Check for NTFS
            if b'NTFS' in boot_sector[0:512]:
                self.filesystem_type = 'NTFS'
                print("[+] Detected NTFS filesystem")
                return 'NTFS'
            
            # Check for ext2/3/4
            # ext superblock is at offset 1024
            superblock = self.reader.read(1024, 1024)
            ext_magic = struct.unpack('<H', superblock[56:58])[0]
            if ext_magic == 0xEF53:
                self.filesystem_type = 'ext4'
                print("[+] Detected ext4 filesystem")
                return 'ext4'
            
            # Check for FAT32
            if boot_sector[82:90] == b'FAT32   ' or boot_sector[54:59] == b'FAT32':
                self.filesystem_type = 'FAT32'
                print("[+] Detected FAT32 filesystem")
                return 'FAT32'
            
            # Check for exFAT
            if boot_sector[3:11] == b'EXFAT   ':
                self.filesystem_type = 'exFAT'
                print("[+] Detected exFAT filesystem")
                return 'exFAT'
            
            print("[!] Unknown filesystem type")
            self.filesystem_type = 'Unknown'
            return 'Unknown'
            
        except Exception as e:
            print(f"[!] Error detecting filesystem: {e}")
            return 'Unknown'
    
    def extract_block_metadata(self, block_offset, block_size):
        """Extract metadata for a specific block"""
        if not self.detected_fs:
            self.detect_filesystem()
            self.detected_fs = True
        
        # Read block data
        block_data = self.reader.read(block_offset, block_size)
        
        metadata = {
            'filesystem': self.filesystem_type,
            'timestamps': None,
            'inode_info': None
        }
        
        # Try to extract filesystem-specific metadata
        if self.filesystem_type == 'NTFS':
            # Check if this block contains MFT entry
            if block_data[0:4] == b'FILE':
                timestamps = NTFSMetadataExtractor.parse_mft_entry(block_data)
                metadata['timestamps'] = timestamps
        
        elif self.filesystem_type == 'ext4':
            # Check if this block contains inode
            inode_metadata = Ext4MetadataExtractor.parse_inode(block_data)
            if inode_metadata:
                metadata['timestamps'] = inode_metadata.timestamps
                metadata['inode_info'] = inode_metadata
        
        elif self.filesystem_type == 'FAT32':
            # Check if this block contains directory entries
            # Try every 32 bytes (directory entry size)
            for i in range(0, min(len(block_data), 512), 32):
                entry = block_data[i:i+32]
                if entry[0] != 0 and entry[0] != 0xE5:  # Not empty or deleted
                    timestamps = FAT32MetadataExtractor.parse_directory_entry(entry)
                    if timestamps:
                        metadata['timestamps'] = timestamps
                        break
        
        return metadata
    
    def scan_for_filesystem_structures(self):
        """Scan disk for filesystem metadata structures"""
        structures = {
            'mft_entries': [],      # NTFS
            'inodes': [],           # ext4
            'dir_entries': []       # FAT32
        }
        
        if not self.detected_fs:
            self.detect_filesystem()
            self.detected_fs = True
        
        print(f"[*] Scanning for {self.filesystem_type} structures...")
        
        # Scan strategy depends on filesystem
        if self.filesystem_type == 'NTFS':
            # MFT usually starts at a fixed location
            # Scan first 100MB for MFT entries
            self._scan_for_mft_entries(structures, max_offset=100*1024*1024)
        
        elif self.filesystem_type == 'ext4':
            # Inodes are in inode tables
            # Scan for inode structures
            self._scan_for_inodes(structures, max_offset=50*1024*1024)
        
        elif self.filesystem_type == 'FAT32':
            # Directory entries are throughout the disk
            self._scan_for_directory_entries(structures, max_offset=50*1024*1024)
        
        return structures
    
    def _scan_for_mft_entries(self, structures, max_offset):
        """Scan for NTFS MFT entries"""
        offset = 0
        chunk_size = 1024  # MFT entry size
        
        while offset < max_offset:
            try:
                data = self.reader.read(offset, chunk_size)
                if data[0:4] == b'FILE':
                    timestamps = NTFSMetadataExtractor.parse_mft_entry(data)
                    if timestamps:
                        structures['mft_entries'].append({
                            'offset': offset,
                            'timestamps': timestamps
                        })
                
                offset += chunk_size
                
            except:
                break
        
        print(f"[+] Found {len(structures['mft_entries'])} MFT entries")
    
    def _scan_for_inodes(self, structures, max_offset):
        """Scan for ext4 inodes"""
        offset = 0
        chunk_size = 256  # ext4 inode size
        
        while offset < max_offset:
            try:
                data = self.reader.read(offset, chunk_size)
                metadata = Ext4MetadataExtractor.parse_inode(data)
                if metadata and metadata.file_size > 0:
                    structures['inodes'].append({
                        'offset': offset,
                        'metadata': metadata
                    })
                
                offset += chunk_size
                
            except:
                break
        
        print(f"[+] Found {len(structures['inodes'])} inodes")
    
    def _scan_for_directory_entries(self, structures, max_offset):
        """Scan for FAT32 directory entries"""
        offset = 0
        chunk_size = 512  # Read sectors
        
        while offset < max_offset:
            try:
                data = self.reader.read(offset, chunk_size)
                
                # Check each 32-byte directory entry
                for i in range(0, 512, 32):
                    entry = data[i:i+32]
                    if entry[0] != 0 and entry[0] != 0xE5:
                        timestamps = FAT32MetadataExtractor.parse_directory_entry(entry)
                        if timestamps:
                            structures['dir_entries'].append({
                                'offset': offset + i,
                                'timestamps': timestamps
                            })
                
                offset += chunk_size
                
            except:
                break
        
        print(f"[+] Found {len(structures['dir_entries'])} directory entries")


# Test function
def test_metadata_extraction():
    """Test metadata extraction"""
    print("=" * 60)
    print("  Metadata Extraction Test")
    print("=" * 60)
    
    # Test NTFS timestamp conversion
    print("\n[*] Testing NTFS FILETIME conversion...")
    # Example: 2024-01-01 00:00:00
    test_filetime = 133475328000000000
    dt = NTFSMetadataExtractor._filetime_to_datetime(test_filetime)
    print(f"    FILETIME {test_filetime} → {dt}")
    
    # Test ext4 timestamp conversion
    print("\n[*] Testing ext4 Unix timestamp conversion...")
    # Example: 2024-01-01 00:00:00
    test_unix = 1704067200
    dt = Ext4MetadataExtractor._unix_to_datetime(test_unix)
    print(f"    Unix timestamp {test_unix} → {dt}")
    
    # Test FAT32 date/time conversion
    print("\n[*] Testing FAT32 date/time conversion...")
    # Example: 2024-01-01 12:30:00
    test_date = 0x5C21  # Year 2024, Month 1, Day 1
    test_time = 0x6260  # Hour 12, Minute 30, Second 0
    dt = FAT32MetadataExtractor._fat_datetime(test_date, test_time)
    print(f"    FAT date {test_date:04x}, time {test_time:04x} → {dt}")
    
    print("\n[+] Metadata extraction test complete")


if __name__ == '__main__':
    test_metadata_extraction()
