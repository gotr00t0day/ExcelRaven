#!/usr/bin/env python3
"""
Hex Analyzer - Manual byte-level analysis tool for corrupted Excel files
Provides additional techniques for extracting hidden data
"""

import os
import sys
import re
import binascii
import argparse
from colorama import Fore, Style, init

init(autoreset=True)

class HexAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        with open(file_path, 'rb') as f:
            self.data = f.read()
        self.file_size = len(self.data)
    
    def create_hex_dump(self, output_file=None, bytes_per_line=16):
        """Create a formatted hex dump of the file"""
        if not output_file:
            output_file = f"{self.file_path}.hex"
        
        print(f"{Fore.CYAN}[*] Creating hex dump: {output_file}{Style.RESET_ALL}")
        
        with open(output_file, 'w') as f:
            for i in range(0, len(self.data), bytes_per_line):
                chunk = self.data[i:i + bytes_per_line]
                
                # Hex representation
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                hex_part = hex_part.ljust(bytes_per_line * 3 - 1)
                
                # ASCII representation
                ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                
                # Write line
                f.write(f"{i:08x}  {hex_part}  |{ascii_part}|\n")
        
        print(f"{Fore.GREEN}[+] Hex dump saved to: {output_file}{Style.RESET_ALL}")
    
    def find_file_signatures(self):
        """Search for embedded file signatures"""
        print(f"\n{Fore.YELLOW}[*] Searching for file signatures...{Style.RESET_ALL}")
        
        signatures = {
            'ZIP/Office': b'PK\x03\x04',
            'OLE/Office': b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1',
            'PDF': b'%PDF',
            'JPEG': b'\xff\xd8\xff',
            'PNG': b'\x89PNG\r\n\x1a\n',
            'GIF': b'GIF8',
            'RAR': b'Rar!\x1a\x07\x00',
            'MP3': b'ID3',
            'EXE': b'MZ',
            'XML': b'<?xml',
        }
        
        found_signatures = []
        for name, sig in signatures.items():
            pos = 0
            while True:
                pos = self.data.find(sig, pos)
                if pos == -1:
                    break
                found_signatures.append((name, pos, sig))
                print(f"{Fore.GREEN}[+] Found {name} signature at offset: 0x{pos:08x} ({pos}){Style.RESET_ALL}")
                pos += 1
        
        return found_signatures
    
    def extract_embedded_files(self):
        """Extract embedded files based on signatures"""
        print(f"\n{Fore.YELLOW}[*] Extracting embedded files...{Style.RESET_ALL}")
        
        signatures = self.find_file_signatures()
        
        for i, (name, pos, sig) in enumerate(signatures):
            if name in ['ZIP/Office', 'OLE/Office', 'PDF']:
                # Try to extract the embedded file
                try:
                    # Find reasonable end point (next signature or end of file)
                    end_pos = len(self.data)
                    for next_name, next_pos, next_sig in signatures:
                        if next_pos > pos and next_pos < end_pos:
                            end_pos = next_pos
                    
                    # Extract embedded file
                    embedded_data = self.data[pos:end_pos]
                    
                    # Determine file extension
                    ext_map = {
                        'ZIP/Office': 'zip',
                        'OLE/Office': 'ole',
                        'PDF': 'pdf'
                    }
                    ext = ext_map.get(name, 'bin')
                    
                    output_file = f"{self.file_path}_embedded_{i}.{ext}"
                    with open(output_file, 'wb') as f:
                        f.write(embedded_data)
                    
                    print(f"{Fore.GREEN}[+] Extracted {name} file: {output_file} ({len(embedded_data)} bytes){Style.RESET_ALL}")
                    
                except Exception as e:
                    print(f"{Fore.RED}[-] Failed to extract {name} at {pos}: {e}{Style.RESET_ALL}")
    
    def search_for_credentials_in_hex(self):
        """Search for credential patterns in hex data"""
        print(f"\n{Fore.YELLOW}[*] Searching for credentials in hex data...{Style.RESET_ALL}")
        
        # Convert data to hex string for pattern matching
        hex_string = binascii.hexlify(self.data).decode('ascii')
        
        # Common credential patterns in hex
        patterns = {
            'username': r'757365726e616d65',  # "username" in hex
            'password': r'70617373776f7264',  # "password" in hex
            'admin': r'61646d696e',          # "admin" in hex
            'secret': r'736563726574',       # "secret" in hex
            'token': r'746f6b656e',          # "token" in hex
            'api_key': r'6170695f6b6579',    # "api_key" in hex
        }
        
        found_patterns = []
        for name, pattern in patterns.items():
            matches = []
            pos = 0
            while True:
                match = re.search(pattern, hex_string[pos:], re.IGNORECASE)
                if not match:
                    break
                
                match_pos = (pos + match.start()) // 2  # Convert hex position to byte position
                matches.append(match_pos)
                pos += match.end()
            
            if matches:
                print(f"{Fore.GREEN}[+] Found '{name}' pattern at positions: {matches}{Style.RESET_ALL}")
                found_patterns.extend([(name, pos) for pos in matches])
        
        return found_patterns
    
    def extract_strings_around_positions(self, positions, context_size=50):
        """Extract readable strings around specific byte positions"""
        print(f"\n{Fore.YELLOW}[*] Extracting context around found patterns...{Style.RESET_ALL}")
        
        for name, pos in positions:
            start = max(0, pos - context_size)
            end = min(len(self.data), pos + context_size)
            context = self.data[start:end]
            
            # Try to decode as ASCII
            try:
                ascii_text = context.decode('ascii', errors='ignore')
                if ascii_text.strip():
                    print(f"{Fore.CYAN}[{name}] ASCII context at {pos}: {ascii_text.strip()}{Style.RESET_ALL}")
            except:
                pass
            
            # Try to decode as UTF-16
            try:
                utf16_text = context.decode('utf-16le', errors='ignore')
                if utf16_text.strip():
                    print(f"{Fore.CYAN}[{name}] UTF-16 context at {pos}: {utf16_text.strip()}{Style.RESET_ALL}")
            except:
                pass
    
    def search_base64_patterns(self):
        """Search for base64 encoded strings that might contain credentials"""
        print(f"\n{Fore.YELLOW}[*] Searching for base64 patterns...{Style.RESET_ALL}")
        
        # Extract printable strings
        ascii_strings = re.findall(b'[ -~]{20,}', self.data)
        
        base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        
        for string in ascii_strings:
            try:
                text = string.decode('ascii')
                matches = base64_pattern.findall(text)
                
                for match in matches:
                    try:
                        # Try to decode base64
                        import base64
                        decoded = base64.b64decode(match + '==')  # Add padding if needed
                        decoded_text = decoded.decode('utf-8', errors='ignore')
                        
                        # Check if decoded text looks like credentials
                        if any(keyword in decoded_text.lower() for keyword in ['password', 'user', 'admin', 'secret', 'token']):
                            print(f"{Fore.GREEN}[+] Suspicious base64: {match}{Style.RESET_ALL}")
                            print(f"    Decoded: {decoded_text.strip()}")
                            
                    except:
                        pass
            except:
                pass
    
    def analyze_entropy(self, block_size=256):
        """Analyze entropy to find encrypted or compressed sections"""
        print(f"\n{Fore.YELLOW}[*] Analyzing entropy (block size: {block_size})...{Style.RESET_ALL}")
        
        import math
        from collections import Counter
        
        high_entropy_blocks = []
        
        for i in range(0, len(self.data), block_size):
            block = self.data[i:i + block_size]
            if len(block) < block_size:
                continue
            
            # Calculate entropy
            byte_counts = Counter(block)
            entropy = 0
            for count in byte_counts.values():
                prob = count / len(block)
                entropy -= prob * math.log2(prob)
            
            # High entropy might indicate encryption or compression
            if entropy > 7.5:  # Threshold for high entropy
                high_entropy_blocks.append((i, entropy))
                print(f"{Fore.YELLOW}[!] High entropy block at offset 0x{i:08x}: {entropy:.2f}{Style.RESET_ALL}")
        
        return high_entropy_blocks
    
    def search_unicode_strings(self):
        """Search for Unicode strings that might contain credentials"""
        print(f"\n{Fore.YELLOW}[*] Searching for Unicode strings...{Style.RESET_ALL}")
        
        # Look for UTF-16 encoded strings
        unicode_pattern = re.compile(b'(?:[a-zA-Z0-9@._-]\x00){4,}')
        matches = unicode_pattern.findall(self.data)
        
        credential_keywords = ['password', 'username', 'admin', 'secret', 'token', 'key', 'login']
        
        for match in matches:
            try:
                text = match.decode('utf-16le').strip('\x00')
                if any(keyword in text.lower() for keyword in credential_keywords):
                    print(f"{Fore.GREEN}[+] Credential-like Unicode string: {text}{Style.RESET_ALL}")
            except:
                pass

def main():
    parser = argparse.ArgumentParser(description="Hex Analyzer - Manual byte-level analysis for corrupted Excel files")
    parser.add_argument("file", help="Path to the file to analyze")
    parser.add_argument("--hex-dump", action="store_true", help="Create hex dump")
    parser.add_argument("--signatures", action="store_true", help="Search for file signatures")
    parser.add_argument("--extract", action="store_true", help="Extract embedded files")
    parser.add_argument("--strings", action="store_true", help="Search for credential strings")
    parser.add_argument("--base64", action="store_true", help="Search for base64 patterns")
    parser.add_argument("--entropy", action="store_true", help="Analyze entropy")
    parser.add_argument("--unicode", action="store_true", help="Search Unicode strings")
    parser.add_argument("--all", action="store_true", help="Run all analysis methods")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        print(f"{Fore.RED}[-] File not found: {args.file}{Style.RESET_ALL}")
        sys.exit(1)
    
    print(f"{Fore.GREEN}Hex Analyzer v1.0{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'=' * 40}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Analyzing: {args.file}{Style.RESET_ALL}")
    
    analyzer = HexAnalyzer(args.file)
    print(f"{Fore.CYAN}[*] File size: {analyzer.file_size} bytes{Style.RESET_ALL}")
    
    if args.all or args.hex_dump:
        analyzer.create_hex_dump()
    
    if args.all or args.signatures:
        signatures = analyzer.find_file_signatures()
    
    if args.all or args.extract:
        analyzer.extract_embedded_files()
    
    if args.all or args.strings:
        patterns = analyzer.search_for_credentials_in_hex()
        if patterns:
            analyzer.extract_strings_around_positions(patterns)
    
    if args.all or args.base64:
        analyzer.search_base64_patterns()
    
    if args.all or args.entropy:
        analyzer.analyze_entropy()
    
    if args.all or args.unicode:
        analyzer.search_unicode_strings()
    
    print(f"\n{Fore.GREEN}[+] Analysis complete!{Style.RESET_ALL}")

if __name__ == "__main__":
    main() 