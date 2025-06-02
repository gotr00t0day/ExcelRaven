#!/usr/bin/env python3
"""
Excel Forensics Tool - Extract credentials from corrupted Excel documents
Supports .xlsx, .xls, and other Office formats
"""

import os
import sys
import re
import zipfile
import struct
import binascii
import xml.etree.ElementTree as ET
from pathlib import Path
import argparse
from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)

class ExcelForensics:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_size = os.path.getsize(file_path)
        self.credentials = []
        self.strings = []
        
    def analyze_file(self):
        """Main analysis function"""
        print(f"{Fore.CYAN}[*] Analyzing file: {self.file_path}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] File size: {self.file_size} bytes{Style.RESET_ALL}")
        
        # Try multiple extraction methods
        self.extract_as_zip()
        self.extract_raw_strings()
        self.search_credential_patterns()
        self.analyze_hex_dump()
        self.attempt_repair()
        self.search_vba_macros()
        
        return self.credentials
    
    def extract_as_zip(self):
        """Try to extract Excel file as ZIP archive"""
        print(f"\n{Fore.YELLOW}[1] Attempting ZIP extraction...{Style.RESET_ALL}")
        
        try:
            with zipfile.ZipFile(self.file_path, 'r') as zip_ref:
                print(f"{Fore.GREEN}[+] Successfully opened as ZIP archive{Style.RESET_ALL}")
                
                # List all files in the archive
                file_list = zip_ref.namelist()
                print(f"{Fore.CYAN}[*] Files in archive: {len(file_list)}{Style.RESET_ALL}")
                
                # Extract and analyze key files
                for file_name in file_list:
                    if any(keyword in file_name.lower() for keyword in ['shared', 'workbook', 'sheet', 'app', 'core']):
                        try:
                            content = zip_ref.read(file_name)
                            self.analyze_xml_content(content, file_name)
                        except Exception as e:
                            print(f"{Fore.RED}[-] Error reading {file_name}: {e}{Style.RESET_ALL}")
                            
        except zipfile.BadZipFile:
            print(f"{Fore.YELLOW}[!] File is not a valid ZIP archive, trying alternative methods{Style.RESET_ALL}")
            self.try_zip_repair()
        except Exception as e:
            print(f"{Fore.RED}[-] ZIP extraction failed: {e}{Style.RESET_ALL}")
    
    def try_zip_repair(self):
        """Attempt to repair corrupted ZIP structure"""
        print(f"{Fore.YELLOW}[*] Attempting ZIP repair...{Style.RESET_ALL}")
        
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            # Look for ZIP signatures
            zip_signatures = [b'PK\x03\x04', b'PK\x05\x06', b'PK\x01\x02']
            
            for sig in zip_signatures:
                pos = data.find(sig)
                if pos != -1:
                    print(f"{Fore.GREEN}[+] Found ZIP signature at offset: {pos}{Style.RESET_ALL}")
                    
                    # Try to extract from this position
                    repaired_data = data[pos:]
                    
                    # Save repaired file temporarily
                    temp_file = self.file_path + ".repaired"
                    with open(temp_file, 'wb') as f:
                        f.write(repaired_data)
                    
                    # Try to open repaired file
                    try:
                        with zipfile.ZipFile(temp_file, 'r') as zip_ref:
                            print(f"{Fore.GREEN}[+] Successfully repaired ZIP structure{Style.RESET_ALL}")
                            for file_name in zip_ref.namelist():
                                try:
                                    content = zip_ref.read(file_name)
                                    self.analyze_xml_content(content, file_name)
                                except:
                                    pass
                    except:
                        pass
                    finally:
                        # Clean up temp file
                        if os.path.exists(temp_file):
                            os.remove(temp_file)
                    
        except Exception as e:
            print(f"{Fore.RED}[-] ZIP repair failed: {e}{Style.RESET_ALL}")
    
    def analyze_xml_content(self, content, file_name):
        """Analyze XML content for credentials"""
        try:
            # Try to parse as XML
            root = ET.fromstring(content)
            xml_text = ET.tostring(root, encoding='unicode')
            
            # Search for credential patterns in XML
            self.find_credentials_in_text(xml_text, f"XML:{file_name}")
            
        except ET.ParseError:
            # If not valid XML, treat as raw text
            try:
                text = content.decode('utf-8', errors='ignore')
                self.find_credentials_in_text(text, f"Raw:{file_name}")
            except:
                pass
    
    def extract_raw_strings(self):
        """Extract all printable strings from the file"""
        print(f"\n{Fore.YELLOW}[2] Extracting raw strings...{Style.RESET_ALL}")
        
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            # Extract ASCII strings (min length 4)
            ascii_strings = re.findall(b'[ -~]{4,}', data)
            
            # Extract Unicode strings
            unicode_strings = re.findall(b'(?:[ -~]\x00){4,}', data)
            
            print(f"{Fore.GREEN}[+] Found {len(ascii_strings)} ASCII strings{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Found {len(unicode_strings)} Unicode strings{Style.RESET_ALL}")
            
            # Analyze strings for credentials
            for string in ascii_strings:
                try:
                    text = string.decode('ascii')
                    self.strings.append(text)
                    self.find_credentials_in_text(text, "ASCII_STRING")
                except:
                    pass
            
            for string in unicode_strings:
                try:
                    text = string.decode('utf-16le')
                    self.strings.append(text)
                    self.find_credentials_in_text(text, "UNICODE_STRING")
                except:
                    pass
                    
        except Exception as e:
            print(f"{Fore.RED}[-] String extraction failed: {e}{Style.RESET_ALL}")
    
    def search_credential_patterns(self):
        """Search for common credential patterns"""
        print(f"\n{Fore.YELLOW}[3] Searching for credential patterns...{Style.RESET_ALL}")
        
        # Common credential patterns
        patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'password_field': r'(?i)(password|passwd|pwd|pass)\s*[:=]\s*["\']?([^\s"\']+)',
            'username_field': r'(?i)(username|user|login|account)\s*[:=]\s*["\']?([^\s"\']+)',
            'api_key': r'(?i)(api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*["\']?([A-Za-z0-9\-_]{20,})',
            'token': r'(?i)(token|bearer)\s*[:=]\s*["\']?([A-Za-z0-9\-_\.]{20,})',
            'connection_string': r'(?i)(server|host|database|db)\s*[:=]\s*["\']?([^\s"\']+)',
            'base64_creds': r'[A-Za-z0-9+/]{20,}={0,2}',
            'hash': r'\b[a-fA-F0-9]{32,128}\b',
        }
        
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            # Convert to text for pattern matching
            text = data.decode('utf-8', errors='ignore')
            
            for pattern_name, pattern in patterns.items():
                matches = re.findall(pattern, text)
                if matches:
                    print(f"{Fore.GREEN}[+] Found {pattern_name} patterns: {len(matches)}{Style.RESET_ALL}")
                    for match in matches[:10]:  # Limit output
                        if isinstance(match, tuple):
                            credential = f"{pattern_name}: {' = '.join(match)}"
                        else:
                            credential = f"{pattern_name}: {match}"
                        
                        self.credentials.append({
                            'type': pattern_name,
                            'value': credential,
                            'source': 'PATTERN_MATCH'
                        })
                        print(f"  {Fore.CYAN}{credential}{Style.RESET_ALL}")
                        
        except Exception as e:
            print(f"{Fore.RED}[-] Pattern search failed: {e}{Style.RESET_ALL}")
    
    def find_credentials_in_text(self, text, source):
        """Find credentials in given text"""
        # Look for common credential indicators
        cred_keywords = ['password', 'passwd', 'pwd', 'pass', 'username', 'user', 'login', 'auth', 'token', 'key', 'secret']
        
        lines = text.split('\n')
        for i, line in enumerate(lines):
            for keyword in cred_keywords:
                if keyword.lower() in line.lower():
                    self.credentials.append({
                        'type': 'KEYWORD_MATCH',
                        'value': line.strip(),
                        'source': source,
                        'line': i + 1
                    })
    
    def analyze_hex_dump(self):
        """Analyze file as hex dump for hidden data"""
        print(f"\n{Fore.YELLOW}[4] Analyzing hex dump...{Style.RESET_ALL}")
        
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            # Look for interesting byte patterns
            # Hidden text often appears after null bytes or specific markers
            
            # Search for data after null byte sequences
            null_pattern = b'\x00' * 4
            pos = 0
            while True:
                pos = data.find(null_pattern, pos)
                if pos == -1:
                    break
                
                # Look for printable text after null bytes
                start_pos = pos + len(null_pattern)
                if start_pos < len(data):
                    chunk = data[start_pos:start_pos + 100]
                    if b'\x00' in chunk:
                        chunk = chunk[:chunk.find(b'\x00')]
                    
                    if len(chunk) > 4 and all(32 <= b <= 126 for b in chunk):
                        try:
                            text = chunk.decode('ascii')
                            if any(keyword in text.lower() for keyword in ['pass', 'user', 'login', 'auth']):
                                print(f"{Fore.GREEN}[+] Found hidden text after null bytes: {text}{Style.RESET_ALL}")
                                self.credentials.append({
                                    'type': 'HIDDEN_TEXT',
                                    'value': text,
                                    'source': f'HEX_OFFSET_{pos}',
                                    'offset': pos
                                })
                        except:
                            pass
                
                pos += 1
                if pos > len(data) - 100:  # Don't search too close to end
                    break
                    
        except Exception as e:
            print(f"{Fore.RED}[-] Hex analysis failed: {e}{Style.RESET_ALL}")
    
    def attempt_repair(self):
        """Attempt to repair file structure"""
        print(f"\n{Fore.YELLOW}[5] Attempting file repair...{Style.RESET_ALL}")
        
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            # Common Office file signatures
            signatures = {
                'xlsx': b'PK\x03\x04',
                'xls': b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1',
                'docx': b'PK\x03\x04',
                'doc': b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
            }
            
            for file_type, sig in signatures.items():
                pos = data.find(sig)
                if pos > 0:  # Found signature not at beginning
                    print(f"{Fore.GREEN}[+] Found {file_type} signature at offset {pos}{Style.RESET_ALL}")
                    
                    # Extract data from signature position
                    repaired_data = data[pos:]
                    
                    # Save repaired file
                    repaired_file = f"{self.file_path}.repaired.{file_type}"
                    with open(repaired_file, 'wb') as f:
                        f.write(repaired_data)
                    
                    print(f"{Fore.GREEN}[+] Saved repaired file: {repaired_file}{Style.RESET_ALL}")
                    
                    # Try to analyze repaired file
                    if file_type in ['xlsx', 'docx']:
                        try:
                            repaired_forensics = ExcelForensics(repaired_file)
                            repaired_forensics.extract_as_zip()
                            self.credentials.extend(repaired_forensics.credentials)
                        except:
                            pass
                    
        except Exception as e:
            print(f"{Fore.RED}[-] File repair failed: {e}{Style.RESET_ALL}")
    
    def search_vba_macros(self):
        """Search for VBA macro code that might contain credentials"""
        print(f"\n{Fore.YELLOW}[6] Searching for VBA macros...{Style.RESET_ALL}")
        
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            # Look for VBA project signatures
            vba_signatures = [
                b'Microsoft Visual Basic',
                b'VBA',
                b'ThisWorkbook',
                b'Module',
                b'Sub ',
                b'Function ',
                b'Attribute VB_'
            ]
            
            for sig in vba_signatures:
                if sig in data:
                    print(f"{Fore.GREEN}[+] Found VBA signature: {sig.decode('ascii', errors='ignore')}{Style.RESET_ALL}")
                    
                    # Extract surrounding text
                    pos = data.find(sig)
                    start = max(0, pos - 200)
                    end = min(len(data), pos + 200)
                    chunk = data[start:end]
                    
                    try:
                        text = chunk.decode('utf-8', errors='ignore')
                        self.find_credentials_in_text(text, 'VBA_MACRO')
                    except:
                        pass
                        
        except Exception as e:
            print(f"{Fore.RED}[-] VBA search failed: {e}{Style.RESET_ALL}")
    
    def save_results(self, output_file=None):
        """Save extracted credentials to file"""
        if not self.credentials:
            print(f"{Fore.YELLOW}[!] No credentials found{Style.RESET_ALL}")
            return
        
        if not output_file:
            output_file = f"{self.file_path}_credentials.txt"
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"Excel Forensics Report - {self.file_path}\n")
                f.write("=" * 50 + "\n\n")
                
                f.write(f"File Size: {self.file_size} bytes\n")
                f.write(f"Total Credentials Found: {len(self.credentials)}\n\n")
                
                for i, cred in enumerate(self.credentials, 1):
                    f.write(f"[{i}] Type: {cred['type']}\n")
                    f.write(f"    Source: {cred['source']}\n")
                    f.write(f"    Value: {cred['value']}\n")
                    if 'offset' in cred:
                        f.write(f"    Offset: {cred['offset']}\n")
                    if 'line' in cred:
                        f.write(f"    Line: {cred['line']}\n")
                    f.write("\n")
                
                # Also save extracted strings
                f.write("\n" + "=" * 50 + "\n")
                f.write("EXTRACTED STRINGS\n")
                f.write("=" * 50 + "\n\n")
                
                for i, string in enumerate(self.strings[:100], 1):  # Limit to first 100
                    f.write(f"[{i}] {string}\n")
            
            print(f"{Fore.GREEN}[+] Results saved to: {output_file}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to save results: {e}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description="Excel Forensics Tool - Extract credentials from corrupted Excel files")
    parser.add_argument("file", help="Path to the Excel file to analyze")
    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        print(f"{Fore.RED}[-] File not found: {args.file}{Style.RESET_ALL}")
        sys.exit(1)
    
    print(f"{Fore.GREEN}Excel Forensics Tool v1.0{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'=' * 40}{Style.RESET_ALL}")
    
    # Create forensics analyzer
    forensics = ExcelForensics(args.file)
    
    # Analyze the file
    credentials = forensics.analyze_file()
    
    # Display results
    print(f"\n{Fore.GREEN}{'=' * 40}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}ANALYSIS COMPLETE{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'=' * 40}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Total credentials found: {len(credentials)}{Style.RESET_ALL}")
    
    if credentials:
        print(f"\n{Fore.YELLOW}CREDENTIALS SUMMARY:{Style.RESET_ALL}")
        for i, cred in enumerate(credentials, 1):
            print(f"{Fore.CYAN}[{i}] {cred['type']}: {cred['value'][:100]}{'...' if len(cred['value']) > 100 else ''}{Style.RESET_ALL}")
    
    # Save results
    forensics.save_results(args.output)
    
    if credentials:
        print(f"\n{Fore.GREEN}[+] Credentials successfully extracted from corrupted Excel file!{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.YELLOW}[!] No credentials found. File may require manual analysis.{Style.RESET_ALL}")

if __name__ == "__main__":
    main() 