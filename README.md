# Excel Forensics Tool

A comprehensive Python tool for extracting credentials and sensitive data from corrupted Excel documents by analyzing and modifying their byte structure.

## Features

- **Multi-format Support**: Works with `.xlsx`, `.xls`, `.docx`, and other Office formats
- **ZIP Archive Analysis**: Extracts and analyzes embedded XML files in modern Office documents
- **Raw Byte Analysis**: Searches for hidden text patterns in file bytes
- **String Extraction**: Extracts ASCII and Unicode strings from binary data
- **Pattern Matching**: Uses regex to find common credential patterns
- **File Repair**: Attempts to repair corrupted file structures
- **VBA Macro Detection**: Searches for embedded VBA code that might contain credentials
- **Hex Dump Analysis**: Analyzes raw hex data for hidden information
- **Advanced Hex Forensics**: Deep binary analysis with entropy detection and embedded file extraction

## Installation

1. Install required dependencies:
```bash
pip install -r requirements.txt
```

2. Make the script executable:
```bash
chmod +x excel_forensics.py hex_analyzer.py
```

### Optional Enhanced Dependencies

For advanced forensics capabilities, you can install additional tools:
```bash
# Enhanced file type detection
pip install python-magic

# Advanced OLE file analysis
pip install olefile oletools

# Binary analysis and extraction
pip install binwalk

# Pattern matching engine
pip install yara-python
```

## Usage

### Basic Usage
```bash
python excel_forensics.py corrupted_file.xlsx
```

### With Output File
```bash
python excel_forensics.py corrupted_file.xlsx -o extracted_credentials.txt
```

### Verbose Mode
```bash
python excel_forensics.py corrupted_file.xlsx -v
```

### Advanced Hex Analysis
```bash
# Run all advanced analysis methods
python hex_analyzer.py corrupted_file.xlsx --all

# Specific analysis types
python hex_analyzer.py file.xlsx --signatures --extract --entropy
python hex_analyzer.py file.xlsx --hex-dump --base64 --unicode
```

## Analysis Methods

The tool uses multiple techniques to extract credentials:

### 1. ZIP Archive Extraction
Modern Excel files (.xlsx) are ZIP archives containing XML files. The tool:
- Attempts to open the file as a ZIP archive
- Extracts and analyzes XML content
- Searches for credential patterns in XML data

### 2. File Structure Repair
If the ZIP structure is corrupted:
- Searches for ZIP signatures (`PK` headers) within the file
- Attempts to reconstruct the archive from found signatures
- Creates temporary repaired files for analysis

### 3. Raw String Extraction
Extracts printable strings from the binary data:
- ASCII strings (minimum 4 characters)
- Unicode strings (UTF-16 encoding)
- Searches extracted strings for credential indicators

### 4. Pattern Recognition
Uses regex patterns to find:
- Email addresses
- Password fields (`password=`, `pwd:`, etc.)
- Username fields (`user=`, `login:`, etc.)
- API keys and tokens
- Connection strings
- Base64 encoded credentials
- Hash values

### 5. Hex Dump Analysis
Analyzes raw bytes to find:
- Hidden text after null byte sequences
- Embedded credentials in binary data
- Metadata that might contain sensitive information

### 6. VBA Macro Detection
Searches for VBA project signatures and extracts:
- Macro code that might contain hardcoded credentials
- VBA project metadata
- Embedded script content

## Advanced Hex Analysis

The `hex_analyzer.py` tool provides sophisticated byte-level forensics capabilities:

### File Signature Detection
```bash
python hex_analyzer.py file.xlsx --signatures
```
- Detects embedded file signatures (ZIP, PDF, JPEG, PNG, etc.)
- Identifies multiple file formats within a single document
- Maps file structure and embedded content locations

### Embedded File Extraction
```bash
python hex_analyzer.py file.xlsx --extract
```
- Automatically extracts embedded files based on signatures
- Supports ZIP/Office, OLE, PDF, and other formats
- Creates separate files for each embedded component

### Entropy Analysis
```bash
python hex_analyzer.py file.xlsx --entropy
```
- Calculates entropy for data blocks to identify:
  - Encrypted sections (high entropy)
  - Compressed data
  - Random or obfuscated content
- Helps locate hidden or protected areas

### Hex Pattern Matching
```bash
python hex_analyzer.py file.xlsx --strings
```
- Converts text to hex patterns for precise matching
- Searches for credential keywords in hex format:
  - `username` → `757365726e616d65`
  - `password` → `70617373776f7264`
  - `admin` → `61646d696e`
- Provides context around found patterns

### Base64 Detection & Decoding
```bash
python hex_analyzer.py file.xlsx --base64
```
- Identifies base64 encoded strings
- Automatically decodes suspicious patterns
- Filters for credential-related decoded content
- Handles various encoding formats and padding

### Unicode String Analysis
```bash
python hex_analyzer.py file.xlsx --unicode
```
- Detects UTF-16 encoded strings
- Searches for credential keywords in Unicode format
- Handles null-byte separated Unicode text
- Extracts hidden Unicode metadata

### Formatted Hex Dumps
```bash
python hex_analyzer.py file.xlsx --hex-dump
```
- Creates formatted hex dumps with ASCII representation
- 16 bytes per line with offset addresses
- Side-by-side hex and ASCII view
- Saves to `.hex` files for manual analysis

### Advanced Analysis Example
```bash
# Complete forensics analysis
python hex_analyzer.py suspicious.xlsx --all

# Output:
# [*] Creating hex dump: suspicious.xlsx.hex
# [+] Found ZIP/Office signature at offset: 0x00000000 (0)
# [+] Found XML signature at offset: 0x00000156 (342)
# [+] Extracted ZIP/Office file: suspicious.xlsx_embedded_0.zip (15234 bytes)
# [+] Found 'password' pattern at positions: [1250, 2847]
# [+] Suspicious base64: YWRtaW46cGFzc3dvcmQxMjM=
#     Decoded: admin:password123
# [!] High entropy block at offset 0x00003000: 7.89
# [+] Credential-like Unicode string: database_password
```

## Example Output

```
Excel Forensics Tool v1.0
========================================
[*] Analyzing file: corrupted_spreadsheet.xlsx
[*] File size: 15432 bytes

[1] Attempting ZIP extraction...
[+] Successfully opened as ZIP archive
[*] Files in archive: 12

[2] Extracting raw strings...
[+] Found 145 ASCII strings
[+] Found 23 Unicode strings

[3] Searching for credential patterns...
[+] Found email patterns: 2
  email: admin@company.com
  email: user@domain.org
[+] Found password_field patterns: 1
  password_field: password = SecretPass123

[4] Analyzing hex dump...
[+] Found hidden text after null bytes: admin:password123

[5] Attempting file repair...
[+] Found xlsx signature at offset 0

[6] Searching for VBA macros...
[+] Found VBA signature: ThisWorkbook

========================================
ANALYSIS COMPLETE
========================================
Total credentials found: 4

CREDENTIALS SUMMARY:
[1] email: admin@company.com
[2] email: user@domain.org
[3] password_field: password = SecretPass123
[4] HIDDEN_TEXT: admin:password123

[+] Results saved to: corrupted_spreadsheet.xlsx_credentials.txt
[+] Credentials successfully extracted from corrupted Excel file!
```

## Advanced Usage

### Manual Hex Analysis
For deeply corrupted files, you might need to manually examine the hex dump:

```bash
# Create a hex dump for manual analysis
hexdump -C corrupted_file.xlsx > file.hex

# Or use xxd for a cleaner output
xxd corrupted_file.xlsx > file.hex

# Or use the built-in hex analyzer
python hex_analyzer.py corrupted_file.xlsx --hex-dump
```

### Binary Analysis with Custom Patterns
The tool can be extended to search for custom patterns by modifying the `patterns` dictionary in the `search_credential_patterns()` method.

### Working with Different Encodings
The tool automatically handles:
- ASCII encoding
- UTF-8 encoding
- UTF-16 Little Endian (common in Office files)
- Raw binary data

### Combining Tools for Maximum Coverage
```bash
# Step 1: Basic forensics analysis
python excel_forensics.py file.xlsx -o basic_results.txt

# Step 2: Advanced hex analysis
python hex_analyzer.py file.xlsx --all

# Step 3: Manual review of hex dump
python hex_analyzer.py file.xlsx --hex-dump
# Then review the .hex file manually
```

## Common Credential Locations in Excel Files

1. **XML Metadata**: Connection strings in `xl/connections.xml`
2. **VBA Projects**: Hardcoded credentials in macro code
3. **Custom Properties**: Hidden metadata in `docProps/custom.xml`
4. **Embedded Objects**: Credentials in embedded files
5. **Cell Comments**: Hidden text in cell comment metadata
6. **External Links**: Database connection strings in external links
7. **Binary Streams**: Credentials in OLE compound document streams
8. **Encrypted Sections**: Password-protected areas with weak encryption

## Tips for Success

1. **Try Multiple File Extensions**: Sometimes changing the extension helps
2. **Check for Embedded Files**: Look for other Office documents embedded within
3. **Examine Temporary Files**: Check for `.tmp` files created during repair
4. **Use Multiple Tools**: Combine with other forensics tools like `binwalk`, `strings`, or `oletools`
5. **Manual Review**: Always manually review extracted strings for false positives
6. **Entropy Analysis**: Use entropy to identify encrypted or compressed sections
7. **Base64 Decoding**: Check all base64 strings for hidden credentials
8. **Unicode Analysis**: Don't forget UTF-16 encoded strings

## Security Notes

- Only use this tool on files you own or have explicit permission to analyze
- Be aware that extracted credentials might be encoded or obfuscated
- Some credentials might be split across multiple locations in the file
- Always verify extracted credentials before use

## Troubleshooting

### File Not Recognized
If the tool doesn't recognize the file format:
- Try renaming the file with different extensions (.xlsx, .xls, .zip)
- Use `file` command to check the actual file type
- Examine the file header with a hex editor
- Use the signature detection feature to identify embedded formats

### No Credentials Found
If no credentials are extracted:
- The file might be heavily encrypted or obfuscated
- Credentials might be stored in non-standard locations
- Try manual hex analysis or other forensics tools
- Check for steganography or hidden data techniques
- Use entropy analysis to find encrypted sections
- Look for base64 or other encoded strings

### Large Files
For very large files:
- The tool might take considerable time to analyze
- Consider splitting the analysis into smaller chunks
- Use the verbose mode to monitor progress
- Run specific analysis methods instead of --all

### High Entropy Sections
If entropy analysis shows encrypted sections:
- These might contain protected credentials
- Try common passwords or dictionary attacks
- Look for encryption keys elsewhere in the file
- Check for weak encryption implementations

## Contributing

Feel free to contribute improvements:
- Add support for additional file formats
- Improve pattern recognition
- Add new analysis techniques
- Enhance performance for large files

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always ensure you have proper authorization before analyzing files that don't belong to you. 
