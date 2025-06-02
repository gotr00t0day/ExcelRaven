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

## Installation

1. Install required dependencies:
```bash
pip install -r requirements.txt
```

2. Make the script executable:
```bash
chmod +x excel_forensics.py
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
```

### Binary Analysis with Custom Patterns
The tool can be extended to search for custom patterns by modifying the `patterns` dictionary in the `search_credential_patterns()` method.

### Working with Different Encodings
The tool automatically handles:
- ASCII encoding
- UTF-8 encoding
- UTF-16 Little Endian (common in Office files)
- Raw binary data

## Common Credential Locations in Excel Files

1. **XML Metadata**: Connection strings in `xl/connections.xml`
2. **VBA Projects**: Hardcoded credentials in macro code
3. **Custom Properties**: Hidden metadata in `docProps/custom.xml`
4. **Embedded Objects**: Credentials in embedded files
5. **Cell Comments**: Hidden text in cell comment metadata
6. **External Links**: Database connection strings in external links

## Tips for Success

1. **Try Multiple File Extensions**: Sometimes changing the extension helps
2. **Check for Embedded Files**: Look for other Office documents embedded within
3. **Examine Temporary Files**: Check for `.tmp` files created during repair
4. **Use Multiple Tools**: Combine with other forensics tools like `binwalk`, `strings`, or `oletools`
5. **Manual Review**: Always manually review extracted strings for false positives

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

### No Credentials Found
If no credentials are extracted:
- The file might be heavily encrypted or obfuscated
- Credentials might be stored in non-standard locations
- Try manual hex analysis or other forensics tools
- Check for steganography or hidden data techniques

### Large Files
For very large files:
- The tool might take considerable time to analyze
- Consider splitting the analysis into smaller chunks
- Use the verbose mode to monitor progress

## Contributing

Feel free to contribute improvements:
- Add support for additional file formats
- Improve pattern recognition
- Add new analysis techniques
- Enhance performance for large files

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always ensure you have proper authorization before analyzing files that don't belong to you. 
