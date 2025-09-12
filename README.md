# Windows Patch Database Manager

A comprehensive tool for downloading, storing, and managing a database of Windows patches from Microsoft Update Catalog.

## Features

### 🆕 New Database Functionality
- **Systematic patch discovery**: Automatically discover all Windows patches using multiple search strategies
- **SQLite database storage**: Store patches locally for fast searching and offline reference
- **Advanced search capabilities**: Search by KB number, title, classification, architecture, date ranges, and more
- **Bulk operations**: Import thousands of patches efficiently
- **JSON export**: Export filtered patch data for integration with other tools
- **Command-line interface**: Full CLI for database management and operations

### Legacy Functionality
- Fetch individual patches by KB number or search term
- Export patch information to JSON format
- Support for both Microsoft Update Catalog and Download Center

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Kishan9518/fetch_microsoft_updates.git
cd fetch_microsoft_updates
```

2. Install dependencies:
```bash
pip install beautifulsoup4 requests
```

## Quick Start

### Initialize Database
```bash
python3 patch_manager.py init
```

### Update Database with Recent Patches
```bash
python3 patch_manager.py update --method recent --max-patches 500
```

### Search for Patches
```bash
# Search by KB number
python3 patch_manager.py search --kb-number 5043076

# Search by title
python3 patch_manager.py search --title "Cumulative Update"

# Search security updates
python3 patch_manager.py search --classification "Security Updates"
```

### Get Database Information
```bash
python3 patch_manager.py info
```

## Usage

### Database Management

#### Initialize Database
```bash
python3 patch_manager.py init [--db-path custom.db]
```

#### Update Database
```bash
# Recent patches (last 30 days)
python3 patch_manager.py update --method recent --max-patches 1000

# Critical and security patches
python3 patch_manager.py update --method critical --max-patches 2000

# Comprehensive discovery (all available patches)
python3 patch_manager.py update --method all --max-patches 5000
```

#### Search Patches
```bash
# Basic searches
python3 patch_manager.py search --kb-number 5043076
python3 patch_manager.py search --title "Windows 11"
python3 patch_manager.py search --classification "Security Updates"
python3 patch_manager.py search --architecture "x64"

# Advanced searches
python3 patch_manager.py search --date-from 2024-01-01 --date-to 2024-12-31
python3 patch_manager.py search --product "Windows 11" --limit 10

# JSON output
python3 patch_manager.py search --title "Cumulative" --format json
```

#### Export Data
```bash
# Export all patches
python3 patch_manager.py export --output all_patches.json

# Export filtered patches
python3 patch_manager.py export --output security.json --classification "Security Updates"
python3 patch_manager.py export --output recent.json --limit 100
```

### Legacy Script (Individual Patch Lookup)

```bash
# Basic usage
python3 get_microsoft_patches.py KB5043076 patch_details.json

# With database integration
python3 get_microsoft_patches.py "Cumulative Update" patches.json --save-to-db patches.db

# Help
python3 get_microsoft_patches.py --help
```

## Database Schema

The SQLite database contains two main tables:

### `patches` table
- Stores main patch information (KB numbers, titles, classifications, etc.)
- Includes metadata like MSRC numbers, severity levels, architecture info
- Tracks installation requirements and dependencies

### `download_urls` table  
- Stores download links for each patch
- Includes file names, sizes, and checksums
- Supports multiple download options per patch

## Search Strategies

The system uses multiple strategies to discover Windows patches:

1. **Product-based searches**: Windows 11, Windows 10, Windows Server versions
2. **Classification searches**: Security Updates, Critical Updates, Feature Updates
3. **Keyword searches**: Common update terms and patterns
4. **KB range searches**: Systematic scanning of KB number ranges
5. **Date-based filtering**: Recent patches and historical data

## Examples

### Complete Workflow Example
```bash
# 1. Initialize database
python3 patch_manager.py init --db-path windows_patches.db

# 2. Populate with recent critical patches
python3 patch_manager.py update --method critical --max-patches 1000

# 3. Search for Windows 11 security updates
python3 patch_manager.py search --product "Windows 11" --classification "Security"

# 4. Export security patches for analysis
python3 patch_manager.py export --output security_analysis.json --classification "Security Updates"

# 5. Get database statistics
python3 patch_manager.py info
```

### Integration with Legacy Script
```bash
# Fetch specific patch and add to database
python3 get_microsoft_patches.py KB5043076 kb5043076.json --save-to-db windows_patches.db

# Search term with database integration
python3 get_microsoft_patches.py "Monthly Rollup" monthly.json --save-to-db windows_patches.db
```

## Demo

Run the included demo to see the system in action:
```bash
python3 demo.py
```

This demonstrates:
- Database initialization
- Sample patch data insertion
- Search functionality
- Export capabilities
- CLI interface examples

## Output Formats

### JSON Export Format
```json
{
  "patches": [
    {
      "id": 1,
      "update_id": "uuid-string",
      "title": "Patch Title",
      "kb_number": "5043076",
      "classification": "Security Updates",
      "last_updated": "2024-09-12",
      "architecture": "x64",
      "products_applicable": "Windows 11",
      "download_urls": [
        {
          "file_name": "patch.msu",
          "download_url": "https://...",
          "file_size": 1234567
        }
      ]
    }
  ]
}
```

### Table Format (CLI)
```
KB         Title                                              Classification       Date        
--------------------------------------------------------------------------------------------
5043076    2024-09 Cumulative Update for Windows 11...        Security Updates     2024-09-12
5043064    2024-09 Cumulative Update for Windows 10...        Security Updates     2024-09-12
```

## Configuration

### Environment Variables
- `PATCH_DB_PATH`: Default database file path
- `PATCH_LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)

### Command Options
- `--db-path`: Custom database file location  
- `--verbose`: Enable debug logging
- `--format`: Output format (table, json)
- `--limit`: Limit search results

## Troubleshooting

### Common Issues

1. **Network connectivity errors**: The system requires internet access to fetch patches from Microsoft servers
2. **Rate limiting**: The system includes delays between requests to avoid being blocked
3. **Database locks**: Close other applications that might be accessing the database file

### Logging

Enable verbose logging for troubleshooting:
```bash
python3 patch_manager.py --verbose search --title "test"
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is open source. Please check the repository for license details.

## Changelog

### Version 2.0 (Latest)
- ✅ Added comprehensive SQLite database functionality
- ✅ Implemented systematic patch discovery system
- ✅ Created full command-line interface
- ✅ Added advanced search and filtering capabilities
- ✅ Included bulk patch processing
- ✅ Added JSON export functionality
- ✅ Maintained backward compatibility with legacy script

### Version 1.0 (Legacy)
- ✅ Individual patch lookup by KB number or search term
- ✅ Microsoft Update Catalog integration
- ✅ JSON output format
