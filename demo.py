#!/usr/bin/env python3
"""
Demo script for the Windows Patch Database system.

This script demonstrates the functionality with sample data when external
network access is not available.
"""

import json
import os
from datetime import datetime, timedelta
from patch_database import PatchDatabase
from patch_manager import PatchManager

def create_sample_patches():
    """Create sample patch data for demonstration."""
    base_date = datetime.now()
    
    sample_patches = [
        {
            'update_id': 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
            'title': '2024-09 Cumulative Update for Windows 11 Version 23H2 for x64-based Systems (KB5043076)',
            'kb_number': '5043076',
            'version': '22631.4169',
            'last_updated': (base_date - timedelta(days=5)).strftime('%Y-%m-%d'),
            'classification': 'Security Updates',
            'languages': 'English',
            'architecture': 'x64',
            'products_applicable': 'Windows 11',
            'update_size': '890 MB',
            'description': 'This security update includes quality improvements and security fixes.',
            'msrc_number': 'MS24-09',
            'msrc_severity': 'Critical',
            'superseeds': '["KB5042562", "KB5041585"]',
            'requires_restart': 'Yes',
            'requires_connectivity': 'No',
            'requires_user_input': 'No',
            'uninstallable': 'Yes',
            'more_info': 'https://support.microsoft.com/kb/5043076',
            'support_url': 'https://support.microsoft.com/kb/5043076',
            'download_urls': [
                {
                    'file_name': 'windows11.0-kb5043076-x64_abcd1234.msu',
                    'download_link': 'https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2024/09/windows11.0-kb5043076-x64_abcd1234.msu',
                    'file_size': 934281216
                }
            ]
        },
        {
            'update_id': 'b2c3d4e5-f6g7-8901-bcde-f23456789012',
            'title': '2024-09 Cumulative Update for Windows 10 Version 22H2 for x64-based Systems (KB5043064)',
            'kb_number': '5043064', 
            'version': '19045.4894',
            'last_updated': (base_date - timedelta(days=5)).strftime('%Y-%m-%d'),
            'classification': 'Security Updates',
            'languages': 'English',
            'architecture': 'x64',
            'products_applicable': 'Windows 10',
            'update_size': '512 MB',
            'description': 'This security update includes quality improvements and security fixes for Windows 10.',
            'msrc_number': 'MS24-09',
            'msrc_severity': 'Critical',
            'superseeds': '["KB5041578", "KB5040442"]',
            'requires_restart': 'Yes',
            'requires_connectivity': 'No',
            'requires_user_input': 'No',
            'uninstallable': 'Yes',
            'more_info': 'https://support.microsoft.com/kb/5043064',
            'support_url': 'https://support.microsoft.com/kb/5043064',
            'download_urls': [
                {
                    'file_name': 'windows10.0-kb5043064-x64_efgh5678.msu',
                    'download_link': 'https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2024/09/windows10.0-kb5043064-x64_efgh5678.msu',
                    'file_size': 536870912
                }
            ]
        },
        {
            'update_id': 'c3d4e5f6-g7h8-9012-cdef-345678901234',
            'title': 'Servicing Stack Update for Windows 11 Version 23H2 for x64-based Systems (KB5042099)',
            'kb_number': '5042099',
            'version': '22631.4037',
            'last_updated': (base_date - timedelta(days=15)).strftime('%Y-%m-%d'),
            'classification': 'Updates',
            'languages': 'English',
            'architecture': 'x64',
            'products_applicable': 'Windows 11',
            'update_size': '12 MB',
            'description': 'Servicing stack updates improve the reliability of the update process.',
            'msrc_number': 'N/A',
            'msrc_severity': 'N/A',
            'superseeds': '["KB5041999"]',
            'requires_restart': 'May require restart',
            'requires_connectivity': 'No',
            'requires_user_input': 'No',
            'uninstallable': 'No',
            'more_info': 'https://support.microsoft.com/kb/5042099',
            'support_url': 'https://support.microsoft.com/kb/5042099',
            'download_urls': [
                {
                    'file_name': 'ssu-22631.4037-x64_ijkl9012.msu',
                    'download_link': 'https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2024/08/ssu-22631.4037-x64_ijkl9012.msu',
                    'file_size': 12582912
                }
            ]
        },
        {
            'update_id': 'd4e5f6g7-h8i9-0123-defg-456789012345',
            'title': 'Microsoft .NET Framework 4.8.1 Security Update for Windows 11 (KB5043050)',
            'kb_number': '5043050',
            'version': '4.8.9232.0',
            'last_updated': (base_date - timedelta(days=8)).strftime('%Y-%m-%d'),
            'classification': 'Security Updates',
            'languages': 'English',
            'architecture': 'x86, x64',
            'products_applicable': 'Windows 11, Windows 10',
            'update_size': '45 MB',
            'description': 'Security update for Microsoft .NET Framework 4.8.1.',
            'msrc_number': 'MS24-09',
            'msrc_severity': 'Important',
            'superseeds': '["KB5042887"]',
            'requires_restart': 'May require restart',
            'requires_connectivity': 'No',
            'requires_user_input': 'No',
            'uninstallable': 'Yes',
            'more_info': 'https://support.microsoft.com/kb/5043050',
            'support_url': 'https://support.microsoft.com/kb/5043050',
            'download_urls': [
                {
                    'file_name': 'ndp481-kb5043050-x64_mnop3456.exe',
                    'download_link': 'https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2024/09/ndp481-kb5043050-x64_mnop3456.exe',
                    'file_size': 47185920
                }
            ]
        },
        {
            'update_id': 'e5f6g7h8-i9j0-1234-efgh-567890123456',
            'title': 'Windows Defender Antivirus Update for Windows 11 (KB2267602)',
            'kb_number': '2267602',
            'version': '1.403.2134.0',
            'last_updated': (base_date - timedelta(days=1)).strftime('%Y-%m-%d'),
            'classification': 'Definition Updates',
            'languages': 'All Languages',
            'architecture': 'x64',
            'products_applicable': 'Windows 11, Windows 10',
            'update_size': '180 MB',
            'description': 'Latest virus and spyware definitions for Windows Defender Antivirus.',
            'msrc_number': 'N/A',
            'msrc_severity': 'N/A',
            'superseeds': 'N/A',
            'requires_restart': 'No',
            'requires_connectivity': 'No',
            'requires_user_input': 'No',
            'uninstallable': 'No',
            'more_info': 'https://support.microsoft.com/kb/2267602',
            'support_url': 'https://support.microsoft.com/kb/2267602',
            'download_urls': [
                {
                    'file_name': 'mpam-fe.exe',
                    'download_link': 'https://go.microsoft.com/fwlink/?LinkID=121721',
                    'file_size': 188743680
                }
            ]
        }
    ]
    
    return sample_patches

def run_demo():
    """Run the complete demonstration."""
    print("=" * 60)
    print("Windows Patch Database System Demo")
    print("=" * 60)
    
    db_path = "/tmp/demo_patches.db"
    
    # Clean up any existing demo database
    if os.path.exists(db_path):
        os.remove(db_path)
        
    print(f"\n1. Initializing database at: {db_path}")
    manager = PatchManager(db_path)
    success = manager.init_database()
    
    if not success:
        print("Failed to initialize database!")
        return
        
    print("✓ Database initialized successfully")
    
    print("\n2. Adding sample Windows patches to database...")
    sample_patches = create_sample_patches()
    
    with PatchDatabase(db_path) as db:
        for i, patch in enumerate(sample_patches, 1):
            patch_id = db.insert_patch(patch)
            print(f"  ✓ Added patch {i}: {patch['title'][:60]}... (ID: {patch_id})")
    
    print(f"\n3. Database statistics:")
    info = manager.get_database_info()
    if info:
        print(f"  • Total patches: {info['total_patches']}")
        print(f"  • Database size: {info['database_size_mb']} MB")
        print(f"  • Latest update: {info['latest_update']}")
        print(f"  • Classifications:")
        for classification in info['classifications']:
            print(f"    - {classification['classification']}: {classification['count']} patches")
    
    print(f"\n4. Demonstrating search functionality:")
    
    # Search by KB number
    print(f"\n  4a. Searching for KB5043076:")
    results = manager.search_patches(kb_number="5043076")
    if results:
        patch = results[0]
        print(f"      ✓ Found: {patch['title']}")
        print(f"        Classification: {patch['classification']}")
        print(f"        Size: {patch['update_size']}")
        print(f"        Architecture: {patch['architecture']}")
    
    # Search by classification
    print(f"\n  4b. Searching for Security Updates:")
    results = manager.search_patches(classification="Security Updates")
    print(f"      ✓ Found {len(results)} security updates")
    for patch in results[:3]:  # Show first 3
        print(f"        - {patch['kb_number']}: {patch['title'][:50]}...")
    
    # Search by product
    print(f"\n  4c. Searching for Windows 11 patches:")
    results = manager.search_patches(products_applicable="Windows 11")
    print(f"      ✓ Found {len(results)} Windows 11 patches")
    
    print(f"\n5. Exporting patches to JSON:")
    export_file = "/tmp/demo_patches_export.json"
    success = manager.export_patches(export_file)
    if success and os.path.exists(export_file):
        file_size = os.path.getsize(export_file) / 1024  # KB
        print(f"  ✓ Exported to {export_file} ({file_size:.1f} KB)")
        
        # Show a snippet of the exported data
        with open(export_file, 'r') as f:
            data = json.load(f)
            print(f"  • Export contains {len(data['patches'])} patches")
    
    print(f"\n6. Command-line interface examples:")
    print(f"  The following commands would work with this database:")
    print(f"")
    print(f"  # Search for patches")
    print(f"  python3 patch_manager.py --db-path {db_path} search --kb-number 5043076")
    print(f"  python3 patch_manager.py --db-path {db_path} search --title 'Cumulative Update'")
    print(f"  python3 patch_manager.py --db-path {db_path} search --classification 'Security Updates'")
    print(f"")
    print(f"  # Get database info")
    print(f"  python3 patch_manager.py --db-path {db_path} info")
    print(f"")
    print(f"  # Export specific patches")
    print(f"  python3 patch_manager.py --db-path {db_path} export --output security.json --classification 'Security Updates'")
    
    print(f"\n7. Database file details:")
    if os.path.exists(db_path):
        file_size = os.path.getsize(db_path) / 1024  # KB
        print(f"  • File: {db_path}")
        print(f"  • Size: {file_size:.1f} KB")
        print(f"  • Contains complete patch metadata and download information")
    
    print(f"\n" + "=" * 60)
    print("Demo completed successfully!")
    print("The database system is ready for production use with live data.")
    print("=" * 60)

if __name__ == "__main__":
    run_demo()