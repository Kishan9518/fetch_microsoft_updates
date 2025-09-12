#!/usr/bin/env python3
"""
Windows Patch Database Manager

A comprehensive tool for downloading and managing a database of Windows patches
from Microsoft Update Catalog.
"""

import argparse
import json
import sys
import os
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime

from patch_database import PatchDatabase
from patch_discovery import PatchDiscovery

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class PatchManager:
    """Main application class for managing Windows patch database."""
    
    def __init__(self, db_path: str = "windows_patches.db"):
        """
        Initialize the patch manager.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self.discovery = PatchDiscovery()
        
    def init_database(self) -> bool:
        """
        Initialize the patch database.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            with PatchDatabase(self.db_path) as db:
                db.create_tables()
                logger.info(f"Database initialized: {self.db_path}")
                return True
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            return False
            
    def update_database(self, max_patches: int = 1000, discovery_method: str = "all") -> bool:
        """
        Update the database with new patches.
        
        Args:
            max_patches: Maximum number of patches to discover and add
            discovery_method: Method to use for discovery ('all', 'recent', 'critical')
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with PatchDatabase(self.db_path) as db:
                logger.info(f"Starting database update with method: {discovery_method}")
                
                patches_added = 0
                
                if discovery_method == "all":
                    # Bulk discovery of all patches
                    for patch in self.discovery.bulk_discover_all_patches(max_patches):
                        try:
                            db.insert_patch(patch)
                            patches_added += 1
                            if patches_added % 10 == 0:
                                logger.info(f"Added {patches_added} patches...")
                        except Exception as e:
                            logger.debug(f"Failed to insert patch: {e}")
                            
                elif discovery_method == "recent":
                    # Recent patches (last 30 days)
                    patches = self.discovery.discover_recent_patches(days_back=30)
                    patches_added = db.insert_patches_bulk(patches[:max_patches])
                    
                elif discovery_method == "critical":
                    # Critical and security patches
                    patches = self.discovery.discover_critical_patches()
                    patches_added = db.insert_patches_bulk(patches[:max_patches])
                    
                else:
                    logger.error(f"Unknown discovery method: {discovery_method}")
                    return False
                    
                logger.info(f"Database update completed. Added {patches_added} patches")
                return True
                
        except Exception as e:
            logger.error(f"Failed to update database: {e}")
            return False
            
    def search_patches(self, **search_criteria) -> List[Dict[str, Any]]:
        """
        Search for patches in the database.
        
        Args:
            **search_criteria: Search parameters
            
        Returns:
            List of matching patches
        """
        try:
            with PatchDatabase(self.db_path) as db:
                return db.search_patches(**search_criteria)
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []
            
    def get_database_info(self) -> Optional[Dict[str, Any]]:
        """
        Get information about the database.
        
        Returns:
            Database statistics or None if failed
        """
        try:
            with PatchDatabase(self.db_path) as db:
                return db.get_database_stats()
        except Exception as e:
            logger.error(f"Failed to get database info: {e}")
            return None
            
    def export_patches(self, output_file: str, search_criteria: Optional[Dict] = None) -> bool:
        """
        Export patches to JSON file.
        
        Args:
            output_file: Output file path
            search_criteria: Optional search criteria to filter exports
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with PatchDatabase(self.db_path) as db:
                if search_criteria:
                    patches = db.search_patches(**search_criteria)
                    with open(output_file, 'w', encoding='utf-8') as f:
                        json.dump({'patches': patches}, f, indent=2, default=str)
                else:
                    db.export_to_json(output_file)
                    
                logger.info(f"Exported patches to: {output_file}")
                return True
                
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False


def main():
    """Main entry point for the patch database manager."""
    
    parser = argparse.ArgumentParser(
        description="Windows Patch Database Manager - Download and manage Windows patches",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Initialize database
  %(prog)s init
  
  # Update database with recent patches
  %(prog)s update --method recent --max-patches 500
  
  # Search for patches by KB number
  %(prog)s search --kb-number 5043076
  
  # Search for patches by title
  %(prog)s search --title "Cumulative Update"
  
  # Get database statistics
  %(prog)s info
  
  # Export all patches to JSON
  %(prog)s export --output patches.json
  
  # Export security patches only
  %(prog)s export --output security.json --classification "Security Updates"
        """
    )
    
    parser.add_argument('--db-path', default='windows_patches.db',
                       help='Path to SQLite database file (default: windows_patches.db)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Init command
    parser_init = subparsers.add_parser('init', help='Initialize the patch database')
    
    # Update command  
    parser_update = subparsers.add_parser('update', help='Update database with new patches')
    parser_update.add_argument('--method', choices=['all', 'recent', 'critical'], 
                              default='recent', help='Discovery method to use')
    parser_update.add_argument('--max-patches', type=int, default=1000,
                              help='Maximum number of patches to discover')
    
    # Search command
    parser_search = subparsers.add_parser('search', help='Search for patches')
    parser_search.add_argument('--kb-number', help='Search by KB number')
    parser_search.add_argument('--title', help='Search by title (partial match)')
    parser_search.add_argument('--classification', help='Search by classification')
    parser_search.add_argument('--architecture', help='Search by architecture')
    parser_search.add_argument('--product', help='Search by product')
    parser_search.add_argument('--date-from', help='Search from date (YYYY-MM-DD)')
    parser_search.add_argument('--date-to', help='Search to date (YYYY-MM-DD)')
    parser_search.add_argument('--limit', type=int, default=50, help='Limit results')
    parser_search.add_argument('--format', choices=['table', 'json'], default='table',
                              help='Output format')
    
    # Info command
    parser_info = subparsers.add_parser('info', help='Show database information')
    
    # Export command
    parser_export = subparsers.add_parser('export', help='Export patches to JSON')
    parser_export.add_argument('--output', required=True, help='Output JSON file')
    parser_export.add_argument('--kb-number', help='Filter by KB number')
    parser_export.add_argument('--classification', help='Filter by classification')
    parser_export.add_argument('--limit', type=int, help='Limit number of patches')
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        
    # Create patch manager
    manager = PatchManager(args.db_path)
    
    if args.command == 'init':
        success = manager.init_database()
        sys.exit(0 if success else 1)
        
    elif args.command == 'update':
        success = manager.update_database(args.max_patches, args.method)
        sys.exit(0 if success else 1)
        
    elif args.command == 'search':
        # Build search criteria
        criteria = {}
        if args.kb_number:
            criteria['kb_number'] = args.kb_number
        if args.title:
            criteria['title'] = args.title
        if args.classification:
            criteria['classification'] = args.classification
        if args.architecture:
            criteria['architecture'] = args.architecture
        if args.product:
            criteria['products_applicable'] = args.product
        if args.date_from:
            criteria['date_from'] = args.date_from
        if args.date_to:
            criteria['date_to'] = args.date_to
        if args.limit:
            criteria['limit'] = args.limit
            
        patches = manager.search_patches(**criteria)
        
        if args.format == 'json':
            print(json.dumps(patches, indent=2, default=str))
        else:
            # Table format
            if patches:
                print(f"\nFound {len(patches)} patches:\n")
                print(f"{'KB':<10} {'Title':<50} {'Classification':<20} {'Date':<12}")
                print("-" * 92)
                for patch in patches:
                    kb = patch.get('kb_number', 'N/A')[:9]
                    title = patch.get('title', 'N/A')[:49]
                    classification = patch.get('classification', 'N/A')[:19]
                    date = patch.get('last_updated', 'N/A')[:11]
                    print(f"{kb:<10} {title:<50} {classification:<20} {date:<12}")
            else:
                print("No patches found matching the search criteria.")
                
    elif args.command == 'info':
        info = manager.get_database_info()
        if info:
            print(f"\nWindows Patch Database Information:")
            print(f"Database file: {args.db_path}")
            print(f"Total patches: {info['total_patches']}")
            print(f"Database size: {info['database_size_mb']} MB")
            print(f"Latest update: {info['latest_update']}")
            print(f"\nPatch classifications:")
            for classification in info['classifications'][:10]:  # Top 10
                print(f"  {classification['classification']}: {classification['count']}")
        else:
            print("Failed to get database information. Make sure the database is initialized.")
            sys.exit(1)
            
    elif args.command == 'export':
        # Build export criteria
        criteria = {}
        if args.kb_number:
            criteria['kb_number'] = args.kb_number
        if args.classification:
            criteria['classification'] = args.classification
        if args.limit:
            criteria['limit'] = args.limit
            
        success = manager.export_patches(args.output, criteria if criteria else None)
        sys.exit(0 if success else 1)
        
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()