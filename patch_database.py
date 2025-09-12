#!/usr/bin/env python3
"""
Windows Patch Database Management Module

This module provides functionality to create and manage a SQLite database
for storing Windows patch information from Microsoft Update Catalog.
"""

import sqlite3
import json
import os
import logging
from datetime import datetime
from typing import List, Dict, Optional, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class PatchDatabase:
    """Manages SQLite database for Windows patch storage and retrieval."""
    
    def __init__(self, db_path: str = "windows_patches.db"):
        """
        Initialize the patch database.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self.connection = None
        
    def connect(self):
        """Establish connection to the database."""
        try:
            self.connection = sqlite3.connect(self.db_path)
            self.connection.row_factory = sqlite3.Row  # Enable dict-like access
            logger.info(f"Connected to database: {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Failed to connect to database: {e}")
            raise
            
    def disconnect(self):
        """Close database connection."""
        if self.connection:
            self.connection.close()
            self.connection = None
            logger.info("Disconnected from database")
            
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
        
    def create_tables(self):
        """Create the database schema for Windows patches."""
        if not self.connection:
            raise RuntimeError("Database connection not established")
            
        try:
            cursor = self.connection.cursor()
            
            # Main patches table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS patches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    update_id TEXT UNIQUE NOT NULL,
                    title TEXT NOT NULL,
                    kb_number TEXT,
                    version TEXT,
                    last_updated DATE,
                    classification TEXT,
                    languages TEXT,
                    architecture TEXT,
                    products_applicable TEXT,
                    update_size TEXT,
                    description TEXT,
                    msrc_number TEXT,
                    msrc_severity TEXT,
                    superseeds TEXT,
                    requires_restart TEXT,
                    requires_connectivity TEXT,
                    requires_user_input TEXT,
                    is_installable TEXT,
                    more_info TEXT,
                    support_url TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Download URLs table (one-to-many relationship with patches)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS download_urls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    patch_id INTEGER,
                    file_name TEXT,
                    download_url TEXT,
                    file_size INTEGER,
                    digest TEXT,
                    architectures TEXT,
                    languages TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (patch_id) REFERENCES patches (id) ON DELETE CASCADE
                )
            ''')
            
            # Create indexes for better performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_patches_kb_number ON patches(kb_number)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_patches_update_id ON patches(update_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_patches_title ON patches(title)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_patches_classification ON patches(classification)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_patches_last_updated ON patches(last_updated)')
            
            # Database metadata table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS db_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Insert initial metadata
            cursor.execute('''
                INSERT OR REPLACE INTO db_metadata (key, value) 
                VALUES ('version', '1.0'), ('created_at', ?)
            ''', (datetime.now().isoformat(),))
            
            self.connection.commit()
            logger.info("Database schema created successfully")
            
        except sqlite3.Error as e:
            logger.error(f"Failed to create database schema: {e}")
            raise
            
    def insert_patch(self, patch_data: Dict[str, Any]) -> int:
        """
        Insert a single patch into the database.
        
        Args:
            patch_data: Dictionary containing patch information
            
        Returns:
            The ID of the inserted patch
        """
        if not self.connection:
            raise RuntimeError("Database connection not established")
            
        try:
            cursor = self.connection.cursor()
            
            # Extract main patch data
            patch_values = (
                patch_data.get('update_id', ''),
                patch_data.get('title', ''),
                str(patch_data.get('kb_number', '')) if patch_data.get('kb_number') else None,
                patch_data.get('version', ''),
                patch_data.get('last_updated', ''),
                patch_data.get('classification', ''),
                patch_data.get('languages', ''),
                patch_data.get('architecture', ''),
                patch_data.get('products_applicable', ''),
                patch_data.get('update_size', ''),
                patch_data.get('description', ''),
                patch_data.get('msrc_number', ''),
                patch_data.get('msrc_severity', ''),
                json.dumps(patch_data.get('superseeds', [])) if isinstance(patch_data.get('superseeds'), list) else str(patch_data.get('superseeds', '')),
                patch_data.get('requires_restart', ''),
                patch_data.get('requires_connectivity', ''),
                patch_data.get('requires_user_input', ''),
                str(patch_data.get('uninstallable', '')),
                patch_data.get('more_info', ''),
                patch_data.get('support_url', ''),
                datetime.now().isoformat()
            )
            
            cursor.execute('''
                INSERT OR REPLACE INTO patches (
                    update_id, title, kb_number, version, last_updated, classification,
                    languages, architecture, products_applicable, update_size, description,
                    msrc_number, msrc_severity, superseeds, requires_restart, requires_connectivity,
                    requires_user_input, is_installable, more_info, support_url, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', patch_values)
            
            patch_id = cursor.lastrowid
            
            # Insert download URLs if they exist
            download_urls = patch_data.get('download_urls', [])
            if download_urls:
                # Handle both list and JSON string formats
                if isinstance(download_urls, str):
                    try:
                        download_urls = json.loads(download_urls)
                    except json.JSONDecodeError:
                        download_urls = []
                        
                for download in download_urls:
                    if isinstance(download, dict):
                        cursor.execute('''
                            INSERT INTO download_urls (
                                patch_id, file_name, download_url, file_size, digest, architectures, languages
                            ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            patch_id,
                            download.get('file_name', ''),
                            download.get('download_link', download.get('download_url', download.get('url', ''))),
                            download.get('size', 0) if download.get('size') else 0,
                            download.get('digest', ''),
                            download.get('architectures', ''),
                            download.get('languages', '')
                        ))
            
            self.connection.commit()
            logger.debug(f"Inserted patch: {patch_data.get('title', 'Unknown')} (ID: {patch_id})")
            return patch_id
            
        except sqlite3.Error as e:
            logger.error(f"Failed to insert patch: {e}")
            self.connection.rollback()
            raise
            
    def insert_patches_bulk(self, patches: List[Dict[str, Any]]) -> int:
        """
        Insert multiple patches in a single transaction.
        
        Args:
            patches: List of patch dictionaries
            
        Returns:
            Number of patches inserted
        """
        if not self.connection:
            raise RuntimeError("Database connection not established")
            
        inserted_count = 0
        try:
            for patch in patches:
                self.insert_patch(patch)
                inserted_count += 1
                
            logger.info(f"Successfully inserted {inserted_count} patches")
            return inserted_count
            
        except Exception as e:
            logger.error(f"Bulk insert failed after {inserted_count} patches: {e}")
            raise
            
    def search_patches(self, **kwargs) -> List[Dict[str, Any]]:
        """
        Search patches based on various criteria.
        
        Args:
            **kwargs: Search criteria (kb_number, title, classification, etc.)
            
        Returns:
            List of matching patches
        """
        if not self.connection:
            raise RuntimeError("Database connection not established")
            
        try:
            cursor = self.connection.cursor()
            
            # Build dynamic query
            conditions = []
            values = []
            
            if 'kb_number' in kwargs and kwargs['kb_number']:
                conditions.append("kb_number LIKE ?")
                values.append(f"%{kwargs['kb_number']}%")
                
            if 'title' in kwargs and kwargs['title']:
                conditions.append("title LIKE ?")
                values.append(f"%{kwargs['title']}%")
                
            if 'classification' in kwargs and kwargs['classification']:
                conditions.append("classification LIKE ?")
                values.append(f"%{kwargs['classification']}%")
                
            if 'architecture' in kwargs and kwargs['architecture']:
                conditions.append("architecture LIKE ?")
                values.append(f"%{kwargs['architecture']}%")
                
            if 'products_applicable' in kwargs and kwargs['products_applicable']:
                conditions.append("products_applicable LIKE ?")
                values.append(f"%{kwargs['products_applicable']}%")
                
            # Date range search
            if 'date_from' in kwargs and kwargs['date_from']:
                conditions.append("last_updated >= ?")
                values.append(kwargs['date_from'])
                
            if 'date_to' in kwargs and kwargs['date_to']:
                conditions.append("last_updated <= ?")
                values.append(kwargs['date_to'])
            
            # Build final query
            query = "SELECT * FROM patches"
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            query += " ORDER BY last_updated DESC"
            
            # Add limit if specified
            if 'limit' in kwargs and kwargs['limit']:
                query += f" LIMIT {int(kwargs['limit'])}"
                
            cursor.execute(query, values)
            rows = cursor.fetchall()
            
            # Convert to list of dictionaries
            patches = []
            for row in rows:
                patch = dict(row)
                # Get download URLs for this patch
                cursor.execute("SELECT * FROM download_urls WHERE patch_id = ?", (patch['id'],))
                downloads = [dict(dl) for dl in cursor.fetchall()]
                patch['download_urls'] = downloads
                patches.append(patch)
                
            logger.info(f"Found {len(patches)} patches matching search criteria")
            return patches
            
        except sqlite3.Error as e:
            logger.error(f"Search failed: {e}")
            raise
            
    def get_patch_by_id(self, patch_id: int) -> Optional[Dict[str, Any]]:
        """
        Get a patch by its database ID.
        
        Args:
            patch_id: Database ID of the patch
            
        Returns:
            Patch dictionary or None if not found
        """
        if not self.connection:
            raise RuntimeError("Database connection not established")
            
        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT * FROM patches WHERE id = ?", (patch_id,))
            row = cursor.fetchone()
            
            if row:
                patch = dict(row)
                # Get download URLs
                cursor.execute("SELECT * FROM download_urls WHERE patch_id = ?", (patch_id,))
                downloads = [dict(dl) for dl in cursor.fetchall()]
                patch['download_urls'] = downloads
                return patch
            return None
            
        except sqlite3.Error as e:
            logger.error(f"Failed to get patch by ID: {e}")
            raise
            
    def get_database_stats(self) -> Dict[str, Any]:
        """
        Get database statistics.
        
        Returns:
            Dictionary with database statistics
        """
        if not self.connection:
            raise RuntimeError("Database connection not established")
            
        try:
            cursor = self.connection.cursor()
            
            # Get total patch count
            cursor.execute("SELECT COUNT(*) as total_patches FROM patches")
            total_patches = cursor.fetchone()['total_patches']
            
            # Get count by classification
            cursor.execute("""
                SELECT classification, COUNT(*) as count 
                FROM patches 
                GROUP BY classification 
                ORDER BY count DESC
            """)
            classifications = [dict(row) for row in cursor.fetchall()]
            
            # Get latest update date
            cursor.execute("SELECT MAX(last_updated) as latest_update FROM patches")
            latest_update = cursor.fetchone()['latest_update']
            
            # Get database size
            db_size = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
            
            return {
                'total_patches': total_patches,
                'classifications': classifications,
                'latest_update': latest_update,
                'database_size_bytes': db_size,
                'database_size_mb': round(db_size / (1024 * 1024), 2)
            }
            
        except sqlite3.Error as e:
            logger.error(f"Failed to get database stats: {e}")
            raise
            
    def export_to_json(self, output_file: str, limit: Optional[int] = None):
        """
        Export all patches to JSON file.
        
        Args:
            output_file: Path to output JSON file
            limit: Optional limit on number of patches to export
        """
        try:
            patches = self.search_patches(limit=limit)
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump({'patches': patches}, f, indent=2, default=str)
            logger.info(f"Exported {len(patches)} patches to {output_file}")
        except Exception as e:
            logger.error(f"Failed to export to JSON: {e}")
            raise