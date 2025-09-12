#!/usr/bin/env python3
"""
Windows Patch Discovery Module

This module provides functionality to systematically discover and download
Windows patches from Microsoft Update Catalog.
"""

import logging
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Generator, Optional
from get_microsoft_patches import find_microsoft_catelogue_updates, get_patch_link, get_microsoft_download_center_update

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class PatchDiscovery:
    """Handles systematic discovery of Windows patches."""
    
    def __init__(self, delay_between_requests: float = 1.0):
        """
        Initialize patch discovery.
        
        Args:
            delay_between_requests: Delay between requests to avoid rate limiting
        """
        self.delay = delay_between_requests
        
        # Common Windows products to search for
        self.windows_products = [
            "Windows 11",
            "Windows 10",
            "Windows Server 2022",
            "Windows Server 2019",
            "Windows Server 2016",
            "Windows 8.1",
            "Windows 7"
        ]
        
        # Common patch classifications
        self.patch_classifications = [
            "Security Updates",
            "Critical Updates", 
            "Updates",
            "Update Rollups",
            "Service Packs",
            "Feature Packs",
            "Drivers",
            "Tools"
        ]
        
        # Common search terms for systematic discovery
        self.search_terms = [
            "Cumulative Update",
            "Security Update",
            "Monthly Rollup",
            "Servicing Stack Update",
            "Feature Update",
            "Quality Update",
            ".NET Framework",
            "Visual C++",
            "Windows Defender"
        ]
        
    def discover_patches_by_product(self, product: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Discover patches for a specific Windows product.
        
        Args:
            product: Windows product name (e.g., "Windows 11")
            limit: Maximum number of patches to discover
            
        Returns:
            List of patch dictionaries
        """
        logger.info(f"Discovering patches for product: {product}")
        
        all_patches = []
        try:
            patches = find_microsoft_catelogue_updates(product)
            if patches:
                all_patches.extend(patches)
                logger.info(f"Found {len(patches)} patches for {product}")
                
                if limit and len(all_patches) >= limit:
                    all_patches = all_patches[:limit]
                    
            time.sleep(self.delay)  # Rate limiting
            
        except Exception as e:
            logger.error(f"Failed to discover patches for {product}: {e}")
            
        return all_patches
        
    def discover_patches_by_search_terms(self, search_terms: Optional[List[str]] = None, 
                                       limit_per_term: int = 100) -> List[Dict[str, Any]]:
        """
        Discover patches using systematic search terms.
        
        Args:
            search_terms: List of search terms to use
            limit_per_term: Maximum patches per search term
            
        Returns:
            List of patch dictionaries
        """
        if search_terms is None:
            search_terms = self.search_terms
            
        all_patches = []
        patch_ids = set()  # To avoid duplicates
        
        for term in search_terms:
            logger.info(f"Searching for patches with term: {term}")
            try:
                patches = find_microsoft_catelogue_updates(term)
                if patches:
                    # Deduplicate based on update_id
                    new_patches = []
                    for patch in patches[:limit_per_term]:
                        patch_id = patch.get('update_id')
                        if patch_id and patch_id not in patch_ids:
                            patch_ids.add(patch_id)
                            new_patches.append(patch)
                            
                    all_patches.extend(new_patches)
                    logger.info(f"Found {len(new_patches)} new patches for term: {term}")
                    
                time.sleep(self.delay)  # Rate limiting
                
            except Exception as e:
                logger.error(f"Failed to search for term '{term}': {e}")
                
        logger.info(f"Total unique patches discovered: {len(all_patches)}")
        return all_patches
        
    def discover_patches_by_kb_range(self, start_kb: int, end_kb: int, 
                                   batch_size: int = 10) -> List[Dict[str, Any]]:
        """
        Discover patches by searching KB number ranges.
        
        Args:
            start_kb: Starting KB number
            end_kb: Ending KB number
            batch_size: Number of KBs to process in each batch
            
        Returns:
            List of patch dictionaries
        """
        logger.info(f"Discovering patches for KB range: {start_kb} to {end_kb}")
        
        all_patches = []
        current_kb = start_kb
        
        while current_kb <= end_kb:
            batch_end = min(current_kb + batch_size - 1, end_kb)
            logger.info(f"Processing KB batch: {current_kb} to {batch_end}")
            
            for kb_num in range(current_kb, batch_end + 1):
                try:
                    # Try Microsoft Catalog first
                    kb_search = f"KB{kb_num}"
                    patches = find_microsoft_catelogue_updates(kb_search)
                    
                    if patches:
                        all_patches.extend(patches)
                        logger.debug(f"Found patches for {kb_search}")
                    else:
                        # Try download center if catalog search fails
                        patch_links = get_patch_link(str(kb_num))
                        if patch_links:
                            for link in patch_links:
                                dl_patches = get_microsoft_download_center_update(link, str(kb_num))
                                if dl_patches:
                                    all_patches.extend(dl_patches)
                                    
                    time.sleep(self.delay)  # Rate limiting
                    
                except Exception as e:
                    logger.debug(f"Failed to find patches for KB{kb_num}: {e}")
                    
            current_kb = batch_end + 1
            
        logger.info(f"Found {len(all_patches)} patches in KB range {start_kb}-{end_kb}")
        return all_patches
        
    def discover_recent_patches(self, days_back: int = 30) -> List[Dict[str, Any]]:
        """
        Discover patches released in the last N days.
        
        Args:
            days_back: Number of days to look back
            
        Returns:
            List of recent patch dictionaries
        """
        logger.info(f"Discovering patches from the last {days_back} days")
        
        # Use search terms that are likely to find recent patches
        recent_terms = [
            "Cumulative Update",
            "Security Update", 
            "Monthly Rollup",
            "Quality Update",
            datetime.now().strftime("%B %Y"),  # Current month/year
            (datetime.now() - timedelta(days=30)).strftime("%B %Y")  # Previous month
        ]
        
        all_patches = self.discover_patches_by_search_terms(recent_terms, limit_per_term=50)
        
        # Filter by date if possible
        cutoff_date = datetime.now() - timedelta(days=days_back)
        filtered_patches = []
        
        for patch in all_patches:
            try:
                if patch.get('last_updated'):
                    # Try to parse the date string
                    patch_date_str = patch['last_updated']
                    if isinstance(patch_date_str, str):
                        # Handle different date formats
                        for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%m/%d/%Y"]:
                            try:
                                patch_date = datetime.strptime(patch_date_str.split()[0], fmt)
                                if patch_date >= cutoff_date:
                                    filtered_patches.append(patch)
                                break
                            except ValueError:
                                continue
                    else:
                        filtered_patches.append(patch)  # Include if we can't parse date
                else:
                    filtered_patches.append(patch)  # Include if no date
                    
            except Exception as e:
                logger.debug(f"Date filtering error for patch: {e}")
                filtered_patches.append(patch)  # Include on error
                
        logger.info(f"Found {len(filtered_patches)} recent patches")
        return filtered_patches
        
    def discover_critical_patches(self) -> List[Dict[str, Any]]:
        """
        Discover critical and security patches.
        
        Returns:
            List of critical patch dictionaries
        """
        logger.info("Discovering critical and security patches")
        
        critical_terms = [
            "Critical Update",
            "Security Update", 
            "Important Update",
            "Windows Security",
            "Security Only",
            "Out-of-band"
        ]
        
        all_patches = self.discover_patches_by_search_terms(critical_terms, limit_per_term=200)
        
        # Filter for critical/security classifications
        critical_patches = []
        for patch in all_patches:
            classification = patch.get('classification', '').lower()
            severity = patch.get('msrc_severity', '').lower()
            title = patch.get('title', '').lower()
            
            if any(term in classification for term in ['critical', 'security', 'important']) or \
               any(term in severity for term in ['critical', 'important']) or \
               any(term in title for term in ['security', 'critical']):
                critical_patches.append(patch)
                
        logger.info(f"Found {len(critical_patches)} critical/security patches")
        return critical_patches
        
    def bulk_discover_all_patches(self, max_patches: int = 10000) -> Generator[Dict[str, Any], None, None]:
        """
        Perform bulk discovery of all available Windows patches.
        
        Args:
            max_patches: Maximum number of patches to discover
            
        Yields:
            Individual patch dictionaries as they are discovered
        """
        logger.info(f"Starting bulk discovery of up to {max_patches} patches")
        
        discovered_count = 0
        patch_ids = set()
        
        # Strategy 1: Search by Windows products
        for product in self.windows_products:
            if discovered_count >= max_patches:
                break
                
            patches = self.discover_patches_by_product(product, limit=500)
            for patch in patches:
                if discovered_count >= max_patches:
                    break
                    
                patch_id = patch.get('update_id')
                if patch_id and patch_id not in patch_ids:
                    patch_ids.add(patch_id)
                    discovered_count += 1
                    yield patch
                    
        # Strategy 2: Search by common terms
        if discovered_count < max_patches:
            patches = self.discover_patches_by_search_terms(
                limit_per_term=min(200, (max_patches - discovered_count) // len(self.search_terms))
            )
            for patch in patches:
                if discovered_count >= max_patches:
                    break
                    
                patch_id = patch.get('update_id')
                if patch_id and patch_id not in patch_ids:
                    patch_ids.add(patch_id)
                    discovered_count += 1
                    yield patch
                    
        # Strategy 3: Recent KB ranges (last 2 years worth)
        if discovered_count < max_patches:
            # Estimate recent KB numbers (this is approximate)
            current_year = datetime.now().year
            start_kb = (current_year - 2022) * 100000 + 5000000  # Rough estimate
            end_kb = start_kb + 50000  # Search a reasonable range
            
            patches = self.discover_patches_by_kb_range(
                start_kb, min(end_kb, start_kb + (max_patches - discovered_count))
            )
            for patch in patches:
                if discovered_count >= max_patches:
                    break
                    
                patch_id = patch.get('update_id')
                if patch_id and patch_id not in patch_ids:
                    patch_ids.add(patch_id)
                    discovered_count += 1
                    yield patch
                    
        logger.info(f"Bulk discovery completed. Found {discovered_count} unique patches")
        
    def get_discovery_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about discovery capabilities.
        
        Returns:
            Dictionary with discovery statistics
        """
        return {
            'supported_products': len(self.windows_products),
            'search_terms': len(self.search_terms), 
            'products': self.windows_products,
            'classifications': self.patch_classifications,
            'delay_between_requests': self.delay
        }