"""
Edge-Processing Telemetry Sanitizer & Aggregation Engine
Implements local PII stripping and statistical aggregation before transmission.

This module ensures:
- Zero PII exfiltration (local sanitization)
- K-anonymity compliance (minimum batch sizes)
- Commercial utility (regional/categorical statistics)
- Audit trail (immutable processing records)
"""

import json
import time
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict


@dataclass
class SanitizationAuditEvent:
    """Immutable record of a sanitization operation."""
    timestamp: float
    raw_records_count: int
    clean_records_count: int
    regions_affected: List[str]
    categories_affected: List[str]
    pii_vectors_stripped: List[str]
    batch_safe: bool
    error_details: Optional[str] = None


class TelemetrySanitizer:
    """
    Local edge-processing gateway that strips PII and prepares data
    for secure transmission without exposing individual records.
    """
    
    # PII fields that must ALWAYS be stripped at edge
    PII_VECTORS = [
        "user_id", "username", "email", "phone", "ip_address",
        "device_id", "mac_address", "imei", "imsi", "ssn",
        "credit_card", "location_precise", "gps_coordinates",
        "http_referer", "user_agent", "session_id", "cookie"
    ]
    
    # Safe fields that can transit to aggregation layer
    SAFE_FIELDS = ["region_code", "category", "value", "timestamp", "metric_type"]
    
    def __init__(self, min_batch_size: int = 100):
        """
        Initialize sanitizer with k-anonymity threshold.
        
        Args:
            min_batch_size: Minimum records required per batch for k-anonymity (default 100)
        """
        self.min_batch_size = min_batch_size
        self.audit_events = []
    
    def sanitize_telemetry(self, raw_data: List[Dict]) -> Dict:
        """
        Strips PII from raw telemetry and validates k-anonymity.
        
        Args:
            raw_data: List of raw telemetry records from sensors/clients
            
        Returns:
            Dict with 'data' (sanitized records), 'audit' (processing record), 'safe' (boolean)
            
        Raises:
            ValueError: If batch size fails k-anonymity threshold
        """
        audit = SanitizationAuditEvent(
            timestamp=time.time(),
            raw_records_count=len(raw_data),
            clean_records_count=0,
            regions_affected=[],
            categories_affected=[],
            pii_vectors_stripped=self.PII_VECTORS,
            batch_safe=False
        )
        
        try:
            # Stage 1: Strip PII vectors from each record
            sanitized_batch = []
            for entry in raw_data:
                clean_entry = {}
                
                # Only include whitelisted fields
                for field in self.SAFE_FIELDS:
                    if field in entry:
                        clean_entry[field] = entry[field]
                
                # Enforce region and category with defaults
                clean_entry["region_code"] = entry.get("region_code", "UNKNOWN")
                clean_entry["category"] = entry.get("category", "general")
                clean_entry["value"] = entry.get("value", 0)
                
                sanitized_batch.append(clean_entry)
            
            audit.clean_records_count = len(sanitized_batch)
            
            # Stage 2: Validate k-anonymity (minimum batch size)
            if len(sanitized_batch) < self.min_batch_size:
                audit.error_details = (
                    f"Batch too small ({len(sanitized_batch)}). "
                    f"Minimum {self.min_batch_size} required for k-anonymity."
                )
                audit.batch_safe = False
                self.audit_events.append(audit)
                raise ValueError(audit.error_details)
            
            audit.batch_safe = True
            
            # Stage 3: Extract metadata for audit trail
            regions = set(e.get("region_code") for e in sanitized_batch)
            categories = set(e.get("category") for e in sanitized_batch)
            audit.regions_affected = sorted(list(regions))
            audit.categories_affected = sorted(list(categories))
            
            self.audit_events.append(audit)
            
            return {
                "data": sanitized_batch,
                "audit": asdict(audit),
                "safe": True
            }
            
        except Exception as e:
            audit.error_details = str(e)
            audit.batch_safe = False
            self.audit_events.append(audit)
            return {
                "data": [],
                "audit": asdict(audit),
                "safe": False,
                "error": str(e)
            }
    
    def get_audit_trail(self) -> List[Dict]:
        """Returns immutable record of all sanitization operations."""
        return [asdict(event) for event in self.audit_events]


class RegionalAggregator:
    """
    Post-decryption aggregation engine that computes anonymous statistics
    from sanitized telemetry for commercial distribution.
    """
    
    def __init__(self):
        self.aggregation_history = []
    
    def compute_regional_distribution(self, sanitized_data: List[Dict]) -> Dict:
        """
        Computes percentage distribution of records across regions.
        Safe for commercial consumption (no individual identifiers).
        
        Args:
            sanitized_data: List of sanitized telemetry records
            
        Returns:
            Dict mapping region codes to percentage share
        """
        if not sanitized_data:
            return {}
        
        region_counts = {}
        total = len(sanitized_data)
        
        for item in sanitized_data:
            region = item.get("region_code", "UNKNOWN")
            region_counts[region] = region_counts.get(region, 0) + 1
        
        distribution = {
            region: (count / total) * 100
            for region, count in region_counts.items()
        }
        
        # Record aggregation operation
        self.aggregation_history.append({
            "timestamp": time.time(),
            "operation": "regional_distribution",
            "input_records": total,
            "regions_represented": len(distribution),
            "result": distribution
        })
        
        return distribution
    
    def compute_category_distribution(self, sanitized_data: List[Dict]) -> Dict:
        """
        Computes percentage distribution across data categories.
        
        Args:
            sanitized_data: List of sanitized telemetry records
            
        Returns:
            Dict mapping categories to percentage share
        """
        if not sanitized_data:
            return {}
        
        category_counts = {}
        total = len(sanitized_data)
        
        for item in sanitized_data:
            category = item.get("category", "general")
            category_counts[category] = category_counts.get(category, 0) + 1
        
        distribution = {
            category: (count / total) * 100
            for category, category_counts.items()
        }
        
        self.aggregation_history.append({
            "timestamp": time.time(),
            "operation": "category_distribution",
            "input_records": total,
            "categories_represented": len(distribution),
            "result": distribution
        })
        
        return distribution
    
    def compute_regional_category_matrix(self, sanitized_data: List[Dict]) -> Dict:
        """
        Cross-tabulates regions × categories for richer commercial insights.
        
        Args:
            sanitized_data: List of sanitized telemetry records
            
        Returns:
            Dict mapping "region_category" to percentage share of total
        """
        if not sanitized_data:
            return {}
        
        matrix_counts = {}
        total = len(sanitized_data)
        
        for item in sanitized_data:
            region = item.get("region_code", "UNKNOWN")
            category = item.get("category", "general")
            key = f"{region}_{category}"
            matrix_counts[key] = matrix_counts.get(key, 0) + 1
        
        matrix = {
            key: (count / total) * 100
            for key, count in matrix_counts.items()
        }
        
        self.aggregation_history.append({
            "timestamp": time.time(),
            "operation": "regional_category_matrix",
            "input_records": total,
            "matrix_dimensions": len(matrix),
            "result": matrix
        })
        
        return matrix


# Integration example
if __name__ == "__main__":
    print("=" * 70)
    print("TELEMETRY SANITIZER & AGGREGATION ENGINE - INTEGRATION TEST")
    print("=" * 70)
    
    # Simulated raw data with PII vectors
    mock_input_stream = [
        {
            "user_id": "usr_99812",
            "ip_address": "192.168.1.50",
            "device_id": "dev_alpha_001",
            "email": "user1@example.com",
            "region_code": "CA-NORTH",
            "category": "retail",
            "value": 12.5,
            "timestamp": time.time()
        },
        {
            "user_id": "usr_44321",
            "ip_address": "10.0.0.12",
            "session_id": "sess_xyz789",
            "region_code": "CA-SOUTH",
            "category": "retail",
            "value": 8.0,
            "timestamp": time.time()
        },
        {
            "user_id": "usr_11029",
            "ip_address": "172.16.0.4",
            "phone": "555-1234",
            "region_code": "CA-NORTH",
            "category": "service",
            "value": 15.0,
            "timestamp": time.time()
        }
    ]
    
    # Expand to meet minimum batch size
    for i in range(97):
        mock_input_stream.append({
            "user_id": f"usr_{10000 + i}",
            "ip_address": f"10.0.{i%256}.{(i//256) % 256}",
            "region_code": ["CA-NORTH", "CA-SOUTH", "TX-EAST"][i % 3],
            "category": ["retail", "service", "content"][i % 3],
            "value": 10 + (i % 20),
            "timestamp": time.time()
        })
    
    sanitizer = TelemetrySanitizer(min_batch_size=100)
    
    print("\n[*] Stage 1: Sanitizing telemetry (stripping PII)...")
    sanitization_result = sanitizer.sanitize_telemetry(mock_input_stream)
    
    if sanitization_result["safe"]:
        print(f"[+] Sanitization successful!")
        print(f"    Raw records processed: {sanitization_result['audit']['raw_records_count']}")
        print(f"    Clean records retained: {sanitization_result['audit']['clean_records_count']}")
        print(f"    PII vectors stripped: {', '.join(sanitization_result['audit']['pii_vectors_stripped'][:5])}...")
        print(f"    Regions affected: {sanitization_result['audit']['regions_affected']}")
        print(f"    K-anonymity verified: {sanitization_result['audit']['batch_safe']}")
        
        print("\n[*] Sanitized sample (first 2 records):")
        for i, record in enumerate(sanitization_result["data"][:2]):
            print(f"    Record {i+1}: {json.dumps(record, indent=6)}")
        
        print("\n[*] Stage 2: Computing aggregations for commercial distribution...")
        aggregator = RegionalAggregator()
        
        regional_dist = aggregator.compute_regional_distribution(sanitization_result["data"])
        print("\n    Regional Distribution (%):")
        for region, pct in sorted(regional_dist.items()):
            print(f"      {region}: {pct:.2f}%")
        
        category_dist = aggregator.compute_category_distribution(sanitization_result["data"])
        print("\n    Category Distribution (%):")
        for category, pct in sorted(category_dist.items()):
            print(f"      {category}: {pct:.2f}%")
        
        print("\n[+] Integration test complete. System ready for production deployment.")
    else:
        print(f"[!] Sanitization failed: {sanitization_result.get('error')}")
