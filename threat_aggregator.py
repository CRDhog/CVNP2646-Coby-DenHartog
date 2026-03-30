import json
import os
from datetime import datetime
from typing import Dict, List, Tuple, Set
from collections import defaultdict
import logging
import argparse
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('aggregator.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Constants
DEFAULT_CONFIDENCE_THRESHOLD = 85
DEFAULT_THREAT_LEVELS = {"high", "critical"}
DEFAULT_INDICATOR_TYPES = {"ip", "domain"}
DEFAULT_OUTPUT_DIR = "output"

def load_feed(filepath: str) -> Dict:
    """Load JSON from file, return parsed data."""
    try:
        with open(filepath) as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading {filepath}: {str(e)}")
        return {}

def normalize_indicator(indicator: Dict, source_name: str) -> Dict:
    """Convert to standard format."""
    normalized = {
        "id": indicator.get("id") or indicator.get("ioc_id") or indicator.get("threat_id"),
        "type": map_type(indicator),
        "value": map_value(indicator),
        "confidence": map_confidence(indicator),
        "threat_level": map_threat_level(indicator),
        "first_seen": map_first_seen(indicator),
        "sources": [source_name]
    }
    return normalized

def map_type(item: Dict) -> str:
    """Map different field names to 'type'."""
    return (
        item.get("type") or 
        item.get("indicator_type") or 
        item.get("category")
    )

def map_value(item: Dict) -> str:
    """Map different field names to 'value'."""
    return (
        item.get("value") or 
        item.get("indicator_value") or 
        item.get("ioc")
    )

def map_confidence(item: Dict) -> int:
    """Map different field names to 'confidence'."""
    return (
        item.get("confidence") or 
        item.get("score") or 
        item.get("reliability")
    )

def map_threat_level(item: Dict) -> str:
    """Map different field names to 'threat_level'."""
    return (
        item.get("threat") or 
        item.get("severity") or 
        item.get("risk")
    )

def map_first_seen(item: Dict) -> str:
    """Map different field names to 'first_seen'."""
    return (
        item.get("first_seen") or 
        item.get("discovered") or 
        item.get("seen_at")
    )

def validate_indicators(indicators: List[Dict]) -> Tuple[List[Dict], List[str]]:
    """Check data quality, return (valid, errors)."""
    valid_indicators = []
    errors = []
    
    for idx, indicator in enumerate(indicators):
        # Check required fields
        if not all(key in indicator for key in ["id", "type", "value", "confidence"]):
            errors.append(f"Missing required fields in indicator {idx}")
            continue
            
        # Validate confidence range
        if not (0 <= indicator["confidence"] <= 100):
            errors.append(f"Invalid confidence in indicator {idx}: {indicator['confidence']}")
            continue
            
        # Validate type
        if indicator["type"] not in ["ip", "domain", "hash", "url"]:
            errors.append(f"Invalid type in indicator {idx}: {indicator['type']}")
            continue
            
        # Validate value
        if not isinstance(indicator["value"], str) or not indicator["value"].strip():
            errors.append(f"Invalid value in indicator {idx}")
            continue
            
        valid_indicators.append(indicator)
        
    return valid_indicators, errors

def deduplicate_indicators(indicators: List[Dict]) -> Tuple[List[Dict], Dict]:
    """Remove duplicates, merge sources."""
    dedup_map = defaultdict(list)  # Maps (type, value) to list of indicators
    stats = {
        "total": len(indicators),
        "duplicates_found": 0,
        "duplicates_removed": 0
    }
    
    # Group by type and value
    for indicator in indicators:
        key = (indicator["type"], indicator["value"])
        dedup_map[key].append(indicator)
    
    result = []
    for key, group in dedup_map.items():
        if len(group) > 1:
            # Found duplicates, pick highest confidence
            best = max(group, key=lambda x: x["confidence"])
            sources = set()
            for item in group:
                sources.update(item["sources"])
            best["sources"] = sorted(list(sources))
            result.append(best)
            stats["duplicates_found"] += 1
            stats["duplicates_removed"] += len(group) - 1
        else:
            result.append(group[0])
    
    return result, stats

def filter_indicators(indicators: List[Dict], 
                     min_conf: int = DEFAULT_CONFIDENCE_THRESHOLD,
                     levels: Set[str] = DEFAULT_THREAT_LEVELS,
                     types: Set[str] = DEFAULT_INDICATOR_TYPES) -> List[Dict]:
    """Apply filters."""
    filtered = []
    
    for indicator in indicators:
        if (indicator["confidence"] >= min_conf and
            indicator["threat_level"] in levels and
            indicator["type"] in types):
            filtered.append(indicator)
            
    return filtered

def transform_to_firewall(indicators: List[Dict]) -> str:
    """Generate firewall JSON."""
    lines = []
    for indicator in indicators:
        lines.append(f"{indicator['value']} # {indicator['type']} ({indicator['confidence']}% confidence)")
    return "\n".join(lines)

def transform_to_siem(indicators: List[Dict]) -> str:
    """Generate SIEM JSON."""
    events = []
    for indicator in indicators:
        event = {
            "timestamp": datetime.now().isoformat(),
            "indicator": indicator["value"],
            "type": indicator["type"],
            "confidence": indicator["confidence"],
            "threat_level": indicator["threat_level"],
            "sources": ", ".join(indicator["sources"]),
            "tags": ["threat_intel"]
        }
        events.append(json.dumps(event))
    return "\n".join(events)

def generate_statistics(stats_data: Dict) -> str:
    """Calculate and format statistics."""
    return f"""
PROCESSING STATISTICS
{'='*50}
Total indicators loaded: {stats_data['total_loaded']}
Indicators after validation: {stats_data['valid_count']}
Errors encountered: {stats_data['error_count']}
Duplicates found: {stats_data['duplicates_found']}
Duplicates removed: {stats_data['duplicates_removed']}
Filtered indicators: {stats_data['filtered_count']}
"""

def write_outputs(firewall_data: str, siem_data: str, report_text: str, output_dir: str):
    """Save all files."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    with open(os.path.join(output_dir, "firewall_blocklist.txt"), "w") as f:
        f.write(firewall_data)
        
    with open(os.path.join(output_dir, "siem_feed.log"), "w") as f:
        f.write(siem_data)
        
    with open(os.path.join(output_dir, "report.txt"), "w") as f:
        f.write(report_text)
        
    logger.info(f"Outputs saved to {output_dir}")

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Threat Intelligence Aggregator")
    parser.add_argument("--feeds", nargs="+", help="List of JSON feed paths")
    parser.add_argument("--threshold", type=int, default=DEFAULT_CONFIDENCE_THRESHOLD, 
                        help="Confidence threshold")
    parser.add_argument("--threat-levels", nargs="+", default=list(DEFAULT_THREAT_LEVELS),
                        help="Allowed threat levels")
    parser.add_argument("--types", nargs="+", default=list(DEFAULT_INDICATOR_TYPES),
                        help="Allowed indicator types")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR,
                        help="Output directory")
    return parser.parse_args()

def main():
    """Orchestrate the pipeline."""
    args = parse_args()
    
    if not args.feeds:
        logger.error("No feed paths provided")
        return
    
    # Track statistics
    stats = {
        "total_loaded": 0,
        "valid_count": 0,
        "error_count": 0,
        "duplicates_found": 0,
        "duplicates_removed": 0,
        "filtered_count": 0
    }
    
    # Load feeds
    all_indicators = []
    for feed_path in args.feeds:
        feed_name = os.path.basename(feed_path).split('.')[0]
        feed_data = load_feed(feed_path)
        
        # Handle different schemas
        if "indicators" in feed_data:  # VendorA schema
            for item in feed_data["indicators"]:
                all_indicators.append(normalize_indicator(item, feed_name))
                
        elif "data" in feed_data:  # VendorB schema
            for item in feed_data["data"]:
                all_indicators.append(normalize_indicator(item, feed_name))
                
        elif "threats" in feed_data:  # VendorC schema
            for item in feed_data["threats"]:
                all_indicators.append(normalize_indicator(item, feed_name))
    
    stats["total_loaded"] = len(all_indicators)
    
    # Validate indicators
    valid_indicators, errors = validate_indicators(all_indicators)
    stats["valid_count"] = len(valid_indicators)
    stats["error_count"] = len(errors)
    
    # Deduplicate indicators
    deduped_indicators, dedup_stats = deduplicate_indicators(valid_indicators)
    stats.update(dedup_stats)
    
    # Filter indicators
    filtered_indicators = filter_indicators(
        deduped_indicators,
        min_conf=args.threshold,
        levels=set(args.threat_levels),
        types=set(args.types)
    )
    stats["filtered_count"] = len(filtered_indicators)
    
    # Transform to outputs
    firewall_data = transform_to_firewall(filtered_indicators)
    siem_data = transform_to_siem(filtered_indicators)
    report_text = generate_human_readable_report(filtered_indicators)
    
    # Write outputs
    write_outputs(firewall_data, siem_data, report_text, args.output_dir)
    
    # Log statistics
    logger.info(generate_statistics(stats))
    
    # Log errors if any
    if errors:
        logger.warning(f"Encountered {len(errors)} validation errors:")
        for err in errors:
            logger.warning(err)

def generate_human_readable_report(indicators: List[Dict]) -> str:
    """Generate human-readable report."""
    report = [
        "THREAT INTELLIGENCE REPORT",
        "=" * 50,
        f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "SUMMARY",
        "-" * 30,
        f"Total indicators processed: {len(indicators)}",
        "",
        "INDICATORS",
        "-" * 30
    ]
    
    for indicator in indicators:
        report.append(f"- {indicator['value']} ({indicator['type']})")
        report.append(f"  Confidence: {indicator['confidence']}%")
        report.append(f"  Threat Level: {indicator['threat_level']}")
        report.append(f"  Sources: {', '.join(indicator['sources'])}")
        report.append("")
        
    return "\n".join(report)

if __name__ == "__main__":
    main()