# backup_planner.py
import os
import json
import random
import datetime
from typing import Dict, List, Tuple, Any

def load_config(filepath: str) -> Dict[str, Any] | None:
    """Load and parse JSON configuration file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Configuration file '{filepath}' not found.")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON syntax in '{filepath}': {str(e)}")
        return None

def validate_config(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate configuration against schema."""
    errors = []
    
    # Level 1: Structure validation
    if not isinstance(config, dict):
        errors.append("Configuration must be a JSON object")
        return False, errors
    
    # Level 2: Required fields
    if "plan_name" not in config:
        errors.append("Missing required field: 'plan_name'")
    if "sources" not in config:
        errors.append("Missing required field: 'sources'")
    if "destination" not in config:
        errors.append("Missing required field: 'destination'")
    
    # Level 3: Type validation
    if "plan_name" in config and not isinstance(config["plan_name"], str):
        errors.append(f"'plan_name' must be a string, got {type(config['plan_name']).__name__}")
    if "sources" in config and not isinstance(config["sources"], list):
        errors.append(f"'sources' must be a list, got {type(config['sources']).__name__}")
    if "destination" in config and not isinstance(config["destination"], dict):
        errors.append(f"'destination' must be an object, got {type(config['destination']).__name__}")
    
    # Level 4: Value validation
    if "sources" in config and isinstance(config["sources"], list):
        if len(config["sources"]) == 0:
            errors.append("Sources list cannot be empty")
        else:
            for i, source in enumerate(config["sources"]):
                if not isinstance(source, dict):
                    errors.append(f"Source {i}: must be an object")
                    continue
                if "path" not in source:
                    errors.append(f"Source {i}: missing 'path' field")
                elif not isinstance(source["path"], str) or source["path"] == "":
                    errors.append(f"Source {i}: 'path' must be a non-empty string")
    
    if "destination" in config and isinstance(config["destination"], dict):
        dest = config["destination"]
        if "base_path" not in dest:
            errors.append("Destination: missing 'base_path' field")
        elif not isinstance(dest["base_path"], str) or dest["base_path"] == "":
            errors.append("Destination: 'base_path' must be a non-empty string")
    
    return len(errors) == 0, errors

def simulate_backup(config: Dict[str, Any]) -> Dict[str, Any]:
    """Simulate backup operations without performing actual file I/O."""
    now = datetime.datetime.now()
    timestamp = now.strftime("%Y-%m-%dT%H:%M:%S")
    
    report = {
        "plan_name": config.get("plan_name", ""),
        "mode": "DRY-RUN",
        "timestamp": timestamp,
        "summary": {
            "total_sources": 0,
            "total_files": 0,
            "total_size_mb": 0.0
        },
        "operations": []
    }
    
    sources = config.get("sources", [])
    report["summary"]["total_sources"] = len(sources)
    
    for source in sources:
        source_name = source.get("name", "Unknown")
        path = source.get("path", "")
        recursive = source.get("recursive", False)
        include_patterns = source.get("include_patterns", [])
        exclude_patterns = source.get("exclude_patterns", [])
        
        # Generate simulated files
        files = []
        count = random.randint(5, 15)
        for _ in range(count):
            filename = random.choice(["capture", "flow", "dns", "auth", "netstat"])
            ext = random.choice(["pcapng", "cap", "json", "csv", "log"])
            size = round(random.uniform(1, 100), 1)
            files.append({
                "name": f"{filename}_{random.randint(2020, 2024)}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}.{ext}",
                "size_mb": size
            })
        
        report["summary"]["total_files"] += len(files)
        report["summary"]["total_size_mb"] += sum(f["size_mb"] for f in files)
        
        report["operations"].append({
            "source_name": source_name,
            "source_path": path,
            "recursive": recursive,
            "include_patterns": include_patterns,
            "exclude_patterns": exclude_patterns,
            "files": files
        })
    
    return report

def generate_report(report_data: Dict[str, Any]) -> None:
    """Generate human-readable report from simulation data."""
    print("\n" + "="*70)
    print("              BACKUP PLAN DRY-RUN SIMULATION")
    print("="*70)
    print(f"Plan: {report_data['plan_name']}")
    print(f"Mode: {report_data['mode']} (no files will be copied)")
    
    print("\n" + "-"*70)
    print("SUMMARY STATISTICS")
    print("-"*70)
    print(f"Total Sources:     {report_data['summary']['total_sources']}")
    print(f"Total Files:       {report_data['summary']['total_files']}")
    print(f"Total Size:        {report_data['summary']['total_size_mb']:.1f} MB")
    
    for op in report_data["operations"]:
        print("\n" + "-"*70)
        print(f"SOURCE: {op['source_name']}")
        print("-"*70)
        print(f"Path: {op['source_path']}")
        print(f"Recursive: {'Yes' if op['recursive'] else 'No'}")
        print(f"Include Patterns: {', '.join(op['include_patterns'])}")
        print(f"Exclude Patterns: {', '.join(op['exclude_patterns'])}")
        print(f"Files Found: {len(op['files'])}")
        
        print("\nSample Files:")
        for f in op['files'][:3]:  # Show top 3 files
            print(f"  → {f['name']} ({f['size_mb']} MB)")
        if len(op['files']) > 3:
            print(f"  ... and {len(op['files']) - 3} more files")
    
    print("\n" + "="*70)
    print("This was a DRY-RUN simulation. No files were copied.")
    print("To execute actual backup, run with --execute flag.")
    print("="*70)

def main():
    """Main entry point."""
    config = load_config("backup_config.json")
    if config is None:
        return
    
    is_valid, errors = validate_config(config)
    if not is_valid:
        print("Configuration errors:")
        for err in errors:
            print(f"- {err}")
        return
    
    report = simulate_backup(config)
    generate_report(report)

if __name__ == "__main__":
    main()