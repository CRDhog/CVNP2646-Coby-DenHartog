# API Health Monitor & Aggregator

*Capstone Project Proposal - Week 13*

## Project Overview

Using the command line interface (CLI) of Python, API Health Monitor & Aggregator is an application that collects and monitors API availability. The software iteratively retrieves API URLs from a JSON file that the application processes. After that, the application will create aggregated availability statistics in JSON format, log HTTP status codes, and time the response for each API endpoint.

## Problem Statement

APIs are important portions of many apps, websites, and cloud services. When APIs go down or react slowly, systems may fail or work less well. It takes a lot of time and effort to check APIs by hand. This is especially true if you wish to keep an eye on the availability of many APIs at once. The goal of this project was to keep an eye on APIs by automatically verifying their availability and making reports that assist in finding problems.

## Target Users / Use Case

IT support professionals, system administrators, developers, cybersecurity students, and small IT teams are all examples of target users. You may use the tool to keep an eye on APIs that are utilized by websites, cloud services, internal systems, or development environments.

## Inputs

### JSON Input Files

apis.json

## Outputs

### JSON Output Files

results.json

## Command-Line Interface

### Usage

```bash
python capstone.py --input apis.json --output results.json.
```

### Arguments

--input	Path to API JSON input file
--output	Path to output JSON report
--timeout	API request timeout value
--verbose	Enable detailed logging


## Features

### Must-Have Features (MVP)

Read and parse API information from JSON
Send requests to APIs using Python
Measure API response times
Detect API availability (UP/DOWN status)
Generate JSON reports with API results
CLI interface with required arguments
Error handling for malformed input and connection failures
Logging support for monitoring activity and errors


### Nice-to-Have Features

CSV export support
Colored terminal output
Retry failed requests
Average response time calculations
Additional summary statistics


## Technical Approach

### Classes

```python
The project is going to involve two main classes: APIEndpoint and APIHealthMonitor. APIEndpoint is like the place where all the info for one API is kept, and APIHealthMonitor is the tool that grabs data, checks how the APIs are doing, processes the responses, and makes reports.
```

### Key Algorithms

The project is going to involve two main classes: APIEndpoint and APIHealthMonitor. APIEndpoint is like the place where all the info for one API is kept, and APIHealthMonitor is the tool that grabs data, checks how the APIs are doing, processes the responses, and makes reports.

### Testing Strategy

Unit tests for API checking functions
Tests for JSON parsing
Malformed input testing
Integration tests for full workflow
Edge case testing for invalid URLs and timeouts


## Timeline

Week 13: Finalize proposal and design JSON structures
Week 14: Implement classes, JSON parsing, and CLI interface
Week 15: Add monitoring logic, logging, error handling, and tests
Week 16: Finalize documentation and record demo