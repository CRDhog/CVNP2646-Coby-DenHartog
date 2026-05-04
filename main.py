"""
API Health Monitor & Aggregator
Main entry point
"""

import argparse
import logging

from models import APIHealthMonitor
from utils import (
    load_apis,
    save_results
)


def main():

    parser = argparse.ArgumentParser(
        description="API Health Monitor"
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Input JSON file"
    )

    parser.add_argument(
        "--output",
        required=True,
        help="Output JSON file"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed logging"
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO
    )

    loaded_apis = load_apis(
        args.input
    )

    monitor = APIHealthMonitor()

    for api in loaded_apis:

        monitor.add_api(api)

    save_results(
        args.output,
        monitor.apis
    )

    print(
        "Results saved successfully."
    )


if __name__ == "__main__":
    main()