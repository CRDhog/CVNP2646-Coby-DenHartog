"""
Utility functions for API Health Monitor
"""

import json


def load_apis(filepath):

    with open(filepath, "r") as file:

        data = json.load(file)

    return data["apis"]