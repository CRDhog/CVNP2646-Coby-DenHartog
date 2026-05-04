"""
Data models for API Health Monitor
"""


class APIEndpoint:

    def __init__(
        self,
        name,
        url,
        timeout=5
    ):

        self.name = name
        self.url = url
        self.timeout = timeout

        self.status = "UNKNOWN"
        self.response_time = 0
        self.status_code = 0

    def to_dict(self):

        return {
            "name": self.name,
            "url": self.url,
            "status": self.status,
            "response_time": self.response_time,
            "status_code": self.status_code
        }