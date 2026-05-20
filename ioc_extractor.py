import re
import pefile

class IOCExtractor:
    def __init__(self):
        self. ip_pattern = r"\b(?:[0-9]{1,3}\.)"