import re

REGEX = re.compile(r'[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+\b')

def extract(string):
    return set(REGEX.findall(string))