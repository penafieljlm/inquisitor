import re

REGEX = re.compile(r'[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+')

def extract(string):
	return set(REGEX.findall(string))