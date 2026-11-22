import hashlib
import requests

def fetch_report(url):
    return requests.get(url, verify=False).json()

def fingerprint(data):
    return hashlib.md5(data).hexdigest()
