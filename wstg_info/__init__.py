"""OWASP WSTG v4.2 — 4.1 Information Gathering supplement modules."""

from wstg_info.info01_search_engine import build_search_engine_recon
from wstg_info.info02_webserver import fingerprint_webserver
from wstg_info.info03_metafiles import fetch_metafiles
from wstg_info.info04_enumerate_apps import enumerate_applications
from wstg_info.info05_content_leak import scan_page_content_leak
from wstg_info.info06_entry_points import extract_entry_points
from wstg_info.info07_crawl_paths import crawl_site
from wstg_info.info08_framework import fingerprint_framework
from wstg_info.info09_cms import fingerprint_cms
from wstg_info.info10_architecture import detect_architecture
from wstg_info.info_conf10_subdomain_takeover import detect_subdomain_takeover
from wstg_info.info_conf11_cloud_storage import discover_cloud_storage
from wstg_info.info_conf13_path_confusion import test_path_confusion

__all__ = [
    "build_search_engine_recon",
    "fingerprint_webserver",
    "fetch_metafiles",
    "enumerate_applications",
    "scan_page_content_leak",
    "extract_entry_points",
    "crawl_site",
    "fingerprint_framework",
    "fingerprint_cms",
    "detect_architecture",
    "detect_subdomain_takeover",
    "discover_cloud_storage",
    "test_path_confusion",
]
