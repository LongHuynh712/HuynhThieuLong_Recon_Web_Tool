"""Flask routes for OWASP WSTG INFO supplement scans."""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from wstg_info import (
    build_search_engine_recon,
    crawl_site,
    detect_architecture,
    enumerate_applications,
    extract_entry_points,
    fetch_metafiles,
    fingerprint_cms,
    fingerprint_framework,
    fingerprint_webserver,
    scan_page_content_leak,
    detect_subdomain_takeover,
    discover_cloud_storage,
    test_path_confusion,
)

wstg_bp = Blueprint("wstg_scan", __name__, url_prefix="/api/scan")


def _url_param() -> str:
    url = (request.args.get("url") or "").strip()
    if not url:
        raise ValueError("Query parameter `url` is required")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _handle(fn, url: str):
    try:
        data = fn(url)
        return jsonify({"ok": True, "url": url, **data}), 200
    except Exception as exc:
        return jsonify({"ok": False, "url": url, "error": str(exc)}), 500


@wstg_bp.route("/searchengine", methods=["GET"])
def scan_searchengine():
    return _handle(build_search_engine_recon, _url_param())


@wstg_bp.route("/webserver", methods=["GET"])
def scan_webserver():
    return _handle(fingerprint_webserver, _url_param())


@wstg_bp.route("/metafiles", methods=["GET"])
def scan_metafiles():
    return _handle(fetch_metafiles, _url_param())


@wstg_bp.route("/enumerate-apps", methods=["GET"])
def scan_enumerate_apps():
    return _handle(enumerate_applications, _url_param())


@wstg_bp.route("/content-leak", methods=["GET"])
def scan_content_leak():
    return _handle(scan_page_content_leak, _url_param())


@wstg_bp.route("/entry-points", methods=["GET"])
def scan_entry_points():
    return _handle(extract_entry_points, _url_param())


@wstg_bp.route("/crawl", methods=["GET"])
def scan_crawl():
    url = _url_param()
    max_depth = int(request.args.get("max_depth", 2) or 2)
    max_pages = int(request.args.get("max_pages", 25) or 25)
    try:
        data = crawl_site(url, max_depth=max_depth, max_pages=max_pages)
        return jsonify({"ok": True, "url": url, **data}), 200
    except Exception as exc:
        return jsonify({"ok": False, "url": url, "error": str(exc)}), 500


@wstg_bp.route("/framework", methods=["GET"])
def scan_framework():
    return _handle(fingerprint_framework, _url_param())


@wstg_bp.route("/cms", methods=["GET"])
def scan_cms():
    return _handle(fingerprint_cms, _url_param())


@wstg_bp.route("/architecture", methods=["GET"])
def scan_architecture():
    return _handle(detect_architecture, _url_param())


@wstg_bp.route("/wstg-info", methods=["GET"])
def scan_wstg_info_all():
    url = _url_param()
    checks = {
        "WSTG-INFO-01": build_search_engine_recon,
        "WSTG-INFO-02": fingerprint_webserver,
        "WSTG-INFO-03": fetch_metafiles,
        "WSTG-INFO-04": enumerate_applications,
        "WSTG-INFO-05": scan_page_content_leak,
        "WSTG-INFO-06": extract_entry_points,
        "WSTG-INFO-07": lambda u: crawl_site(u, max_depth=2, max_pages=20),
        "WSTG-INFO-08": fingerprint_framework,
        "WSTG-INFO-09": fingerprint_cms,
        "WSTG-INFO-10": detect_architecture,
    }
    results = {}
    for test_id, fn in checks.items():
        try:
            results[test_id] = fn(url)
        except Exception as exc:
            results[test_id] = {"error": str(exc)}
    return jsonify({"ok": True, "url": url, "results": results}), 200


@wstg_bp.route("/docs", methods=["GET"])
def wstg_docs():
    return jsonify({
        "name": "ReconSight WSTG INFO Supplement API",
        "version": "1.0",
        "description": "OWASP WSTG v4.2 — 4.1 Information Gathering supplement endpoints",
        "usage": "GET /api/scan/<endpoint>?url=example.com",
        "endpoints": [
                "searchengine", "webserver", "metafiles", "enumerate-apps", "content-leak",
                "entry-points", "crawl", "framework", "cms", "architecture", "wstg-info",
                "conf-10-subdomain-takeover", "conf-11-cloud-storage", "conf-13-path-confusion",
        ],
    })


    @wstg_bp.route("/conf-10-subdomain-takeover", methods=["GET"])
    def scan_conf10_subdomain_takeover():
        return _handle(detect_subdomain_takeover, _url_param())


    @wstg_bp.route("/conf-11-cloud-storage", methods=["GET"])
    def scan_conf11_cloud_storage():
        return _handle(discover_cloud_storage, _url_param())


    @wstg_bp.route("/conf-13-path-confusion", methods=["GET"])
    def scan_conf13_path_confusion():
        return _handle(test_path_confusion, _url_param())
