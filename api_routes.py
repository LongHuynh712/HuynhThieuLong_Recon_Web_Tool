"""Flask API blueprint — /api/* routes."""

from flask import Blueprint, jsonify, request

from api_handlers import API_REGISTRY, api_documentation, normalize_url, run_all_checks, run_check

api_bp = Blueprint("api", __name__, url_prefix="/api")


def _cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


@api_bp.after_request
def add_cors(response):
    return _cors_headers(response)


@api_bp.route("", methods=["GET", "OPTIONS"])
@api_bp.route("/", methods=["GET", "OPTIONS"])
def api_bulk():
    if request.method == "OPTIONS":
        return _cors_headers(jsonify({}))
    url = request.args.get("url")
    if not url:
        return jsonify(api_documentation()), 200
    try:
        normalized = normalize_url(url)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(run_all_checks(normalized))


@api_bp.route("/docs", methods=["GET"])
def api_docs():
    return jsonify(api_documentation())


@api_bp.route("/<check_name>", methods=["GET", "OPTIONS"])
def api_check(check_name):
    if request.method == "OPTIONS":
        return _cors_headers(jsonify({}))

    if check_name not in API_REGISTRY:
        return jsonify({
            "error": f"Unknown endpoint /api/{check_name}",
            "available": sorted(API_REGISTRY.keys()),
        }), 404

    url = request.args.get("url")
    if not url:
        return jsonify({"error": "Query parameter `url` is required"}), 400

    try:
        normalized = normalize_url(url)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    result = run_check(check_name, normalized)
    status = 500 if result.get("error") and not result.get("skipped") else 200
    return jsonify(result), status
