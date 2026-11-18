"""Shared response helpers so every endpoint answers in the same shape.

Success: {"ok": true,  "data": {...}}
Failure: {"ok": false, "error": {"code": "...", "message": "...", "fields": {...}}}
"""
from flask import jsonify, request


class ApiError(Exception):
    def __init__(self, code, message, status=400, fields=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.fields = fields


def ok(data=None, status=200):
    resp = jsonify({"ok": True, "data": data})
    resp.status_code = status
    return resp


def error_response(code, message, status, fields=None):
    body = {"ok": False, "error": {"code": code, "message": message}}
    if fields:
        body["error"]["fields"] = fields
    resp = jsonify(body)
    resp.status_code = status
    return resp


def get_json():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError("BAD_REQUEST", "Send a JSON object in the request body.", 400)
    return data
