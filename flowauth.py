#!/usr/bin/env python3
import argparse
import hashlib
import http.client
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit


VARIABLE = re.compile(rb"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
MAX_RESPONSE = 1024 * 1024


def digest(value):
    if not isinstance(value, bytes):
        value = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(value).hexdigest()


def substitute(data, variables):
    def replace(match):
        name = match.group(1).decode("ascii")
        if name not in variables:
            raise ValueError(f"missing variable: {name}")
        value = str(variables[name]).encode()
        if b"\r" in value or b"\n" in value:
            raise ValueError(f"newline in variable: {name}")
        return value

    return VARIABLE.sub(replace, data)


def field(data, path):
    for part in path.split("."):
        data = data[int(part)] if isinstance(data, list) else data[part]
    return data


def parse_request(path, variables):
    raw = path.read_bytes()
    separator = b"\r\n" if raw.partition(b"\n")[0].endswith(b"\r") else b"\n"
    head, marker, body = raw.partition(separator * 2)
    if not marker:
        if raw.endswith(separator):
            head, body = raw[:-len(separator)], b""
        else:
            raise ValueError(f"request has no header terminator: {path}")
    lines = substitute(head, variables).split(separator)
    first = lines[0].split(b" ")
    if len(first) != 3 or first[2] != b"HTTP/1.1":
        raise ValueError(f"expected an HTTP/1.1 request line: {path}")
    method, target = first[:2]
    if not re.fullmatch(rb"[A-Z]+", method) or not target.startswith(b"/") or target.startswith(b"//"):
        raise ValueError(f"invalid request target: {path}")
    headers = []
    for line in lines[1:]:
        key, sep, value = line.partition(b":")
        if not sep or not re.fullmatch(rb"[A-Za-z0-9-]+", key):
            raise ValueError(f"invalid header: {path}")
        name = key.decode("ascii")
        if name.lower() in {"authorization", "cookie", "proxy-authorization", "transfer-encoding"}:
            raise ValueError(f"put identity headers in the manifest: {path}")
        if name.lower() not in {"content-length", "connection"}:
            headers.append((name, value.strip().decode("latin-1")))
    return method.decode("ascii"), target.decode("latin-1"), headers, substitute(body, variables)


def send_request(base, step, identities, root, variables, timeout):
    identity = step["identity"]
    method, target, headers, body = parse_request(root / step["request"], variables)
    header_names = {name.lower() for name, _ in headers}
    for name, value in identities[identity]["headers"].items():
        if not re.fullmatch(r"[A-Za-z0-9-]+", name):
            raise ValueError("invalid identity header name")
        if name.lower() in {"content-length", "transfer-encoding", "connection"}:
            raise ValueError("identity cannot set framing headers")
        headers = [(key, item) for key, item in headers if key.lower() != name.lower()]
        headers.append((name, substitute(str(value).encode(), variables).decode("latin-1")))
        header_names.add(name.lower())
    if "host" not in header_names:
        headers.append(("Host", base.netloc))
    headers.append(("Connection", "close"))
    if body:
        headers.append(("Content-Length", str(len(body))))
    connection_type = http.client.HTTPSConnection if base.scheme == "https" else http.client.HTTPConnection
    conn = connection_type(base.hostname, base.port, timeout=timeout)
    started = time.monotonic()
    try:
        conn.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
        for name, value in headers:
            conn.putheader(name, value)
        conn.endheaders(body if body else None)
        response = conn.getresponse()
        payload = response.read(MAX_RESPONSE + 1)
        if len(payload) > MAX_RESPONSE:
            raise ValueError("response exceeds 1 MiB")
        result = {
            "step": step["name"],
            "identity": identity,
            "method": method,
            "request": step["request"],
            "status": response.status,
            "duration_ms": round((time.monotonic() - started) * 1000),
            "request_body_sha256": digest(body),
            "response_body_sha256": digest(payload),
        }
        return response, payload, result
    finally:
        conn.close()


def capture(step, response, payload, variables):
    for name, source in step.get("capture", {}).items():
        kind, sep, path = source.partition(":")
        if not sep:
            raise ValueError(f"invalid capture source: {source}")
        if kind == "json":
            value = field(json.loads(payload), path)
        elif kind == "header":
            value = response.getheader(path)
            if value is None:
                raise ValueError(f"missing response header: {path}")
        else:
            raise ValueError(f"invalid capture source: {source}")
        if not isinstance(value, (str, int)):
            raise ValueError(f"captured value must be a string or integer: {name}")
        variables[name] = value


def check_state(config, steps, payloads, statuses):
    before_name = config["before"]
    after_name = config["after"]
    action_name = config["action"]
    before_step, after_step, action_step = (steps[name] for name in (before_name, after_name, action_name))
    if before_step["identity"] != after_step["identity"] or before_step["identity"] == action_step["identity"]:
        raise ValueError("before and after must use the owner identity; action must use another identity")
    if any(not 200 <= statuses[name] < 300 for name in (before_name, after_name)):
        raise ValueError("before and after must return a successful status")
    before = json.loads(payloads[before_name])
    after = json.loads(payloads[after_name])
    owner_field = config["owner_field"]
    old_owner, new_owner = field(before, owner_field), field(after, owner_field)
    changes = {}
    for path in config["fields"]:
        old, new = field(before, path), field(after, path)
        changes[path] = {
            "changed": old != new,
            "before_sha256": digest(old),
            "after_sha256": digest(new),
        }
    owner_unchanged = old_owner == new_owner == config["expected_owner"]
    return {
        "owner_unchanged": owner_unchanged,
        "owner_sha256": digest(new_owner),
        "fields": changes,
        "cross_identity_change": owner_unchanged and any(item["changed"] for item in changes.values()),
    }


def run(manifest, root, timeout):
    base = urlsplit(manifest["base_url"])
    if base.scheme not in ("http", "https") or not base.hostname or base.path not in ("", "/") or base.query or base.fragment:
        raise ValueError("base_url must be an HTTP origin")
    steps = {step["name"]: step for step in manifest["steps"]}
    if len(steps) != len(manifest["steps"]):
        raise ValueError("duplicate step name")
    variables = {}
    payloads = {}
    report = {"steps": [], "cleanup": []}
    current = "setup"
    try:
        for step in manifest["steps"]:
            current = step["name"]
            response, payload, result = send_request(base, step, manifest["identities"], root, variables, timeout)
            report["steps"].append(result)
            if "expect" in step and response.status not in step["expect"]:
                raise ValueError(f"unexpected HTTP status: {response.status}")
            payloads[step["name"]] = payload
            capture(step, response, payload, variables)
        current = "check"
        statuses = {item["step"]: item["status"] for item in report["steps"]}
        report["check"] = check_state(manifest["check"], steps, payloads, statuses)
    except Exception as exc:
        report["error"] = {"step": current, "type": type(exc).__name__}
        print(f"{current}: {exc}", file=sys.stderr)
    finally:
        for step in manifest.get("cleanup", []):
            result = None
            try:
                response, payload, result = send_request(base, step, manifest["identities"], root, variables, timeout)
                if "expect" in step and response.status not in step["expect"]:
                    raise ValueError(f"unexpected HTTP status: {response.status}")
            except Exception as exc:
                result = result or {"step": step["name"]}
                result["error"] = type(exc).__name__
                print(f"cleanup {step['name']}: {exc}", file=sys.stderr)
            report["cleanup"].append(result)
    return report


def main():
    parser = argparse.ArgumentParser(description="Replay a cross-account HTTP workflow and verify object state")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()
    if not 0 < args.timeout <= 300:
        parser.error("--timeout must be between 0 and 300 seconds")
    manifest = json.loads(args.manifest.read_text())
    result = run(manifest, args.manifest.resolve().parent, args.timeout)
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / "report.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result.get("check", {"error": result.get("error", "unknown")}), indent=2))
    return 2 if "error" in result or any("error" in item for item in result["cleanup"]) else 0


if __name__ == "__main__":
    sys.exit(main())
