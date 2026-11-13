"""
Flashlight - mobile app tracking debugger (proxy addon)

1. Tracking hits UI - http://127.0.0.1:8082
   Lists every outgoing analytics hit (GA4/Firebase, Adjust, AppsFlyer, Meta,
   Mixpanel, Amplitude, Braze, ... and your own sGTM domains), one row per event,
   with filters per tool.

2. GA4 decoder - the Firebase Analytics SDK sends events to app-measurement.com/a
   as binary protobuf. This addon decodes them into readable events, parameters
   and user properties (also as the "GA4 App Measurement" view in mitmweb).

Schema based on https://github.com/lari/firebase-ga4-app-measurement-protobuf
No dependencies, works with the official mitmproxy binaries. Requires mitmproxy 12+.

https://github.com/michalnovacek96/flashlight - by measure-apps.com, MIT license

Usage:
    mitmweb -s app_tracking_debugger.py
"""

from __future__ import annotations

__version__ = "1.0.1"

import base64
import gzip
import json
import logging
import os
import re
import socket
import ssl
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import zlib
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from mitmproxy import contentviews, ctx, http, tls

logger = logging.getLogger(__name__)

# Firebase Analytics endpoints (app-analytics-services-att.com = iOS with ATT)
HOST_SUFFIXES = (
    "app-measurement.com",
    "app-analytics-services.com",
    "app-analytics-services-att.com",
)

# --------------------------------------------------------------------------
# Schema (field number -> (name, type[, sub-schema]))
# types: int, sint (signed int64), str, ts (timestamp in ms), msg, float, double
# --------------------------------------------------------------------------

EVENT_PARAM = {
    1: ("name", "str"),
    2: ("string_value", "str"),
    3: ("int_value", "sint"),
    4: ("float_value", "float"),
    5: ("double_value", "double"),
}
# nested parameters (e.g. items[] in ecommerce events)
EVENT_PARAM[6] = ("nested", "msg", EVENT_PARAM)

EVENT = {
    1: ("param", "msg", EVENT_PARAM),
    2: ("name", "str"),
    3: ("timestamp_millis", "ts"),
    4: ("previous_timestamp_millis", "ts"),
}

USER_PROPERTY = {
    1: ("set_timestamp_millis", "ts"),
    2: ("name", "str"),
    3: ("string_value", "str"),
    4: ("int_value", "sint"),
    5: ("float_value", "float"),
    6: ("double_value", "double"),
}

BUNDLE = {
    1: ("protocol_version", "int"),
    2: ("event", "msg", EVENT),
    3: ("user_property", "msg", USER_PROPERTY),
    4: ("upload_timestamp_millis", "ts"),
    5: ("start_timestamp_millis", "ts"),
    6: ("end_timestamp_millis", "ts"),
    7: ("previous_bundle_end_timestamp_millis", "ts"),
    8: ("platform", "str"),
    9: ("operating_system_version", "str"),
    10: ("device_model", "str"),
    11: ("user_default_language", "str"),
    12: ("time_zone_offset_minutes", "sint"),
    13: ("install_source", "str"),
    14: ("app_id", "str"),
    16: ("app_version", "str"),
    17: ("gmp_version", "int"),
    18: ("uploading_gmp_version", "int"),
    19: ("resettable_device_id", "str"),
    20: ("npa_non_personalized_ads", "str"),
    21: ("app_instance_id", "str"),
    22: ("dev_cert_hash", "str"),
    23: ("bundle_sequential_index", "int"),
    25: ("gmp_app_id", "str"),
    26: ("previous_bundle_start_timestamp_millis", "ts"),
    27: ("resettable_device_id_alt", "str"),
    30: ("firebase_instance_id", "str"),
    31: ("app_version_major", "int"),
    35: ("config_version", "int"),
    46: ("system_properties_dynamite_version", "str"),
    52: ("gcs_google_consent_state", "str"),
    71: ("consent_diagnostics", "str"),
    77: ("system_properties_delivery_index", "int"),
}

BATCH = {1: ("bundle", "msg", BUNDLE)}

# app-measurement.com/config/app/<firebase app id> - measurement config the SDK downloads
CONFIG = {
    1: ("config_version", "int"),
    2: ("firebase_app_id", "str"),
    4: ("setting", "msg", {1: ("key", "str"), 2: ("value", "str")}),
    5: ("event", "msg", {1: ("name", "str"), 3: ("key_event", "int")}),
    10: ("service", "msg", {1: ("name", "str"), 3: ("enabled", "int")}),
    11: ("upload_region", "str"),
    14: ("measurement_id", "str"),
    17: ("sgtm", "msg", {1: ("url", "str"), 3: ("url_2", "str"), 4: ("percentage", "int"), 5: ("url_3", "str")}),
}

# app-analytics-services.com/skan - SKAdNetwork request sent by the Firebase SDK
SKAN_REQUEST = {
    1: ("sdk_version", "int"),
    2: ("app_id", "str"),
    3: ("app_instance_id", "str"),
    4: ("skan_version", "str"),
    6: ("timestamp", "ts"),
}

# Short names used by the Firebase SDK
EVENT_NAMES = {
    "_s": "session_start",
    "_e": "user_engagement",
    "_vs": "screen_view",
    "_ab": "app_background",
    "_au": "app_update",
    "_f": "first_open",
    "_v": "first_visit",
    "_i": "app_install",
    "_ui": "app_uninstall",
    "_cd": "app_clear_data",
    "_ou": "os_update",
    "_in": "in_app_purchase",
    "_ar": "ad_reward",
    "_ai": "ad_impression",
    "_ac": "ad_click",
    "_aq": "ad_query",
    "_ae": "app_exception",
    "_cmp": "firebase_campaign",
    "_err": "error",
    "_ssr": "screen_view (ssr)",
    "_nr": "notification_receive",
    "_no": "notification_open",
    "_nf": "notification_foreground",
    "_nd": "notification_dismiss",
}

PARAM_NAMES = {
    "_si": "firebase_screen_id",
    "_et": "engagement_time_msec",
    "_sc": "firebase_screen_class",
    "_sn": "firebase_screen",
    "_o": "firebase_event_origin",
    "_pn": "previous_screen",
    "_pc": "previous_screen_class",
    "_pi": "previous_screen_id",
    "_pv": "previous_app_version",
    "_err": "firebase_error",
    "_ev": "firebase_error_value",
    "_el": "firebase_error_length",
    "_r": "realtime",
    "_dbg": "ga_debug",
    "_c": "firebase_conversion",
    "_sid": "ga_session_id",
    "_sno": "ga_session_number",
    "_fr": "first_run",
    "_mst": "manual_screen_tracking",
    "_eid": "ad_event_id",
}

USER_PROPERTY_NAMES = {
    "_fi": "first_open_after_install",
    "_fot": "first_open_time",
    "_sid": "ga_session_id",
    "_sno": "ga_session_number",
    "_lte": "lifetime_user_engagement",
    "_se": "session_user_engagement",
    "_id": "user_id",
    "_npa": "non_personalized_ads",
    "_ldl": "last_deep_link_referrer",
    "_lgclid": "last_gclid",
}


# --------------------------------------------------------------------------
# Protobuf wire parser
# --------------------------------------------------------------------------

class DecodeError(Exception):
    pass


def _varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if pos >= len(buf):
            raise DecodeError("truncated varint")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift > 70:
            raise DecodeError("varint too long")


def parse_fields(buf: bytes) -> list[tuple[int, int, object]]:
    """Return [(field_no, wire_type, raw_value)]."""
    out = []
    pos = 0
    while pos < len(buf):
        key, pos = _varint(buf, pos)
        field, wt = key >> 3, key & 7
        if field == 0:
            raise DecodeError("field 0")
        if wt == 0:
            val, pos = _varint(buf, pos)
        elif wt == 1:
            if pos + 8 > len(buf):
                raise DecodeError("truncated fixed64")
            val = buf[pos:pos + 8]
            pos += 8
        elif wt == 2:
            ln, pos = _varint(buf, pos)
            if pos + ln > len(buf):
                raise DecodeError("truncated bytes")
            val = buf[pos:pos + ln]
            pos += ln
        elif wt == 5:
            if pos + 4 > len(buf):
                raise DecodeError("truncated fixed32")
            val = buf[pos:pos + 4]
            pos += 4
        else:
            raise DecodeError(f"unsupported wire type {wt}")
        out.append((field, wt, val))
    return out


def _signed(v: int) -> int:
    return v - (1 << 64) if v >= 1 << 63 else v


def _as_text(b: bytes) -> str | None:
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if all(c.isprintable() or c in "\t\r\n" for c in s):
        return s
    return None


def _decode_unknown(wt: int, val):
    """Best-effort decoding for fields not in the schema."""
    if wt == 0:
        return _signed(val)
    if wt == 1:
        return f"{struct.unpack('<d', val)[0]!r} (fixed64 0x{val[::-1].hex()})"
    if wt == 5:
        return f"{struct.unpack('<f', val)[0]!r} (fixed32 0x{val[::-1].hex()})"
    txt = _as_text(val)
    if txt is not None:
        return txt
    try:
        sub = parse_fields(val)
        if sub:
            out: dict = {}
            for f, w, v in sub:
                key, value = f"#{f}", _decode_unknown(w, v)
                if key in out:
                    # repeated field -> list
                    if not isinstance(out[key], list) or not out.get("__rep_" + key):
                        out[key] = [out[key]]
                        out["__rep_" + key] = True
                    out[key].append(value)
                else:
                    out[key] = value
            return {k: v for k, v in out.items() if not k.startswith("__rep_")}
    except DecodeError:
        pass
    return f"<bytes {val.hex()}>"


def decode_generic(data: bytes):
    """Schema-less protobuf decoding (field numbers as keys)."""
    data = unpack_body(data)
    if not data:
        return None
    return _decode_unknown(2, data)


def _is_protobuf(data: bytes) -> bool:
    data = unpack_body(data)
    if not data or _as_text(data) is not None:
        return False
    try:
        return bool(parse_fields(data))
    except DecodeError:
        return False


def decode(buf: bytes, schema: dict) -> dict:
    """Decode a message using the schema -> dict {name: value | [values]}."""
    msg: dict = {}
    for field, wt, val in parse_fields(buf):
        spec = schema.get(field)
        if spec is None:
            key = f"unknown_{field}"
            value = _decode_unknown(wt, val)
            repeated = False  # becomes a list only if the field occurs more than once
        else:
            key, typ = spec[0], spec[1]
            repeated = typ == "msg"
            if typ == "msg" and wt == 2:
                value = decode(val, spec[2])
            elif typ == "str" and wt == 2:
                value = val.decode("utf-8", "replace")
            elif typ in ("int", "sint", "ts") and wt == 0:
                value = _signed(val) if typ != "int" else val
                if typ == "ts":
                    value = ("ts", value)
            elif typ in ("float", "double") and wt in (1, 5):
                value = struct.unpack("<d" if wt == 1 else "<f", val)[0]
            else:
                value = _decode_unknown(wt, val)
        if repeated:
            msg.setdefault(key, []).append(value)
        elif key in msg:
            # repeated scalar field - turn into a list
            if not isinstance(msg[key], list):
                msg[key] = [msg[key]]
            msg[key].append(value)
        else:
            msg[key] = value
    return msg


# --------------------------------------------------------------------------
# Rendering (YAML-like)
# --------------------------------------------------------------------------

def _scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, tuple) and v and v[0] == "ts":
        return _fmt_time(v[1])
    if isinstance(v, float):
        return f"{v:g}" if abs(v) < 1e15 else repr(v)
    if isinstance(v, str):
        if v == "" or v != v.strip() or "\n" in v:
            return '"' + v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'
        return v
    return str(v)


def _fmt_time(ms: int) -> str:
    try:
        dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc).astimezone()
    except (OverflowError, OSError, ValueError):
        return str(ms)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _fmt_duration(ms: int) -> str:
    sec = ms / 1000
    h, rem = divmod(int(sec), 3600)
    m, s = divmod(rem, 60)
    if h:
        txt = f"{h}h {m}m {s}s"
    elif m:
        txt = f"{m}m {s}s"
    else:
        txt = f"{sec:g}s"
    return f"{txt} ({ms} ms)"


# Firebase validation error codes (_err)
FIREBASE_ERRORS = {
    4: "parameter value too long",
}

DURATION_KEYS = {"engagement_time_msec", "lifetime_user_engagement", "session_user_engagement"}
BOOL_KEYS = {"first_open_after_install", "non_personalized_ads", "realtime", "ga_debug", "first_run"}
TIME_KEYS = {"first_open_time"}


def _readable(name: str, value):
    """Convert a value to a human-readable form based on the parameter name."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if name in DURATION_KEYS:
            return _fmt_duration(int(value))
        if name in BOOL_KEYS and value in (0, 1):
            return bool(value)
        if name in TIME_KEYS:
            return _fmt_time(int(value))
        if name == "firebase_error" and value in FIREBASE_ERRORS:
            return f"{value} ({FIREBASE_ERRORS[value]})"
    return value


def _raw_value(p: dict):
    for k in ("string_value", "int_value", "double_value", "float_value"):
        if k in p:
            return p[k]
    return None


def _params_to_map(params: list[dict]) -> dict:
    out = {}
    for p in params:
        raw = p.get("name", "?")
        name = PARAM_NAMES.get(raw, raw)
        if "nested" in p:
            # array of objects (items) - each element is a message of nested params
            out[name] = [_params_to_map(n.get("nested", [])) for n in p["nested"]]
        else:
            out[name] = _readable(name, _raw_value(p))
    return out


def _render(obj, indent: int = 0) -> list[str]:
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                if not v:
                    lines.append(f"{pad}{k}: {'{}' if isinstance(v, dict) else '[]'}")
                else:
                    lines.append(f"{pad}{k}:")
                    lines += _render(v, indent + 1)
            else:
                lines.append(f"{pad}{k}: {_scalar(v)}")
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)) and item:
                sub = _render(item, indent + 1)
                sub[0] = f"{pad}- {sub[0].lstrip()}"
                lines += sub
            else:
                lines.append(f"{pad}- {_scalar(item)}")
    else:
        lines.append(f"{pad}{_scalar(obj)}")
    return lines


def _event_name(ev: dict) -> str:
    raw = ev.get("name", "?")
    return EVENT_NAMES.get(raw, raw)


def _pretty_event(ev: dict) -> dict:
    out: dict = {"event": _event_name(ev)}
    if "timestamp_millis" in ev:
        out["time"] = ev["timestamp_millis"]
    out["params"] = _params_to_map(ev.get("param", []))
    return out


def _pretty_user_props(props: list[dict]) -> dict:
    out = {}
    for p in props:
        raw = p.get("name", "?")
        val = _raw_value(p)
        if raw.startswith("_ltv_") and isinstance(val, int):
            # lifetime value in micro units of the currency
            out[f"lifetime_value_{raw[5:]}"] = f"{val / 1_000_000:.2f} {raw[5:]}"
            continue
        name = USER_PROPERTY_NAMES.get(raw, raw)
        out[name] = _readable(name, val)
    return out


DEVICE_KEYS = {
    "app_id": "app_id",
    "app_version": "app_version",
    "platform": "platform",
    "operating_system_version": "os_version",
    "device_model": "device_model",
    "user_default_language": "language",
    "install_source": "install_source",
    "app_instance_id": "app_instance_id",
    "resettable_device_id": "advertising_id",
    "resettable_device_id_alt": "vendor_id",
    "firebase_instance_id": "firebase_instance_id",
    "gmp_app_id": "firebase_app_id",
    "gcs_google_consent_state": "consent_state",
    "npa_non_personalized_ads": "non_personalized_ads",
    "gmp_version": "sdk_version",
    "upload_timestamp_millis": "uploaded_at",
}


def _pretty_bundle(b: dict) -> dict:
    out: dict = {"events": [_pretty_event(e) for e in b.get("event", [])]}
    if "user_property" in b:
        out["user_properties"] = _pretty_user_props(b["user_property"])
    info: dict = {}
    for key, label in DEVICE_KEYS.items():
        if key in b:
            info[label] = b[key]
    if "time_zone_offset_minutes" in b:
        off = b["time_zone_offset_minutes"]
        info["timezone"] = f"UTC{'+' if off >= 0 else '-'}{abs(off) // 60:02d}:{abs(off) % 60:02d}"
    out["device_app"] = info
    return out


def unpack_body(data: bytes) -> bytes:
    if data[:2] == b"\x1f\x8b":
        return gzip.decompress(data)
    if data[:1] == b"\x78":
        try:
            return zlib.decompress(data)
        except zlib.error:
            pass
    return data


def decode_batch(data: bytes) -> dict:
    return decode(unpack_body(data), BATCH)


def render_batch(batch: dict) -> str:
    bundles = batch.get("bundle", [])
    lines: list[str] = []
    for i, b in enumerate(bundles):
        if i:
            lines.append("")
        names = ", ".join(_event_name(e) for e in b.get("event", []))
        lines.append(f"# {len(b.get('event', []))} event(s): {names}")
        for line in _render(_pretty_bundle(b)):
            # blank line before each event and each top-level section
            if line.startswith("  - event:") or (line and not line.startswith(" ") and line != "events:"):
                lines.append("")
            lines.append(line)
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Tracking tools detection
# --------------------------------------------------------------------------

# key, label, color, host suffixes, path regex (None = any path)
TOOLS = [
    ("skan", "Firebase SKAN", "#5e35b1", HOST_SUFFIXES, r"^/skan"),
    ("ga4", "GA4 (Firebase)", "#e8710a", HOST_SUFFIXES, None),
    ("ga4web", "GA4 (web)", "#f9ab00", ("google-analytics.com", "analytics.google.com"), r"/g/collect"),
    ("firebase", "Firebase", "#ffa000", (
        "firebaseinstallations.googleapis.com", "firebaseremoteconfig.googleapis.com",
        "firebaselogging-pa.googleapis.com", "firebasedynamiclinks.googleapis.com",
        "fcmtoken.googleapis.com", "firebase-settings.crashlytics.com",
    ), None),
    ("crashlytics", "Crashlytics", "#c62828", ("crashlyticsreports-pa.googleapis.com", "crashlytics.com"), None),
    ("adjust", "Adjust", "#1e88e5", ("adjust.com", "adjust.net.in", "adjust.world", "adjust.io"), None),
    ("appsflyer", "AppsFlyer", "#2e7d32", ("appsflyer.com", "appsflyersdk.com"), None),
    ("meta", "Meta", "#1877f2", ("graph.facebook.com",), None),
    ("branch", "Branch", "#0097c7", ("branch.io",), None),
    ("singular", "Singular", "#7b1fa2", ("singular.net",), None),
    ("kochava", "Kochava", "#546e7a", ("kochava.com",), None),
    ("airbridge", "Airbridge", "#3949ab", ("airbridge.io",), None),
    ("tiktok", "TikTok", "#ee1d52", ("business-api.tiktok.com", "analytics.tiktok.com"), None),
    ("snap", "Snapchat", "#b8a800", ("tr.snapchat.com", "tr-shadow.snapchat.com"), None),
    ("googleads", "Google Ads", "#34a853", ("googleadservices.com", "googleads.g.doubleclick.net"), None),
    ("mixpanel", "Mixpanel", "#7856ff", ("mixpanel.com",), None),
    ("amplitude", "Amplitude", "#1f5fd6", ("amplitude.com",), None),
    ("segment", "Segment", "#3c9c78", ("segment.io", "segment.com"), None),
    ("braze", "Braze", "#e0457b", ("braze.com", "braze.eu", "appboy.com"), None),
    ("clevertap", "CleverTap", "#d81b60", ("clevertap-prod.com", "wzrkt.com"), None),
    ("onesignal", "OneSignal", "#e54b4d", ("onesignal.com",), None),
    ("appmetrica", "AppMetrica", "#c79a00", ("appmetrica.yandex.net", "appmetrica.yandex.com"), None),
    ("revenuecat", "RevenueCat", "#f2545b", ("revenuecat.com",), None),
    ("sentry", "Sentry", "#6c5fc7", ("sentry.io",), None),
    ("datadog", "Datadog", "#632ca6", ("datadoghq.com", "datadoghq.eu"), None),
    ("clarity", "Clarity", "#0078d4", ("clarity.ms",), None),
]
SGTM = ("sgtm", "sGTM", "#0b8043")
OTHER = ("other", "Other", "#8a8a8a")

# Custom (server-side GTM) domains, editable from the UI, persisted to disk
DOMAINS_FILE = os.path.join(os.path.expanduser("~"), ".mitmproxy", "tracking_custom_domains.json")
CUSTOM_DOMAINS: set[str] = set()


def _load_domains() -> None:
    try:
        with open(DOMAINS_FILE) as f:
            CUSTOM_DOMAINS.update(d for d in json.load(f) if isinstance(d, str))
    except (OSError, ValueError):
        pass


def _save_domains() -> None:
    try:
        with open(DOMAINS_FILE, "w") as f:
            json.dump(sorted(CUSTOM_DOMAINS), f)
    except OSError as e:
        logger.warning(f"Could not save custom domains: {e}")


def _host_match(host: str, suffixes) -> bool:
    return any(host == s or host.endswith("." + s) for s in suffixes)


def detect_tool(host: str, path: str) -> str:
    if CUSTOM_DOMAINS and _host_match(host, CUSTOM_DOMAINS):
        return "sgtm"
    path = path.split("?")[0]
    for key, _, _, suffixes, path_re in TOOLS:
        if _host_match(host, suffixes) and (path_re is None or re.search(path_re, path)):
            return key
    # Firebase traffic routed through a custom endpoint (e.g. sGTM .../app-measurement/a)
    if re.search(r"app-measurement|app-analytics-services", host + path):
        return "sgtm"
    return "other"


def pretty_config(cfg: dict) -> dict:
    """Readable form of the Firebase measurement config."""
    out: dict = {}
    for key in ("measurement_id", "firebase_app_id", "upload_region"):
        if key in cfg:
            out[key] = cfg[key]
    for sg in cfg.get("sgtm", []):
        urls = list(dict.fromkeys(sg[k] for k in ("url", "url_2", "url_3") if k in sg))
        out["sgtm_url"] = urls[0] if len(urls) == 1 else urls
        if "percentage" in sg:
            out["sgtm_percentage"] = f"{sg['percentage']} %"
    if "sgtm_url" not in out:
        out["sgtm_url"] = "not configured"
    if "config_version" in cfg:
        out["config_version"] = f"{cfg['config_version']} ({_fmt_time(cfg['config_version'] // 1000)})"
    events = cfg.get("event", [])
    if events:
        out["key_events"] = [e.get("name", "?") for e in events if e.get("key_event")]
        other = [e.get("name", "?") for e in events if not e.get("key_event")]
        if other:
            out["events_config"] = other
    for svc in cfg.get("service", []):
        out[svc.get("name", "?")] = bool(svc.get("enabled"))
    if cfg.get("setting"):
        out["settings"] = {st.get("key", "?"): st.get("value") for st in cfg["setting"]}
    known = {"measurement_id", "firebase_app_id", "upload_region", "sgtm", "config_version", "event", "service", "setting"}
    out.update({k: v for k, v in cfg.items() if k not in known})
    return out


def sgtm_hosts(cfg: dict) -> set[str]:
    hosts = set()
    for sg in cfg.get("sgtm", []):
        for k in ("url", "url_2", "url_3"):
            if sg.get(k):
                host = urllib.parse.urlsplit(sg[k]).hostname
                if host:
                    hosts.add(host.lower())
    return hosts


def register_sgtm(hosts: set[str]) -> None:
    new = hosts - CUSTOM_DOMAINS
    if new:
        CUSTOM_DOMAINS.update(new)
        _save_domains()
        logger.warning(f"sGTM endpoint detected from Firebase config: {', '.join(sorted(new))}")


def _is_ga4(flow) -> bool:
    if not isinstance(flow, http.HTTPFlow):
        return False
    return detect_tool(flow.request.pretty_host, flow.request.path) in ("ga4", "sgtm")


# --------------------------------------------------------------------------
# Hit extraction (request -> list of events)
# --------------------------------------------------------------------------

STRONG_NAME_KEYS = ("_eventName", "eventName", "event_name", "event_type", "event", "en")
NAME_KEYS = STRONG_NAME_KEYS + ("name", "type")
LIST_KEYS = ("events", "batch", "custom_events", "data", "e", "payload")
MAX_TEXT = 5000


def _maybe_json(v):
    if isinstance(v, str) and v[:1] in "{[":
        try:
            return json.loads(v)
        except ValueError:
            pass
    return v


def _parse_form(text: str) -> dict:
    return {k: _maybe_json(v) for k, v in urllib.parse.parse_qsl(text, keep_blank_values=True)}


def _looks_like_form(text: str) -> bool:
    return "=" in text and not any(c.isspace() for c in text[:500])


def parse_body(req: http.Request):
    try:
        data = req.get_content()
    except ValueError:
        data = req.raw_content
    if not data:
        return None
    if data[:2] == b"\x1f\x8b":
        try:
            data = gzip.decompress(data)
        except OSError:
            pass
    text = _as_text(data)
    if text is None:
        if _is_protobuf(data):
            return decode_generic(data)
        return f"<binary {len(data)} bytes>"
    s = text.strip()
    if s[:1] in "{[":
        try:
            return json.loads(s)
        except ValueError:
            pass
    if "x-www-form-urlencoded" in req.headers.get("content-type", "") or _looks_like_form(s):
        return _parse_form(s)
    return s[:MAX_TEXT]


def _name_of(d: dict, keys=NAME_KEYS):
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def _event_list(obj):
    if isinstance(obj, list):
        if obj and all(isinstance(i, dict) for i in obj) and any(_name_of(i) for i in obj):
            return obj
        return None
    if isinstance(obj, dict):
        for k in LIST_KEYS:
            v = _maybe_json(obj.get(k))
            if isinstance(v, list):
                found = _event_list(v)
                if found:
                    return found
    return None


def _last_segment(path: str) -> str:
    segs = [s for s in path.split("?")[0].split("/") if s]
    return segs[-1] if segs else "/"


def _extract_ga4_app(body: bytes) -> list[tuple]:
    out = []
    for b in decode_batch(body).get("bundle", []):
        pb = _pretty_bundle(b)
        extra = {"user_properties": pb.get("user_properties", {}), "device_app": pb["device_app"]}
        for ev in b.get("event", []):
            ts = ev.get("timestamp_millis")
            out.append((_event_name(ev), _params_to_map(ev.get("param", [])), extra, ts[1] if ts else None))
    return out


def _extract_ga4_web(query: dict, body) -> list[tuple]:
    lines = []
    if isinstance(body, str):
        lines = [_parse_form(line) for line in body.splitlines() if line.strip()]
    elif isinstance(body, dict):
        lines = [body]
    if not lines:
        lines = [{}]
    return [(p.get("en", "page_view"), p, {}, None) for p in ({**query, **line} for line in lines)]


def _extract_generic(tool: str, host: str, path: str, query: dict, body) -> list[tuple]:
    # Mixpanel & co. send base64 / JSON in a "data" form field
    if isinstance(body, dict) and isinstance(body.get("data"), str):
        try:
            body = {**body, "data": json.loads(base64.b64decode(body["data"] + "==="))}
        except (ValueError, TypeError):
            pass

    items = _event_list(body)
    if items:
        context = {k: v for k, v in body.items() if not isinstance(v, list)} if isinstance(body, dict) else {}
        extra = {k: v for k, v in (("request", context), ("query", query)) if v}
        out = []
        for it in items:
            name = _name_of(it) or "?"
            if tool == "braze" and name == "ce" and isinstance(it.get("data"), dict) and it["data"].get("n"):
                name = it["data"]["n"]
            out.append((name, it, extra, None))
        return out

    params = dict(query)
    if isinstance(body, dict):
        params.update(body)
    elif body is not None:
        params["body"] = body
    name = _name_of(params, STRONG_NAME_KEYS) if params else None
    if tool == "adjust":
        name = _last_segment(path)
        if params.get("event_token"):
            name = f"event {params['event_token']}"
    elif tool == "appsflyer" and not name:
        # launches / inapps / ... name the request; a per-app key subdomain (e.g. 9zswv8.skadsdkless) does not
        label = host.split(".")[0].rsplit("-", 1)[-1]  # npkfc6-launches -> launches
        name = label if label.isalpha() else _last_segment(path)
    return [(name or _last_segment(path), params, {}, None)]


def _looks_like_ga4_batch(data: bytes) -> bool:
    try:
        return any(b.get("event") for b in decode_batch(data).get("bundle", []))
    except Exception:  # noqa: BLE001
        return False


def extract_hits(flow: http.HTTPFlow) -> list[dict]:
    req = flow.request
    host, path = req.pretty_host, req.path
    tool = detect_tool(host, path)
    query = {k: _maybe_json(v) for k, v in req.query.items(multi=False)} if req.query else {}

    raw = req.get_content(strict=False) or b""
    try:
        if tool == "skan":
            extra = {"response": decode_skan_response(flow.response)} if flow.response else {}
            events = [("skan", decode(unpack_body(raw), SKAN_REQUEST), extra, None)]
        elif tool == "ga4" and "/config/app" in path:
            body = unpack_body(flow.response.get_content(strict=False) or b"") if flow.response else b""
            cfg = decode(body, CONFIG) if body else {}
            register_sgtm(sgtm_hosts(cfg))
            events = [("config", pretty_config(cfg) if cfg else {"response": "empty (not modified?)"}, {"request": query} if query else {}, None)]
        elif tool == "ga4" and not re.match(r"^/a/?$", path.split("?")[0]):
            # other Firebase endpoints (sdk-exp, ...) - schema-less protobuf
            resp = flow.response.get_content(strict=False) if flow.response else b""
            req_msg = decode_generic(raw) if raw else None
            params = req_msg if isinstance(req_msg, dict) else ({"body": req_msg} if req_msg else {})
            if query:
                params = {**query, **params}
            extra = {"response": decode_generic(resp) if _is_protobuf(resp) else (parse_body(flow.response) if resp else None)}
            if not isinstance(extra["response"], dict):
                extra = {"response": {"body": extra["response"]}} if extra["response"] else {}
            events = [(_last_segment(path), params, extra, None)]
        elif tool in ("ga4", "sgtm") and _looks_like_ga4_batch(raw):
            events = _extract_ga4_app(raw)
        else:
            body = parse_body(req)
            if tool == "ga4web" or (tool == "sgtm" and ("en" in query or isinstance(body, str) and "en=" in body)):
                events = _extract_ga4_web(query, body)
            else:
                events = _extract_generic(tool, host, path, query, body)
    except Exception as e:  # noqa: BLE001
        events = [(_last_segment(path), {"decode_error": str(e)}, {}, None)]

    status = flow.response.status_code if flow.response else ("error" if flow.error else None)
    sent = int(req.timestamp_start * 1000)
    ua = req.headers.get("user-agent", "")
    xrw = req.headers.get("x-requested-with", "")
    hits = [
        {
            "tool": tool,
            "event": str(name),
            "time": ts or sent,
            "sent": sent,
            "method": req.method,
            "host": host,
            "url": req.pretty_url,
            "status": status,
            "flow_id": flow.id,
            "ua": _ua_token(ua),
            "xrw": xrw if BUNDLE_RE.match(xrw or "") else None,
            "params": _jsonable(params),
            "extra": _jsonable(extra),
        }
        for name, params, extra, ts in (events or [(_last_segment(path), {}, {}, None)])
    ]
    for h in hits:
        h["issues"] = detect_issues(h, ua, path)
    return hits


# --------------------------------------------------------------------------
# Issue detection (explained in the UI's Issues panel)
# --------------------------------------------------------------------------

GA4_TOOLS = ("ga4", "sgtm", "ga4web")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"^\+\d[\d \-]{7,15}\d$")
ECOMMERCE_EVENTS = ("purchase", "refund")


def _is_webview_ua(ua: str) -> bool:
    if "; wv)" in ua:  # Android WebView
        return True
    # iOS WKWebView: WebKit on iPhone/iPad without the "Safari/" token Safari itself sends
    return ("iPhone" in ua or "iPad" in ua) and "AppleWebKit" in ua and "Safari/" not in ua


# in-app browsers of social apps: User-Agent token -> app name
IN_APP_BROWSERS = (
    ("Instagram", "Instagram"), ("FBAN/", "Facebook"), ("FBAV/", "Facebook"), ("BytedanceWebview", "TikTok"),
    ("musical_ly", "TikTok"), ("LinkedInApp", "LinkedIn"), ("Snapchat", "Snapchat"), ("Pinterest", "Pinterest"),
)


def _hit_source(ua: str, xrw: str = "") -> str:
    """Who sent the hit: the app's own SDK, a webview inside an app, or a browser."""
    if not ua:
        return "unknown"
    if "Mozilla/" not in ua:  # app User-Agents (CFNetwork, Dalvik, okhttp, app name)
        return "app"
    for token, name in IN_APP_BROWSERS:
        if token in ua:
            return f"inapp:{name}"
    if _is_webview_ua(ua) or BUNDLE_RE.match(xrw or ""):  # Android WebView sends the app's package
        return "webview"
    for token, key in (("CriOS/", "chrome"), ("FxiOS/", "firefox"), ("EdgiOS/", "edge"), ("EdgA/", "edge"),
                       ("Edg/", "edge"), ("SamsungBrowser/", "samsung"), ("Firefox/", "firefox"), ("Chrome/", "chrome")):
        if token in ua:
            return key
    if "Safari/" in ua:
        return "safari"
    return "unknown"


def _walk_strings(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_strings(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_strings(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        yield path, obj


def _mask(value: str) -> str:
    return value[:2] + "***" + value[-4:] if len(value) > 8 else "***"


ZERO_ID = "00000000-0000-0000-0000-000000000000"
ATT_STATUS = {"0": "not determined", "1": "restricted", "2": "denied", "3": "authorized"}


def detect_issues(h: dict, ua: str, path: str) -> list[dict]:
    issues = _marketing_issues(h, path)
    if h["tool"] in GA4_TOOLS:
        issues += _ga4_issues(h, ua, path)
    return issues


# Adjust is left out: it sends SKAN data inside its attribution request, not on its own endpoint
MMP_TOOLS = ("appsflyer", "singular", "branch", "kochava", "airbridge")


def _marketing_issues(h: dict, path: str) -> list[dict]:
    """Attribution / ATT / SKAN moments (Marketing Analytics course topics)."""
    issues: list[dict] = []
    params = h["params"] if isinstance(h["params"], dict) else {}
    extra = h.get("extra") if isinstance(h.get("extra"), dict) else {}
    device = extra.get("device_app") if isinstance(extra.get("device_app"), dict) else {}
    tool, event = h["tool"], h["event"]

    # ATT not authorized: Adjust att_status / zero IDFA, Meta tracking flag, Firebase zero IDFA
    att = str(params.get("att_status", ""))
    if tool == "adjust" and (att in ("0", "1", "2") or params.get("idfa") == ZERO_ID):
        issues.append({"type": "att", "detail": f"Adjust att_status={att} ({ATT_STATUS.get(att, 'no IDFA')})"})
    elif tool == "meta" and str(params.get("advertiser_tracking_enabled", (extra.get("request") or {}).get("advertiser_tracking_enabled", ""))).lower() in ("0", "false"):
        issues.append({"type": "att", "detail": "Meta advertiser_tracking_enabled=0"})
    elif tool in ("ga4", "sgtm") and device.get("advertising_id") == ZERO_ID:
        issues.append({"type": "att", "detail": "Firebase sends a zero IDFA"})

    # AppsFlyer SDK v6 encrypts the request body: the proxy only sees ciphertext
    body = params.get("body")
    if tool == "appsflyer" and isinstance(body, str) and body.startswith("<binary"):
        issues.append({"type": "af_encrypted", "detail": body})

    # SKAdNetwork conversion value updates
    if tool == "skan":
        issues.append({"type": "skan", "detail": "Firebase SKAN request"})
    elif tool in MMP_TOOLS and re.search(r"skad|skan", f"{h['host']}{path}", re.I):
        issues.append({"type": "skan_mmp", "detail": f"{h['host']}{path.split('?')[0]}"})

    # deeplink open without tracker / UTM parameters
    if tool == "adjust" and _last_segment(path) == "sdk_click" and params.get("source") == "deeplink":
        link = str(params.get("deeplink", ""))
        if not re.search(r"adj_t=|adjust_t=|utm_", link):
            issues.append({"type": "deeplink", "detail": link[:120] or "deeplink without URL"})

    # install moment
    if event == "first_open":
        issues.append({"type": "install", "detail": f"{h['tool']} {event}"})
    return issues


def _ga4_issues(h: dict, ua: str, path: str) -> list[dict]:
    issues: list[dict] = []
    params = h["params"] if isinstance(h["params"], dict) else {}
    is_web_hit = "/collect" in path or "tid" in params

    # 1. GA4 web tag running inside the app's webview
    if is_web_hit and _hit_source(ua) == "webview":  # not Instagram & co.: that's your site in their app
        issues.append({"type": "webview", "detail": f"{h['host']} from an in-app webview"})

    # 2. Firebase validation error: the SDK dropped data
    if "firebase_error" in params:
        detail = f"error {params['firebase_error']}"
        if params.get("firebase_error_value"):
            detail += f" on {params['firebase_error_value']}"
        if params.get("firebase_error_length"):
            detail += f" (length {params['firebase_error_length']})"
        issues.append({"type": "firebase_error", "detail": detail})

    # 3. debug mode in the traffic
    # ga_debug = Firebase _dbg, _dbg / ep.debug_mode = GA4 web
    if any(params.get(k) in (True, 1, "1", "true") for k in ("ga_debug", "_dbg", "ep.debug_mode")):
        issues.append({"type": "debug", "detail": "debug flag set on this event"})

    # 4. ecommerce without the data GA4 needs (Firebase payloads have clean parameter names)
    if h["event"] in ECOMMERCE_EVENTS and not is_web_hit:
        # revenue not counted at all (critical)
        revenue = [f"missing {p}" for p in ("currency", "value") if p not in params]
        if isinstance(params.get("value"), str):
            revenue.append("value is text, not a number")
        if revenue:
            issues.append({"type": "ecommerce_revenue", "detail": "; ".join(revenue)})
        # revenue counted, but no deduplication / item reports (warning)
        items = params.get("items")
        rest = ["missing transaction_id"] if "transaction_id" not in params else []
        if not items:
            rest.append("no items")
        elif any(isinstance(i, dict) and "item_id" not in i and "item_name" not in i for i in items):
            rest.append("item without item_id and item_name")
        if rest:
            issues.append({"type": "ecommerce", "detail": "; ".join(rest)})

    # 5. personal data sent to Google
    extra = h.get("extra") if isinstance(h.get("extra"), dict) else {}
    found = []
    for key, value in list(_walk_strings(params)) + list(_walk_strings(extra.get("user_properties", {}), "user_properties")):
        if EMAIL_RE.search(value) or PHONE_RE.match(value.strip()):
            found.append(f"{key} = {_mask(value)}")
    if found:
        issues.append({"type": "pii", "detail": ", ".join(found[:3])})
    return issues


def decode_skan_response(resp) -> dict:
    data = unpack_body(resp.get_content(strict=False) or b"")
    if not data:
        return {}
    try:
        return decode(data, {})
    except DecodeError:
        txt = _as_text(data)
        return {"body": txt[:MAX_TEXT] if txt is not None else f"<binary {len(data)} bytes>"}


# User-Agent prefixes that don't identify an app
GENERIC_UA = {"mozilla", "dalvik", "okhttp", "cfnetwork", "darwin", "go-http-client", "curl", "python-requests",
              "applecoremedia", "com.apple.webkit.networking", "nsurlsession", "java", "grpc-objc", "grpc-java"}


def _ua_token(ua: str) -> str | None:
    tok = ua.split("/")[0].strip()
    if not tok or " " in tok or tok.lower() in GENERIC_UA or tok.lower().startswith("grpc"):
        return None
    return tok



def _jsonable(obj):
    if isinstance(obj, tuple) and len(obj) == 2 and obj[0] == "ts":
        return _fmt_time(obj[1])
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


# --------------------------------------------------------------------------
# Hit store + web UI server
# --------------------------------------------------------------------------

class HitStore:
    def __init__(self, maxlen: int = 5000):
        self.lock = threading.Lock()
        self.hits: deque = deque(maxlen=maxlen)
        self.next_id = 1
        self.gen = 0

    def add(self, hits: list[dict]) -> None:
        with self.lock:
            for h in hits:
                h["id"] = self.next_id
                self.next_id += 1
                self.hits.append(h)

    def since(self, after: int) -> tuple[int, list[dict]]:
        with self.lock:
            return self.gen, [h for h in self.hits if h["id"] > after]

    def clear(self) -> None:
        with self.lock:
            self.hits.clear()
            self.gen += 1

    def assign_app(self, token: str, bundle: str) -> None:
        """A UA token got linked to an app -> tag earlier hits with it (client reloads)."""
        with self.lock:
            changed = False
            for h in self.hits:
                if h.get("ua") == token and not h.get("app"):
                    h["app"] = bundle
                    changed = True
            if changed:
                self.gen += 1

    def reclassify(self) -> None:
        """Re-run tool detection after custom domains changed (client reloads)."""
        with self.lock:
            for h in self.hits:
                h["tool"] = detect_tool(h["host"], urllib.parse.urlsplit(h["url"]).path)
            self.gen += 1


STORE = HitStore()


# --------------------------------------------------------------------------
# Connection state: the last device that sent anything through the proxy
# --------------------------------------------------------------------------
DEVICE: dict | None = None
PROXY = {"ip": None, "port": 8080}


def _ua_device(ua: str) -> tuple[str | None, str | None]:
    """(device, OS) from a User-Agent: platform + OS version; the model only on Android
    (iPhones send just "iPhone"). Apps write their own User-Agent, so this is a hint."""
    m = re.search(r"\b(iPhone|iPad|iPod)\b.*?OS (\d+)[_.](\d+)", ua)
    if m:
        return m.group(1), f"iOS {m.group(2)}.{m.group(3)}"
    m = re.search(r"\bAndroid (\d+(?:\.\d+)?)", ua)
    if m:
        model = re.search(r"Android [\d.]+;(?: [a-z]{2}[-_][A-Za-z]{2};)? ([^;)]+?)(?: Build[/)]|\))", ua)
        model = model.group(1).strip() if model else None
        return (model if model and model not in ("K", "wv") else None), f"Android {m.group(1)}"
    m = re.search(r"\bDarwin/(\d+)", ua)
    if m and "CFNetwork" in ua:
        darwin = int(m.group(1))  # Darwin 24 = iOS 18, Darwin 25 = iOS 26
        ios = 26 + darwin - 25 if darwin >= 25 else darwin - 6
        return None, f"iOS {ios}" if 13 <= ios <= 40 else "iOS"
    m = re.search(r"\b(iPhone|iPad)\b", ua)
    if m:
        return m.group(1), "iOS"
    return None, None


# hosts that pin their certificates: they refuse the proxy even when the phone trusts it, so they prove nothing
PINNED_HOSTS = ("apple.com", "icloud.com", "mzstatic.com", "apple-cloudkit.com", "icloud-content.com", "cdn-apple.com",
                "apple-dns.net", "aaplimg.com")


def _note_device(client, tls_result: str | None = None, ua: str = "", https: bool = False) -> None:
    """Remember the phone behind a client connection.

    tls_result: "ok" when the phone accepted the proxy's certificate (HTTPS works),
    "fail" when it refused it (certificate not installed / not trusted, or pinning).
    https: a decrypted HTTPS request arrived. Only this proves the phone trusts the certificate:
    with TLS 1.3 the handshake looks finished to the proxy before the phone has checked the certificate.
    """
    global DEVICE
    try:
        ip = client.peername[0]
    except (AttributeError, IndexError, TypeError):
        return
    ip = ip.removeprefix("::ffff:")
    if ip in ("127.0.0.1", "::1") or ip.startswith("127."):
        return  # traffic from this computer, not a phone
    if not DEVICE or DEVICE["ip"] != ip:
        DEVICE = {"ip": ip, "name": None, "seen": time.time(), "model": None, "os": None,
                  "tls_ok": 0, "tls_fail": 0, "tls_fail_host": None, "https_ok": 0}
        threading.Thread(target=_resolve_device_name, args=(ip,), daemon=True).start()
    DEVICE["seen"] = time.time()
    if ua:
        model, os_ = _ua_device(ua)
        if model and not DEVICE["model"]:
            DEVICE["model"] = model
        # keep the most precise OS version seen (iOS 18.1 beats iOS 18 beats iOS)
        if os_ and len(os_) > len(DEVICE["os"] or ""):
            DEVICE["os"] = os_
    if https:
        DEVICE["https_ok"] += 1
    if tls_result == "ok":
        DEVICE["tls_ok"] += 1
    elif tls_result == "fail":
        host = (getattr(client, "sni", None) or "").lower()
        if host.endswith(PINNED_HOSTS):
            return  # Apple's own services refuse every proxy, even with a trusted certificate
        DEVICE["tls_fail"] += 1
        DEVICE["tls_fail_host"] = host or None
        if host:
            DEVICE.setdefault("tls_fail_hosts", [])
            if host not in DEVICE["tls_fail_hosts"]:
                DEVICE["tls_fail_hosts"].append(host)


def _resolve_device_name(ip: str) -> None:
    """Network name of the phone (reverse DNS / Bonjour, e.g. Michals-iPhone), if the network has one."""
    try:
        host = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return
    name = host.split(".")[0] if not re.fullmatch(r"[\d.:]+", host) else None
    if name and DEVICE and DEVICE["ip"] == ip:
        DEVICE["name"] = name


def _local_ip() -> str | None:
    """LAN address of this computer (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            ip = s.getsockname()[0]
        return None if ip.startswith("127.") else ip
    except OSError:
        return None


# --------------------------------------------------------------------------
# App identification (bundle ID from the hits -> App Store / Google Play)
# --------------------------------------------------------------------------

APPS: dict[str, dict] = {}
APPS_LOCK = threading.Lock()
LOOKUP_ENABLED = True
BUNDLE_RE = re.compile(r"^[A-Za-z][\w-]*(\.[\w-]+){1,}$")
BUNDLE_KEYS = ("app_id", "bundle_id", "bundleId", "package_name", "packageName", "app_package")
APPSTORE_COUNTRIES = ("", "cz", "sk", "gb", "de", "pl", "fr", "it", "es", "nl", "at")

try:
    import certifi

    _SSL = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL = ssl.create_default_context()


def _http_get(url: str) -> tuple[int, bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=8, context=_SSL) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""


def _lookup_appstore(bundle: str) -> dict | None:
    for country in APPSTORE_COUNTRIES:
        q = urllib.parse.urlencode({"bundleId": bundle, **({"country": country} if country else {})})
        status, body = _http_get(f"https://itunes.apple.com/lookup?{q}")
        results = json.loads(body or b"{}").get("results") if status == 200 else None
        if results:
            r = results[0]
            return {
                "name": r.get("trackName"),
                "seller": r.get("sellerName"),
                "icon": r.get("artworkUrl100") or r.get("artworkUrl60"),
                "url": (r.get("trackViewUrl") or "").split("?")[0],
                "store": "App Store",
            }
    return None


def _lookup_play(bundle: str) -> dict | None:
    status, body = _http_get(f"https://play.google.com/store/apps/details?id={urllib.parse.quote(bundle)}&hl=en")
    if status != 200:
        return None
    page = body.decode("utf-8", "replace")
    title = re.search(r'<meta property="og:title" content="([^"]*)"', page)
    image = re.search(r'<meta property="og:image" content="([^"]*)"', page)
    if not title:
        return None
    import html

    name = html.unescape(title.group(1)).removesuffix(" - Apps on Google Play")
    return {
        "name": name,
        "icon": html.unescape(image.group(1)) if image else None,
        "url": f"https://play.google.com/store/apps/details?id={bundle}",
        "store": "Google Play",
    }


def _lookup_app(bundle: str, platform: str | None) -> None:
    info = None
    try:
        if platform != "android":
            info = _lookup_appstore(bundle)
        if not info and platform != "ios":
            info = _lookup_play(bundle)
    except Exception as e:  # noqa: BLE001
        logger.info(f"App lookup for {bundle} failed: {e}")
    with APPS_LOCK:
        APPS[bundle].update(info or {})
        APPS[bundle]["status"] = "found" if info else "not_found"


UA_APPS: dict[str, str] = {}  # User-Agent app token -> bundle ID


def register_apps(hits: list[dict]) -> None:
    """Pick bundle IDs out of the hits, tag each hit with its app and look new apps up in the stores."""
    for h in hits:
        _register_hit_app(h)
        if not h.get("app") and h.get("ua") in UA_APPS:
            h["app"] = UA_APPS[h["ua"]]


def _register_hit_app(h: dict) -> None:
    extra = h.get("extra") if isinstance(h.get("extra"), dict) else {}
    device = extra.get("device_app") if isinstance(extra.get("device_app"), dict) else {}
    params = h.get("params") if isinstance(h.get("params"), dict) else {}
    platform = str(device.get("platform") or params.get("platform") or params.get("os_name") or "").lower() or None
    version = device.get("app_version") or params.get("app_version")
    for src in (device, params, {"app_id": h.get("xrw")}):
        for key in BUNDLE_KEYS:
            bundle = src.get(key)
            if not isinstance(bundle, str) or not BUNDLE_RE.match(bundle):
                continue
            h["app"] = bundle
            token = h.get("ua")
            if token and UA_APPS.get(token) != bundle:
                UA_APPS[token] = bundle
                STORE.assign_app(token, bundle)
            with APPS_LOCK:
                app = APPS.get(bundle)
                if app is None:
                    app = APPS[bundle] = {"bundle": bundle, "platform": platform, "status": "pending"}
                    if LOOKUP_ENABLED:
                        threading.Thread(target=_lookup_app, args=(bundle, platform), daemon=True).start()
                    else:
                        app["status"] = "not_found"
                if version and isinstance(version, (str, int, float)):
                    app["version"] = str(version)
                if platform and not app.get("platform"):
                    app["platform"] = platform


def _apps_payload() -> list[dict]:
    with APPS_LOCK:
        return [dict(a) for a in APPS.values()]


# favicon domain per tool (shown as the tool's logo in the UI)
LOGO_DOMAINS = {
    "skan": "firebase.google.com", "ga4": "analytics.google.com", "ga4web": "analytics.google.com",
    "firebase": "firebase.google.com", "crashlytics": "firebase.google.com", "adjust": "adjust.com",
    "appsflyer": "appsflyer.com", "meta": "facebook.com", "branch": "branch.io", "singular": "singular.net",
    "kochava": "kochava.com", "airbridge": "airbridge.io", "tiktok": "tiktok.com", "snap": "snapchat.com",
    "googleads": "ads.google.com", "mixpanel": "mixpanel.com", "amplitude": "amplitude.com",
    "segment": "segment.com", "braze": "braze.com", "clevertap": "clevertap.com", "onesignal": "onesignal.com",
    "appmetrica": "appmetrica.yandex.com", "revenuecat": "revenuecat.com", "sentry": "sentry.io",
    "datadog": "datadoghq.com", "clarity": "clarity.microsoft.com", "sgtm": "tagmanager.google.com",
}


# product icons where the site favicon is just the generic Google "G"
LOGO_URLS = {
    "ga4": "https://www.gstatic.com/analytics-suite/header/suite/v2/ic_analytics.svg",
    "ga4web": "https://www.gstatic.com/analytics-suite/header/suite/v2/ic_analytics.svg",
    "sgtm": "https://www.gstatic.com/analytics-suite/header/suite/v2/ic_tag_manager.svg",
}


def _logo(key: str) -> str | None:
    if key in LOGO_URLS:
        return LOGO_URLS[key]
    domain = LOGO_DOMAINS.get(key)
    return f"https://www.google.com/s2/favicons?domain={domain}&sz=64" if domain else None


def _tools_payload() -> list[dict]:
    return [{"key": k, "label": label, "color": c, "logo": _logo(k)} for k, label, c, *_ in TOOLS] + [
        {"key": k, "label": label, "color": c, "logo": _logo(k)} for k, label, c in (SGTM, OTHER)
    ]


def _mitmweb_token_query() -> str:
    """mitmweb 12+ requires a token for its UI; return '?token=...' so links open logged in."""
    auth = ctx.master.addons.get("webauth") if hasattr(ctx.master, "addons") else None
    for attr in ("_password", "password", "token"):
        tok = getattr(auth, attr, None)
        if isinstance(tok, str) and tok:
            return f"?token={tok}"
    tok = getattr(ctx.options, "web_password", "") or ""
    if tok and not tok.startswith("$"):  # plain password, not an argon2 hash
        return f"?token={tok}"
    return ""


class _Handler(BaseHTTPRequestHandler):
    mitmweb_url: str | None = None

    def log_message(self, *args):  # silence access log
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json")

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        if url.path == "/":
            self._send(200, UI_HTML.replace("{{VERSION}}", __version__).encode(), "text/html; charset=utf-8")
        elif url.path == "/api/hits":
            q = urllib.parse.parse_qs(url.query)
            try:
                after = int(q.get("after", ["0"])[0])
            except ValueError:
                after = 0
            gen, hits = STORE.since(after)
            self._json({
                "gen": gen,
                "hits": hits,
                "tools": _tools_payload(),
                "domains": sorted(CUSTOM_DOMAINS),
                "apps": _apps_payload(),
                "mitmweb": self.mitmweb_url,
                "device": DEVICE,
                "proxy": PROXY,
            })
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        url = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        data = self.rfile.read(length) if length else b""
        if url.path == "/api/clear":
            STORE.clear()
            self._json({"ok": True})
        elif url.path == "/api/domains":
            try:
                domains = json.loads(data or b"[]")
            except ValueError:
                return self._json({"error": "invalid JSON"}, 400)
            cleaned = set()
            for d in domains if isinstance(domains, list) else []:
                d = str(d).strip().lower()
                d = re.sub(r"^[a-z]+://", "", d).split("/")[0].split(":")[0]
                if d:
                    cleaned.add(d)
            CUSTOM_DOMAINS.clear()
            CUSTOM_DOMAINS.update(cleaned)
            _save_domains()
            STORE.reclassify()
            self._json({"domains": sorted(CUSTOM_DOMAINS)})
        else:
            self._send(404, b"not found", "text/plain")


# --------------------------------------------------------------------------
# Proxy integration
# --------------------------------------------------------------------------

class GA4AppMeasurement(contentviews.Contentview):
    name = "GA4 App Measurement"
    syntax_highlight = "yaml"

    def prettify(self, data: bytes, metadata: contentviews.Metadata) -> str:
        return render_batch(decode_batch(data))

    def render_priority(self, data: bytes, metadata: contentviews.Metadata) -> float:
        flow = metadata.flow
        if not data or flow is None or not _is_ga4(flow):
            return 0
        # request body only (the response is empty / unrelated)
        if metadata.http_message is not None and not isinstance(metadata.http_message, http.Request):
            return 0
        # only claim real GA4 batches (config, sGTM etc. use other formats)
        return 10 if _looks_like_ga4_batch(data) else 0


contentviews.add(GA4AppMeasurement)


class FirebaseSKAN(contentviews.Contentview):
    name = "Firebase SKAN"
    syntax_highlight = "yaml"

    def prettify(self, data: bytes, metadata: contentviews.Metadata) -> str:
        is_request = isinstance(metadata.http_message, http.Request)
        msg = decode(unpack_body(data), SKAN_REQUEST if is_request else {})
        return "\n".join(_render(_jsonable(msg))) + "\n"

    def render_priority(self, data: bytes, metadata: contentviews.Metadata) -> float:
        flow = metadata.flow
        if not data or flow is None or not isinstance(flow, http.HTTPFlow):
            return 0
        return 10 if detect_tool(flow.request.pretty_host, flow.request.path) == "skan" else 0


contentviews.add(FirebaseSKAN)


class FirebaseConfig(contentviews.Contentview):
    name = "Firebase Config"
    syntax_highlight = "yaml"

    def prettify(self, data: bytes, metadata: contentviews.Metadata) -> str:
        cfg = pretty_config(decode(unpack_body(data), CONFIG))
        return "\n".join(_render(_jsonable(cfg))) + "\n"

    def render_priority(self, data: bytes, metadata: contentviews.Metadata) -> float:
        flow = metadata.flow
        if not data or flow is None or not isinstance(flow, http.HTTPFlow):
            return 0
        if isinstance(metadata.http_message, http.Request) or "/config/app" not in flow.request.path:
            return 0
        return 10 if detect_tool(flow.request.pretty_host, flow.request.path) == "ga4" else 0


contentviews.add(FirebaseConfig)


class FirebaseProtobuf(contentviews.Contentview):
    """Fallback for binary protobuf payloads of any detected tool (Firebase sdk-exp, ...)."""

    name = "Tracking Protobuf"
    syntax_highlight = "yaml"

    def prettify(self, data: bytes, metadata: contentviews.Metadata) -> str:
        return "\n".join(_render(_jsonable(decode_generic(data)))) + "\n"

    def render_priority(self, data: bytes, metadata: contentviews.Metadata) -> float:
        flow = metadata.flow
        if not data or flow is None or not isinstance(flow, http.HTTPFlow):
            return 0
        if detect_tool(flow.request.pretty_host, flow.request.path) == "other":
            return 0
        return 5 if _is_protobuf(data) else 0


contentviews.add(FirebaseProtobuf)


class AppTrackingDebugger:
    def __init__(self):
        self.server: ThreadingHTTPServer | None = None

    def load(self, loader):
        loader.add_option("tracking_ui_port", int, 8082, "Port of the Flashlight UI (0 = off).")
        loader.add_option("tracking_ui_open", bool, True, "Open the Flashlight UI in the browser when mitmweb starts.")
        loader.add_option("tracking_app_lookup", bool, True, "Look up the app name in the App Store / Google Play by its bundle ID.")
        _load_domains()

    def configure(self, updated):
        global LOOKUP_ENABLED
        if "tracking_app_lookup" in updated:
            LOOKUP_ENABLED = ctx.options.tracking_app_lookup

    def running(self):
        port = ctx.options.tracking_ui_port
        if not port or self.server:
            return
        PROXY["ip"] = _local_ip()
        PROXY["port"] = getattr(ctx.options, "listen_port", None) or 8080
        web_port = getattr(ctx.options, "web_port", None)
        _Handler.mitmweb_url = f"http://127.0.0.1:{web_port}/{_mitmweb_token_query()}" if web_port else None
        try:
            self.server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
        except OSError as e:
            logger.warning(f"Flashlight UI could not start on port {port}: {e}")
            return
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        logger.warning(f"Flashlight {__version__} UI: http://127.0.0.1:{port}")
        # open the UI together with mitmweb - once per process, not on every script reload
        # (mitmweb's own tab is turned off with web_open_browser: false in config.yaml)
        if web_port and ctx.options.tracking_ui_open and not os.environ.get("ATD_UI_OPENED"):
            os.environ["ATD_UI_OPENED"] = "1"
            webbrowser.open(f"http://127.0.0.1:{port}")

    def done(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    def http_connect(self, flow: http.HTTPFlow) -> None:
        _note_device(flow.client_conn)

    def tls_established_client(self, data: tls.TlsData) -> None:
        _note_device(data.context.client, "ok")

    def tls_failed_client(self, data: tls.TlsData) -> None:
        _note_device(data.context.client, "fail")

    def request(self, flow: http.HTTPFlow) -> None:
        _note_device(flow.client_conn, ua=flow.request.headers.get("user-agent", ""), https=flow.request.scheme == "https")
        tool = detect_tool(flow.request.pretty_host, flow.request.path)
        if tool == "other":
            return
        # tag for quick filtering in mitmweb: ~comment GA4  /  ~marked
        flow.marked = ":bar_chart:"
        labels = {key: label for key, label, *_ in TOOLS}
        flow.comment = "GA4" if tool in ("ga4", "sgtm") else labels[tool]

    def response(self, flow: http.HTTPFlow) -> None:
        self._record(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        if isinstance(flow, http.HTTPFlow):
            self._record(flow)

    def _record(self, flow: http.HTTPFlow) -> None:
        try:
            hits = extract_hits(flow)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Tracking hit extraction failed: {e}")
            return
        register_apps(hits)
        STORE.add(hits)
        for h in hits:
            if h["tool"] in ("ga4", "sgtm"):
                params = ", ".join(f"{k}={v}" for k, v in h["params"].items())
                logger.info(f"[{h['tool'].upper()}] {h['event']} | {params}")


addons = [AppTrackingDebugger()]


UI_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Flashlight | measure-apps.com</title>
<link rel="icon" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0MDAgNDAwIj48ZGVmcz48Y2xpcFBhdGggaWQ9InIiPjxyZWN0IHdpZHRoPSI0MDAiIGhlaWdodD0iNDAwIiByeD0iODgiLz48L2NsaXBQYXRoPjxjbGlwUGF0aCBpZD0iYiI+PHBhdGggZD0iTTEzMSAyMzEgTDMxOCAtMTc2IEw1ODYgOTIgTDE3OSAyNzkgWiIvPjwvY2xpcFBhdGg+PC9kZWZzPjxyZWN0IHdpZHRoPSI0MDAiIGhlaWdodD0iNDAwIiByeD0iODgiIGZpbGw9IiNGRkZGRkYiLz48ZyBjbGlwLXBhdGg9InVybCgjcikiPjxnIGZpbGw9IiNDNEM0QkUiPjxyZWN0IHg9IjI0IiB5PSI0MiIgd2lkdGg9IjM1MiIgaGVpZ2h0PSIzNCIgcng9IjE3Ii8+PHJlY3QgeD0iMjQiIHk9IjEwNyIgd2lkdGg9IjM1MiIgaGVpZ2h0PSIzNCIgcng9IjE3Ii8+PHJlY3QgeD0iMjQiIHk9IjE3MiIgd2lkdGg9IjM1MiIgaGVpZ2h0PSIzNCIgcng9IjE3Ii8+PC9nPjxwYXRoIGQ9Ik0xMzEgMjMxIEwzMTggLTE3NiBMNTg2IDkyIEwxNzkgMjc5IFoiIGZpbGw9IiNGRkU3QTYiLz48ZyBjbGlwLXBhdGg9InVybCgjYikiPjxnIGZpbGw9IiMxMTExMTEiPjxyZWN0IHg9IjI0IiB5PSI0MiIgd2lkdGg9IjM1MiIgaGVpZ2h0PSIzNCIgcng9IjE3Ii8+PHJlY3QgeD0iMjQiIHk9IjEwNyIgd2lkdGg9IjM1MiIgaGVpZ2h0PSIzNCIgcng9IjE3Ii8+PHJlY3QgeD0iMjQiIHk9IjE3MiIgd2lkdGg9IjM1MiIgaGVpZ2h0PSIzNCIgcng9IjE3Ii8+PC9nPjwvZz48L2c+PGcgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoMTIwIDI5MCkgcm90YXRlKDQ1KSI+PHJlY3QgeD0iLTI4IiB5PSIwIiB3aWR0aD0iNTYiIGhlaWdodD0iMTAwIiByeD0iMTQiIGZpbGw9IiMxMTExMTEiLz48cGF0aCBkPSJNLTQ0IC01MCBMNDQgLTUwIEwzMCAwIEwtMzAgMCBaIiBmaWxsPSIjMTExMTExIi8+PHJlY3QgeD0iLTQ3IiB5PSItNjIiIHdpZHRoPSI5NCIgaGVpZ2h0PSIxOCIgcng9IjkiIGZpbGw9IiNGRkE1MUYiLz48L2c+PHJlY3QgeD0iMyIgeT0iMyIgd2lkdGg9IjM5NCIgaGVpZ2h0PSIzOTQiIHJ4PSI4NSIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjRTRFNEUwIiBzdHJva2Utd2lkdGg9IjYiLz48L3N2Zz4=">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter+Tight:wght@400;600;800&family=JetBrains+Mono:wght@400;500;700&display=swap">
<style>
:root {
  color-scheme: light;
  --bg: #F7F7F5; --panel: #FFFFFF; --text: #111111; --muted: #555555; --line: #E4E4E0;
  --hover: #F0F0EC; --sel: #E6F4F2; --accent: #2A9D8F; --accent-text: #1F7A6F; --err: #D93025;
  --lens: #FFA51F; --beam: #FFC233; --beam-solid: #FFE7A6; --lens-off: #D6D6D2;
  --sans: "Inter Tight", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --mono: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
html, body { margin: 0; height: 100%; }
body { background: var(--bg); color: var(--text); font: 13px/1.4 var(--sans); display: flex; flex-direction: column; }
header { display: flex; align-items: center; gap: 12px; padding: 10px 16px; background: var(--panel); border-bottom: 1px solid var(--line); flex-wrap: wrap; }
header h1 { font-size: 18px; margin: 0; font-weight: 800; line-height: 1.15; letter-spacing: -.01em; }
.brand { display: flex; align-items: center; gap: 10px; margin-right: 12px; }
.brand .fl-icon { width: 34px; height: 34px; flex: none; display: block; }
.brand .by { display: block; font-size: 11px; color: var(--muted); font-weight: 400; letter-spacing: 0; }
.brand .by a { color: var(--accent-text); text-decoration: none; }
.brand .by a:hover { text-decoration: underline; }
button, input { font: inherit; color: inherit; }
button { background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 5px 10px; cursor: pointer; }
button:hover { background: var(--hover); }
input[type=search], input[type=text] { background: var(--bg); border: 1px solid var(--line); border-radius: 6px; padding: 6px 10px; min-width: 0; }
#search { width: 260px; max-width: 100%; font-family: var(--mono); font-size: 12px; }
#search.bad { border-color: var(--err); }
.bar { display: flex; gap: 6px; flex-wrap: wrap; padding: 10px 16px; background: var(--panel); border-bottom: 1px solid var(--line); align-items: center; }
.chip { display: inline-flex; align-items: center; gap: 6px; border: 1px solid var(--line); border-radius: 999px; padding: 3px 10px 3px 8px; cursor: pointer; user-select: none; background: var(--panel); }
.chip .sw { width: 10px; height: 10px; border-radius: 50%; }
.lg { width: 16px; height: 16px; border-radius: 3px; flex: none; vertical-align: middle; }
.lg + .sw { display: none; }
.lg.broken { display: none; }
.lg.broken + .sw { display: inline-block; }

.apps { display: none; }
.adv { display: none; background: var(--bg); }
.adv.open { display: block; }
.adv .bar { background: var(--bg); padding-left: 24px; }
.adv-toggle { margin-left: auto; border: 0; background: none; color: var(--accent-text); font: inherit; font-size: 13px; cursor: pointer; padding: 3px 4px; }
.adv-toggle .dot { display: inline-block; min-width: 16px; padding: 0 5px; margin-left: 4px; border-radius: 999px; background: var(--accent); color: #fff; font-size: 11px; line-height: 16px; text-align: center; }
.apps.has { display: flex; }
.chip .app-ic { width: 16px; height: 16px; border-radius: 4px; flex: none; }
.chip .noicon { display: inline-block; border: 1px dashed var(--muted); }
.chip code { font-family: var(--mono); font-size: 12px; }
.chip .n { color: var(--muted); font-variant-numeric: tabular-nums; }
.chip.on { border-color: var(--c); box-shadow: inset 0 0 0 1px var(--c); background: color-mix(in srgb, var(--c) 12%, var(--panel)); }
.chip.off { opacity: .55; }
.domains { display: none; gap: 8px; align-items: center; padding: 10px 16px; background: var(--panel); border-bottom: 1px solid var(--line); flex-wrap: wrap; }
.domains.open { display: flex; }
.domains.flash { background: color-mix(in srgb, var(--accent) 14%, var(--panel)); transition: background .4s; }
.domains .note { color: var(--accent-text); font-weight: 600; }
.warn { display: inline-block; width: 16px; height: 16px; margin-right: 6px; border-radius: 50%; background: var(--err); color: #fff; font-size: 11px; font-weight: 700; line-height: 16px; text-align: center; vertical-align: 1px; }
.warn.info { background: var(--accent); }
.warn.warning { background: none; color: var(--err); box-shadow: inset 0 0 0 1.5px var(--err); }
.iwarn { border: 1px solid var(--line); border-left: 3px solid var(--err); border-radius: 6px; padding: 8px 10px; margin: 0 0 12px; font-size: 12px; }
.iwarn.info { border-left-color: var(--accent); }
.iwarn.warning { border-left-color: color-mix(in srgb, var(--err) 45%, var(--line)); }
.iwarn b { display: block; font-size: 13px; margin-bottom: 2px; }
.cta-box { margin: 0 0 12px; padding: 9px 12px; border-radius: 6px; background: color-mix(in srgb, var(--accent) 9%, var(--panel)); font-size: 12px; line-height: 1.5; }
.cta-box a { color: var(--accent-text); font-weight: 600; text-decoration: none; }
.cta-box a:hover { text-decoration: underline; }
.domains .dspacer { flex: 1; }
button.danger { color: var(--err); }
button.icon { font-size: 18px; line-height: 1; padding: 3px 9px; }
.dwrap { position: relative; display: inline-block; }
.dwrap .n { color: var(--muted); font-variant-numeric: tabular-nums; }
.dwrap .pop { display: none; position: absolute; top: calc(100% + 6px); left: 0; z-index: 10; width: max-content; min-width: 240px; max-width: min(520px, 90vw); background: var(--panel); border: 1px solid var(--line); border-radius: 8px; box-shadow: 0 6px 20px rgba(0,0,0,.12); padding: 10px 12px; }
.dwrap:hover .pop { display: block; }
.dwrap .pop::before { content: ""; position: absolute; top: -8px; left: 0; right: 0; height: 8px; }
.pop .ttl { font-size: 11px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); margin-bottom: 6px; }
.pop ul { margin: 0; padding: 0; list-style: none; font-family: var(--mono); font-size: 12px; }
.pop li { padding: 3px 0; overflow-wrap: anywhere; }
.domains input { width: 420px; max-width: 100%; }
.hint { color: var(--muted); }
.ver { position: fixed; right: 8px; bottom: 3px; z-index: 5; font-family: var(--mono); font-size: 10px; color: var(--muted); opacity: .55; pointer-events: none; }
main { flex: 1; display: flex; min-height: 0; }
#list { flex: 1 1 60%; overflow: auto; min-width: 0; }
#detail { flex: 1 1 40%; overflow: auto; border-left: 1px solid var(--line); background: var(--panel); padding: 16px; min-width: 0; }
table.hits { width: 100%; border-collapse: collapse; table-layout: fixed; }
.hits td { padding: 6px 10px; border-bottom: 1px solid var(--line); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.hits tr { cursor: pointer; }
.hits tr:hover td { background: var(--hover); }
.hits tr.sel td { background: var(--sel); }
.t { width: 112px; color: var(--muted); font-family: var(--mono); font-size: 12px; }
.tool { width: 156px; }
.tool .lg { margin-right: 6px; }
.ev { font-weight: 600; }
.url { width: 38%; color: var(--muted); font-family: var(--mono); font-size: 12px; }
.hits thead th { position: sticky; top: 0; z-index: 1; background: var(--panel); text-align: left; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); padding: 8px 10px; border-bottom: 1px solid var(--line); white-space: nowrap; }

.st { width: 64px; text-align: left; font-family: var(--mono); font-size: 12px; color: var(--muted); }
.st.bad { color: var(--err); }
.badge { display: inline-block; padding: 1px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; color: #fff; background: var(--c); max-width: 100%; overflow: hidden; text-overflow: ellipsis; vertical-align: middle; }
.empty { padding: 40px 16px; text-align: center; color: var(--muted); }
#detail.idle { display: flex; flex-direction: column; }
.promo-card { margin-top: auto; padding: 10px 12px; border: 1px solid var(--line); border-radius: 8px; background: var(--bg); font-size: 12px; color: var(--muted); }
.pc-q { color: var(--text); font-weight: 600; }
.pc-q a { color: var(--accent-text); text-decoration: none; white-space: nowrap; margin-left: 4px; }
.pc-q a:hover { text-decoration: underline; }
.promo-card ul { list-style: none; margin: 6px 0 0; padding: 0; }
.promo-card li { position: relative; padding: 1px 0 1px 16px; }
.promo-card li::before { content: "✓"; position: absolute; left: 0; color: var(--accent-text); }
.promo-card li b { color: var(--text); font-weight: 600; }
#detail h2 { margin: 0 0 6px; font-size: 17px; word-break: break-all; }
.meta { color: var(--muted); font-size: 12px; margin-bottom: 12px; word-break: break-all; }
.meta div { margin: 2px 0; }
.actions { display: flex; gap: 8px; margin-bottom: 14px; flex-wrap: wrap; }
.actions a { color: var(--accent-text); text-decoration: none; border: 1px solid var(--line); border-radius: 6px; padding: 5px 10px; }
h3 { font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); margin: 18px 0 6px; }
table.kv { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 12px; }
.kv td { border-bottom: 1px solid var(--line); padding: 4px 6px; vertical-align: top; word-break: break-word; }
.kv td:first-child { width: 34%; color: var(--muted); }
.kv pre { margin: 0; white-space: pre-wrap; }
/* Flashlight icon: the beam and the lens light up when a device is connected */
@keyframes fl-beam{0%,15%{opacity:0;transform:scale(.2)}24%{opacity:1;transform:scale(1)}32%{opacity:.15}40%{opacity:1}48%{opacity:.45}58%,100%{opacity:1;transform:scale(1)}}
@keyframes fl-lens{0%,15%{fill:#D6D6D2}24%{fill:#FFA51F}32%{fill:#D6D6D2}40%{fill:#FFA51F}48%{fill:#FFE08A}58%,100%{fill:#FFA51F}}
@keyframes fl-pulse{0%,100%{opacity:.35}50%{opacity:1}}
.fl-icon .beam{opacity:0;transform-box:view-box;transform-origin:155px 255px}
.fl-icon .lens{fill:#D6D6D2}
.fl-icon.is-on .beam{animation:fl-beam 1.4s ease-out both}
.fl-icon.is-on .lens{animation:fl-lens 1.4s ease-out both}
/* HTTPS blocked: the light is on but the rows stay unreadable, red lens, unsteady beam */
@keyframes fl-beam-bad{0%,100%{opacity:.55}8%{opacity:.15}14%{opacity:.6}52%{opacity:.45}56%{opacity:.1}62%{opacity:.55}}
@keyframes fl-lens-bad{0%,100%{fill:#D93025}8%{fill:#D6D6D2}14%{fill:#D93025}56%{fill:#D6D6D2}62%{fill:#D93025}}
.fl-icon .enc{display:none}
.fl-icon.is-on.is-blocked .dec{display:none}
.fl-icon.is-on.is-blocked .enc{display:inline}
.fl-icon.is-on.is-blocked .beam{animation:fl-beam-bad 2.6s ease-in-out infinite;transform:none}
.fl-icon.is-on.is-blocked .lens{animation:fl-lens-bad 2.6s ease-in-out infinite}
@media (prefers-reduced-motion:reduce){.fl-icon.is-on .beam,.fl-icon.is-on .lens{animation-duration:1ms}.fl-icon.is-on.is-blocked .beam{animation:none;opacity:.55}.fl-icon.is-on.is-blocked .lens{animation:none;fill:#D93025}}
.onboard-wrap { min-height: 100%; display: flex; align-items: center; justify-content: center; padding: 32px 16px; }
.onboard { width: 100%; max-width: 540px; text-align: center; }
.onboard .fl-icon { width: 96px; height: 96px; display: block; margin: 0 auto; }
.onboard h2 { font-size: 24px; font-weight: 800; letter-spacing: -.01em; margin: 18px 0 8px; }
.onboard p { margin: 0 0 18px; color: var(--muted); font-size: 15px; line-height: 1.6; letter-spacing: .01em; }
.onboard ol { text-align: left; background: var(--panel); border: 1px solid var(--line); border-radius: 12px; margin: 0 0 18px; padding: 18px 22px 4px 44px; font-size: 15px; line-height: 1.6; letter-spacing: .01em; }
.onboard ol li { margin: 0 0 14px; padding-left: 4px; }
/* connect steps: Wi-Fi + proxy (every time) highlighted on top, the certificate (once per phone) in a box below */
.onboard ol.tint { background: var(--sel); border-color: color-mix(in srgb, var(--accent) 30%, var(--line)); margin-bottom: 12px; }
.onboard ol.tint code { background: #fff; }
.onboard .cert { text-align: left; background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 14px 22px 4px; margin: 0 0 18px; }
.onboard .cert ol { background: none; border: 0; border-radius: 0; margin: 0; padding: 0 0 0 22px; }
.onboard .cert-hd { display: flex; align-items: center; gap: 8px; margin: 0 0 10px; color: var(--muted); font-size: 12px; font-weight: 600; letter-spacing: .04em; text-transform: uppercase; }
.onboard .cert-hd .pill { padding: 1px 9px; border-radius: 999px; background: var(--sel); color: var(--accent-text); letter-spacing: .02em; text-transform: none; }
.onboard code { font-family: var(--mono); font-size: 13px; letter-spacing: 0; white-space: nowrap; background: var(--panel); border: 1px solid var(--line); border-radius: 4px; padding: 1px 6px; }
.onboard .foot { font-family: var(--mono); font-size: 12px; color: var(--muted); }
.onboard .foot b { color: var(--text); font-weight: 500; }
.onboard .conn { display: flex; align-items: center; gap: 10px; text-align: left; background: var(--sel); border: 1px solid color-mix(in srgb, var(--accent) 30%, var(--line)); border-radius: 12px; padding: 14px 22px; margin: 0 0 12px; font-size: 15px; font-weight: 600; }
.onboard .conn small { margin-left: auto; color: var(--muted); font-family: var(--mono); font-size: 12px; font-weight: 400; }
.onboard .cert-hd .hs { margin-left: auto; white-space: nowrap; font-size: 13px; letter-spacing: .01em; text-transform: none; }
.onboard .cert-hd .hs.ok { color: var(--accent-text); }
.onboard .cert-hd .hs.bad { color: var(--err); }
.onboard .next { color: var(--muted); font-size: 14px; margin: 0 0 18px; }
.onboard .next .em, .onboard .cert-hd .hs.wait .em { display: inline-block; animation: fl-pulse 1.6s ease-in-out infinite; }
@media (max-width: 800px) {
  .url { width: 34%; }
  main { flex-direction: column; }
  #detail { border-left: 0; border-top: 1px solid var(--line); flex-basis: 50%; }
  .tool { width: 132px; }
}
</style>
</head>
<body>
<header id="hdr">
  <div class="brand">
    <span id="hdrIcon" title="No device connected"></span>
    <h1>Flashlight<span class="by">Mobile app tracking debugger · by <a href="https://www.measure-apps.com" target="_blank" rel="noopener">measure-apps.com</a></span></h1>
  </div>
  <input type="search" id="search" placeholder="Search">
  <span class="dwrap">
    <button id="domainsBtn">sGTM domains <span class="n" id="domainsCount"></span></button>
    <div class="pop" id="domainsPop"></div>
  </span>
  <button id="pause">Pause</button>
  <button id="clear">Clear</button>
  <span class="hint" id="count"></span>
</header>
<div class="domains" id="domains">
  <span>Custom sGTM domains:</span>
  <input type="text" id="domainsInput" placeholder="sgtm.example.com, data.example.cz">
  <button id="domainsSave">Save</button>
  <span class="hint">Comma separated. Subdomains match too.</span>
  <span class="note" id="domainsNote"></span>
  <span class="dspacer"></span>
  <button id="domainsForget" class="danger">Forget domains</button>
  <button id="domainsClose" class="icon" title="Close" aria-label="Close">&times;</button>
</div>
<div class="bar" id="chips"></div>
<div class="adv" id="adv">
  <div class="bar apps" id="apps"></div>
</div>
<div class="ver">v{{VERSION}}</div>
<main>
  <div id="list"></div>
  <div id="detail"></div>
</main>
<script>
const S = { hits: [], gen: null, after: 0, tools: {}, toolOrder: [], sel: new Set(), q: "", selected: null, paused: false, mitmweb: null, domains: [], device: null, proxy: {}, offline: false };
const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch (e) { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} },
};
S.sel = new Set(store.get("atd.sel", []));
S.q = store.get("atd.q", "");
S.appSel = null;  // every page load starts on "All apps"
S.advOpen = store.get("atd.adv", false);  // advanced filter (apps) open or closed
$("search").value = S.q;
setQuery(S.q);

function fmtTime(ms) {
  const d = new Date(ms);
  return d.toLocaleTimeString([], { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}
function fmtVal(v) {
  if (v === null || v === undefined) return "";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}
function endpoint(u) {
  try { const x = new URL(u); return x.host + x.pathname; } catch (e) { return u; }
}
function inApp(h) { return !S.appSel || h.app === S.appSel; }
function visible(h) {
  if (!inApp(h)) return false;
  if (S.sel.size ? !S.sel.has(h.tool) : h.tool === "other") return false;
  if (!S.q) return true;
  // regex (case-insensitive); an invalid pattern falls back to plain text search
  const test = S.re ? (txt => S.re.test(txt)) : (txt => txt.toLowerCase().includes(S.q.toLowerCase()));
  return test(h.event) || test(h.url) || test(String(h.status ?? "")) || test(JSON.stringify(h.params));
}
function setQuery(q) {
  S.q = q;
  S.re = null;
  let bad = false;
  if (q) { try { S.re = new RegExp(q, "i"); } catch (e) { bad = true; } }
  $("search").classList.toggle("bad", bad);
  $("search").title = bad ? "Invalid regex - searching as plain text" : "Regex supported, e.g. purchase|add_to_cart";
}
function tool(key) { return S.tools[key] || { label: key, color: "#888" }; }
function logoImg(t) {
  return t.logo ? `<img class="lg" src="${esc(t.logo)}" alt="" loading="lazy" onerror="this.classList.add('broken')">` : "";
}
function renderApps(apps) {
  if (apps) S.apps = apps;
  apps = S.apps || [];
  const counts = {};
  for (const h of S.hits) {
    if (h.tool === "other") continue;
    if (h.app) counts[h.app] = (counts[h.app] || 0) + 1;
  }
  apps = apps.filter(a => counts[a.bundle] || S.appSel === a.bundle);  // hide apps left with no hits (e.g. after Clear)
  const html = `<span class="chip ${S.appSel ? "off" : "on"}" style="--c:var(--accent)" data-b=""><span class="n">All apps</span> ${apps.length}</span>` +
    apps.map(a => {
      const found = a.status === "found";
      const icon = found && a.icon ? `<img class="lg app-ic" src="${esc(a.icon)}" alt="">` : `<span class="app-ic noicon"></span>`;
      const name = found && a.name ? esc(a.name) : `<code>${esc(a.bundle)}</code>`;
      return `<span class="chip ${S.appSel === a.bundle ? "on" : S.appSel ? "off" : ""}" style="--c:var(--accent)" data-b="${esc(a.bundle)}" title="${esc(a.bundle)}">${icon}${name} <span class="n">${counts[a.bundle] || 0}</span></span>`;
    }).join("");
  if (html !== S.appsHtml) { S.appsHtml = html; $("apps").innerHTML = html; }
  $("apps").classList.toggle("has", apps.length > 0);
}
function renderChips() {
  const counts = {};
  for (const h of S.hits) if (inApp(h)) counts[h.tool] = (counts[h.tool] || 0) + 1;
  const keys = S.toolOrder.filter(k => counts[k] || S.sel.has(k));
  const total = S.hits.filter(h => h.tool !== "other" && inApp(h)).length;
  let html = `<span class="chip ${S.sel.size ? "off" : "on"}" style="--c:var(--accent)" data-k=""><span class="n">All tools</span> ${total}</span>`;
  for (const k of keys) {
    const t = tool(k);
    const cls = S.sel.size ? (S.sel.has(k) ? "on" : "off") : (k === "other" ? "off" : "");
    html += `<span class="chip ${cls}" style="--c:${t.color}" data-k="${esc(k)}">${logoImg(t)}<span class="sw" style="background:${t.color}"></span>${esc(t.label)} <span class="n">${counts[k] || 0}</span></span>`;
  }
  if (!keys.length) html += `<span class="hint">Waiting for tracking requests…</span>`;
  // advanced filter (apps) behind a toggle; the badge counts active filters while it is closed
  const active = S.appSel ? 1 : 0;
  html += `<button class="adv-toggle" type="button">${S.advOpen ? "Hide filters ▴" : "More filters ▾"}${active ? `<span class="dot">${active}</span>` : ""}</button>`;
  $("chips").innerHTML = html;
  $("adv").classList.toggle("open", !!S.advOpen);
}

// ---- Flashlight icon + connection states ----
// idle (no device) -> waiting (device connected, no tracking hit yet) -> hits; pause / proxy down = off
// rows of unreadable characters; the beam reveals readable events in them
const FL_BEAM = "M131 231 L318 -176 L586 92 L179 279 Z";
const FL_ROWS = [  // [y, unreadable, readable, x where the readable word sits inside the beam]
  [72, "x9Qa7zKp2LmW4vRt", "purchase", 219],
  [137, "Hq5%Uv0#bT6yZc1&", "page_view", 188],
  [202, "3fPz8@Lk1Xr7Vn4$", "first_open", 158],
];  // only above the flashlight, nothing around it
function flIcon(uid, on, big, blocked) {
  const rows = big
    ? [`<g font-family="JetBrains Mono, ui-monospace, Menlo, monospace" font-size="34" font-weight="500" fill="#C4C4BE">${FL_ROWS.map(([y, a]) => `<text x="22" y="${y}">${esc(a)}</text>`).join("")}</g>`,
       `<g font-family="JetBrains Mono, ui-monospace, Menlo, monospace" font-size="34" font-weight="800" fill="#111111">${FL_ROWS.filter(r => r[2]).map(([y, , b, x]) => `<text x="${x}" y="${y}">${esc(b)}</text>`).join("")}</g>`,
       `<g font-family="JetBrains Mono, ui-monospace, Menlo, monospace" font-size="34" font-weight="500" fill="#8E8E88">${FL_ROWS.map(([y, a]) => `<text x="22" y="${y}">${esc(a)}</text>`).join("")}</g>`]
    : ["#C4C4BE", "#111111", "#A9A9A3"].map(c => `<g fill="${c}">${[42, 107, 172].map(y => `<rect x="24" y="${y}" width="352" height="34" rx="17"/>`).join("")}</g>`);
  return `<svg class="fl-icon ${on ? "is-on" : ""} ${blocked ? "is-blocked" : ""}" viewBox="0 0 400 400" aria-hidden="true">
<defs><clipPath id="fl-rr-${uid}"><rect width="400" height="400" rx="88"/></clipPath><clipPath id="fl-bm-${uid}"><path d="${FL_BEAM}"/></clipPath></defs>
<rect width="400" height="400" rx="88" fill="#FFFFFF"/>
<g clip-path="url(#fl-rr-${uid})">${rows[0]}
<g class="beam"><path d="${FL_BEAM}" fill="#FFE7A6"/><g clip-path="url(#fl-bm-${uid})"><g class="dec">${rows[1]}</g><g class="enc">${rows[2]}</g></g></g></g>
<g transform="translate(120 290) rotate(45)"><rect x="-28" y="0" width="56" height="100" rx="14" fill="#111111"/><path d="M-44 -50 L44 -50 L30 0 L-30 0 Z" fill="#111111"/><rect class="lens" x="-47" y="-62" width="94" height="18" rx="9" fill="#FFA51F"/></g>
<rect x="3" y="3" width="394" height="394" rx="85" fill="none" stroke="#E4E4E0" stroke-width="6"/></svg>`;
}
// HTTPS state of the connected phone: some refused TLS handshakes are normal (pinned Apple hosts are
// ignored server-side), ok only after a real decrypted HTTPS request
function httpsState(d) {
  if (d.https_ok) return "ok";
  return (d.tls_fail_hosts || []).length >= 2 ? "bad" : "wait";
}
function deviceLabel(d) { return [d.name, d.model, d.os, d.ip].filter(Boolean).join(" · "); }
// phone connected, but it refused the certificate and nothing works over HTTPS yet
function httpsBlocked() { return !!(S.device && (S.device.tls_fail_hosts || []).length >= 2 && !S.device.https_ok) && connState() === "waiting"; }
function connState() {
  if (S.offline) return "offline";
  // "other" = non-tracking traffic, hidden by default: it means connected, not "hits"
  if (S.hits.some(h => h.tool !== "other")) return "hits";
  return S.device ? "waiting" : "idle";
}
function renderIcon() {
  const st = connState();
  const on = !S.paused && (st === "hits" || st === "waiting");
  const box = $("hdrIcon");
  if (!box.firstElementChild) box.innerHTML = flIcon("hdr", false);
  // adding the class again restarts the flicker (after connect / Resume)
  box.firstElementChild.classList.toggle("is-on", on);
  box.firstElementChild.classList.toggle("is-blocked", on && httpsBlocked());
  box.title = S.paused ? "Paused" : on && httpsBlocked() ? "HTTPS is blocked: the iPhone doesn't trust the certificate" : st === "offline" ? "Proxy not running" : S.device ? `Connected: ${deviceLabel(S.device)}` : "No device connected";
}
function onboarding() {
  // one screen: the steps stay visible, each one shows its live state once the iPhone connects
  const on = connState() === "waiting";
  const d = S.device;
  const hs = on ? httpsState(d) : null;
  const server = S.proxy.ip ? esc(S.proxy.ip) : "&lt;your computer's IP&gt;";
  const st = { ok: `<span class="hs ok">✅ Trusted</span>`, bad: `<span class="hs bad">❌ Not trusted yet</span>`, wait: `<span class="hs wait"><span class="em">⏳</span> Checking</span>` }[hs] || "";
  return `<div class="onboard-wrap"><div class="onboard${on ? " on" : ""}">${flIcon("big", on, true, on && httpsBlocked())}
    <h2>Connect your iPhone.</h2>
    ${on ? `<div class="conn">✅ iPhone connected<small>${esc(d.ip || "")}</small></div>`
      : `<ol class="tint"><li>Join the same Wi-Fi as this computer.</li>
      <li>Set the Wi-Fi proxy to Manual: Server <code>${server}</code>, Port <code>${esc(S.proxy.port || 8080)}</code></li></ol>`}
    <div class="cert"><div class="cert-hd">Certificate <span class="pill">Only once per iPhone</span>${st}</div>
    ${hs === "ok" ? "" : `<ol start="3"><li>Open <code>mitm.it</code> in Safari on the iPhone, download the certificate and install it in Settings → General → VPN &amp; Device Management.</li>
      <li>Trust it: Settings → General → About → Certificate Trust Settings → turn it on.</li></ol>`}</div>
    ${on ? `<div class="next"><span class="em">⏳</span> Open your app. The first hit shows up here.</div>` : ""}
    ${S.offline ? `<div class="foot">Proxy is not running</div>` : ""}</div></div>`;
}

function renderList() {
  const rows = [];
  let n = 0;
  for (let i = S.hits.length - 1; i >= 0; i--) {
    const h = S.hits[i];
    if (!visible(h)) continue;
    n++;
    if (rows.length >= 2000) continue;
    const t = tool(h.tool);
    const bad = h.status === "error" || (typeof h.status === "number" && h.status >= 400);
    rows.push(`<tr data-id="${h.id}" class="${h.id === S.selected ? "sel" : ""}">
      <td class="t">${fmtTime(h.time)}</td>
      <td class="tool">${logoImg(t)}${esc(t.label)}</td>
      <td class="url" title="${esc(h.url)}">${esc(endpoint(h.url))}</td>
      <td class="st ${bad ? "bad" : ""}">${esc(h.status ?? "")}</td>
      <td class="ev" title="${esc(h.event)}">${issueMark(h)}${esc(h.event)}</td></tr>`);
  }
  const head = `<thead><tr><th class="t">Time</th><th class="tool">Tool</th><th class="url">URL</th><th class="st">Status</th><th class="ev">Event name</th></tr></thead>`;
  const html = rows.length ? `<table class="hits">${head}<tbody>${rows.join("")}</tbody></table>`
    : connState() !== "hits" && !S.sel.size ? onboarding() : `<div class="empty">No hits match the filter.</div>`;
  // keep the DOM (and its animations) when nothing changed
  if (html !== S.listHtml) { S.listHtml = html; $("list").innerHTML = html; }
  $("count").textContent = `${n} hit${n === 1 ? "" : "s"}`;
}

// nested objects / arrays -> one row per value with a path key (#1.#3, items[0].item_id)
function flatten(obj, prefix, out) {
  for (const [k, v] of Object.entries(obj)) {
    const key = Array.isArray(obj) ? `${prefix}[${k}]` : (prefix ? `${prefix}.${k}` : k);
    if (v && typeof v === "object" && Object.keys(v).length) flatten(v, key, out);
    else out.push([key, v]);
  }
  return out;
}
function kvTable(obj) {
  const rows = flatten(obj || {}, "", []).map(([k, v]) =>
    `<tr><td>${esc(k)}</td><td>${esc(typeof v === "object" && v !== null ? JSON.stringify(v) : fmtVal(v))}</td></tr>`);
  return rows.length ? `<table class="kv">${rows.join("")}</table>` : `<div class="hint">—</div>`;
}

// shown in the detail panel while no hit is selected
const EMPTY_DETAIL = `<div class="empty">Select a hit to see its parameters.</div>
  <div class="promo-card">
    <div class="pc-q">Do you want to skip trial and error in mobile app attribution?
      <a href="https://www.measure-apps.com/courses/marketing-analytics?utm_source=tracking-debugger&amp;utm_medium=app&amp;utm_campaign=detail" target="_blank" rel="noopener">Explore the course →</a></div>
    <ul>
      <li><b>Dev spec handbook:</b> what to ask devs for, and what you handle yourself</li>
      <li><b>Live sandbox app:</b> test and debug tracking without touching production</li>
      <li><b>iOS measurement decoded:</b> ATT, IDFA, and SKAN schemas in practice</li>
    </ul>
  </div>`;

function renderDetail() {
  const h = S.hits.find(x => x.id === S.selected);
  $("detail").classList.toggle("idle", !h);
  if (!h) { $("detail").innerHTML = EMPTY_DETAIL; return; }
  const t = tool(h.tool);
  let html = `<span class="badge" style="--c:${t.color}">${esc(t.label)}</span>
    <h2>${esc(h.event)}</h2>
    <div class="meta">
      <div>Event time: ${esc(new Date(h.time).toLocaleString())}</div>
      ${h.sent !== h.time ? `<div>Sent: ${esc(new Date(h.sent).toLocaleString())}</div>` : ""}
      <div>${esc(h.method)} ${esc(h.url)}</div>
      <div>Status: ${esc(h.status ?? "—")}</div>
    </div>
    <div class="actions">
      <button id="copy">Copy JSON</button>
      ${S.mitmweb ? `<a href="${esc(S.mitmweb)}#/flows/${esc(h.flow_id)}/request" target="_blank" rel="noopener">Open in mitmweb</a>` : ""}
    </div>
    ${issueCard(h)}
    <h3>Parameters</h3>${kvTable(h.params)}`;
  for (const [name, sec] of Object.entries(h.extra || {})) html += `<h3>${esc(name.replace(/_/g, " "))}</h3>${kvTable(sec)}`;
  $("detail").innerHTML = html;
  $("copy").onclick = () => {
    const txt = JSON.stringify({ tool: t.label, event: h.event, params: h.params, ...h.extra }, null, 2);
    (navigator.clipboard ? navigator.clipboard.writeText(txt) : Promise.reject()).then(
      () => { $("copy").textContent = "Copied"; setTimeout(() => { const b = $("copy"); if (b) b.textContent = "Copy JSON"; }, 1200); },
      () => prompt("Copy:", txt));
  };
}

function render() { S.cross = crossIssues(S.hits); renderApps(); renderChips(); renderList(); }

// ---- Issue copy (edit here) ----
// level: "critical" = data is lost or there is a legal risk (solid red !, use rarely)
//        "warning"  = data is likely incomplete or skewed, depends on the setup (outlined red !)
//        "info"     = context worth knowing, nothing is broken (teal i)
const ISSUES = {
  webview: {
    level: "warning",
    title: "GA4 web tracking inside a webview",
    why: "The webview sends its own web session next to the Firebase SDK. GA4 counts the same user twice and the funnel breaks where the webview starts.",
    fix: "Pass the web events to the native Firebase SDK through a JavaScript bridge instead of sending them from the web tag.",
  },
  ga4_mmp_link: {
    level: "warning",
    title: "Adjust is not linked to GA4",
    why: "Adjust only sends attribution to GA4 when it gets the Firebase app_instance_id. Without it, re-attributed users end up as direct traffic in GA4.",
    fix: "Read the app_instance_id from Firebase and set it as an Adjust session partner parameter before the Adjust SDK starts.",
  },
  mmp_revenue: {
    level: "warning",
    title: "Revenue is missing in the MMP",
    why: "GA4 sees the purchase, but the MMP or Meta does not get the revenue. ROAS in the MMP and in the ad networks stays empty and campaigns optimize blind.",
    fix: "Send the purchase to the MMP and Meta with revenue and currency, from the same place in the code as the GA4 event.",
  },
  deeplink: {
    level: "warning",
    title: "Deeplink open without attribution parameters",
    why: "The app opened from a link, but the link carries no tracker or UTM parameters. Neither the MMP nor GA4 can tell which campaign brought the user.",
    fix: "Build campaign links with the MMP's link builder, or add UTM parameters to every deeplink you put in a campaign.",
  },
  att: {
    level: "info",
    title: "ATT not authorized on this device",
    why: "Without ATT consent the MMP gets no IDFA. Attribution falls back to SKAN and probabilistic methods and ad networks lose user-level data.",
    fix: "Expected for many users. Check when the ATT prompt appears and test both answers before a release.",
  },
  af_encrypted: {
    level: "info",
    title: "AppsFlyer encrypts this request",
    why: "The AppsFlyer SDK encrypts the request body with a key built into the SDK, so no proxy can read it.",
    fix: "Test the events in the AppsFlyer UI instead.",
  },
  skan: {
    level: "info",
    title: "SKAdNetwork is active",
    why: "Apple reports installs from iOS ad campaigns through SKAN postbacks. What the ad networks see depends on your conversion value schema.",
    fix: "Check that the conversion value schema maps to your key events and fits the measurement windows.",
  },
  skan_mmp: {
    level: "info",
    title: "Your MMP measures SKAN",
    why: "The MMP SDK manages SKAdNetwork conversion values in the app. What the ad networks see depends on the conversion value schema set in the MMP.",
    fix: "Check that the conversion value schema maps to your key events and fits the measurement windows.",
  },
  install: {
    level: "info",
    title: "Install moment",
    why: "This is the event GA4 and the MMP attribute the install to. Everything the user does later inherits that source.",
    fix: "first_open and the MMP's first session should fire once, on the very first launch. Reinstall the app to test it again.",
  },
  firebase_error: {
    level: "critical",
    title: "Firebase dropped data",
    why: "The SDK rejected a parameter or an event. It never reaches GA4 and nothing in the app tells you.",
    fix: "Error 4 means a value longer than 100 characters. Shorten it or split it into two parameters. Other codes point to invalid names or too many parameters.",
  },
  debug: {
    level: "info",
    title: "Debug mode is on",
    why: "GA4 marks debug events as developer traffic. With the developer traffic filter active, they are left out of your reports.",
    fix: "Fine on a test build. Make sure -FIRDebugEnabled / debug_mode is never part of a release build.",
  },
  ecommerce_revenue: {
    level: "critical",
    title: "Purchase revenue is not counted",
    why: "Without currency or a numeric value GA4 does not count the revenue of this purchase at all.",
    fix: "Send value as a number and currency (ISO code, e.g. EUR) on every purchase and refund.",
  },
  ecommerce: {
    level: "warning",
    title: "Purchase is missing ecommerce data",
    why: "Without transaction_id GA4 cannot deduplicate purchases. Without items the item reports stay empty.",
    fix: "Send transaction_id and items with item_id or item_name on every purchase and refund.",
  },
  pii: {
    level: "critical",
    title: "Personal data sent to Google",
    why: "Email addresses and phone numbers are not allowed in GA4. Google can delete the data, and it is a GDPR problem on your side.",
    fix: "Remove it or hash it before sending. Never use an email address as user_id.",
  },
};
// ---- Course calls to action (edit here) ----
// One CTA per hit: the CTA of the hit's main issue (critical > warning > info), otherwise the hit's tool ("tool:<key>").
const COURSES = {
  webview: { name: "Webview Measurement Course", url: "https://www.measure-apps.com/courses/webview-measurement" },
  marketing: { name: "Marketing Analytics Course", url: "https://www.measure-apps.com/courses/marketing-analytics" },
  // not a course: AppsFlyer's own guide (no UTM parameters)
  afdocs: { name: "AppsFlyer", url: "https://support.appsflyer.com/hc/en-us/articles/360001559405-Testing-the-SDK-integration-for-marketers", external: true },
};
const CTAS = {
  // [course, technical fact (one sentence), link text pointing to the concrete lesson / artifact]
  // issue based
  af_encrypted: ["afdocs", "AppsFlyer encrypts this request, so Flashlight can't read the event data. Test the events in the AppsFlyer UI instead.",
    "How to test in AppsFlyer"],
  webview: ["webview", "The webview sends its own GA4 session next to the Firebase SDK, so one user counts twice and the funnel breaks where the webview starts.",
    "Get the JavaScript bridge spec, GTM tag template and test app"],
  ga4_mmp_link: ["marketing", "Adjust needs the Firebase app_instance_id as a partner parameter, otherwise re-attributed users show up as direct traffic in GA4.",
    "See how partner parameters connect Adjust with GA4"],
  att: ["marketing", "No ATT consent means no IDFA (device ID). Don't switch the SDK off, the MMP moves to non-identifying measurement on its own.",
    "See what changes for MMPs and ad networks without ATT"],
  skan: ["marketing", "Apple only sends a conversion value above crowd anonymity tier 0, and later postbacks carry coarse values only.",
    "Build your schema in the SKAN conversion schema builder"],
  skan_mmp: ["marketing", "Your app is using SKAN. With a weak conversion value schema, your iOS campaigns optimize on almost no data.",
    "Learn how to set up SKAN right"],
  install: ["marketing", "first_open also fires on reinstalls. Real first installs are the ones with previous_first_open_count = 0.",
    "Get the BigQuery query for first-ever installs"],
  // tool based: hits of these tools without any issue (fact from the course lesson + link phrased like documentation)
  "tool:adjust": ["marketing", "Adjust exports raw data for free, but Google Ads and Meta installs first arrive as organic and get their real source later in an install_update row.",
    "See the Adjust to BigQuery export guide"],
  "tool:appsflyer": ["marketing", "AppsFlyer charges for raw data export (Data Locker), while Adjust exports raw data to cloud storage for free.",
    "Compare MMP features and raw export workflows"],
  "tool:meta": ["marketing", "The Meta SDK only measures Meta campaigns, every new network means another SDK and app release, and two networks can claim the same install.",
    "See the 5 problems with ad network SDKs and when an MMP pays off"],
  "tool:tiktok": ["marketing", "The TikTok SDK only measures TikTok campaigns, every new network means another SDK and app release, and two networks can claim the same install.",
    "See the 5 problems with ad network SDKs and when an MMP pays off"],
  "tool:snap": ["marketing", "The Snapchat SDK only measures Snapchat campaigns, every new network means another SDK and app release, and two networks can claim the same install.",
    "See the 5 problems with ad network SDKs and when an MMP pays off"],
  "tool:googleads": ["marketing", "Android installs and deep link campaigns are measurable today, iOS install campaigns also need ATT, a SKAN schema and on-device measurement (Firebase SDK 11.14.0+).",
    "Check if you're ready for Google Ads app campaigns"],
};
function mainIssue(h) {
  // critical before warning before info; the first one is the only message shown for the hit
  return issuesOf(h).slice().sort((a, b) => sev(a) - sev(b))[0] || null;
}
function ctaKey(h) {
  // the CTA belongs to the hit's one shown issue; an Adjust / ad network hit without issues gets its tool's CTA.
  // CTAs are always shown (no close button) for now.
  const main = mainIssue(h);
  if (main) return CTAS[main.type] ? main.type : null;
  return CTAS["tool:" + h.tool] ? "tool:" + h.tool : null;
}
// exactly one message per hit: the green course box when the hit's main issue (or tool) has a CTA,
// otherwise one box with the main issue. Other issues are only in the tooltip of the list marker.
function issueCard(h) {
  const k = ctaKey(h);
  if (k) {
    const [course, text, link] = CTAS[k];
    const c = COURSES[course];
    const url = c.external ? c.url : `${c.url}?utm_source=tracking-debugger&utm_medium=app&utm_campaign=${k.startsWith("tool:") ? "tool-" + k.slice(5) : "issue-" + k}`;
    return `<div class="cta-box">${esc(text)} <a href="${esc(url)}" target="_blank" rel="noopener">${esc(link)}&nbsp;→</a></div>`;
  }
  const main = mainIssue(h);
  if (!main) return "";
  const info = issueInfo(main.type);
  const details = [...new Set(issuesOf(h).filter(i => i.type === main.type).map(i => i.detail).filter(Boolean))];
  return `<div class="iwarn ${info.level}"><b>${esc(info.title)}</b>${details.length ? `<div>${esc(details.join(" · "))}</div>` : ""}<div class="hint">${esc(info.fix)}</div></div>`;
}

// ---- Checks that need several hits of the same app ----
function crossIssues(hits) {
  const out = {};
  const add = (h, issue) => (out[h.id] = out[h.id] || []).push(issue);
  const apps = {};
  for (const h of hits) (apps[h.app || ""] = apps[h.app || ""] || []).push(h);
  for (const list of Object.values(apps)) {
    const ga4 = list.filter(h => h.tool === "ga4" || h.tool === "sgtm");
    const adjust = list.filter(h => h.tool === "adjust");
    const meta = list.filter(h => h.tool === "meta");
    const purchase = ga4.find(h => h.event === "purchase");
    if (purchase && adjust.length && !adjust.some(h => h.params && h.params.revenue !== undefined))
      add(purchase, { type: "mmp_revenue", detail: "GA4 purchase, no Adjust event with revenue" });
    if (purchase && meta.length && !meta.some(h => /purchase/i.test(h.event)))
      add(purchase, { type: "mmp_revenue", detail: "GA4 purchase, no Meta purchase event" });
    const ids = [...new Set(ga4.map(h => h.extra && h.extra.device_app && h.extra.device_app.app_instance_id).filter(Boolean))];
    if (ids.length && adjust.length && !adjust.some(h => ids.some(id => JSON.stringify(h.params).includes(id)))) {
      const hit = adjust.find(h => h.event === "session") || adjust[0];
      add(hit, { type: "ga4_mmp_link", detail: "Adjust requests don't carry the Firebase app_instance_id" });
    }
  }
  return out;
}
// checks that are switched off: detected, but not shown anywhere
const HIDDEN_ISSUES = new Set(["debug", "deeplink", "mmp_revenue"]);
function issuesOf(h) { return [...(h.issues || []), ...((S.cross || {})[h.id] || [])].filter(i => !HIDDEN_ISSUES.has(i.type)); }

function issueInfo(type) { return ISSUES[type] || { title: type, why: "", fix: "", level: "warning" }; }
const SEVERITY = { critical: 0, warning: 1, info: 2 };
function sev(i) { return SEVERITY[issueInfo(i.type).level] ?? 1; }
function issueMark(h) {
  // the list only flags critical problems; warnings and info are shown in the hit detail
  const list = issuesOf(h).filter(i => issueInfo(i.type).level === "critical");
  if (!list.length) return "";
  return `<span class="warn critical" title="${esc(list.map(i => issueInfo(i.type).title).join(", "))}">!</span>`;
}

async function poll() {
  if (!S.paused) {
    try {
      const r = await fetch(`/api/hits?after=${S.after}`);
      const d = await r.json();
      if (!S.toolOrder.length) {
        for (const t of d.tools) { S.tools[t.key] = t; S.toolOrder.push(t.key); }
      }
      S.mitmweb = d.mitmweb;
      const before = connState() + JSON.stringify(S.device && [S.device.ip, S.device.name, S.device.model, S.device.os, !!S.device.https_ok, (S.device.tls_fail_hosts || []).length, S.device.tls_fail_host]) + JSON.stringify(S.proxy);
      S.offline = false; S.device = d.device || null; S.proxy = d.proxy || {};
      if (before !== connState() + JSON.stringify(S.device && [S.device.ip, S.device.name, S.device.model, S.device.os, !!S.device.https_ok, (S.device.tls_fail_hosts || []).length, S.device.tls_fail_host]) + JSON.stringify(S.proxy)) renderList();
      renderIcon();
      renderApps(d.apps || []);
      if (JSON.stringify(d.domains) !== JSON.stringify(S.domains)) {
        const added = S.domainsLoaded ? d.domains.filter(x => !S.domains.includes(x)) : [];
        S.domains = d.domains;
        renderDomains();
        if (document.activeElement !== $("domainsInput")) $("domainsInput").value = d.domains.join(", ");
        if (added.length && !S.savingDomains) {
          // detected automatically (Firebase config) -> show the settings with the new domain
          $("domains").classList.add("open", "flash");
          $("domainsNote").textContent = "Detected automatically: " + added.join(", ");
          setTimeout(() => $("domains").classList.remove("flash"), 2500);
        }
      }
      S.domainsLoaded = true;
      if (d.gen !== S.gen) {
        // server list was cleared or reclassified -> reload everything
        const first = S.gen === null && S.after === 0;
        S.gen = d.gen; S.hits = []; S.after = 0;
        if (!first) { render(); renderDetail(); return poll(); }
      }
      if (d.hits.length) {
        S.hits.push(...d.hits);
        S.after = d.hits[d.hits.length - 1].id;
        render(); renderIcon();
        if (S.selected) renderDetail();
      }
    } catch (e) {
      $("count").textContent = "Disconnected from the proxy";
      if (!S.offline) { S.offline = true; renderList(); renderIcon(); }
    }
  }
  setTimeout(poll, 1000);
}

$("apps").addEventListener("click", e => {
  const a = e.target.closest(".chip"); if (!a) return;
  S.appSel = a.dataset.b || null;
  renderApps();
  render();
});
$("chips").addEventListener("click", e => {
  if (e.target.closest(".adv-toggle")) {
    S.advOpen = !S.advOpen;
    store.set("atd.adv", S.advOpen);
    renderChips();
    return;
  }
  const c = e.target.closest(".chip"); if (!c) return;
  const k = c.dataset.k;
  if (!k) S.sel.clear();
  else if (S.sel.has(k)) S.sel.delete(k);
  else S.sel.add(k);
  store.set("atd.sel", [...S.sel]);
  render();
});
$("list").addEventListener("click", e => {
  const tr = e.target.closest("tr[data-id]"); if (!tr) return;
  S.selected = Number(tr.dataset.id);
  document.querySelectorAll(".hits tr.sel").forEach(x => x.classList.remove("sel"));
  tr.classList.add("sel");
  renderDetail();
});
$("search").addEventListener("input", e => { setQuery(e.target.value.trim()); store.set("atd.q", S.q); renderList(); });
$("pause").onclick = () => {
  S.paused = !S.paused;
  $("pause").textContent = S.paused ? "Resume" : "Pause";
  $("hdr").classList.toggle("paused", S.paused);
  renderIcon();
};
$("clear").onclick = async () => { await fetch("/api/clear", { method: "POST" }); S.selected = null; renderDetail(); renderIcon(); };
function renderDomains() {
  $("domainsCount").textContent = S.domains.length ? `(${S.domains.length})` : "";
  $("domainsPop").innerHTML = `<div class="ttl">Remembered sGTM domains</div>` + (S.domains.length
    ? `<ul>${S.domains.map(x => `<li>${esc(x)}</li>`).join("")}</ul>`
    : `<div class="hint">None yet. They are detected from the Firebase config or added by hand.</div>`);
}
async function saveDomains(list) {
  S.savingDomains = true;
  const r = await fetch("/api/domains", { method: "POST", body: JSON.stringify(list) });
  const d = await r.json();
  S.savingDomains = false;
  S.domains = d.domains; renderDomains();
  $("domainsInput").value = d.domains.join(", "); $("domainsNote").textContent = "";
}
$("domainsBtn").onclick = () => $("domains").classList.toggle("open");
$("domainsClose").onclick = () => $("domains").classList.remove("open");
$("domainsForget").onclick = async () => {
  if (!S.domains.length) return;
  if (!confirm(`Forget all ${S.domains.length} remembered sGTM domain(s)?`)) return;
  await saveDomains([]);
};
$("domainsSave").onclick = async () => {
  await saveDomains($("domainsInput").value.split(/[\s,]+/).filter(Boolean));
  $("domainsSave").textContent = "Saved";
  setTimeout(() => $("domainsSave").textContent = "Save", 1200);
};
$("domainsInput").addEventListener("keydown", e => { if (e.key === "Enter") $("domainsSave").click(); });
render();
renderDetail();
renderDomains();
poll();
</script>
</body>
</html>
"""
