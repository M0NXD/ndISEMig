#!/usr/bin/env python3
"""
ndISEMig
Backup and restore ISE configuration via the ERS API.
Supports ISE 2.4 through 3.6+.
"""

from __future__ import annotations

__version__ = "0.50"

import copy
import csv
import json
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime
import urllib3
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── Version utilities ────────────────────────────────────────────────────────

def parse_ver(version_str: str) -> tuple[int, ...]:
    """'3.3.0.458' → (3, 3, 0, 458).  Returns (0,) on any parse failure."""
    try:
        return tuple(int(x) for x in str(version_str).strip().split("."))
    except Exception:
        return (0,)


def ver_lt(version_str: str, major: int, minor: int = 0) -> bool:
    """True when version_str is older than major.minor."""
    return parse_ver(version_str) < (major, minor)


def ver_gte(version_str: str, major: int, minor: int = 0) -> bool:
    """True when version_str is major.minor or newer."""
    return parse_ver(version_str) >= (major, minor)


def ver_display(version_str: str) -> str:
    """Return a short human-readable version label, e.g. '3.3' or 'unknown'."""
    v = parse_ver(version_str)
    if not v or v == (0,):
        return "unknown"
    return ".".join(str(x) for x in v[:2])


# ── Resource catalogue ──────────────────────────────────────────────────────
#
# Each resource entry:
#   ers      – ERS path segment  (/ers/config/<ers>)
#   key      – root JSON key in the API response body
#   min_ver  – (major, minor) tuple; resource skipped if ISE < this version
#              omit or None means "available since 2.4"
#
# Resources not listed here that return 404 are automatically skipped.

RESOURCE_CATEGORIES = {
    "Identity & Users": {
        "resources": {
            "Identity Groups":        {"ers": "identitygroup",         "key": "IdentityGroup"},
            "Internal Users":         {"ers": "internaluser",          "key": "InternalUser"},
            "Guest Types":            {"ers": "guesttype",             "key": "GuestType"},
            "Guest Users":            {"ers": "guestuser",             "key": "GuestUser"},
            "Sponsor Groups":         {"ers": "sponsorgroup",          "key": "SponsorGroup"},
        }
    },
    "Network Devices": {
        "resources": {
            "Network Device Groups":  {"ers": "networkdevicegroup",    "key": "NetworkDeviceGroup"},
            "Network Devices (NADs)": {"ers": "networkdevice",         "key": "NetworkDevice"},
        }
    },
    "Endpoints": {
        "resources": {
            "Endpoint Groups":        {"ers": "endpointgroup",         "key": "EndPointGroup"},
            "Endpoints":              {"ers": "endpoint",              "key": "ERSEndPoint"},
        }
    },
    "Authorization": {
        "resources": {
            "Downloadable ACLs":      {"ers": "downloadableacl",       "key": "DownloadableAcl"},
            "Allowed Protocols":      {"ers": "allowedprotocols",      "key": "AllowedProtocols"},
            "Authorization Profiles": {"ers": "authorizationprofile",  "key": "AuthorizationProfile"},
        }
    },
    "TrustSec": {
        "resources": {
            "Security Groups (SGT)":  {"ers": "sgt",                   "key": "Sgt"},
            "Security Group ACLs":    {"ers": "sgacl",                 "key": "Sgacl"},
            "Egress Matrix Cells":    {"ers": "egressmatrixcell",      "key": "EgressMatrixCell"},
            "SG IP Mappings":         {"ers": "sgmapping",             "key": "SGMapping"},
            "SG IP Mapping Groups":   {"ers": "sgmappinggroup",        "key": "SGMappingGroup"},
            "SGT VLAN/VN":            {"ers": "sgtvnvlan",             "key": "SgtVnVlanContainer"},
        }
    },
    "TACACS+": {
        "resources": {
            "TACACS Profiles":        {"ers": "tacacsprofile",         "key": "TacacsProfile"},
            "TACACS Command Sets":    {"ers": "tacacscommandsets",     "key": "TacacsCommandSets"},
            "TACACS Ext Servers":     {"ers": "tacacsexternalservers", "key": "TacacsExternalServer"},
            "TACACS Server Seq":      {"ers": "tacacsserversequence",  "key": "TacacsServerSequence"},
        }
    },
    "RADIUS": {
        "resources": {
            "Ext RADIUS Servers":     {"ers": "externalradiusserver",  "key": "ExternalRadiusServer"},
            "RADIUS Server Seq":      {"ers": "radiusserversequence",  "key": "RadiusServerSequence"},
        }
    },
    "Identity Sources": {
        "resources": {
            "ID Store Sequences":     {"ers": "idstoresequence",       "key": "IdStoreSequence"},
            "REST ID Stores":         {"ers": "restidstore",           "key": "RESTIDStore",
                                       "min_ver": (2, 6)},
            "Certificate Profiles":   {"ers": "certificateprofile",    "key": "CertificateProfile"},
        }
    },
    "Portals & Guest": {
        "resources": {
            "Guest Locations/SSIDs":  {"ers": "guestlocation",         "key": "LocationIdentification"},
            "Portal Themes":          {"ers": "portaltheme",           "key": "PortalTheme"},
            "Hotspot Portals":        {"ers": "hotspotportal",         "key": "HotspotPortal"},
            "Self-Reg Portals":       {"ers": "selfregportal",         "key": "SelfRegPortal"},
            "Sponsor Portals":        {"ers": "sponsorportal",         "key": "SponsorPortal"},
            "My Devices Portals":     {"ers": "mydeviceportal",        "key": "MyDevicePortal"},
            "BYOD Portals":           {"ers": "byodportal",            "key": "BYODPortal"},
        }
    },
    "Profiling": {
        "resources": {
            "Profiler Profiles":      {"ers": "profilerprofile",       "key": "ProfilerProfile"},
        }
    },
    "ANC Policies": {
        "resources": {
            "ANC Policies":           {"ers": "ancpolicy",             "key": "ErsAncPolicy"},
        }
    },
    "ISE 3.x Features": {
        "resources": {
            "Filter-IP Policies":     {"ers": "filteripolicy",         "key": "ERSFilterIpPolicy",
                                       "min_ver": (3, 0)},
        }
    },
    # Policy Sets and the policy library objects they reference are NOT exposed
    # by the ERS API.  They live on the OpenAPI gateway (/api/v1/policy/...),
    # which is a separate API surface introduced in ISE 3.1.  These resources
    # are only available when "Enable OpenAPI" is ticked on the connection and
    # the gateway probe succeeds.
    "OpenAPI (ISE 3.1+)": {
        "api": "openapi",
        "resources": {
            "NA Dictionaries":        {"ers": "na_dictionary", "key": "", "api": "openapi",
                                       "min_ver": (3, 1), "ptype": "network-access",
                                       "kind": "dictionary"},
            "NA Library Conditions":  {"ers": "na_condition",  "key": "", "api": "openapi",
                                       "min_ver": (3, 1), "ptype": "network-access",
                                       "kind": "condition"},
            "NA Policy Sets":         {"ers": "na_policyset",  "key": "", "api": "openapi",
                                       "min_ver": (3, 1), "ptype": "network-access",
                                       "kind": "policyset"},
            "DA Dictionaries":        {"ers": "da_dictionary", "key": "", "api": "openapi",
                                       "min_ver": (3, 1), "ptype": "device-admin",
                                       "kind": "dictionary"},
            "DA Library Conditions":  {"ers": "da_condition",  "key": "", "api": "openapi",
                                       "min_ver": (3, 1), "ptype": "device-admin",
                                       "kind": "condition"},
            "DA Policy Sets":         {"ers": "da_policyset",  "key": "", "api": "openapi",
                                       "min_ver": (3, 1), "ptype": "device-admin",
                                       "kind": "policyset"},
            # Overlaps with ERS, but reachable over the 443 gateway — useful when
            # the legacy ERS port (9060) is blocked or unreliable.
            "Endpoints (OpenAPI)":    {"ers": "oapi_endpoint", "key": "", "api": "openapi",
                                       "min_ver": (3, 2), "kind": "endpoint"},
            "TrustSec Virtual Nets":  {"ers": "ts_vn",        "key": "", "api": "openapi",
                                       "min_ver": (3, 1), "kind": "ts_vn"},
            "TrustSec SG-VN Maps":    {"ers": "ts_sgvn",      "key": "", "api": "openapi",
                                       "min_ver": (3, 1), "kind": "ts_sgvn"},
            "TrustSec VN-VLAN Maps":  {"ers": "ts_vnvlan",    "key": "", "api": "openapi",
                                       "min_ver": (3, 1), "kind": "ts_vnvlan"},
            # Native IPsec is configured over the OpenAPI gateway (/api/v1/ipsec),
            # NOT ERS — added in ISE 3.3.  Keyed by hostName+nadIp; the pre-shared
            # key is write-only and not returned by GET, so imported tunnels need
            # their PSK re-entered (same caveat as RADIUS/TACACS secrets).
            "Native IPsec":           {"ers": "nativeipsec",  "key": "", "api": "openapi",
                                       "min_ver": (3, 3), "kind": "ipsec"},
        }
    },
}

# Creation order: dependencies before objects that reference them.
IMPORT_ORDER = [
    "identitygroup", "networkdevicegroup", "endpointgroup",
    "downloadableacl", "allowedprotocols", "sgt", "sgacl",
    "tacacsprofile", "tacacscommandsets", "tacacsexternalservers",
    "externalradiusserver", "certificateprofile", "restidstore",
    "guesttype", "sponsorgroup", "guestlocation", "portaltheme",
    "authorizationprofile",
    "tacacsserversequence", "radiusserversequence", "idstoresequence",
    "networkdevice", "endpoint",
    "internaluser", "guestuser",
    "sgmapping", "sgmappinggroup", "egressmatrixcell", "sgtvnvlan",
    "hotspotportal", "selfregportal", "sponsorportal", "mydeviceportal",
    "byodportal", "profilerprofile",
    "ancpolicy",
    "filteripolicy",
    # OpenAPI policy objects — dictionaries and library conditions must exist
    # before the policy sets / rules that reference them.
    "na_dictionary", "da_dictionary",
    "na_condition", "da_condition",
    "na_policyset", "da_policyset",
    # Other OpenAPI resources (order-independent relative to ERS).
    "ts_vn", "ts_sgvn", "ts_vnvlan",
    "oapi_endpoint", "nativeipsec",
]

# Server-managed fields that must not appear in POST or PUT bodies.
STRIP_ON_WRITE = {"id", "link", "portalType", "displayName"}

# ERS request timeouts as (connect, read) seconds.  The connect timeout is
# generous because some deployments are slow to accept the TCP connection on
# 9060 (a single 10 s connect would fail on the first try and only succeed on
# a retry).  Once the session's connection is established it is reused.
ERS_TIMEOUT = (20, 30)

# OpenAPI (/api/v1) gateway — used for Policy Sets and policy library objects
# that ERS does not expose.  Available on ISE 3.1+ with Open API enabled.
OPENAPI_PORT_DEFAULT = 443

# OpenAPI paths (relative to <base>/api/v1) for resources beyond Policy Sets.
# NOTE: these are the documented paths but vary slightly by ISE release — if a
# resource logs "Not supported — skipped" (HTTP 404), confirm the exact path in
# your node's Swagger UI (https://<ise>/api/swagger-ui/index.html) and adjust.
OAPI_ENDPOINT_PATH = "/endpoint"          # ISE 3.2+ (also /endpoint/bulk)
OAPI_TRUSTSEC_PATHS = {
    "ts_vn":     "/trustsec/virtualnetwork",   # TrustSec Virtual Networks
    "ts_sgvn":   "/trustsec/sgvnmapping",       # Security Group ↔ VN mappings
    "ts_vnvlan": "/trustsec/vnvlanmapping",     # VN ↔ VLAN mappings
}
OAPI_IPSEC_PATH = "/ipsec"                # Native IPsec connections (ISE 3.3+)
# Server-managed fields stripped from OpenAPI write bodies (wrappers and rules).
OAPI_STRIP = {"id", "link", "hitCounts"}
# Additional fields stripped from a policy-set body on write.  "default" is
# dropped because the target's default set already exists and is not re-created;
# the "_authentication"/"_authorization" keys are this tool's own carriers.
OAPI_SET_STRIP = OAPI_STRIP | {"default", "_authentication", "_authorization"}

# Placeholder used when ISE cannot export hashed passwords.
DEFAULT_USER_PASSWORD = "ISEmigration1!"

# Placeholder shared secret for imported network devices.  RADIUS/TACACS shared
# secrets are write-only and never returned by GET, but ISE *rejects* creation
# of a device whose RADIUS/TACACS block has no secret — so we inject this
# placeholder to let the device import, and the operator resets it afterward.
DEFAULT_SHARED_SECRET = "ISEmigration1!"

# Resources that use a field other than "name" as the natural unique key.
ALT_LOOKUP_FIELD: dict[str, str] = {
    "endpoint": "mac",
}

# Resources that carry a systemDefined flag — skip those on import.
HAS_SYSTEM_DEFINED = {
    "identitygroup", "endpointgroup", "sgt", "sgacl",
    "authorizationprofile", "allowedprotocols",
}

# Fields that were introduced in specific ISE versions.
# When importing INTO an older target, these are stripped.
VERSION_GATED_FIELDS: dict[str, list[dict]] = {
    # allowedprotocols: TEAP support added in 2.7
    "allowedprotocols": [
        {"fields": ["allowTeap", "teapEapMsList", "teapEapMsRequireCryptoBinding",
                    "teapEapMsAcceptClientCert", "teapEapMsRequireClientCert"],
         "min_ver": (2, 7)},
    ],
    # sgacl: TRAFFIC_STEERING type added in 3.5
    "sgacl": [
        {"fields": ["trafficSteering"],
         "min_ver": (3, 5)},
    ],
    # networkdevice: TACACS TLS settings added in 3.3
    "networkdevice": [
        {"fields": ["tacacsTlsSettings"],
         "min_ver": (3, 3)},
    ],
    # internaluser: custom attributes added in 3.3
    "internaluser": [
        {"fields": ["customAttributes"],
         "min_ver": (3, 3)},
    ],
}


# ── HTTP session with retry/backoff ──────────────────────────────────────────
#
# ISE caps concurrent ERS connections and returns HTTP 429 ("Too Many Requests")
# under load; Cisco's own guidance is to space requests out and back off on 429.
# The app server can also surface transient 502/503/504 during failover or while
# busy.  A urllib3 Retry on the adapter absorbs these automatically (it honours a
# Retry-After header when ISE sends one) and also retries connection-level
# failures, which the original generous connect timeout was working around.
#
# raise_on_status=False keeps non-200 *responses* flowing back to the existing
# per-call status handling — only genuine network exhaustion raises.  POST/PUT
# are included in the retried methods: a 429 means the request was rejected (not
# processed) so a retry is safe, and on the rare 5xx-after-write the callers
# already treat ISE's duplicate-object error as a skip.

RETRY_STATUSES = (429, 502, 503, 504)
RETRY_TOTAL = 4
RETRY_BACKOFF = 1.5   # urllib3 sleeps backoff*2**(n-1): ~1.5, 3, 6, 12 s


def build_retrying_session(username: str, password: str,
                           verify_ssl: bool) -> requests.Session:
    """A requests Session that retries 429/5xx and connection errors."""
    session = requests.Session()
    session.auth = (username, password)
    session.headers.update({
        "Accept": "application/json",
        "Content-Type": "application/json",
    })
    session.verify = verify_ssl
    # allowed_methods is the modern name (urllib3 ≥1.26); fall back to the older
    # method_whitelist on legacy urllib3 so this works across requests vintages.
    retry_kw = dict(
        total=RETRY_TOTAL,
        connect=RETRY_TOTAL,
        read=RETRY_TOTAL,
        status=RETRY_TOTAL,
        backoff_factor=RETRY_BACKOFF,
        status_forcelist=RETRY_STATUSES,
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    try:
        retry = Retry(allowed_methods=frozenset(
            ["GET", "POST", "PUT", "DELETE"]), **retry_kw)
    except TypeError:
        retry = Retry(method_whitelist=frozenset(
            ["GET", "POST", "PUT", "DELETE"]), **retry_kw)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


# ── ISE API client ──────────────────────────────────────────────────────────

class ISEClient:
    """Thin wrapper around the ISE ERS API (default port 9060)."""

    def __init__(self, host: str, username: str, password: str,
                 port: int = 9060, verify_ssl: bool = False):
        self.host = host
        self.port = port
        self.base = f"https://{host}:{port}/ers"
        self.version: str = ""          # populated after test_connection()
        self.session = build_retrying_session(username, password, verify_ssl)

    # ── Connection ──────────────────────────────────────────────────────────

    def test_connection(self) -> tuple[bool, str, str]:
        """Return (ok, version_string, message)."""
        # The ISE software version is exposed by op/systemconfig/iseversion
        # (ISE 2.x+).  Fall back to an internaluser list purely as a bare
        # connectivity/ERS-enabled probe on nodes where that op is unavailable.
        non_json = False   # saw HTTP 200 but the body was not ERS JSON
        for url in (
            f"{self.base}/config/op/systemconfig/iseversion",
            f"{self.base}/config/internaluser?size=1&page=1",
        ):
            try:
                r = self.session.get(url, timeout=ERS_TIMEOUT)
                if r.status_code == 200:
                    # A 200 alone is not proof of ERS — the API gateway returns
                    # an HTML page (still 200) when ERS is disabled or the wrong
                    # port is used.  Require a real JSON body.
                    try:
                        body = r.json()
                    except Exception:
                        non_json = True
                        continue   # try the next endpoint before giving up
                    self.version = self._parse_iseversion(body)
                    return True, self.version, "Connected"
                if r.status_code in (401, 403):
                    return False, "", (
                        f"Authentication failed (HTTP {r.status_code}). "
                        "Check credentials and that the account has the ERS Admin role.")
                # Non-200, non-auth → try next fallback URL
            except requests.exceptions.ConnectionError as exc:
                return False, "", f"Connection refused: {exc}"
            except requests.exceptions.Timeout:
                return False, "", (
                    f"Connection timed out (connect {ERS_TIMEOUT[0]} s). "
                    "The ERS port may be slow or blocked — try again, or check "
                    "that port 9060 is reachable.")
            except Exception as exc:
                return False, "", str(exc)
        if non_json:
            return False, "", (
                "Reached the server but it did not return ERS JSON (got an "
                "HTML/empty body). The ERS API is likely disabled on this node, "
                f"or the ERS port {self.port} is wrong — ERS normally uses 9060. "
                "Enable it under Administration › System › Settings › ERS Settings. "
                "(The OpenAPI gateway on 443 is separate from ERS.)")
        return False, "", "Unable to reach ERS API on either test endpoint"

    @staticmethod
    def _parse_iseversion(body) -> str:
        """Extract the ISE software version from an op/systemconfig/iseversion
        body, e.g. {'OperationResult': {'resultValue': [{'name': 'version',
        'value': '3.4.0.608'}, ...]}} → '3.4.0.608'.  Returns '' if absent."""
        if not isinstance(body, dict):
            return ""
        rv = body.get("OperationResult", {}).get("resultValue", [])
        if isinstance(rv, list):
            for entry in rv:
                if isinstance(entry, dict) and entry.get("name") == "version":
                    return entry.get("value", "") or ""
        return ""

    def get_version(self) -> str:
        """Return cached version string; fetch from ISE if not yet populated."""
        if self.version:
            return self.version
        try:
            r = self.session.get(
                f"{self.base}/config/op/systemconfig/iseversion",
                timeout=ERS_TIMEOUT)
            if r.status_code == 200:
                self.version = self._parse_iseversion(r.json())
        except Exception:
            pass
        return self.version

    # ── Read ────────────────────────────────────────────────────────────────

    def list_all(self, resource: str, page_size: int = 100) -> list | None:
        """
        Return list of stub dicts {id, name, link}, or None if unsupported.
        Raises PermissionError on 401/403.
        Raises RuntimeError on unexpected HTTP status or network errors.
        """
        items: list = []
        page = 1
        while True:
            url = f"{self.base}/config/{resource}?size={page_size}&page={page}"
            try:
                r = self.session.get(url, timeout=ERS_TIMEOUT)
                if r.status_code == 404:
                    return None       # not available on this ISE version
                if r.status_code in (401, 403):
                    raise PermissionError(
                        f"Auth failed for /{resource} (HTTP {r.status_code}). "
                        "Ensure the account has the ERS Admin role.")
                if r.status_code != 200:
                    raise RuntimeError(
                        f"HTTP {r.status_code} for /{resource}: {r.text[:200]}")
                try:
                    body = r.json()
                except Exception:
                    raise RuntimeError(
                        f"/{resource} returned HTTP 200 but not JSON — the ERS "
                        f"API is likely disabled or the ERS port ({self.port}) "
                        "is wrong (ERS uses 9060). Check ERS Settings.")
                sr = body.get("SearchResult", {}) if isinstance(body, dict) else {}
                chunk = sr.get("resources", [])
                items.extend(chunk)
                if len(chunk) < page_size:
                    break
                page += 1
            except (PermissionError, RuntimeError):
                raise
            except Exception as exc:
                raise RuntimeError(
                    f"Request error for /{resource}: {exc}") from exc
        return items

    def get_detail(self, resource: str, item_id: str) -> dict | None:
        """Return parsed JSON for a single item.

        Returns None only on HTTP 404 (the item vanished between the list and
        the detail fetch).  Raises RuntimeError on any other HTTP status or a
        network error so the caller can surface the loss instead of silently
        dropping the object from the backup.
        """
        try:
            r = self.session.get(
                f"{self.base}/config/{resource}/{item_id}", timeout=ERS_TIMEOUT)
        except Exception as exc:
            raise RuntimeError(str(exc)) from exc
        if r.status_code == 200:
            try:
                return r.json()
            except Exception as exc:
                raise RuntimeError(f"HTTP 200 but non-JSON body: {exc}") from exc
        if r.status_code == 404:
            return None
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")

    def get_all_details(self, resource: str, key: str,
                        progress_cb=None, error_cb=None) -> list | None:
        """
        Fetch full detail for every item of a resource type.
        Returns list of detail dicts, or None if resource is unsupported.
        Raises PermissionError / RuntimeError on list-level API failures.

        A failure to fetch one item's detail does NOT abort the run: error_cb,
        if given, is called with (identifier, exception) so the export can log
        the loss and flag the backup as partial rather than silently omit it.
        """
        stubs = self.list_all(resource)
        if stubs is None:
            return None
        total = len(stubs)
        results = []
        for idx, stub in enumerate(stubs):
            item_id = stub.get("id")
            if item_id:
                try:
                    detail = self.get_detail(resource, item_id)
                except Exception as exc:
                    if error_cb:
                        error_cb(stub.get("name") or item_id, exc)
                    detail = None
                if detail and key in detail:
                    results.append(detail[key])
            if progress_cb:
                progress_cb(idx + 1, total)
        return results

    def get_by_name(self, resource: str, name: str) -> dict | None:
        """Look up a resource by name. Returns full JSON response or None."""
        try:
            name = str(name)
            # ISE stores endpoint MACs uppercase; normalise so a lookup with a
            # lowercase MAC in the backup still matches (ISE treats the address
            # case-insensitively, but the /name/ path match does not).
            if resource == "endpoint":
                name = name.upper()
            # safe=":" preserves colons so MAC addresses (AA:BB:CC:DD:EE:FF) aren't percent-encoded
            safe = requests.utils.quote(name, safe=":")
            r = self.session.get(
                f"{self.base}/config/{resource}/name/{safe}", timeout=ERS_TIMEOUT)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return None

    # ── Write ───────────────────────────────────────────────────────────────

    def create(self, resource: str, key: str, payload: dict
               ) -> tuple[bool, str]:
        """Return (success, message)."""
        body = {key: {k: v for k, v in payload.items()
                      if k not in STRIP_ON_WRITE}}
        try:
            r = self.session.post(
                f"{self.base}/config/{resource}", json=body, timeout=ERS_TIMEOUT)
            if r.status_code in (200, 201):
                return True, "Created"
            return False, f"HTTP {r.status_code}: {r.text[:300]}"
        except Exception as exc:
            return False, str(exc)

    def update(self, resource: str, item_id: str, key: str, payload: dict
               ) -> tuple[bool, str]:
        """Return (success, message). Strips all server-managed fields."""
        body = {key: {k: v for k, v in payload.items()
                      if k not in STRIP_ON_WRITE}}
        try:
            r = self.session.put(
                f"{self.base}/config/{resource}/{item_id}",
                json=body, timeout=ERS_TIMEOUT)
            if r.status_code in (200, 201):
                return True, "Updated"
            return False, f"HTTP {r.status_code}: {r.text[:300]}"
        except Exception as exc:
            return False, str(exc)


# ── ISE OpenAPI client ───────────────────────────────────────────────────────

class OpenAPIClient:
    """
    Thin wrapper around the ISE OpenAPI gateway (/api/v1, default port 443).

    Unlike ERS, the OpenAPI wraps GET payloads in a {"response": ...} envelope
    and accepts flat (un-enveloped) bodies on POST/PUT.  It is the only API that
    exposes Policy Sets, policy rules, library conditions, and dictionaries, and
    it exists on ISE 3.1+ when Open API is enabled (Administration › System ›
    Settings › API Settings › API Service Settings).
    """

    def __init__(self, host: str, username: str, password: str,
                 port: int = OPENAPI_PORT_DEFAULT, verify_ssl: bool = False):
        self.host = host
        self.port = port
        self.base = f"https://{host}:{port}/api/v1"
        self.session = build_retrying_session(username, password, verify_ssl)

    def test_connection(self) -> tuple[bool, str]:
        """Probe the policy OpenAPI. Return (ok, message)."""
        url = f"{self.base}/policy/network-access/policy-set"
        try:
            r = self.session.get(url, timeout=15)
            if r.status_code == 200:
                return True, "OpenAPI reachable"
            if r.status_code in (401, 403):
                return False, (
                    f"OpenAPI authorization failed (HTTP {r.status_code}). "
                    "Enable Open API under Administration › System › Settings › "
                    "API Settings, and ensure the account has the required role.")
            if r.status_code == 404:
                return False, (
                    "OpenAPI policy endpoint not found (HTTP 404) — "
                    "requires ISE 3.1+ with Open API enabled.")
            return False, f"HTTP {r.status_code}: {r.text[:200]}"
        except requests.exceptions.ConnectionError as exc:
            return False, f"Cannot reach OpenAPI on port {self.port}: {exc}"
        except requests.exceptions.Timeout:
            return False, "OpenAPI connection timed out (15 s)"
        except Exception as exc:
            return False, str(exc)

    def get(self, path: str) -> list | dict | None:
        """
        GET <base><path> and return the unwrapped "response" payload.
        Returns None on 404 (resource unsupported).
        Raises PermissionError on 401/403, RuntimeError on other failures.
        """
        url = f"{self.base}{path}"
        try:
            r = self.session.get(url, timeout=30)
            if r.status_code == 404:
                return None
            if r.status_code in (401, 403):
                raise PermissionError(
                    f"Auth failed for {path} (HTTP {r.status_code}).")
            if r.status_code != 200:
                raise RuntimeError(
                    f"HTTP {r.status_code} for {path}: {r.text[:200]}")
            body = r.json()
            if isinstance(body, dict) and "response" in body:
                return body["response"]
            return body
        except (PermissionError, RuntimeError):
            raise
        except Exception as exc:
            raise RuntimeError(f"Request error for {path}: {exc}") from exc

    def post(self, path: str, body: dict) -> tuple[bool, str, dict]:
        """POST a flat body. Return (ok, message, created_object)."""
        url = f"{self.base}{path}"
        try:
            r = self.session.post(url, json=body, timeout=30)
            if r.status_code in (200, 201):
                obj: dict = {}
                try:
                    j = r.json()
                    if isinstance(j, dict):
                        resp = j.get("response", j)
                        obj = resp if isinstance(resp, dict) else {}
                except Exception:
                    pass
                # The new id often comes back only in the Location header.
                loc = r.headers.get("Location", "")
                if loc and not obj.get("id"):
                    obj["id"] = loc.rstrip("/").rsplit("/", 1)[-1]
                return True, "Created", obj
            return False, f"HTTP {r.status_code}: {r.text[:300]}", {}
        except Exception as exc:
            return False, str(exc), {}

    def put(self, path: str, body: dict) -> tuple[bool, str]:
        """PUT a flat body. Return (ok, message)."""
        url = f"{self.base}{path}"
        try:
            r = self.session.put(url, json=body, timeout=30)
            if r.status_code in (200, 201):
                return True, "Updated"
            return False, f"HTTP {r.status_code}: {r.text[:300]}"
        except Exception as exc:
            return False, str(exc)


# ── GUI constants ────────────────────────────────────────────────────────────

BG        = "#1e1e2e"
BG2       = "#313244"
BG3       = "#45475a"
FG        = "#cdd6f4"
ACCENT    = "#89b4fa"
GREEN     = "#a6e3a1"
RED       = "#f38ba8"
YELLOW    = "#f9e2af"
MAUVE     = "#cba6f7"
FONT_MONO = ("Courier New", 10)
FONT_UI   = ("Segoe UI", 10)


# ── Main application ─────────────────────────────────────────────────────────

class MigrationApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"ndISEMig {__version__}")
        self.geometry("1180x780")
        self.minsize(960, 620)
        self.configure(bg=BG)

        self.src_client: ISEClient | None = None
        self.dst_client: ISEClient | None = None
        self.src_oapi_client: OpenAPIClient | None = None
        self.dst_oapi_client: OpenAPIClient | None = None
        self.backup_data: dict | None = None
        self._stop_flag = threading.Event()
        self._running   = threading.Lock()   # one operation at a time

        # Flat map: ers_key → (display_name, obj_key, min_ver_tuple | None, api)
        # api is "ers" (default) or "openapi".
        self._ers_map: dict[str, tuple[str, str, tuple | None, str]] = {}
        # OpenAPI-only detail: ers_key → {"ptype": ..., "kind": ...}
        self._oapi_info: dict[str, dict] = {}
        for cat in RESOURCE_CATEGORIES.values():
            for name, info in cat["resources"].items():
                api = info.get("api", "ers")
                self._ers_map[info["ers"]] = (
                    name, info["key"], info.get("min_ver"), api)
                if api == "openapi":
                    self._oapi_info[info["ers"]] = {
                        "ptype": info.get("ptype", ""), "kind": info["kind"]}

        self._apply_theme()
        self._build_ui()

    # ── Theme ────────────────────────────────────────────────────────────────

    def _apply_theme(self):
        s = ttk.Style(self)
        try:
            s.theme_use("clam")
        except Exception:
            pass
        s.configure(".",
                    background=BG, foreground=FG,
                    fieldbackground=BG2, bordercolor=BG3, troughcolor=BG2,
                    font=FONT_UI)
        s.configure("TNotebook",         background=BG, borderwidth=0)
        s.configure("TNotebook.Tab",     background=BG2, foreground=FG,
                    padding=[14, 5])
        s.map("TNotebook.Tab",           background=[("selected", BG3)])
        s.configure("TLabelframe",       background=BG, bordercolor=BG3)
        s.configure("TLabelframe.Label", background=BG, foreground=ACCENT)
        s.configure("TButton",           background=BG3, foreground=FG,
                    padding=6)
        s.map("TButton",                 background=[("active", "#585b70")])
        s.configure("Accent.TButton",    background=ACCENT, foreground=BG)
        s.map("Accent.TButton",          background=[("active", "#74c7ec")])
        s.configure("TEntry",            fieldbackground=BG2, foreground=FG)
        s.configure("TCheckbutton",      background=BG, foreground=FG)
        s.configure("TLabel",            background=BG, foreground=FG)
        s.configure("TFrame",            background=BG)
        s.configure("TSeparator",        background=BG3)
        s.configure("TProgressbar",      troughcolor=BG2, background=ACCENT)
        s.configure("TScrollbar",        background=BG3, troughcolor=BG2)

    # ── Top-level layout ─────────────────────────────────────────────────────

    def _build_ui(self):
        hdr = tk.Frame(self, bg="#11111b", height=48)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text=f"  ndISEMig {__version__}",
                 font=("Segoe UI", 15, "bold"), fg=MAUVE,
                 bg="#11111b").pack(side="left", pady=10)
        tk.Label(hdr, text="ERS API  |  ISE 2.4 – 3.6+",
                 font=FONT_UI, fg=BG3, bg="#11111b").pack(side="right", padx=15)
        ttk.Button(hdr, text="About",
                   command=self._show_about).pack(side="right", padx=4, pady=8)

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=6, pady=6)

        self._build_tab_connections()
        self._build_tab_export()
        self._build_tab_import()
        self._build_tab_log()

        # OpenAPI resources start grayed out until OpenAPI is enabled per
        # connection.
        self._refresh_resource_availability()

    # ── About box ────────────────────────────────────────────────────────────

    ABOUT_TEXT = (
        "Disclaimer of warranties and liability\n\n"
        "This software is provided \"as is\" and \"as available\", without "
        "warranty of any kind, whether express, implied or statutory, "
        "including but not limited to the implied warranties of satisfactory "
        "quality, fitness for a particular purpose, accuracy and "
        "non-infringement. The author makes no representation or warranty that "
        "the software is error-free or secure, that its operation will be "
        "uninterrupted, or that any defect will be corrected.\n\n"
        "Authorised use only. This software is intended solely for use on "
        "networks, systems and devices that you own or are expressly "
        "authorised to audit. You are solely responsible for ensuring that "
        "your use is lawful and properly authorised, and for any consequence "
        "of unauthorised or improper use.\n\n"
        "To the fullest extent permitted by law, and whether in contract, tort "
        "(including negligence), breach of statutory duty or otherwise, the "
        "author shall not be liable for any loss or damage of any kind arising "
        "out of or in connection with the use of, or inability to use, this "
        "software, including but not limited to any direct, indirect, "
        "incidental, special or consequential loss, loss of profits, revenue, "
        "business, goodwill, data or anticipated savings, or business "
        "interruption, even if advised of the possibility of such loss. You "
        "use this software entirely at your own risk and are solely "
        "responsible for maintaining adequate backups and for any outcome that "
        "results from such use.\n\n"
        "Indemnity. To the fullest extent permitted by law, you agree to "
        "indemnify, defend and hold harmless the author against any and all "
        "claims, demands, proceedings, losses, liabilities, damages, costs and "
        "expenses (including reasonable legal fees) arising out of or in "
        "connection with your use of the software, your breach of this notice, "
        "or any unauthorised or unlawful use of the software by you.\n\n"
        "Nothing in this notice excludes or limits the author's liability for "
        "death or personal injury caused by negligence, for fraud or "
        "fraudulent misrepresentation, or for any other liability that cannot "
        "lawfully be excluded or limited under applicable law."
    )

    def _show_about(self):
        win = tk.Toplevel(self)
        win.title(f"About ndISEMig {__version__}")
        win.configure(bg=BG)
        win.geometry("640x560")
        win.minsize(480, 400)
        win.transient(self)

        tk.Label(win, text=f"ndISEMig {__version__}",
                 font=("Segoe UI", 15, "bold"), fg=MAUVE, bg=BG
                 ).pack(anchor="w", padx=16, pady=(14, 0))
        tk.Label(win, text="Backup and restore ISE configuration via the ERS API.",
                 font=FONT_UI, fg=FG, bg=BG
                 ).pack(anchor="w", padx=16, pady=(2, 8))

        # Pack the Close button (and its containing row) before the expanding
        # text body so its space is reserved — otherwise the expand=True body
        # squeezes the button out of view when the window is short.
        btns = tk.Frame(win, bg=BG)
        btns.pack(side="bottom", fill="x", padx=16, pady=(0, 14))
        ttk.Button(btns, text="Close", command=win.destroy
                   ).pack(side="right")

        body = scrolledtext.ScrolledText(
            win, wrap="word", font=FONT_UI,
            bg="#11111b", fg=FG, insertbackground=FG,
            selectbackground=BG3, relief="flat", padx=10, pady=10)
        body.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        body.insert("1.0", self.ABOUT_TEXT)
        body.configure(state="disabled")

    # ── Connections tab ──────────────────────────────────────────────────────

    def _build_tab_connections(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  Connections  ")
        tab.columnconfigure(0, weight=1)
        tab.columnconfigure(1, weight=1)
        # Give the vertical weight to the Notes row (row 1) so any shrinkage is
        # absorbed there — the connection frames (row 0, which hold the Test
        # Connection buttons) keep their natural height and stay fully visible.
        tab.rowconfigure(0, weight=0)
        tab.rowconfigure(1, weight=1)

        src = ttk.LabelFrame(tab, text="Source ISE  (Export From)")
        src.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.src_host = self._field(src, "Hostname / IP", 0, "10.10.20.78")
        self.src_port, src_port_entry = self._field(
            src, "ERS Port", 1, "9060", return_widget=True)
        self.src_user = self._field(src, "Username",      2, "admin")
        self.src_pass = self._field(src, "Password",      3, show="*")
        self.src_ssl  = self._check(src, "Verify SSL",    4)
        self.src_ers  = self._check(
            src, "Enable ERS", 5,
            command=lambda: self._on_ers_toggle(self.src_ers, src_port_entry))
        self.src_ers.set(True)                                 # ERS on by default
        self._set_port_field(self.src_ers, src_port_entry)
        self.src_oapi_port, src_oapi_entry = self._field(
            src, "OpenAPI Port", 7, str(OPENAPI_PORT_DEFAULT),
            return_widget=True)
        self.src_oapi = self._check(
            src, "Enable OpenAPI (3.1+)", 6,
            command=lambda: self._on_oapi_toggle(self.src_oapi, src_oapi_entry))
        self._set_port_field(self.src_oapi, src_oapi_entry)    # start disabled
        self.src_lbl  = tk.Label(src, text="Not connected",
                                 fg=YELLOW, bg=BG, font=FONT_UI)
        self.src_lbl.grid(row=8, column=0, columnspan=2, pady=6)
        ttk.Button(src, text="Test Connection",
                   command=self._test_src
                   ).grid(row=9, column=0, columnspan=2,
                          padx=15, pady=6, sticky="ew")

        dst = ttk.LabelFrame(tab, text="Target ISE  (Import Into)")
        dst.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.dst_host = self._field(dst, "Hostname / IP", 0, "10.10.20.77")
        self.dst_port, dst_port_entry = self._field(
            dst, "ERS Port", 1, "9060", return_widget=True)
        self.dst_user = self._field(dst, "Username",      2, "admin")
        self.dst_pass = self._field(dst, "Password",      3, show="*")
        self.dst_ssl  = self._check(dst, "Verify SSL",    4)
        self.dst_ers  = self._check(
            dst, "Enable ERS", 5,
            command=lambda: self._on_ers_toggle(self.dst_ers, dst_port_entry))
        self.dst_ers.set(True)                                 # ERS on by default
        self._set_port_field(self.dst_ers, dst_port_entry)
        self.dst_oapi_port, dst_oapi_entry = self._field(
            dst, "OpenAPI Port", 7, str(OPENAPI_PORT_DEFAULT),
            return_widget=True)
        self.dst_oapi = self._check(
            dst, "Enable OpenAPI (3.1+)", 6,
            command=lambda: self._on_oapi_toggle(self.dst_oapi, dst_oapi_entry))
        self._set_port_field(self.dst_oapi, dst_oapi_entry)    # start disabled
        self.dst_lbl  = tk.Label(dst, text="Not connected",
                                 fg=YELLOW, bg=BG, font=FONT_UI)
        self.dst_lbl.grid(row=8, column=0, columnspan=2, pady=6)
        ttk.Button(dst, text="Test Connection",
                   command=self._test_dst
                   ).grid(row=9, column=0, columnspan=2,
                          padx=15, pady=6, sticky="ew")

        note = ttk.LabelFrame(tab, text="Notes & Known Limitations")
        note.grid(row=1, column=0, columnspan=2,
                  padx=20, pady=(0, 20), sticky="ew")
        notes = (
            "  ERS API (classic config objects): keep 'Enable ERS' ticked — enable it under "
            "Administration › System › Settings › ERS Settings; account needs the ERS Admin "
            "role; default port 9060.  Untick it for an OpenAPI-only connection.\n"
            "  OpenAPI (Policy Sets, Endpoints, TrustSec VN, Native IPsec): tick 'Enable "
            "OpenAPI' — needs ISE 3.1+ with Open API enabled (API Settings), gateway port 443 "
            "(Native IPsec 3.3+).  Either API works independently of the other.  Policy import "
            "is best-effort; IPsec pre-shared keys must be re-entered after import.\n"
            "  Known limits: RADIUS/TACACS secrets and user password hashes are not exported "
            "(reset after); AD/LDAP stores can't be exported; newer-version fields are stripped\n"
            "  when the target is older.  See the Log tab for per-run compatibility warnings."
        )
        tk.Label(note, text=notes, justify="left", fg=FG, bg=BG,
                 font=FONT_UI).pack(anchor="w", padx=10, pady=8)

    # ── Export tab ───────────────────────────────────────────────────────────

    def _build_tab_export(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  Export  ")

        sel = ttk.LabelFrame(tab, text="Resources to Export")
        sel.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        self.export_vars: dict[str, tk.BooleanVar] = {}
        self.export_sections: list = []
        self._build_checkboxes(sel, self.export_vars,
                               sections=self.export_sections)

        ctrl = ttk.LabelFrame(tab, text="Export Options")
        ctrl.pack(side="right", fill="y", padx=10, pady=10)
        ctrl.pack_propagate(False)
        ctrl.configure(width=248)

        ttk.Button(ctrl, text="Select All",
                   command=lambda: self._set_all(self.export_vars, True)
                   ).pack(fill="x", padx=12, pady=3)
        ttk.Button(ctrl, text="Deselect All",
                   command=lambda: self._set_all(self.export_vars, False)
                   ).pack(fill="x", padx=12, pady=3)
        self._sep(ctrl)

        ttk.Label(ctrl, text="Output File:").pack(anchor="w", padx=12)
        self.export_path = tk.StringVar(value="ise_backup.json")
        ttk.Entry(ctrl, textvariable=self.export_path).pack(fill="x", padx=12,
                                                             pady=3)
        ttk.Button(ctrl, text="Browse…",
                   command=self._browse_export).pack(fill="x", padx=12, pady=3)
        self._sep(ctrl)

        self.export_prog_lbl = ttk.Label(ctrl, text="")
        self.export_prog_lbl.pack(padx=12, pady=2)
        self.export_prog = ttk.Progressbar(ctrl, mode="determinate", length=210)
        self.export_prog.pack(padx=12, pady=4)
        self._sep(ctrl)

        self.export_btn = ttk.Button(ctrl, text="Start Export (JSON)",
                                     style="Accent.TButton",
                                     command=self._start_export)
        self.export_btn.pack(fill="x", padx=12, pady=4)
        ttk.Button(ctrl, text="Export Summary CSVs",
                   command=self._start_csv_export
                   ).pack(fill="x", padx=12, pady=3)
        ttk.Button(ctrl, text="Stop",
                   command=self._stop).pack(fill="x", padx=12, pady=3)

    # ── Import tab ───────────────────────────────────────────────────────────

    def _build_tab_import(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  Import  ")

        sel = ttk.LabelFrame(tab, text="Resources to Import")
        sel.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        self.import_vars: dict[str, tk.BooleanVar] = {}
        self.import_count_labels: dict[str, ttk.Label] = {}
        self.import_sections: list = []
        self._build_checkboxes(sel, self.import_vars,
                               count_labels=self.import_count_labels,
                               sections=self.import_sections)

        ctrl = ttk.LabelFrame(tab, text="Import Options")
        ctrl.pack(side="right", fill="y", padx=10, pady=10)
        ctrl.pack_propagate(False)
        ctrl.configure(width=248)

        ttk.Label(ctrl, text="Backup File:").pack(anchor="w", padx=12)
        self.import_path = tk.StringVar(value="ise_backup.json")
        ttk.Entry(ctrl, textvariable=self.import_path).pack(fill="x", padx=12,
                                                             pady=3)
        ttk.Button(ctrl, text="Browse…",
                   command=self._browse_import).pack(fill="x", padx=12, pady=3)
        ttk.Button(ctrl, text="Load Backup File",
                   command=self._load_backup).pack(fill="x", padx=12, pady=3)
        self._sep(ctrl)

        self.backup_info = ttk.Label(ctrl, text="No file loaded",
                                     wraplength=218, justify="left")
        self.backup_info.pack(padx=12, pady=4)
        self._sep(ctrl)

        self.overwrite_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(ctrl, text="Update existing objects",
                        variable=self.overwrite_var
                        ).pack(anchor="w", padx=12, pady=3)
        self.dry_run_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(ctrl, text="Dry run (no changes made)",
                        variable=self.dry_run_var
                        ).pack(anchor="w", padx=12, pady=3)
        self._sep(ctrl)

        ttk.Button(ctrl, text="Select All",
                   command=lambda: self._set_all(self.import_vars, True)
                   ).pack(fill="x", padx=12, pady=3)
        ttk.Button(ctrl, text="Deselect All",
                   command=lambda: self._set_all(self.import_vars, False)
                   ).pack(fill="x", padx=12, pady=3)
        self._sep(ctrl)

        self.import_prog_lbl = ttk.Label(ctrl, text="")
        self.import_prog_lbl.pack(padx=12, pady=2)
        self.import_prog = ttk.Progressbar(ctrl, mode="determinate", length=210)
        self.import_prog.pack(padx=12, pady=4)
        self._sep(ctrl)

        self.import_btn = ttk.Button(ctrl, text="Start Import",
                                     style="Accent.TButton",
                                     command=self._start_import)
        self.import_btn.pack(fill="x", padx=12, pady=4)
        ttk.Button(ctrl, text="Stop",
                   command=self._stop).pack(fill="x", padx=12, pady=3)

    # ── Log tab ──────────────────────────────────────────────────────────────

    def _build_tab_log(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  Log  ")

        bar = ttk.Frame(tab)
        bar.pack(fill="x", padx=6, pady=4)
        ttk.Button(bar, text="Clear Log",
                   command=self._clear_log).pack(side="left", padx=4)
        ttk.Button(bar, text="Save Log…",
                   command=self._save_log).pack(side="left", padx=4)

        self.log_box = scrolledtext.ScrolledText(
            tab, state="disabled", font=FONT_MONO,
            bg="#11111b", fg=FG, insertbackground=FG, selectbackground=BG3)
        self.log_box.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self.log_box.tag_config("ok",    foreground=GREEN)
        self.log_box.tag_config("error", foreground=RED)
        self.log_box.tag_config("warn",  foreground=YELLOW)
        self.log_box.tag_config("info",  foreground=ACCENT)
        self.log_box.tag_config("head",  foreground=MAUVE,
                                font=(FONT_MONO[0], FONT_MONO[1], "bold"))

    # ── Checkbox builder ─────────────────────────────────────────────────────

    def _build_checkboxes(self, parent: ttk.LabelFrame,
                          var_dict: dict,
                          count_labels: dict | None = None,
                          sections: list | None = None):
        canvas = tk.Canvas(parent, bg=BG, highlightthickness=0)
        sb = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas)
        inner.bind("<Configure>",
                   lambda e: canvas.configure(
                       scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        # Activate mouse-wheel scroll only while hovering over this canvas.
        # <Leave> fires when the mouse moves to a child widget too, so only
        # unbind when the cursor has actually left the canvas bounds.
        def _on_enter(_e):
            canvas.bind_all(
                "<MouseWheel>",
                lambda e: canvas.yview_scroll(int(-e.delta / 120), "units"))

        def _on_leave(e):
            if (e.x < 0 or e.y < 0
                    or e.x >= canvas.winfo_width()
                    or e.y >= canvas.winfo_height()):
                canvas.unbind_all("<MouseWheel>")

        canvas.bind("<Enter>", _on_enter)
        canvas.bind("<Leave>", _on_leave)

        for cat_name, cat_info in RESOURCE_CATEGORIES.items():
            cat_frame = ttk.LabelFrame(inner, text=cat_name)
            cat_frame.pack(fill="x", padx=6, pady=4)

            cat_checkbuttons: list = []
            cat_var = tk.BooleanVar(value=True)
            sel_all = ttk.Checkbutton(
                cat_frame, text="(select all in category)",
                variable=cat_var,
                command=lambda cv=cat_var, res=cat_info["resources"]: [
                    var_dict[r["ers"]].set(cv.get())
                    for r in res.values() if r["ers"] in var_dict
                ])
            sel_all.grid(row=0, column=0, sticky="w", padx=6)
            cat_checkbuttons.append(sel_all)

            for row_idx, (res_name, res_info) in enumerate(
                    cat_info["resources"].items(), start=1):
                var = tk.BooleanVar(value=True)
                var_dict[res_info["ers"]] = var

                label = res_name
                if res_info.get("min_ver"):
                    mv = res_info["min_ver"]
                    label = f"{res_name}  [≥{mv[0]}.{mv[1]}]"

                cb = ttk.Checkbutton(cat_frame, text=label, variable=var)
                cb.grid(row=row_idx, column=0, sticky="w", padx=22)
                cat_checkbuttons.append(cb)

                if count_labels is not None:
                    lbl = ttk.Label(cat_frame, text="", foreground=ACCENT)
                    lbl.grid(row=row_idx, column=1, sticky="w", padx=6)
                    count_labels[res_info["ers"]] = lbl

            # Record every category's controls (tagged by API) so the tab can
            # gray out (disable, not hide) the sections whose API — ERS or
            # OpenAPI — isn't enabled on the relevant connection.
            if sections is not None:
                sections.append({
                    "frame": cat_frame,
                    "title": cat_name,
                    "api": cat_info.get("api", "ers"),
                    "checkbuttons": cat_checkbuttons,
                    "ers_keys": [r["ers"]
                                 for r in cat_info["resources"].values()],
                })

    # ── UI helpers ────────────────────────────────────────────────────────────

    def _field(self, parent, label: str, row: int,
               default: str = "", show: str = "",
               return_widget: bool = False):
        ttk.Label(parent, text=label + ":").grid(
            row=row, column=0, sticky="w", padx=12, pady=5)
        var = tk.StringVar(value=default)
        kw: dict = {"textvariable": var, "width": 30}
        if show:
            kw["show"] = show
        entry = ttk.Entry(parent, **kw)
        entry.grid(row=row, column=1, padx=12, pady=5)
        return (var, entry) if return_widget else var

    def _check(self, parent, label: str, row: int,
               command=None) -> tk.BooleanVar:
        ttk.Label(parent, text=label + ":").grid(
            row=row, column=0, sticky="w", padx=12, pady=5)
        var = tk.BooleanVar(value=False)
        kw: dict = {"variable": var}
        if command is not None:
            kw["command"] = command
        ttk.Checkbutton(parent, **kw).grid(
            row=row, column=1, sticky="w", padx=12)
        return var

    def _set_port_field(self, enabled_var: tk.BooleanVar, entry: ttk.Entry):
        """Enable a port entry only while its API toggle is ticked."""
        entry.configure(state="normal" if enabled_var.get() else "disabled")

    def _on_oapi_toggle(self, enabled_var: tk.BooleanVar, entry: ttk.Entry):
        """Handle an 'Enable OpenAPI' tick: update the port field and the
        resource lists so OpenAPI items are selectable only when OpenAPI is
        on."""
        self._set_port_field(enabled_var, entry)
        self._refresh_resource_availability()

    def _on_ers_toggle(self, enabled_var: tk.BooleanVar, entry: ttk.Entry):
        """Handle an 'Enable ERS' tick: update the ERS port field and the
        resource lists so ERS items are selectable only when ERS is on."""
        self._set_port_field(enabled_var, entry)
        self._refresh_resource_availability()

    def _refresh_resource_availability(self):
        """Gray out the resource sections whose API isn't enabled on the
        connection that drives each tab (Export → source, Import → target).

        Every section stays visible at all times but is disabled and
        unselectable unless its API is enabled, so the full catalogue is always
        on screen.  ERS and the OpenAPI gateway (ISE 3.1+) are independent API
        surfaces: ERS serves the classic config objects, OpenAPI serves Policy
        Sets, dictionaries/conditions, TrustSec VN objects, endpoints and
        Native IPsec.  A connection may use either or both."""
        self._apply_availability(
            self.export_sections, self.export_vars,
            ers_on=self.src_ers.get(), oapi_on=self.src_oapi.get())
        self._apply_availability(
            self.import_sections, self.import_vars,
            ers_on=self.dst_ers.get(), oapi_on=self.dst_oapi.get())

    def _apply_availability(self, sections: list, var_dict: dict,
                            ers_on: bool, oapi_on: bool):
        for sec in sections:
            enabled = oapi_on if sec["api"] == "openapi" else ers_on
            state = "normal" if enabled else "disabled"
            for cb in sec["checkbuttons"]:
                cb.configure(state=state)

            # Only force the selection on an availability *transition*, so
            # toggling one API doesn't wipe the other API's manual picks.
            if sec.get("_enabled") != enabled:
                for k in sec["ers_keys"]:
                    if k in var_dict:
                        var_dict[k].set(enabled)
            sec["_enabled"] = enabled

            api_label = "OpenAPI" if sec["api"] == "openapi" else "ERS"
            suffix = "" if enabled else f"   — enable {api_label} on the connection"
            sec["frame"].configure(text=sec["title"] + suffix)

    def _sep(self, parent):
        ttk.Separator(parent, orient="horizontal").pack(
            fill="x", padx=8, pady=8)

    def _set_all(self, var_dict: dict, value: bool):
        for v in var_dict.values():
            v.set(value)

    def _set_prog(self, bar: ttk.Progressbar, lbl: ttk.Label,
                  current: int, total: int, text: str = ""):
        bar["maximum"] = max(total, 1)
        bar["value"] = current
        lbl.config(text=text[:52])

    # ── Connection testing ────────────────────────────────────────────────────

    def _test_src(self):
        self._test_side("source")

    def _test_dst(self):
        self._test_side("target")

    def _test_side(self, side: str):
        def _port(var: tk.StringVar, default: int) -> int:
            try:
                p = int(var.get().strip())
            except ValueError:
                return default
            return p if 0 < p < 65536 else default

        if side == "source":
            host, port, user = (self.src_host.get().strip(),
                                _port(self.src_port, 9060),
                                self.src_user.get().strip())
            pw, ssl, lbl = self.src_pass.get(), self.src_ssl.get(), self.src_lbl
            ers_on  = self.src_ers.get()
            oapi_on = self.src_oapi.get()
            oapi_port = _port(self.src_oapi_port, OPENAPI_PORT_DEFAULT)
        else:
            host, port, user = (self.dst_host.get().strip(),
                                _port(self.dst_port, 9060),
                                self.dst_user.get().strip())
            pw, ssl, lbl = self.dst_pass.get(), self.dst_ssl.get(), self.dst_lbl
            ers_on  = self.dst_ers.get()
            oapi_on = self.dst_oapi.get()
            oapi_port = _port(self.dst_oapi_port, OPENAPI_PORT_DEFAULT)

        if not ers_on and not oapi_on:
            lbl.config(text="Enable ERS and/or OpenAPI", fg=RED)
            messagebox.showwarning(
                "No API Enabled",
                "Enable ERS and/or OpenAPI on this connection before testing.")
            return

        client = ISEClient(host, user, pw, port, ssl)
        lbl.config(text="Testing…", fg=YELLOW)
        self.update_idletasks()

        def _run():
            # ERS and OpenAPI are independent APIs on separate ports — probe
            # each on its own (only the ones enabled).  OpenAPI is not gated
            # behind ERS, so Policy-Set-only migrations work with ERS disabled,
            # and vice versa.
            ok, ver, msg = (False, "", "ERS disabled")
            if ers_on:
                ok, ver, msg = client.test_connection()

            oapi_client = None
            oapi_ok = False
            oapi_msg = ""
            if oapi_on:
                oapi_client = OpenAPIClient(host, user, pw, oapi_port, ssl)
                oapi_ok, oapi_msg = oapi_client.test_connection()

            def _apply():
                # Build a combined status line from the enabled probes.
                parts = []
                if ers_on:
                    if ok:
                        vd = ver_display(ver)
                        parts.append(f"ERS ✓ (ISE {vd})" if vd != "unknown"
                                     else "ERS ✓ (version unknown)")
                    else:
                        parts.append("ERS ✗")
                if oapi_on:
                    parts.append(f"OpenAPI ✓ ({oapi_port})" if oapi_ok
                                 else "OpenAPI ✗")
                text = "  |  ".join(parts)

                fully_ok = ((not ers_on or ok) and (not oapi_on or oapi_ok))
                any_ok   = (ers_on and ok) or (oapi_on and oapi_ok)
                lbl.config(text=text,
                           fg=GREEN if fully_ok else (YELLOW if any_ok else RED))

                if side == "source":
                    self.src_client = client if (ers_on and ok) else None
                    self.src_oapi_client = oapi_client if oapi_ok else None
                else:
                    self.dst_client = client if (ers_on and ok) else None
                    self.dst_oapi_client = oapi_client if oapi_ok else None

                self.log(f"[{side.upper()}] {text}",
                         "ok" if any_ok else "error")
                if ers_on and not ok:
                    self.log(f"[{side.upper()}] ERS: {msg}",
                             "warn" if any_ok else "error")
                if oapi_on and oapi_ok:
                    self.log(f"[{side.upper()}] OpenAPI enabled (port "
                             f"{oapi_port}) — Policy Sets available.", "ok")
                elif oapi_on:
                    self.log(f"[{side.upper()}] OpenAPI unavailable: {oapi_msg}",
                             "warn")
                self._check_version_compat()

            self.after(0, _apply)

        threading.Thread(target=_run, daemon=True).start()

    def _check_version_compat(self):
        """Log a warning whenever both sides are connected and version mismatch exists."""
        if not (self.src_client and self.dst_client):
            return
        sv = self.src_client.version
        dv = self.dst_client.version
        if not sv or not dv:
            return
        sp = parse_ver(sv)
        dp = parse_ver(dv)
        if sp == dp:
            return
        if dp > sp:
            self.log(
                f"[COMPAT] Upgrade: source ISE {ver_display(sv)} → "
                f"target ISE {ver_display(dv)}.  "
                "Target supports all source features.", "info")
        else:
            self.log(
                f"[COMPAT] *** DOWNGRADE detected: source ISE {ver_display(sv)} → "
                f"target ISE {ver_display(dv)}.  "
                "Version-specific fields will be stripped; some objects may still fail.",
                "warn")

    # ── Export ────────────────────────────────────────────────────────────────

    def _browse_export(self):
        p = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON backup", "*.json"), ("All files", "*.*")],
            initialfile=self.export_path.get())
        if p:
            self.export_path.set(p)

    def _start_export(self):
        if not (self.src_client or self.src_oapi_client):
            messagebox.showerror("No Source Connection",
                                 "Test the source ISE connection first "
                                 "(ERS and/or OpenAPI).")
            return
        selected = [k for k, v in self.export_vars.items() if v.get()]
        if not selected:
            messagebox.showwarning("Nothing Selected",
                                   "Select at least one resource type.")
            return
        if not self._running.acquire(blocking=False):
            messagebox.showwarning("Busy", "Another operation is already running.")
            return
        self._stop_flag.clear()
        self.export_btn.config(state="disabled")
        self.nb.select(3)
        out       = self.export_path.get()
        src_label = f"{self.src_host.get()}:{self.src_port.get()}"
        threading.Thread(target=self._do_export, args=(selected, out, src_label),
                         daemon=True).start()

    def _do_export(self, selected: list[str], out: str, src_label: str):
        src_client = self.src_client   # snapshot; guards against re-test during export
        src_oapi = self.src_oapi_client  # snapshot; None unless OpenAPI was enabled
        src_ver  = src_client.get_version() if src_client else ""
        partial  = False

        backup = {
            "meta": {
                "tool": "ndISEMig",
                "tool_version": __version__,
                "exported_at": datetime.now().isoformat(),
                "source_host": src_label,
                "source_version": src_ver,
                "partial": False,
            },
            "data": {}
        }

        self.log("═" * 64, "head")
        self.log(f"EXPORT STARTED  ▶  {out}", "head")
        self.log(
            f"Source: {src_label}  (ISE {ver_display(src_ver)})", "info")
        self.log("═" * 64, "head")

        n = len(selected)
        try:
            for idx, ers_key in enumerate(selected):
                if self._stop_flag.is_set():
                    self.log("Export stopped by user.", "warn")
                    partial = True
                    break

                display, obj_key, min_ver, api = self._ers_map.get(
                    ers_key, (ers_key, ers_key, None, "ers"))

                # Skip if source ISE is too old for this resource.
                if min_ver and src_ver and ver_lt(src_ver, *min_ver):
                    self.log(
                        f"\n[{idx+1}/{n}] {display}  "
                        f"— skipped (requires ISE {min_ver[0]}.{min_ver[1]}, "
                        f"source is {ver_display(src_ver)})", "warn")
                    continue

                self.log(f"\n[{idx+1}/{n}] {display}", "info")
                self.after(0, lambda i=idx+1, t=n, d=display:
                           self._set_prog(self.export_prog,
                                          self.export_prog_lbl, i, t, d))

                # OpenAPI resources use a separate client and data shape.
                if api == "openapi":
                    if not src_oapi:
                        self.log(
                            "  ⚠  OpenAPI not enabled on the source connection "
                            "— skipped", "warn")
                        continue
                    try:
                        items = self._export_openapi(ers_key, src_oapi)
                        if items is None:
                            self.log("  ⚠  Not supported — skipped", "warn")
                            continue
                        backup["data"][ers_key] = items
                        self.log(f"  ✓  {len(items)} items", "ok")
                    except PermissionError as exc:
                        self.log(f"  ✗  Auth error: {exc}", "error")
                        backup["data"][ers_key] = []
                    except Exception as exc:
                        self.log(f"  ✗  {exc}", "error")
                        backup["data"][ers_key] = []
                    continue

                # ERS resource but ERS isn't connected (e.g. OpenAPI-only run).
                if src_client is None:
                    self.log("  ⚠  ERS not connected on the source — skipped",
                             "warn")
                    continue

                def _pcb(cur, tot, d=display, i=idx+1, t=n):
                    self.after(0, lambda: self._set_prog(
                        self.export_prog, self.export_prog_lbl,
                        i, t, f"{d}  {cur}/{tot}"))

                fetch_errors: list = []

                def _ecb(ident, exc):
                    fetch_errors.append(ident)
                    self.log(f"  ✗  Could not fetch '{ident}': {exc}", "error")

                try:
                    items = src_client.get_all_details(
                        ers_key, obj_key, progress_cb=_pcb, error_cb=_ecb)
                    if items is None:
                        self.log(
                            "  ⚠  Not supported on this ISE version — skipped",
                            "warn")
                        continue
                    backup["data"][ers_key] = items
                    if fetch_errors:
                        partial = True
                        self.log(
                            f"  ⚠  {len(items)} items saved, "
                            f"{len(fetch_errors)} could not be fetched — "
                            "backup marked PARTIAL", "warn")
                    else:
                        self.log(f"  ✓  {len(items)} items", "ok")
                except PermissionError as exc:
                    self.log(f"  ✗  Auth error: {exc}", "error")
                    backup["data"][ers_key] = []
                except Exception as exc:
                    self.log(f"  ✗  {exc}", "error")
                    backup["data"][ers_key] = []

            backup["meta"]["partial"] = partial

            try:
                with open(out, "w", encoding="utf-8") as fh:
                    json.dump(backup, fh, indent=2, default=str)
                total = sum(len(v) for v in backup["data"].values())
                note  = "  (PARTIAL)" if partial else ""
                self.log(f"\n{'═'*64}", "head")
                self.log(
                    f"EXPORT COMPLETE{note}  |  {total} items  →  {out}",
                    "warn" if partial else "ok")
                self.log(f"{'═'*64}", "head")
                self.after(0, lambda: messagebox.showinfo(
                    "Export Complete",
                    ("PARTIAL backup — export was stopped early.\n\n"
                     if partial else "") +
                    f"Exported {total} items to:\n{out}"))
            except Exception as exc:
                self.log(f"Failed to write backup file: {exc}", "error")

        finally:
            self._running.release()
            self.after(0, lambda: self.export_btn.config(state="normal"))
            self.after(0, lambda: self.export_prog_lbl.config(text="Done"))

    # ── CSV export ────────────────────────────────────────────────────────────

    def _start_csv_export(self):
        if not self.src_client:
            messagebox.showerror("No Source Connection",
                                 "Test the source ISE connection first.")
            return
        selected = [k for k, v in self.export_vars.items() if v.get()]
        if not selected:
            messagebox.showwarning("Nothing Selected",
                                   "Select at least one resource type.")
            return
        if not self._running.acquire(blocking=False):
            messagebox.showwarning("Busy", "Another operation is already running.")
            return
        folder = filedialog.askdirectory(title="Select folder for CSV files")
        if not folder:
            self._running.release()
            return
        self._stop_flag.clear()
        self.export_btn.config(state="disabled")
        self.nb.select(3)
        src_host = self.src_host.get()
        threading.Thread(target=self._do_csv_export,
                         args=(selected, folder, src_host), daemon=True).start()

    def _do_csv_export(self, selected: list[str], folder: str, src_host: str):
        src_client   = self.src_client   # snapshot; guards against re-test during export
        src_ver      = src_client.get_version()
        files_written = 0

        self.log("═" * 64, "head")
        self.log(f"CSV EXPORT STARTED  ▶  {folder}", "head")
        self.log(f"Source: {src_host}  (ISE {ver_display(src_ver)})",
                 "info")
        self.log("═" * 64, "head")

        n = len(selected)
        stopped = False
        try:
            for idx, ers_key in enumerate(selected):
                if self._stop_flag.is_set():
                    self.log("CSV export stopped by user.", "warn")
                    stopped = True
                    break

                display, obj_key, min_ver, api = self._ers_map.get(
                    ers_key, (ers_key, ers_key, None, "ers"))

                if min_ver and src_ver and ver_lt(src_ver, *min_ver):
                    self.log(
                        f"\n[{idx+1}/{n}] {display}  "
                        f"— skipped (requires ISE {min_ver[0]}.{min_ver[1]})",
                        "warn")
                    continue

                self.log(f"\n[{idx+1}/{n}] {display}", "info")
                self.after(0, lambda i=idx+1, t=n, d=display:
                           self._set_prog(self.export_prog,
                                          self.export_prog_lbl, i, t, d))

                # CSV flattening targets ERS list resources; nested OpenAPI
                # policy objects don't map cleanly to a single table.
                if api == "openapi":
                    self.log("  ⚠  OpenAPI resources are not exported to CSV "
                             "(use JSON export) — skipped", "warn")
                    continue
                try:
                    items = src_client.get_all_details(ers_key, obj_key)
                    if items is None:
                        self.log("  ⚠  Not supported — skipped", "warn")
                        continue
                    if not items:
                        self.log("  (0 items)", "warn")
                        continue

                    all_keys: list[str] = []
                    for item in items:
                        for k in item.keys():
                            if k not in all_keys:
                                all_keys.append(k)

                    csv_path = f"{folder}/{ers_key}.csv"
                    with open(csv_path, "w", newline="",
                              encoding="utf-8") as fh:
                        writer = csv.DictWriter(fh, fieldnames=all_keys,
                                                extrasaction="ignore")
                        writer.writeheader()
                        for item in items:
                            flat = {
                                k: (json.dumps(v)
                                    if isinstance(v, (dict, list)) else v)
                                for k, v in item.items()
                            }
                            writer.writerow(flat)

                    self.log(f"  ✓  {len(items)} rows  →  {ers_key}.csv", "ok")
                    files_written += 1

                except PermissionError as exc:
                    self.log(f"  ✗  Auth error: {exc}", "error")
                except Exception as exc:
                    self.log(f"  ✗  {exc}", "error")

            self.log(f"\n{'═'*64}", "head")
            if stopped:
                self.log(
                    f"CSV EXPORT STOPPED  |  {files_written} files written  →  {folder}",
                    "warn")
            else:
                self.log(
                    f"CSV EXPORT COMPLETE  |  {files_written} files  →  {folder}",
                    "ok")
            self.log(f"{'═'*64}", "head")
            self.after(0, lambda: messagebox.showinfo(
                "CSV Export " + ("Stopped" if stopped else "Complete"),
                ("Export was stopped early.\n\n" if stopped else "") +
                f"{files_written} CSV file(s) written to:\n{folder}"))
        finally:
            self._running.release()
            self.after(0, lambda: self.export_btn.config(state="normal"))
            self.after(0, lambda: self.export_prog_lbl.config(text="Done"))

    # ── Import ────────────────────────────────────────────────────────────────

    def _browse_import(self):
        p = filedialog.askopenfilename(
            filetypes=[("JSON backup", "*.json"), ("All files", "*.*")])
        if p:
            self.import_path.set(p)

    def _load_backup(self):
        path = self.import_path.get()
        try:
            with open(path, "r", encoding="utf-8") as fh:
                self.backup_data = json.load(fh)
        except Exception as exc:
            messagebox.showerror("Load Error", str(exc))
            self.log(f"Failed to load backup: {exc}", "error")
            return

        meta = self.backup_data.get("meta", {})
        data = self.backup_data.get("data", {})

        partial_note = "*** PARTIAL BACKUP ***\n" if meta.get("partial") else ""
        info = (f"{partial_note}"
                f"Host:    {meta.get('source_host', '?')}\n"
                f"Version: {meta.get('source_version', '?')}\n"
                f"Date:    {str(meta.get('exported_at', '?'))[:19]}\n"
                f"Items:   {sum(len(v) for v in data.values())}")
        self.backup_info.config(
            text=info,
            foreground=YELLOW if meta.get("partial") else FG)

        # Don't auto-select resources whose API is disabled on the target —
        # they're grayed out and unusable, so selecting them would only produce
        # "<API> not enabled — skipped" noise on import.
        ers_on, oapi_on = self.dst_ers.get(), self.dst_oapi.get()
        api_of = {k: sec["api"]
                  for sec in self.import_sections for k in sec["ers_keys"]}
        for ers_key, lbl in self.import_count_labels.items():
            count = len(data.get(ers_key, []))
            lbl.config(text=f"({count})" if count else "")
            available = oapi_on if api_of.get(ers_key) == "openapi" else ers_on
            self.import_vars[ers_key].set(count > 0 and available)

        self.log(f"Loaded backup: {path}", "ok")
        if meta.get("partial"):
            self.log("  WARNING: partial backup — export was stopped early.",
                     "warn")
        self.log(
            f"  Source ISE {meta.get('source_version','?')}  "
            f"exported {str(meta.get('exported_at','?'))[:19]}", "info")

    def _start_import(self):
        if not (self.dst_client or self.dst_oapi_client):
            messagebox.showerror("No Target Connection",
                                 "Test the target ISE connection first "
                                 "(ERS and/or OpenAPI).")
            return
        if not self.backup_data:
            messagebox.showerror("No Backup", "Load a backup file first.")
            return
        selected = [k for k, v in self.import_vars.items() if v.get()]
        if not selected:
            messagebox.showwarning("Nothing Selected",
                                   "Select at least one resource type.")
            return
        if not self._running.acquire(blocking=False):
            messagebox.showwarning("Busy", "Another operation is already running.")
            return
        dry = self.dry_run_var.get()
        if not dry:
            if not messagebox.askyesno(
                    "Confirm Import",
                    f"Import {len(selected)} resource type(s) into "
                    f"{self.dst_host.get()}?\n\n"
                    "Objects will be CREATED on the target ISE.\n"
                    "Passwords and shared secrets must be reset after."):
                self._running.release()
                return
        self._stop_flag.clear()
        self.import_btn.config(state="disabled")
        self.nb.select(3)
        overwrite = self.overwrite_var.get()
        dst_label = f"{self.dst_host.get()}:{self.dst_port.get()}"
        backup_snap = self.backup_data   # snapshot reference; guards against reload during import
        threading.Thread(target=self._do_import,
                         args=(selected, dry, overwrite, dst_label, backup_snap),
                         daemon=True).start()

    def _do_import(self, selected: list[str], dry: bool,
                   overwrite: bool, dst_label: str, backup_snap: dict):
        dst_client = self.dst_client   # snapshot; guards against re-test during import
        dst_oapi = self.dst_oapi_client  # snapshot; None unless OpenAPI was enabled
        data    = backup_snap.get("data", {})
        meta    = backup_snap.get("meta", {})
        src_ver = meta.get("source_version", "")
        dst_ver = dst_client.get_version() if dst_client else ""

        self.log("═" * 64, "head")
        self.log(f"{'[DRY RUN] ' if dry else ''}IMPORT STARTED", "head")
        self.log(
            f"Source backup: ISE {ver_display(src_ver)}"
            f"  ({meta.get('source_host','?')})", "info")
        self.log(
            f"Target:        ISE {ver_display(dst_ver)}"
            f"  ({dst_label})", "info")

        # Version compatibility analysis
        self._log_compat_warnings(src_ver, dst_ver)
        self.log("═" * 64, "head")

        # Sort by dependency order
        ordered = sorted(
            selected,
            key=lambda x: IMPORT_ORDER.index(x) if x in IMPORT_ORDER else 999)

        n = len(ordered)
        stopped = False
        try:
            for idx, ers_key in enumerate(ordered):
                if self._stop_flag.is_set():
                    self.log("Import stopped by user.", "warn")
                    stopped = True
                    break

                display, obj_key, min_ver, api = self._ers_map.get(
                    ers_key, (ers_key, ers_key, None, "ers"))
                items = data.get(ers_key, [])

                # Warn if this resource is too new for the target
                if min_ver and dst_ver and ver_lt(dst_ver, *min_ver):
                    self.log(
                        f"\n[{idx+1}/{n}] {display}  "
                        f"— SKIPPED (requires ISE {min_ver[0]}.{min_ver[1]}, "
                        f"target is {ver_display(dst_ver)})", "warn")
                    continue

                self.log(
                    f"\n[{idx+1}/{n}] {display}  ({len(items)} items)", "info")
                self.after(0, lambda i=idx+1, t=n, d=display:
                           self._set_prog(self.import_prog,
                                          self.import_prog_lbl, i, t, d))

                if not items:
                    self.log("  (no items in backup — skipped)", "warn")
                    continue

                # OpenAPI resources have their own client and write semantics.
                if api == "openapi":
                    if not dst_oapi:
                        self.log(
                            "  ⚠  OpenAPI not enabled on the target connection "
                            "— skipped", "warn")
                        continue
                    created, updated, skipped, failed = self._import_openapi(
                        ers_key, items, dst_oapi, dry, overwrite)
                    self.log(
                        f"  Created: {created}  Updated: {updated}  "
                        f"Skipped: {skipped}  Failed: {failed}",
                        "ok" if not failed else "warn")
                    continue

                # ERS resource but ERS isn't connected (e.g. OpenAPI-only run).
                if not dry and dst_client is None:
                    self.log("  ⚠  ERS not connected on the target — skipped",
                             "warn")
                    continue

                created = updated = skipped = failed = 0

                for i_item, item in enumerate(items):
                    if self._stop_flag.is_set():
                        stopped = True
                        break

                    name = self._item_name(item, ers_key)

                    # Skip built-in system objects
                    if ers_key in HAS_SYSTEM_DEFINED and item.get("systemDefined"):
                        skipped += 1
                        continue

                    if dry:
                        self.log(f"  [DRY] Would import: {name}", "info")
                        created += 1
                        continue

                    existing = self._lookup_existing(ers_key, name, dst_client)

                    if existing and not overwrite:
                        skipped += 1
                    else:
                        clean = self._sanitise(item, ers_key, dst_ver)
                        if existing and overwrite:
                            eid = self._extract_id(existing)
                            if eid:
                                ok, msg = dst_client.update(
                                    ers_key, eid, obj_key, clean)
                                if ok:
                                    updated += 1
                                else:
                                    self.log(
                                        f"  ✗  Update '{name}': {msg}", "error")
                                    failed += 1
                            else:
                                skipped += 1
                        else:
                            ok, msg = dst_client.create(
                                ers_key, obj_key, clean)
                            if ok:
                                created += 1
                            elif self._is_duplicate_error(msg):
                                skipped += 1
                            else:
                                self.log(
                                    f"  ✗  Create '{name}': {msg}", "error")
                                failed += 1

                    self.after(
                        0,
                        lambda ii=i_item, t=len(items), d=display, ri=idx+1:
                        self._set_prog(self.import_prog, self.import_prog_lbl,
                                       ri, n, f"{d}  {ii+1}/{t}"))

                self.log(
                    f"  Created: {created}  Updated: {updated}  "
                    f"Skipped: {skipped}  Failed: {failed}",
                    "ok" if not failed else "warn")

            self.log(f"\n{'═'*64}", "head")
            if stopped:
                self.log("IMPORT STOPPED — completed up to the point above.", "warn")
            else:
                self.log("IMPORT COMPLETE", "ok")
            self.log(f"{'═'*64}", "head")
            if not stopped:
                self.after(0, lambda: messagebox.showinfo(
                    "Import Complete",
                    "Import finished. See the Log tab for a full summary.\n\n"
                    "Remember to:\n"
                    "  • Reset RADIUS/TACACS shared secrets on imported NADs "
                    f"(placeholder: {DEFAULT_SHARED_SECRET})\n"
                    f"  • Reset internal user passwords (placeholder: {DEFAULT_USER_PASSWORD})\n"
                    "  • Verify ID store sequences if AD/LDAP is used"))

        finally:
            self._running.release()
            self.after(0, lambda: self.import_btn.config(state="normal"))
            self.after(0, lambda: self.import_prog_lbl.config(text="Done"))

    def _log_compat_warnings(self, src_ver: str, dst_ver: str):
        """Log version-compatibility notes before import begins."""
        self.log("\n  Compatibility checks:", "info")
        self.log(
            f"  ⚠  RADIUS/TACACS shared secrets not exported — set manually.",
            "warn")
        self.log(
            f"  ⚠  Internal user passwords replaced with placeholder "
            f"'{DEFAULT_USER_PASSWORD}'.", "warn")
        self.log(
            "  ⚠  AD/LDAP stores not exported — ID Store Sequences that "
            "reference them may fail.", "warn")

        if not src_ver or not dst_ver:
            self.log("  ℹ  Version comparison skipped (one or both versions unknown).",
                     "info")
            return

        sp = parse_ver(src_ver)
        dp = parse_ver(dst_ver)

        if dp < sp:
            self.log(
                f"  ⚠  DOWNGRADE: source ISE {ver_display(src_ver)} → "
                f"target ISE {ver_display(dst_ver)}.  "
                "Version-gated fields will be stripped.", "warn")
        elif dp > sp:
            self.log(
                f"  ✓  UPGRADE: source ISE {ver_display(src_ver)} → "
                f"target ISE {ver_display(dst_ver)}.  "
                "Target may have new features not in the backup.", "info")
        else:
            self.log(
                f"  ✓  Same version ({ver_display(src_ver)}) — "
                "full fidelity migration.", "ok")

        # Specific version milestone warnings
        if ver_lt(dst_ver, 2, 7) and ver_gte(src_ver, 2, 7):
            self.log(
                "  ⚠  TEAP fields in AllowedProtocols will be stripped "
                "(TEAP requires ISE 2.7+).", "warn")
        if ver_lt(dst_ver, 2, 6) and ver_gte(src_ver, 2, 6):
            self.log(
                "  ⚠  REST ID Stores will be skipped "
                "(requires ISE 2.6+).", "warn")
        if ver_lt(dst_ver, 3, 0) and ver_gte(src_ver, 3, 0):
            self.log(
                "  ⚠  Filter-IP Policies will be skipped "
                "(requires ISE 3.0+).", "warn")
        if ver_lt(dst_ver, 3, 3) and ver_gte(src_ver, 3, 3):
            self.log(
                "  ⚠  Native IPSec and custom user attributes will be stripped "
                "(requires ISE 3.3+).", "warn")
        if ver_lt(dst_ver, 3, 5) and ver_gte(src_ver, 3, 5):
            self.log(
                "  ⚠  SGACL TRAFFIC_STEERING type will be stripped "
                "(requires ISE 3.5+).", "warn")

    # ── Import helpers ────────────────────────────────────────────────────────

    def _item_name(self, item: dict, ers_key: str) -> str:
        """Return the natural unique identifier for an item."""
        alt = ALT_LOOKUP_FIELD.get(ers_key)
        if alt:
            return item.get(alt) or item.get("name") or item.get("id", "?")
        if ers_key == "guestuser":
            # Username is nested under guestInfo; top-level name is the same value.
            return (item.get("guestInfo", {}).get("userName")
                    or item.get("name", "?"))
        return item.get("name") or item.get("id", "?")

    def _lookup_existing(self, ers_key: str, name: str,
                         client: ISEClient) -> dict | None:
        if name == "?":
            return None
        return client.get_by_name(ers_key, name)

    @staticmethod
    def _extract_id(response: dict) -> str | None:
        # ERS get-by-name wraps the object under a single root key,
        # {"<Key>": {... "id": ...}}.  Return the first non-empty id found among
        # the wrapper values, then fall back to a top-level id, so this is robust
        # to either shape rather than trusting the first nested dict blindly.
        if not isinstance(response, dict):
            return None
        for v in response.values():
            if isinstance(v, dict) and v.get("id"):
                return v["id"]
        return response.get("id")

    @staticmethod
    def _is_duplicate_error(msg: str) -> bool:
        lower = msg.lower()
        return any(kw in lower for kw in
                   ("already exists", "duplicate", "uniqueness", "conflict"))

    def _sanitise(self, item: dict, ers_key: str, dst_ver: str) -> dict:
        """
        Strip server-managed fields, apply source-specific fixes, and remove
        fields that the target ISE version does not support.
        """
        clean = copy.deepcopy({k: v for k, v in item.items()
                               if k not in STRIP_ON_WRITE})

        # ── Internal users ──────────────────────────────────────────────────
        if ers_key == "internaluser":
            if not clean.get("password"):
                clean["password"] = DEFAULT_USER_PASSWORD
            clean.pop("changePassword", None)
            clean.pop("passwordIDStore", None)

        # ── Guest users ─────────────────────────────────────────────────────
        if ers_key == "guestuser":
            # portalId is source-ISE-specific UUID; let target assign default.
            clean.pop("portalId", None)
            for f in ("sponsorUserId", "createTime", "updateTime"):
                clean.pop(f, None)
            gi = clean.setdefault("guestInfo", {})
            if not gi.get("password"):
                gi["password"] = DEFAULT_USER_PASSWORD

        # ── Network devices ──────────────────────────────────────────────────
        if ers_key == "networkdevice":
            # Shared secrets are write-only and never returned by GET.  ISE
            # rejects creation of a device whose RADIUS/TACACS block is present
            # but secret-less, so replace (not just drop) with a placeholder the
            # operator resets afterward.  Only touch blocks that actually exist —
            # don't fabricate empty ones.
            auth = clean.get("authenticationSettings")
            if isinstance(auth, dict):
                auth.pop("radiusSharedSecret", None)
                auth["radiusSharedSecret"] = DEFAULT_SHARED_SECRET
            tac = clean.get("tacacsSettings")
            if isinstance(tac, dict):
                tac.pop("sharedSecret", None)
                tac["sharedSecret"] = DEFAULT_SHARED_SECRET

        # ── Version-gated fields ─────────────────────────────────────────────
        if dst_ver:
            for gate in VERSION_GATED_FIELDS.get(ers_key, []):
                if ver_lt(dst_ver, *gate["min_ver"]):
                    for field in gate["fields"]:
                        clean.pop(field, None)
                        # Also strip from nested dicts (e.g. allowedProtocols sub-objects)
                        for v in clean.values():
                            if isinstance(v, dict):
                                v.pop(field, None)

        return clean

    # ── OpenAPI export / import ────────────────────────────────────────────────

    def _export_openapi(self, ers_key: str, oapi: OpenAPIClient) -> list | None:
        """
        Fetch an OpenAPI policy resource.  Returns a list of objects (policy
        sets carry their rules under "_authentication"/"_authorization"), or
        None if the endpoint is unsupported (404).
        """
        info = self._oapi_info[ers_key]
        ptype, kind = info["ptype"], info["kind"]

        if kind == "dictionary":
            items = oapi.get(f"/policy/{ptype}/dictionaries")
            return items if items is not None else None

        if kind == "condition":
            items = oapi.get(f"/policy/{ptype}/condition")
            return items if items is not None else None

        if kind == "policyset":
            sets = oapi.get(f"/policy/{ptype}/policy-set")
            if sets is None:
                return None
            result = []
            for ps in sets:
                if not isinstance(ps, dict):
                    continue
                ps = dict(ps)
                sid = ps.get("id")
                if sid:
                    ps["_authentication"] = (
                        oapi.get(f"/policy/{ptype}/policy-set/{sid}/authentication")
                        or [])
                    ps["_authorization"] = (
                        oapi.get(f"/policy/{ptype}/policy-set/{sid}/authorization")
                        or [])
                result.append(ps)
            return result

        if kind == "endpoint":
            return self._export_oapi_endpoints(oapi)

        if kind == "ipsec":
            items = oapi.get(OAPI_IPSEC_PATH)
            return items if isinstance(items, list) else (
                None if items is None else [])

        if kind in OAPI_TRUSTSEC_PATHS:
            items = oapi.get(OAPI_TRUSTSEC_PATHS[kind])
            return items if isinstance(items, list) else (
                None if items is None else [])

        return None

    def _export_oapi_endpoints(self, oapi: OpenAPIClient) -> list | None:
        """
        Page through the OpenAPI endpoint collection.  Dedupes by id and stops
        when a page yields no new ids — this is defensive against builds that
        ignore the size/page params and would otherwise loop forever.
        """
        out: list = []
        seen: set = set()
        page, size = 1, 100
        while True:
            if self._stop_flag.is_set():
                break
            chunk = oapi.get(f"{OAPI_ENDPOINT_PATH}?size={size}&page={page}")
            if chunk is None:
                return out if page > 1 else None   # 404 on page 1 → unsupported
            if isinstance(chunk, dict):
                chunk = (chunk.get("response") or chunk.get("resources") or [])
            if not isinstance(chunk, list):
                chunk = []
            new = [e for e in chunk
                   if isinstance(e, dict) and e.get("id") not in seen]
            if not new:
                break
            for e in new:
                seen.add(e.get("id"))
            out.extend(new)
            if len(chunk) < size:
                break
            page += 1
        return out

    def _import_openapi(self, ers_key: str, items: list,
                        oapi: OpenAPIClient, dry: bool, overwrite: bool
                        ) -> tuple[int, int, int, int]:
        """Dispatch an OpenAPI resource to its importer. Returns counts."""
        info = self._oapi_info[ers_key]
        ptype, kind = info["ptype"], info["kind"]

        if kind == "dictionary":
            return self._import_oapi_simple(
                f"/policy/{ptype}/dictionaries", items, oapi, dry, overwrite)
        if kind == "condition":
            return self._import_oapi_simple(
                f"/policy/{ptype}/condition", items, oapi, dry, overwrite)
        if kind == "policyset":
            return self._import_policysets(ptype, items, oapi, dry, overwrite)
        if kind == "endpoint":
            return self._import_oapi_endpoints(items, oapi, dry, overwrite)
        if kind == "ipsec":
            # No "name" field; a tunnel is uniquely identified by its node +
            # NAD IP.  PSK is write-only, so create may fail until re-entered.
            return self._import_oapi_simple(
                OAPI_IPSEC_PATH, items, oapi, dry, overwrite,
                key_fields=("hostName", "nadIp"))
        if kind in OAPI_TRUSTSEC_PATHS:
            return self._import_oapi_simple(
                OAPI_TRUSTSEC_PATHS[kind], items, oapi, dry, overwrite)
        return (0, 0, 0, 0)

    def _import_oapi_simple(self, path: str, items: list,
                            oapi: OpenAPIClient, dry: bool, overwrite: bool,
                            key_fields: tuple = ("name",)
                            ) -> tuple[int, int, int, int]:
        """Create/update flat OpenAPI objects keyed by ``key_fields`` (the
        natural unique key — 'name' for most resources, but e.g. hostName+nadIp
        for Native IPsec tunnels)."""
        def _key(o: dict) -> str:
            return "|".join(str(o.get(f, "")) for f in key_fields)

        created = updated = skipped = failed = 0
        existing: dict[str, str] = {}
        try:
            for o in (oapi.get(path) or []):
                if isinstance(o, dict) and _key(o).strip("|"):
                    existing[_key(o)] = o.get("id")
        except Exception as exc:
            self.log(f"  ⚠  Could not list existing target objects: {exc}",
                     "warn")

        for it in items:
            if self._stop_flag.is_set():
                break
            if not isinstance(it, dict):
                continue
            name = _key(it) or "?"
            body = {k: v for k, v in it.items()
                    if k not in OAPI_STRIP and not k.startswith("_")}

            if dry:
                self.log(f"  [DRY] Would import: {name}", "info")
                created += 1
                continue

            if name in existing:
                eid = existing[name]
                if overwrite and eid:
                    ok, msg = oapi.put(f"{path}/{eid}", body)
                    if ok:
                        updated += 1
                    else:
                        self.log(f"  ✗  Update '{name}': {msg}", "error")
                        failed += 1
                else:
                    skipped += 1
            else:
                ok, msg, _ = oapi.post(path, body)
                if ok:
                    created += 1
                elif self._is_duplicate_error(msg):
                    skipped += 1
                else:
                    self.log(f"  ✗  Create '{name}': {msg}", "error")
                    failed += 1
        return created, updated, skipped, failed

    def _import_oapi_endpoints(self, items: list, oapi: OpenAPIClient,
                               dry: bool, overwrite: bool
                               ) -> tuple[int, int, int, int]:
        """Create/update endpoints over OpenAPI, keyed by MAC address."""
        created = updated = skipped = failed = 0

        def _key(e: dict) -> str:
            return str(e.get("mac") or e.get("name") or "?").upper()

        existing: dict[str, str] = {}
        try:
            for e in (self._export_oapi_endpoints(oapi) or []):
                if isinstance(e, dict) and _key(e) != "?":
                    existing[_key(e)] = e.get("id")
        except Exception as exc:
            self.log(f"  ⚠  Could not list target endpoints: {exc}", "warn")

        for it in items:
            if self._stop_flag.is_set():
                break
            if not isinstance(it, dict):
                continue
            key = _key(it)
            body = {k: v for k, v in it.items()
                    if k not in OAPI_STRIP and not k.startswith("_")}

            if dry:
                self.log(f"  [DRY] Would import endpoint: {key}", "info")
                created += 1
                continue

            eid = existing.get(key) if key != "?" else None
            if eid:
                if overwrite:
                    ok, msg = oapi.put(f"{OAPI_ENDPOINT_PATH}/{eid}", body)
                    if ok:
                        updated += 1
                    else:
                        self.log(f"  ✗  Update '{key}': {msg}", "error")
                        failed += 1
                else:
                    skipped += 1
            else:
                ok, msg, _ = oapi.post(OAPI_ENDPOINT_PATH, body)
                if ok:
                    created += 1
                elif self._is_duplicate_error(msg):
                    skipped += 1
                else:
                    self.log(f"  ✗  Create '{key}': {msg}", "error")
                    failed += 1
        return created, updated, skipped, failed

    def _import_policysets(self, ptype: str, sets: list,
                           oapi: OpenAPIClient, dry: bool, overwrite: bool
                           ) -> tuple[int, int, int, int]:
        """
        Import policy sets and their authN/authZ rules.  Best-effort:
        the default set is never re-created (its rules are still imported into
        the target's existing default set), and rules whose inline conditions
        reference library conditions by ID may not resolve across systems.
        """
        created = updated = skipped = failed = 0
        base = f"/policy/{ptype}/policy-set"

        self.log(
            "  ℹ  Rules reference authz profiles, SGTs and identity sources by "
            "name (these must already exist on the target).  Library-condition "
            "references resolve by ID and may not carry across systems.", "info")

        # Map the target's current sets: name → id, and locate its default set.
        existing: dict[str, str] = {}
        default_id: str | None = None
        try:
            for o in (oapi.get(base) or []):
                if not isinstance(o, dict):
                    continue
                if o.get("name"):
                    existing[o["name"]] = o.get("id")
                if o.get("default"):
                    default_id = o.get("id")
        except Exception as exc:
            self.log(f"  ⚠  Could not list existing policy sets: {exc}", "warn")

        for ps in sets:
            if self._stop_flag.is_set():
                break
            if not isinstance(ps, dict):
                continue
            name = ps.get("name", "?")
            is_default = bool(ps.get("default"))
            authn = ps.get("_authentication") or []
            authz = ps.get("_authorization") or []

            if dry:
                self.log(
                    f"  [DRY] Would import policy set: {name} "
                    f"({len(authn)} authN, {len(authz)} authZ rules)", "info")
                created += 1
                continue

            target_id: str | None = None
            # Rules are only pushed into a set we just created, or into an
            # existing set when the user opted to update existing objects.
            do_rules = False
            if is_default:
                # The default set always exists on the target — never re-created.
                target_id = default_id
                if not target_id:
                    self.log(
                        f"  ⚠  No default set found on target; skipping "
                        f"'{name}' and its rules", "warn")
                    skipped += 1
                    continue
                skipped += 1   # the set itself is not re-created
                do_rules = overwrite
            elif name in existing:
                target_id = existing[name]
                if overwrite and target_id:
                    ok, msg = oapi.put(
                        f"{base}/{target_id}", self._clean_oapi_set(ps))
                    if ok:
                        updated += 1
                        do_rules = True
                    else:
                        self.log(f"  ✗  Update set '{name}': {msg}", "error")
                        failed += 1
                else:
                    skipped += 1
            else:
                ok, msg, obj = oapi.post(base, self._clean_oapi_set(ps))
                if ok:
                    created += 1
                    target_id = obj.get("id") or self._resolve_set_id(
                        oapi, base, name)
                    do_rules = True
                elif self._is_duplicate_error(msg):
                    skipped += 1
                    target_id = self._resolve_set_id(oapi, base, name)
                    do_rules = overwrite
                else:
                    self.log(f"  ✗  Create set '{name}': {msg}", "error")
                    failed += 1
                    continue

            if target_id and do_rules:
                rc, rf = self._import_rules(
                    ptype, target_id, "authentication", authn, oapi)
                ac, af = self._import_rules(
                    ptype, target_id, "authorization", authz, oapi)
                created += rc + ac
                failed += rf + af
                if rc or ac:
                    self.log(
                        f"    ↳ '{name}': +{rc} authN, +{ac} authZ rules", "ok")

        return created, updated, skipped, failed

    def _import_rules(self, ptype: str, set_id: str, rule_type: str,
                      rules: list, oapi: OpenAPIClient) -> tuple[int, int]:
        """Create non-default rules under a policy set. Returns (created, failed)."""
        created = failed = 0
        path = f"/policy/{ptype}/policy-set/{set_id}/{rule_type}"

        existing: set[str] = set()
        try:
            for o in (oapi.get(path) or []):
                nm = (o.get("rule") or {}).get("name") if isinstance(o, dict) else None
                if nm:
                    existing.add(nm)
        except Exception:
            pass

        for rw in rules:
            if self._stop_flag.is_set():
                break
            if not isinstance(rw, dict):
                continue
            rule = rw.get("rule") or {}
            # The default rule of every set is auto-created and cannot be POSTed.
            if rule.get("default"):
                continue
            nm = rule.get("name")
            if nm and nm in existing:
                continue
            ok, msg, _ = oapi.post(path, self._clean_oapi_rule(rw))
            if ok:
                created += 1
            elif self._is_duplicate_error(msg):
                pass
            else:
                self.log(f"  ✗  {rule_type} rule '{nm}': {msg}", "error")
                failed += 1
        return created, failed

    @staticmethod
    def _clean_oapi_set(ps: dict) -> dict:
        """Strip server-managed fields and this tool's rule carriers from a set."""
        return {k: v for k, v in ps.items() if k not in OAPI_SET_STRIP}

    @staticmethod
    def _clean_oapi_rule(rw: dict) -> dict:
        """
        Strip server-managed fields from a rule wrapper and its nested rule.
        The condition tree is left intact so inline conditions port verbatim.
        """
        out = {k: v for k, v in rw.items() if k not in OAPI_STRIP}
        rule = out.get("rule")
        if isinstance(rule, dict):
            out["rule"] = {k: v for k, v in rule.items()
                           if k not in OAPI_STRIP}
        return out

    @staticmethod
    def _resolve_set_id(oapi: OpenAPIClient, base: str, name: str) -> str | None:
        """Look up a policy set's id by name (used when POST omits it)."""
        try:
            for o in (oapi.get(base) or []):
                if isinstance(o, dict) and o.get("name") == name:
                    return o.get("id")
        except Exception:
            pass
        return None

    # ── Log helpers ───────────────────────────────────────────────────────────

    def log(self, msg: str, tag: str = ""):
        ts = datetime.now().strftime("%H:%M:%S")

        def _write():
            self.log_box.config(state="normal")
            self.log_box.insert("end", f"[{ts}]  {msg}\n", tag)
            self.log_box.see("end")
            self.log_box.config(state="disabled")

        self.after(0, _write)

    def _clear_log(self):
        self.log_box.config(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.config(state="disabled")

    def _save_log(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
            initialfile=(
                f"ise_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"))
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.log_box.get("1.0", "end"))
            self.log(f"Log saved  →  {path}", "ok")

    def _stop(self):
        self._stop_flag.set()
        self.log("Stop requested — will halt after the current item.", "warn")


# ── Entry point ──────────────────────────────────────────────────────────────

def main():
    app = MigrationApp()
    app.mainloop()


if __name__ == "__main__":
    main()
