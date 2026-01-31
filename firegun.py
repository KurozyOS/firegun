#!/usr/bin/env python3
"""
FireGun CLI – Firebase pentest & vuln scanner (v1.3)

A security assessment tool for identifying misconfigurations in Firebase services
including Realtime Database (RTDB), Firestore, and Cloud Storage.

Usage:
    firegun scan [options] TARGETS...
    firegun dump-rtdb [options] TARGET
    firegun fs-scan [options] PROJECTS...
    firegun admin-dump-fs [options] PROJECT
    firegun fuzz-rules [options] RULES_FILE PROJECT SCRIPT_FILE
    firegun script [options] SCRIPT_FILE TARGET
    firegun signup [options] EMAIL [PASSWORD]
    firegun signin [options] EMAIL [PASSWORD]
    firegun storage-scan [options] URLS...

Dependencies (requirements.txt):
    httpx>=0.24
    google-cloud-firestore
    google-auth

Notes & ethics:
- Only test assets you own or have explicit, written permission to assess.
- The --exploit flag writes a non-destructive marker; disabled by default.
"""

import argparse
import asyncio
import getpass
import json
import logging
import os
import random
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlparse, urlunparse

import httpx
from google.cloud import firestore as firestore_admin

# -----------------------------------------------------------------------------
# Logging Configuration
# -----------------------------------------------------------------------------

logging.basicConfig(
    level=logging.DEBUG if os.getenv("FIREGUN_DEBUG") else logging.WARNING,
    format="[%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

BANNER = r"""
______ _           _____
|  ___(_)         |  __ \
| |_   _ _ __ ___ | |  \/_   _ _ __
|  _| | | '__/ _ \| | __| | | | '_ \
| |   | | | |  __/\ |_\ \ |_| | | | |
\_|   |_|_|  \___|\____/\__,_|_| |_|
               by kurozy
"""

VERSION = "1.3"
USER_AGENT = f"FireGun/{VERSION} (+https://github.com/kurozy/firegun)"

# Firebase API endpoints
IDENTITY_TOOLKIT_BASE_URL = "https://identitytoolkit.googleapis.com/v1/accounts"
IDENTITY_TOOLKIT_SIGNUP_URL = f"{IDENTITY_TOOLKIT_BASE_URL}:signUp"
IDENTITY_TOOLKIT_SIGNIN_URL = f"{IDENTITY_TOOLKIT_BASE_URL}:signInWithPassword"
FIRESTORE_BASE_URL = "https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents"

# Firebase Storage endpoints
FIREBASE_STORAGE_BASE_URL = "https://firebasestorage.googleapis.com/v0/b/{bucket}/o"
GCS_STORAGE_BASE_URL = "https://storage.googleapis.com/storage/v1/b/{bucket}/o"
GCS_UPLOAD_BASE_URL = "https://storage.googleapis.com/upload/storage/v1/b/{bucket}/o"

# Default configuration
DEFAULT_CONCURRENCY = 10
DEFAULT_TIMEOUT = 30
MAX_RETRIES = 5
INITIAL_BACKOFF_DELAY = 1.0


# -----------------------------------------------------------------------------
# Custom Exceptions
# -----------------------------------------------------------------------------


class FireGunError(Exception):
    """Base exception for FireGun-specific errors."""

    pass


class ConfigurationError(FireGunError):
    """Raised when configuration is invalid or missing."""

    pass


class AuthenticationError(FireGunError):
    """Raised when authentication fails."""

    pass


class ScanError(FireGunError):
    """Raised when a scan operation fails."""

    pass


# -----------------------------------------------------------------------------
# Data Classes for Results
# -----------------------------------------------------------------------------


class ScanResult:
    """Represents the result of a security scan."""

    def __init__(
        self,
        target: str,
        scan_type: str,
        can_read: bool = False,
        can_write: bool = False,
    ):
        self.target = target
        self.scan_type = scan_type
        self.can_read = can_read
        self.can_write = can_write

    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary for JSON serialization."""
        return {
            "target": self.target,
            "type": self.scan_type,
            "read": self.can_read,
            "write": self.can_write,
        }

    def format_status(self, http_code: Optional[int] = None) -> str:
        """
        Format the scan result as a human-readable status string.

        Args:
            http_code: Optional HTTP status code to include when secure.

        Returns:
            Formatted status string like "VULNERABLE : READ/WRITE" or "SECURE (HTTP 403)".
        """
        permissions = []
        if self.can_read:
            permissions.append("READ")
        if self.can_write:
            permissions.append("WRITE")

        if permissions:
            return f"VULNERABLE : {'/'.join(permissions)}"

        code_suffix = f" (HTTP {http_code})" if http_code else ""
        return f"SECURE{code_suffix}"


# -----------------------------------------------------------------------------
# Banner & Output Helpers
# -----------------------------------------------------------------------------


def print_banner() -> None:
    """Display the FireGun ASCII art banner."""
    print(BANNER)


def print_info(message: str) -> None:
    """Print an informational message to stdout."""
    print(f"[*] {message}")


def print_success(message: str) -> None:
    """Print a success message to stdout."""
    print(f"[+] {message}")


def print_warning(message: str) -> None:
    """Print a warning message to stderr."""
    print(f"[!] {message}", file=sys.stderr)


def print_error(message: str) -> None:
    """Print an error message to stderr."""
    print(f"[-] {message}", file=sys.stderr)


# -----------------------------------------------------------------------------
# Configuration & Validation Helpers
# -----------------------------------------------------------------------------


def load_auth_token_from_config(config_path: Optional[Path]) -> Optional[str]:
    """
    Load an authentication token from a JSON configuration file.

    Args:
        config_path: Path to the JSON config file containing 'idToken' or 'auth'.

    Returns:
        The authentication token if found, None otherwise.

    Raises:
        ConfigurationError: If the config file cannot be read or parsed.
    """
    if not config_path:
        return None

    try:
        config_data = json.loads(config_path.read_text())
        return config_data.get("idToken") or config_data.get("auth")
    except FileNotFoundError:
        raise ConfigurationError(f"Config file not found: {config_path}")
    except json.JSONDecodeError as error:
        raise ConfigurationError(f"Invalid JSON in config file '{config_path}': {error}")
    except (OSError, IOError) as error:
        raise ConfigurationError(f"Could not read config file '{config_path}': {error}")


def require_api_key(args: argparse.Namespace) -> str:
    """
    Get the Firebase API key from arguments or environment.

    Args:
        args: Parsed command-line arguments.

    Returns:
        The Firebase API key.

    Raises:
        ConfigurationError: If no API key is provided.
    """
    api_key = getattr(args, "api_key", None) or os.getenv("FIREBASE_API_KEY")
    if not api_key:
        raise ConfigurationError(
            "API Key is required. Use --api-key or set FIREBASE_API_KEY environment variable."
        )
    return api_key


def get_id_token(args: argparse.Namespace) -> Optional[str]:
    """
    Get the Firebase ID token from arguments, environment, or config file.

    Args:
        args: Parsed command-line arguments.

    Returns:
        The ID token if available, None otherwise.
    """
    token = getattr(args, "id_token", None) or os.getenv("FIREBASE_ID_TOKEN")
    if token:
        return token

    config_path = getattr(args, "config", None)
    if config_path:
        try:
            return load_auth_token_from_config(config_path)
        except ConfigurationError:
            return None

    return None


def resolve_targets(raw_targets: List[str]) -> List[str]:
    """
    Resolve a list of targets, expanding file paths into individual lines.

    Args:
        raw_targets: List of targets (URLs, hostnames, or file paths).

    Returns:
        Expanded list of individual targets.
    """
    resolved_targets: List[str] = []

    for target in raw_targets:
        target_path = Path(target)

        if target_path.is_file():
            try:
                lines = target_path.read_text().splitlines()
                resolved_targets.extend(
                    line.strip() for line in lines if line.strip()
                )
            except (OSError, IOError) as error:
                print_error(f"Could not read target file '{target_path}': {error}")
        else:
            resolved_targets.append(target)

    return resolved_targets


# -----------------------------------------------------------------------------
# URL Building Helpers
# -----------------------------------------------------------------------------


def build_rtdb_url(
    raw_url: str,
    auth_token: Optional[str] = None,
    additional_params: Optional[Dict[str, str]] = None,
) -> str:
    """
    Construct a valid Firebase Realtime Database URL.

    Args:
        raw_url: Raw URL or hostname (e.g., "project.firebaseio.com").
        auth_token: Optional authentication token to include.
        additional_params: Optional extra query parameters.

    Returns:
        Properly formatted RTDB URL with .json extension and query params.
    """
    # Ensure URL has a scheme
    if not raw_url.startswith(("http://", "https://")):
        raw_url = f"https://{raw_url}"

    parsed = urlparse(raw_url)
    path = parsed.path or ""

    # Ensure path ends with .json for REST API access
    if not path.endswith(".json"):
        if path in ("", "/"):
            path = "/.json"
        else:
            path = path.rstrip("/") + ".json"

    # Build query parameters
    query_params = dict(parse_qsl(parsed.query))

    if auth_token:
        query_params.setdefault("auth", auth_token)

    if additional_params:
        query_params.update(additional_params)

    query_string = urlencode(query_params)

    return urlunparse((parsed.scheme, parsed.netloc, path, "", query_string, ""))


def append_query_param(url: str, param: str) -> str:
    """
    Append a query parameter to an existing URL.

    Args:
        url: The base URL.
        param: The parameter string to append (e.g., "print=silent").

    Returns:
        URL with the parameter appended.
    """
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{param}"


# -----------------------------------------------------------------------------
# HTTP Client Factory
# -----------------------------------------------------------------------------


def create_http_client(timeout: int = DEFAULT_TIMEOUT) -> httpx.AsyncClient:
    """
    Create a configured async HTTP client.

    Args:
        timeout: Request timeout in seconds.

    Returns:
        Configured httpx.AsyncClient instance.
    """
    return httpx.AsyncClient(
        timeout=timeout,
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
    )


async def http_request_with_backoff(
    request_func: Callable[[], Any],
    max_retries: int = MAX_RETRIES,
    initial_delay: float = INITIAL_BACKOFF_DELAY,
) -> httpx.Response:
    """
    Execute an HTTP request with exponential backoff for rate limiting.

    Implements retry logic with exponential backoff and jitter for handling
    rate limits (429) and server errors (5xx).

    Args:
        request_func: Async callable that performs the HTTP request.
        max_retries: Maximum number of retry attempts.
        initial_delay: Initial delay in seconds before first retry.

    Returns:
        The HTTP response.

    Raises:
        httpx.RequestError: If all retries are exhausted.
        ConnectionError: If unable to complete request after all retries.
    """
    delay = initial_delay
    last_exception: Optional[Exception] = None

    for attempt in range(max_retries):
        try:
            response: httpx.Response = await request_func()

            # Check if we should retry due to rate limiting or server errors
            should_retry = response.status_code == 429 or response.status_code >= 500
            is_last_attempt = attempt >= max_retries - 1

            if should_retry and not is_last_attempt:
                jitter = random.uniform(0, delay / 3)
                sleep_duration = delay + jitter
                print_warning(
                    f"HTTP {response.status_code}. Retrying in {sleep_duration:.2f}s..."
                )
                await asyncio.sleep(sleep_duration)
                delay *= 2
                continue

            return response

        except httpx.RequestError as error:
            last_exception = error
            is_last_attempt = attempt >= max_retries - 1

            if not is_last_attempt:
                jitter = random.uniform(0, delay / 3)
                sleep_duration = delay + jitter
                print_warning(f"Request error: {error}. Retrying in {sleep_duration:.2f}s...")
                await asyncio.sleep(sleep_duration)
                delay *= 2
            else:
                raise

    raise ConnectionError(
        f"Failed to complete request after {max_retries} retries: {last_exception}"
    )


# -----------------------------------------------------------------------------
# Firebase Authentication (Identity Toolkit)
# -----------------------------------------------------------------------------


async def identity_toolkit_request(
    url: str,
    api_key: str,
    email: str,
    password: str,
) -> Optional[str]:
    """
    Make a request to Firebase Identity Toolkit for authentication.

    Args:
        url: The Identity Toolkit endpoint URL.
        api_key: Firebase project API key.
        email: User email address.
        password: User password.

    Returns:
        The ID token if successful, None otherwise.
    """
    params = {"key": api_key}
    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True,
    }

    try:
        async with create_http_client(timeout=20) as client:
            response = await http_request_with_backoff(
                lambda: client.post(url, params=params, json=payload)
            )
            response.raise_for_status()

            data = response.json()
            user_id = data.get("localId")
            print_success(f"Authentication successful. UID={user_id}")
            return data.get("idToken")

    except httpx.HTTPStatusError as error:
        error_message = _extract_error_message(error.response)
        print_error(f"Request failed: {error.response.status_code} - {error_message}")

    except httpx.RequestError as error:
        print_error(f"Request failed: {error}")

    return None


def _extract_error_message(response: httpx.Response) -> str:
    """
    Extract a human-readable error message from an HTTP response.

    Args:
        response: The HTTP error response.

    Returns:
        The error message string.
    """
    try:
        error_info = response.json().get("error", {})
        return error_info.get("message", response.text)
    except (json.JSONDecodeError, AttributeError):
        return response.text


async def signup_user(api_key: str, email: str, password: str) -> Optional[str]:
    """
    Register a new user with Firebase Authentication.

    Args:
        api_key: Firebase project API key.
        email: User email address.
        password: User password.

    Returns:
        The ID token if successful, None otherwise.
    """
    print_info(f"Signing up user {email}...")
    return await identity_toolkit_request(
        IDENTITY_TOOLKIT_SIGNUP_URL, api_key, email, password
    )


async def signin_user(api_key: str, email: str, password: str) -> Optional[str]:
    """
    Sign in an existing user with Firebase Authentication.

    Args:
        api_key: Firebase project API key.
        email: User email address.
        password: User password.

    Returns:
        The ID token if successful, None otherwise.
    """
    print_info(f"Signing in user {email}...")
    return await identity_toolkit_request(
        IDENTITY_TOOLKIT_SIGNIN_URL, api_key, email, password
    )


# -----------------------------------------------------------------------------
# Realtime Database (RTDB) Scanning
# -----------------------------------------------------------------------------


async def exploit_rtdb(client: httpx.AsyncClient, root_url: str) -> bool:
    """
    Write a non-destructive security warning to a vulnerable RTDB.

    This function attempts to write a warning message to alert administrators
    about the misconfiguration. The message is written to a dedicated key
    to minimize impact on existing data.

    Args:
        client: The HTTP client to use.
        root_url: The RTDB root URL.

    Returns:
        True if exploit was successful, False otherwise.
    """
    print_warning(f"Attempting to write security warning to {root_url}")

    warning_message = (
        "Your Firebase Realtime Database is publicly writable. This is a security risk. "
        "Secure your database by updating your rules: https://firebase.google.com/docs/database/security"
    )
    payload = {"__firegun_warning__": warning_message}

    patch_url = append_query_param(root_url, "print=silent")

    response = await http_request_with_backoff(
        lambda: client.patch(patch_url, json=payload, timeout=10)
    )

    if response.status_code == 200:
        print_success(f"Exploit successful (HTTP {response.status_code}): Wrote warning message.")
        return True

    print_error(f"Exploit failed (HTTP {response.status_code}): {response.text}")
    return False


async def scan_rtdb(
    client: httpx.AsyncClient,
    target: str,
    semaphore: asyncio.Semaphore,
    exploit: bool,
    auth_token: Optional[str] = None,
    readout: bool = False,
    results: Optional[List[Dict[str, Any]]] = None,
) -> ScanResult:
    """
    Scan a Firebase Realtime Database for read/write permission vulnerabilities.

    Tests whether the database allows unauthenticated or overly permissive access
    by attempting to read data and write a probe document.

    Args:
        client: The HTTP client to use.
        target: The RTDB target URL or hostname.
        semaphore: Concurrency limiter.
        exploit: Whether to attempt writing a warning message if vulnerable.
        auth_token: Optional authentication token.
        readout: Whether to print readable data if found.
        results: Optional list to append scan results for JSON output.

    Returns:
        ScanResult containing the vulnerability assessment.
    """
    result = ScanResult(target=target, scan_type="rtdb")
    probe_url = build_rtdb_url(target.rstrip("/") + "/__firegun_probe__", auth_token)
    last_status_code: Optional[int] = None

    try:
        async with semaphore:
            # Test READ access using shallow query
            result.can_read, last_status_code = await _test_rtdb_read(
                client, target, auth_token
            )

            # Test WRITE access using probe document
            result.can_write = await _test_rtdb_write(client, probe_url)

        # Print scan result
        status = result.format_status(last_status_code)
        print(f"{target} [{status}]")

        # Append to results for JSON output
        if results is not None:
            results.append(result.to_dict())

        # Perform readout if requested and readable
        if readout and result.can_read:
            await _perform_rtdb_readout(client, target, auth_token)

        # Attempt exploit if requested and writable
        if exploit and result.can_write:
            await exploit_rtdb(client, build_rtdb_url(target, auth_token))

    except httpx.RequestError as error:
        print_error(f"Critical error scanning {target}: {error}")

    return result


async def _test_rtdb_read(
    client: httpx.AsyncClient,
    target: str,
    auth_token: Optional[str],
) -> Tuple[bool, int]:
    """
    Test if an RTDB allows read access.

    Uses a shallow query to minimize data transfer while determining
    if the database is readable. An empty database returning null is
    still considered readable.

    Args:
        client: The HTTP client to use.
        target: The RTDB target.
        auth_token: Optional authentication token.

    Returns:
        Tuple of (can_read, http_status_code).
    """
    shallow_url = build_rtdb_url(target, auth_token, additional_params={"shallow": "true"})

    response = await http_request_with_backoff(lambda: client.get(shallow_url))

    if response.status_code != 200:
        return False, response.status_code

    try:
        data = response.json()
        # null indicates readable but empty; dict/list indicates readable with data
        is_readable = isinstance(data, (dict, list)) or data is None
        return is_readable, response.status_code
    except json.JSONDecodeError:
        # If response isn't valid JSON, check for permission denied message
        is_readable = "Permission denied" not in response.text
        return is_readable, response.status_code


async def _test_rtdb_write(client: httpx.AsyncClient, probe_url: str) -> bool:
    """
    Test if an RTDB allows write access by writing a probe document.

    Writes a small probe document to test write permissions, then immediately
    cleans up by deleting the probe.

    Args:
        client: The HTTP client to use.
        probe_url: URL for the probe document location.

    Returns:
        True if write access is available, False otherwise.
    """
    can_write = False

    try:
        write_url = append_query_param(probe_url, "print=silent")
        write_payload = {"probe": "firegun"}

        response = await http_request_with_backoff(
            lambda: client.put(write_url, json=write_payload)
        )

        # Any 2xx response indicates successful write
        can_write = 200 <= response.status_code < 300

    finally:
        # Always attempt cleanup
        if can_write:
            try:
                await client.delete(probe_url)
            except httpx.RequestError as error:
                logger.debug(f"Failed to clean up probe document: {error}")

    return can_write


async def _perform_rtdb_readout(
    client: httpx.AsyncClient,
    target: str,
    auth_token: Optional[str],
) -> None:
    """
    Read and print the full contents of a readable RTDB.

    Args:
        client: The HTTP client to use.
        target: The RTDB target.
        auth_token: Optional authentication token.
    """
    full_url = build_rtdb_url(target, auth_token)

    response = await http_request_with_backoff(lambda: client.get(full_url))

    if response.status_code == 200:
        print("\n-- Begin RTDB readout --")
        try:
            print(json.dumps(response.json(), indent=2))
        except json.JSONDecodeError:
            print(response.text)
        print("-- End RTDB readout --\n")


# -----------------------------------------------------------------------------
# Firestore Scanning
# -----------------------------------------------------------------------------


def build_firestore_headers(id_token: Optional[str]) -> Dict[str, str]:
    """
    Build HTTP headers for Firestore API requests.

    Args:
        id_token: Optional Firebase ID token for authenticated requests.

    Returns:
        Dictionary of headers.
    """
    headers = {"User-Agent": USER_AGENT}

    if id_token:
        # Firestore v1 prefers OAuth2 access tokens, but Firebase ID tokens
        # work for many configurations that allow authenticated access
        headers["Authorization"] = f"Bearer {id_token}"

    return headers


async def _test_firestore_read(
    client: httpx.AsyncClient,
    base_url: str,
    api_key: str,
    headers: Dict[str, str],
) -> Tuple[bool, int]:
    """
    Test if Firestore allows read access.

    Probes a non-existent document to distinguish between 404 (path is readable
    but document doesn't exist) vs 403/401 (access blocked by rules).

    Args:
        client: The HTTP client to use.
        base_url: Firestore base URL for the project.
        api_key: Firebase API key.
        headers: Request headers.

    Returns:
        Tuple of (can_read, http_status_code).
    """
    probe_url = f"{base_url}/__firegun__/__probe_read__?key={api_key}"

    response = await http_request_with_backoff(
        lambda: client.get(probe_url, headers=headers)
    )

    # 200 = doc exists and readable, 404 = readable path but doc doesn't exist
    can_read = response.status_code in (200, 404)
    return can_read, response.status_code


async def _test_firestore_write(
    client: httpx.AsyncClient,
    base_url: str,
    api_key: str,
    headers: Dict[str, str],
) -> Tuple[bool, int]:
    """
    Test if Firestore allows write access by creating a probe document.

    Attempts to create a document in a test collection, then cleans up
    if successful.

    Args:
        client: The HTTP client to use.
        base_url: Firestore base URL for the project.
        api_key: Firebase API key.
        headers: Request headers.

    Returns:
        Tuple of (can_write, http_status_code).
    """
    create_url = f"{base_url}/__firegun__?documentId=__probe_write__&key={api_key}"
    payload = {"fields": {"probe": {"stringValue": "firegun"}}}

    response = await http_request_with_backoff(
        lambda: client.post(create_url, headers=headers, json=payload)
    )

    can_write = response.status_code in (200, 201)

    if can_write:
        # Clean up the probe document
        delete_url = f"{base_url}/__firegun__/__probe_write__?key={api_key}"
        try:
            await client.delete(delete_url, headers=headers)
        except httpx.RequestError as error:
            logger.debug(f"Failed to clean up Firestore probe document: {error}")

    return can_write, response.status_code


async def enumerate_firestore_collections(
    client: httpx.AsyncClient,
    base_url: str,
    api_key: str,
    headers: Dict[str, str],
) -> None:
    """
    Enumerate and display Firestore collections and sample documents.

    Lists top-level collections and fetches sample documents from each
    to provide visibility into the database structure.

    Args:
        client: The HTTP client to use.
        base_url: Firestore base URL for the project.
        api_key: Firebase API key.
        headers: Request headers.
    """
    print("  [+] Enumerating collections...")

    try:
        list_url = f"{base_url}:listCollectionIds?key={api_key}"
        response = await http_request_with_backoff(
            lambda: client.post(list_url, headers=headers, json={"pageSize": 50})
        )

        if response.status_code == 200:
            collections = response.json().get("collectionIds", [])
            print(f"    [+] Found {len(collections)} collections: {collections}")

            # Sample documents from first 5 collections
            for collection_name in collections[:5]:
                await _sample_firestore_collection(
                    client, base_url, api_key, headers, collection_name
                )

        elif response.status_code in (401, 403):
            print("  [-] Collection enumeration blocked by security rules")

    except httpx.RequestError as error:
        print_error(f"Failed to enumerate collections: {error}")
    except json.JSONDecodeError as error:
        print_error(f"Failed to parse collection list: {error}")


async def _sample_firestore_collection(
    client: httpx.AsyncClient,
    base_url: str,
    api_key: str,
    headers: Dict[str, str],
    collection_name: str,
) -> None:
    """
    Fetch and display sample documents from a Firestore collection.

    Args:
        client: The HTTP client to use.
        base_url: Firestore base URL.
        api_key: Firebase API key.
        headers: Request headers.
        collection_name: Name of the collection to sample.
    """
    docs_url = f"{base_url}/{collection_name}?pageSize=5&key={api_key}"

    try:
        response = await http_request_with_backoff(
            lambda: client.get(docs_url, headers=headers)
        )

        if response.status_code == 200:
            documents = response.json().get("documents", [])
            doc_names = [doc["name"].rsplit("/", 1)[-1] for doc in documents]
            print(f"      - {collection_name} sample docs: {doc_names}")

    except (httpx.RequestError, json.JSONDecodeError, KeyError) as error:
        logger.debug(f"Failed to sample collection {collection_name}: {error}")


async def scan_firestore(
    client: httpx.AsyncClient,
    project: str,
    api_key: str,
    id_token: Optional[str],
    semaphore: asyncio.Semaphore,
    exploit: bool,
    results: Optional[List[Dict[str, Any]]] = None,
) -> ScanResult:
    """
    Scan a Firestore database for access permission vulnerabilities.

    Tests whether the database allows unauthenticated read/write access
    and enumerates collections if readable.

    Args:
        client: The HTTP client to use.
        project: Firebase project ID.
        api_key: Firebase API key.
        id_token: Optional authentication token.
        semaphore: Concurrency limiter.
        exploit: Whether to test write access (creates/deletes probe doc).
        results: Optional list to append results for JSON output.

    Returns:
        ScanResult containing the vulnerability assessment.
    """
    base_url = FIRESTORE_BASE_URL.format(project=project)
    headers = build_firestore_headers(id_token)
    result = ScanResult(target=project, scan_type="firestore")
    last_status_code: Optional[int] = None

    try:
        async with semaphore:
            result.can_read, last_status_code = await _test_firestore_read(
                client, base_url, api_key, headers
            )

            if exploit:
                result.can_write, last_status_code = await _test_firestore_write(
                    client, base_url, api_key, headers
                )

        # Print scan result
        status = result.format_status(last_status_code)
        print(f"Firestore {project} [{status}]")

        if results is not None:
            results.append(result.to_dict())

        # Enumerate collections if readable
        if result.can_read:
            await enumerate_firestore_collections(client, base_url, api_key, headers)

    except httpx.RequestError as error:
        print_error(f"Critical error scanning Firestore {project}: {error}")

    return result


# -----------------------------------------------------------------------------
# Firebase Storage Scanning
# -----------------------------------------------------------------------------


def parse_storage_url(url: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract bucket and object path from a Firebase Storage download URL.

    Parses URLs in the format:
    https://firebasestorage.googleapis.com/v0/b/<bucket>/o/<encoded-object>

    Args:
        url: The Firebase Storage URL to parse.

    Returns:
        Tuple of (bucket_name, object_path) or (None, None) if parsing fails.
    """
    try:
        parsed = urlparse(url)
        path_parts = [part for part in parsed.path.strip("/").split("/") if part]

        # Expected format: v0/b/<bucket>/o/<encoded-object>
        if len(path_parts) >= 5 and path_parts[1] == "b" and path_parts[3] == "o":
            bucket = path_parts[2]
            encoded_object = path_parts[4]
            object_path = unquote(encoded_object)
            return bucket, object_path

    except (ValueError, IndexError) as error:
        logger.debug(f"Failed to parse storage URL '{url}': {error}")

    return None, None


async def _test_storage_upload(
    client: httpx.AsyncClient,
    bucket: str,
    id_token: Optional[str],
) -> Tuple[bool, str]:
    """
    Test if Firebase Storage allows write access by uploading a probe file.

    Tries Firebase Storage API first, then falls back to Cloud Storage API.

    Args:
        client: The HTTP client to use.
        bucket: The storage bucket name.
        id_token: Optional authentication token.

    Returns:
        Tuple of (can_write, api_type) where api_type is "v0" or "gcs".
    """
    headers = {"User-Agent": USER_AGENT, "Content-Type": "text/plain"}
    if id_token:
        headers["Authorization"] = f"Bearer {id_token}"

    probe_content = b"firegun_probe"
    probe_filename = "firegun_probe.txt"

    # Try Firebase Storage v0 API
    firebase_url = (
        f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o"
        f"?name={probe_filename}&uploadType=media"
    )

    response = await http_request_with_backoff(
        lambda: client.post(firebase_url, headers=headers, content=probe_content)
    )

    if response.status_code in (200, 201):
        return True, "v0"

    # Fall back to Cloud Storage JSON API
    gcs_url = (
        f"https://storage.googleapis.com/upload/storage/v1/b/{bucket}/o"
        f"?uploadType=media&name={probe_filename}"
    )

    response = await http_request_with_backoff(
        lambda: client.post(gcs_url, headers=headers, content=probe_content)
    )

    if response.status_code in (200, 201):
        return True, "gcs"

    return False, ""


async def _delete_storage_probe(
    client: httpx.AsyncClient,
    bucket: str,
    id_token: Optional[str],
) -> None:
    """
    Delete the probe file from Firebase Storage.

    Attempts deletion via both Firebase and Cloud Storage APIs.

    Args:
        client: The HTTP client to use.
        bucket: The storage bucket name.
        id_token: Optional authentication token.
    """
    headers = {"User-Agent": USER_AGENT}
    if id_token:
        headers["Authorization"] = f"Bearer {id_token}"

    encoded_filename = quote("firegun_probe.txt", safe="")

    # Try Firebase Storage API
    firebase_url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o/{encoded_filename}"
    try:
        await client.delete(firebase_url, headers=headers)
    except httpx.RequestError as error:
        logger.debug(f"Firebase Storage delete failed: {error}")

    # Try Cloud Storage API
    gcs_url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o/{encoded_filename}"
    try:
        await client.delete(gcs_url, headers=headers)
    except httpx.RequestError as error:
        logger.debug(f"Cloud Storage delete failed: {error}")


async def scan_storage(
    client: httpx.AsyncClient,
    url: str,
    semaphore: asyncio.Semaphore,
    exploit: bool,
    id_token: Optional[str] = None,
    results: Optional[List[Dict[str, Any]]] = None,
) -> ScanResult:
    """
    Scan a Firebase Storage URL for read/write permission vulnerabilities.

    Tests whether the file is publicly readable and optionally tests write
    access by uploading a probe file.

    Args:
        client: The HTTP client to use.
        url: The Firebase Storage file URL.
        semaphore: Concurrency limiter.
        exploit: Whether to test write access.
        id_token: Optional authentication token.
        results: Optional list to append results for JSON output.

    Returns:
        ScanResult containing the vulnerability assessment.
    """
    result = ScanResult(target=url, scan_type="storage")
    bucket, _ = parse_storage_url(url)
    last_status_code: Optional[int] = None

    try:
        async with semaphore:
            # Test READ access
            read_url = url.split("?")[0] + "?alt=media"
            response = await http_request_with_backoff(lambda: client.get(read_url))
            last_status_code = response.status_code
            result.can_read = response.status_code == 200

            # Test WRITE access if requested and bucket was parsed
            if exploit and bucket:
                try:
                    can_write, _ = await _test_storage_upload(client, bucket, id_token)
                    result.can_write = can_write
                finally:
                    if result.can_write:
                        await _delete_storage_probe(client, bucket, id_token)

    except httpx.RequestError as error:
        print_error(f"Critical error scanning {url}: {error}")

    # Print scan result
    status = result.format_status(last_status_code)
    print(f"{url} [{status}]")

    if results is not None:
        results.append(result.to_dict())

    return result


# -----------------------------------------------------------------------------
# Firestore Admin SDK Operations
# -----------------------------------------------------------------------------


def dump_firestore_admin(
    service_account_path: Path,
    project: str,
    output_path: Path,
) -> None:
    """
    Dump entire Firestore database using Admin SDK credentials.

    Uses a service account to bypass security rules and export all
    collections and documents recursively.

    Args:
        service_account_path: Path to the service account JSON file.
        project: Firebase project ID.
        output_path: Path to write the JSON dump.

    Raises:
        FireGunError: If the dump operation fails.
    """
    print_info("Initializing Admin SDK for Firestore dump...")

    try:
        from google.oauth2 import service_account

        credentials = service_account.Credentials.from_service_account_file(
            str(service_account_path)
        )
        client = firestore_admin.Client(project=project, credentials=credentials)

        result: Dict[str, Any] = {}

        def recurse_collection(collection, path: List[str]) -> None:
            """Recursively traverse collections and documents."""
            for document in collection.stream():
                document_path = "/".join(path + [document.id])
                result[document_path] = document.to_dict()

                # Process subcollections
                for subcollection in document.reference.collections():
                    recurse_collection(
                        subcollection,
                        path + [document.id, subcollection.id],
                    )

        # Start recursion from top-level collections
        for collection in client.collections():
            recurse_collection(collection, [collection.id])

        output_path.write_text(json.dumps(result, indent=2, default=str))
        print_success(f"Firestore admin dump written to {output_path}")

    except ImportError:
        raise FireGunError("google-auth package is required for admin operations")
    except FileNotFoundError:
        raise FireGunError(f"Service account file not found: {service_account_path}")
    except Exception as error:
        raise FireGunError(f"Firestore admin dump failed: {error}")


# -----------------------------------------------------------------------------
# Node.js Script Integration
# -----------------------------------------------------------------------------


def check_node_installed() -> bool:
    """
    Check if Node.js is installed and available.

    Returns:
        True if Node.js is available, False otherwise.
    """
    try:
        subprocess.run(
            ["node", "-v"],
            capture_output=True,
            check=True,
            text=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print_error("Node.js not found. Please install it to use this feature.")
        return False


def run_node_script(command: List[str]) -> None:
    """
    Execute a Node.js script with the given arguments.

    Args:
        command: Command list starting with "node" and script path.
    """
    if not check_node_installed():
        return

    try:
        print_info(f"Running Node.js script: {' '.join(command)}")
        subprocess.run(command, check=True, text=True)
    except subprocess.CalledProcessError as error:
        print_error(f"Script execution failed with exit code {error.returncode}")
    except FileNotFoundError:
        print_error("'node' command not found in PATH")


# -----------------------------------------------------------------------------
# Async Task Runners
# -----------------------------------------------------------------------------


async def run_scan(
    rtdb_targets: List[str],
    storage_targets: List[str],
    concurrency: int,
    exploit: bool,
    auth_token: Optional[str],
    readout: bool,
    json_mode: bool,
) -> None:
    """
    Execute concurrent scans on RTDB and Storage targets.

    Args:
        rtdb_targets: List of RTDB targets to scan.
        storage_targets: List of Storage URLs to scan.
        concurrency: Maximum concurrent scans.
        exploit: Whether to attempt exploit on vulnerable targets.
        auth_token: Optional authentication token.
        readout: Whether to print readable RTDB data.
        json_mode: Whether to output results as JSON.
    """
    async with create_http_client() as client:
        semaphore = asyncio.Semaphore(concurrency)
        results: List[Dict[str, Any]] = []

        tasks = []

        for target in rtdb_targets:
            tasks.append(
                scan_rtdb(client, target, semaphore, exploit, auth_token, readout, results)
            )

        for url in storage_targets:
            tasks.append(
                scan_storage(client, url, semaphore, exploit, auth_token, results)
            )

        if tasks:
            await asyncio.gather(*tasks)

        if json_mode:
            print(json.dumps(results, indent=2))


async def run_dump_rtdb(
    target: str,
    auth_token: Optional[str],
    output_path: Optional[Path],
) -> None:
    """
    Dump the entire contents of an RTDB to JSON.

    Args:
        target: The RTDB target URL.
        auth_token: Optional authentication token.
        output_path: Optional file path for output (prints to stdout if None).
    """
    async with create_http_client(timeout=60) as client:
        dump_url = build_rtdb_url(target, auth_token, additional_params={"format": "export"})

        response = await http_request_with_backoff(lambda: client.get(dump_url))
        response.raise_for_status()

        data = response.json()

        if output_path:
            output_path.write_text(json.dumps(data, indent=2))
            print_success(f"RTDB dump written to {output_path}")
        else:
            print(json.dumps(data, indent=2))


async def run_firestore_scan(
    projects: List[str],
    api_key: str,
    id_token: Optional[str],
    concurrency: int,
    exploit: bool,
    json_mode: bool,
) -> None:
    """
    Execute concurrent Firestore scans on multiple projects.

    Args:
        projects: List of Firebase project IDs.
        api_key: Firebase API key.
        id_token: Optional authentication token.
        concurrency: Maximum concurrent scans.
        exploit: Whether to test write access.
        json_mode: Whether to output results as JSON.
    """
    async with create_http_client() as client:
        semaphore = asyncio.Semaphore(concurrency)
        results: List[Dict[str, Any]] = []

        tasks = [
            scan_firestore(client, project, api_key, id_token, semaphore, exploit, results)
            for project in projects
        ]

        await asyncio.gather(*tasks)

        if json_mode:
            print(json.dumps(results, indent=2))


async def run_storage_scan(
    urls: List[str],
    concurrency: int,
    exploit: bool,
    id_token: Optional[str],
    json_mode: bool,
) -> None:
    """
    Execute concurrent Storage scans on multiple URLs.

    Args:
        urls: List of Firebase Storage URLs.
        concurrency: Maximum concurrent scans.
        exploit: Whether to test write access.
        id_token: Optional authentication token.
        json_mode: Whether to output results as JSON.
    """
    async with create_http_client(timeout=20) as client:
        semaphore = asyncio.Semaphore(concurrency)
        results: List[Dict[str, Any]] = []

        tasks = [
            scan_storage(client, url, semaphore, exploit, id_token, results)
            for url in urls
        ]

        await asyncio.gather(*tasks)

        if json_mode:
            print(json.dumps(results, indent=2))


# -----------------------------------------------------------------------------
# CLI Command Handlers
# -----------------------------------------------------------------------------


def handle_scan(args: argparse.Namespace) -> None:
    """
    Handle the 'scan' command for RTDB and Storage scanning.

    Args:
        args: Parsed command-line arguments.
    """
    try:
        auth_token = load_auth_token_from_config(args.config)
    except ConfigurationError as error:
        print_error(str(error))
        sys.exit(1)

    targets = resolve_targets(args.targets)

    if not targets:
        print_error("No valid targets found.")
        return

    # Separate RTDB and Storage targets
    rtdb_targets = [
        target for target in targets
        if "firebasestorage.googleapis.com" not in target
    ]
    storage_targets = [
        target for target in targets
        if "firebasestorage.googleapis.com" in target
    ]

    print_info(
        f"Starting scan on {len(rtdb_targets)} RTDB and "
        f"{len(storage_targets)} Storage targets..."
    )

    asyncio.run(
        run_scan(
            rtdb_targets,
            storage_targets,
            args.concurrency,
            args.exploit,
            auth_token,
            args.readout,
            args.json,
        )
    )


def handle_dump_rtdb(args: argparse.Namespace) -> None:
    """
    Handle the 'dump-rtdb' command for exporting RTDB data.

    Args:
        args: Parsed command-line arguments.
    """
    try:
        auth_token = load_auth_token_from_config(args.config)
    except ConfigurationError as error:
        print_error(str(error))
        sys.exit(1)

    targets = resolve_targets([args.target])

    if not targets:
        print_error(f"Could not resolve target: {args.target}")
        sys.exit(1)

    try:
        asyncio.run(run_dump_rtdb(targets[0], auth_token, args.output))
    except (httpx.RequestError, json.JSONDecodeError, ConnectionError) as error:
        print_error(f"Failed to dump RTDB: {error}")
        sys.exit(1)


def handle_firestore_scan(args: argparse.Namespace) -> None:
    """
    Handle the 'fs-scan' command for Firestore scanning.

    Args:
        args: Parsed command-line arguments.
    """
    try:
        api_key = require_api_key(args)
    except ConfigurationError as error:
        print_error(str(error))
        sys.exit(1)

    id_token = get_id_token(args)
    projects = resolve_targets(args.projects)

    print_info(f"Scanning {len(projects)} Firestore project(s)...")

    asyncio.run(
        run_firestore_scan(
            projects,
            api_key,
            id_token,
            args.concurrency,
            args.exploit,
            args.json,
        )
    )


def handle_storage_scan(args: argparse.Namespace) -> None:
    """
    Handle the 'storage-scan' command for Storage scanning.

    Args:
        args: Parsed command-line arguments.
    """
    urls = resolve_targets(args.urls)

    if not urls:
        print_error("No valid storage URLs found.")
        return

    id_token = get_id_token(args)

    print_info(f"Scanning {len(urls)} Storage URL(s)...")

    asyncio.run(
        run_storage_scan(
            urls,
            args.concurrency,
            args.exploit,
            id_token,
            args.json,
        )
    )


def handle_auth(args: argparse.Namespace) -> None:
    """
    Handle the 'signup' and 'signin' authentication commands.

    Args:
        args: Parsed command-line arguments.
    """
    try:
        api_key = require_api_key(args)
    except ConfigurationError as error:
        print_error(str(error))
        sys.exit(1)

    password = args.password

    if not password:
        try:
            password = getpass.getpass(f"Enter password for {args.email}: ")
        except (EOFError, KeyboardInterrupt):
            print("\n")
            print_error("Aborted.")
            sys.exit(1)

    if args.cmd == "signup":
        asyncio.run(signup_user(api_key, args.email, password))
    elif args.cmd == "signin":
        token = asyncio.run(signin_user(api_key, args.email, password))
        if token:
            print("\n[SUCCESS] Authentication successful.")
            print(f"idToken: {token}")


def handle_admin_dump_firestore(args: argparse.Namespace) -> None:
    """
    Handle the 'admin-dump-fs' command for Admin SDK Firestore dump.

    Args:
        args: Parsed command-line arguments.
    """
    service_account_path = args.service_account or os.getenv(
        "GOOGLE_APPLICATION_CREDENTIALS"
    )

    if not service_account_path:
        print_error(
            "Service account path is required. "
            "Use --service-account or set GOOGLE_APPLICATION_CREDENTIALS."
        )
        sys.exit(1)

    try:
        dump_firestore_admin(Path(service_account_path), args.project, args.output)
    except FireGunError as error:
        print_error(str(error))
        sys.exit(1)


def handle_fuzz_rules(args: argparse.Namespace) -> None:
    """
    Handle the 'fuzz-rules' command for Firestore rules fuzzing.

    Args:
        args: Parsed command-line arguments.
    """
    try:
        api_key = require_api_key(args)
    except ConfigurationError as error:
        print_error(str(error))
        sys.exit(1)

    id_token = args.id_token or os.getenv("FIREBASE_ID_TOKEN")

    command = [
        "node",
        str(args.script),
        "--project", args.project,
        "--apiKey", api_key,
        "--rules", str(args.rules),
    ]

    if id_token:
        command.extend(["--token", id_token])

    run_node_script(command)


def handle_run_script(args: argparse.Namespace) -> None:
    """
    Handle the 'script' command for running custom JS scripts.

    Args:
        args: Parsed command-line arguments.
    """
    token = args.token or os.getenv("FIREBASE_ID_TOKEN")

    command = ["node", str(args.path), args.target]

    if token:
        command.append(token)

    run_node_script(command)


# -----------------------------------------------------------------------------
# CLI Argument Parser Setup
# -----------------------------------------------------------------------------


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create and configure the CLI argument parser.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="firegun",
        description="FireGun CLI – Firebase pentest & vulnerability scanner",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    subparsers = parser.add_subparsers(
        dest="cmd",
        required=True,
        help="Available commands",
    )

    # --- scan command ---
    _add_scan_parser(subparsers)

    # --- dump-rtdb command ---
    _add_dump_rtdb_parser(subparsers)

    # --- fs-scan command ---
    _add_firestore_scan_parser(subparsers)

    # --- storage-scan command ---
    _add_storage_scan_parser(subparsers)

    # --- admin-dump-fs command ---
    _add_admin_dump_parser(subparsers)

    # --- fuzz-rules command ---
    _add_fuzz_rules_parser(subparsers)

    # --- script command ---
    _add_script_parser(subparsers)

    # --- signup command ---
    _add_signup_parser(subparsers)

    # --- signin command ---
    _add_signin_parser(subparsers)

    return parser


def _add_scan_parser(subparsers) -> None:
    """Add the 'scan' subcommand parser."""
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan RTDB or Storage URLs for open permissions",
    )
    scan_parser.add_argument(
        "targets",
        nargs="+",
        help="One or more hosts, URLs, or files containing targets",
    )
    scan_parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help=f"Number of concurrent scans (default: {DEFAULT_CONCURRENCY})",
    )
    scan_parser.add_argument(
        "-e", "--exploit",
        action="store_true",
        help="Attempt to write a non-destructive warning to vulnerable targets",
    )
    scan_parser.add_argument(
        "-r", "--readout",
        action="store_true",
        help="Print readable data from vulnerable RTDBs",
    )
    scan_parser.add_argument(
        "--config",
        type=Path,
        help="JSON config file with idToken or auth token",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON results to stdout",
    )
    scan_parser.set_defaults(func=handle_scan)


def _add_dump_rtdb_parser(subparsers) -> None:
    """Add the 'dump-rtdb' subcommand parser."""
    dump_parser = subparsers.add_parser(
        "dump-rtdb",
        help="Deep dump an entire RTDB to a JSON file",
    )
    dump_parser.add_argument(
        "target",
        help="A single host, URL, or file containing one",
    )
    dump_parser.add_argument(
        "--output",
        type=Path,
        help="Output file path for the dump (prints to console if omitted)",
    )
    dump_parser.add_argument(
        "--config",
        type=Path,
        help="JSON config file with idToken or auth token",
    )
    dump_parser.set_defaults(func=handle_dump_rtdb)


def _add_firestore_scan_parser(subparsers) -> None:
    """Add the 'fs-scan' subcommand parser."""
    fs_parser = subparsers.add_parser(
        "fs-scan",
        help="Test client-side Firestore access",
    )
    fs_parser.add_argument(
        "projects",
        nargs="+",
        help="One or more Firebase project IDs (or file containing them)",
    )
    fs_parser.add_argument(
        "--api-key",
        help="Firebase project API key (or use FIREBASE_API_KEY env var)",
    )
    fs_parser.add_argument(
        "--id-token",
        help="Auth token for scans (or use FIREBASE_ID_TOKEN env var)",
    )
    fs_parser.add_argument(
        "--config",
        type=Path,
        help="JSON config file with idToken (lower priority than --id-token/env var)",
    )
    fs_parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=5,
        help="Number of concurrent scans (default: 5)",
    )
    fs_parser.add_argument(
        "--exploit",
        action="store_true",
        help="Attempt to write to vulnerable collections",
    )
    fs_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON results to stdout",
    )
    fs_parser.set_defaults(func=handle_firestore_scan)


def _add_storage_scan_parser(subparsers) -> None:
    """Add the 'storage-scan' subcommand parser."""
    storage_parser = subparsers.add_parser(
        "storage-scan",
        help="Firebase Storage file read/write test",
    )
    storage_parser.add_argument(
        "urls",
        nargs="+",
        help="Full HTTPS URLs to files or files containing URLs",
    )
    storage_parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=5,
        help="Number of concurrent scans (default: 5)",
    )
    storage_parser.add_argument(
        "--exploit",
        action="store_true",
        help="Try a dummy upload to probe WRITE access",
    )
    storage_parser.add_argument(
        "--id-token",
        help="Optional Firebase ID token for authenticated checks",
    )
    storage_parser.add_argument(
        "--config",
        type=Path,
        help="JSON config file with idToken or auth token",
    )
    storage_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON results to stdout",
    )
    storage_parser.set_defaults(func=handle_storage_scan)


def _add_admin_dump_parser(subparsers) -> None:
    """Add the 'admin-dump-fs' subcommand parser."""
    admin_parser = subparsers.add_parser(
        "admin-dump-fs",
        help="Dump Firestore using Admin SDK (bypasses rules)",
    )
    admin_parser.add_argument(
        "--service-account",
        help="Path to service account JSON file (or use GOOGLE_APPLICATION_CREDENTIALS)",
    )
    admin_parser.add_argument(
        "project",
        help="Firebase project ID",
    )
    admin_parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output file for the dump",
    )
    admin_parser.set_defaults(func=handle_admin_dump_firestore)


def _add_fuzz_rules_parser(subparsers) -> None:
    """Add the 'fuzz-rules' subcommand parser."""
    fuzz_parser = subparsers.add_parser(
        "fuzz-rules",
        help="Fuzz Firestore rules with a JS script",
    )
    fuzz_parser.add_argument(
        "rules",
        type=Path,
        help="Path to firestore.rules file",
    )
    fuzz_parser.add_argument(
        "project",
        help="Firebase project ID",
    )
    fuzz_parser.add_argument(
        "script",
        type=Path,
        help="Path to the fuzzer JS script",
    )
    fuzz_parser.add_argument(
        "--api-key",
        help="Firebase project API key (or use FIREBASE_API_KEY env var)",
    )
    fuzz_parser.add_argument(
        "--id-token",
        help="Optional auth token (or use FIREBASE_ID_TOKEN env var)",
    )
    fuzz_parser.set_defaults(func=handle_fuzz_rules)


def _add_script_parser(subparsers) -> None:
    """Add the 'script' subcommand parser."""
    script_parser = subparsers.add_parser(
        "script",
        help="Run a custom JS pentesting script",
    )
    script_parser.add_argument(
        "path",
        type=Path,
        help="Path to the JS script",
    )
    script_parser.add_argument(
        "target",
        help="Target URL or identifier for the script",
    )
    script_parser.add_argument(
        "--token",
        help="Optional auth token for the script",
    )
    script_parser.set_defaults(func=handle_run_script)


def _add_signup_parser(subparsers) -> None:
    """Add the 'signup' subcommand parser."""
    signup_parser = subparsers.add_parser(
        "signup",
        help="Sign up a new user with email/password",
    )
    signup_parser.add_argument(
        "--api-key",
        help="Firebase API Key (or use FIREBASE_API_KEY env var)",
    )
    signup_parser.add_argument(
        "email",
        help="The user's email address",
    )
    signup_parser.add_argument(
        "password",
        nargs="?",
        help="The user's password (if omitted, will be prompted securely)",
    )
    signup_parser.set_defaults(func=handle_auth)


def _add_signin_parser(subparsers) -> None:
    """Add the 'signin' subcommand parser."""
    signin_parser = subparsers.add_parser(
        "signin",
        help="Sign in a user with email/password",
    )
    signin_parser.add_argument(
        "--api-key",
        help="Firebase API Key (or use FIREBASE_API_KEY env var)",
    )
    signin_parser.add_argument(
        "email",
        help="The user's email address",
    )
    signin_parser.add_argument(
        "password",
        nargs="?",
        help="The user's password (if omitted, will be prompted securely)",
    )
    signin_parser.set_defaults(func=handle_auth)


# -----------------------------------------------------------------------------
# Main Entry Point
# -----------------------------------------------------------------------------


def main() -> None:
    """Main entry point for the FireGun CLI."""
    print_banner()

    parser = create_argument_parser()
    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
