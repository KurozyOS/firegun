# FireGun CLI

**FireGun** is a Python 3.13 CLI tool for pentesting Firebase projects. It provides:

* **Realtime Database (RTDB)** scanning:

  * Read access checks
  * Takeover (write) testing with customizable exploit payload
  * Optional authenticated scans via `idToken` or `auth` in config
  * Deep JSON dump of entire RTDB tree
  * `--readout` flag to print DB contents on read access
* **Firestore** scanning (client‑side via REST API):

  * Read access checks
  * Takeover testing by writing a probe document
  * Nested enumeration of collections and sample documents
* **Firestore Admin SDK** export:

  * Full recursive dump of collections & documents, bypassing security rules
* **Security Rules fuzzing**:

  * Hook into external JavaScript scripts for dynamic rule testing
* **Custom script runner**:

  * Execute any JS extension via `script` subcommand
* **Authentication helpers**:

  * `signup` and `signin` with Firebase Identity Toolkit REST API

---

## Installation

1. Clone this repo or download `firegun.py` into your PATH.
2. Create a virtual environment and install dependencies:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install httpx requests firebase-admin google-cloud-firestore
   ```
3. Make executable:

   ```bash
   chmod +x firegun.py
   ```

---

## Usage

Run `./firegun.py -h` to see top‑level commands:

```bash
$ ./firegun.py -h
usage: firegun.py [-h] {scan,dump-rtdb,fs-scan,admin-dump-fs,fuzz-rules,script,signup,signin} ...

FireGun CLI

positional arguments:
  {scan,dump-rtdb,fs-scan,admin-dump-fs,fuzz-rules,script,signup,signin}
    scan            RTDB scan
    dump-rtdb       Deep RTDB JSON dump
    fs-scan         Client-side Firestore tests
    admin-dump-fs   Admin SDK Firestore dump
    fuzz-rules      Fuzz Firestore Security Rules
    script          Run custom JS extension
    signup          Email/password sign-up
    signin          Email/password sign-in

optional arguments:
  -h, --help       show this help message and exit
```

### 1. Scan Realtime Database

```bash
# Unauthenticated read/write test
./firegun.py scan your-db.firebaseio.com

# Authenticated test (load idToken from config.json)
./firegun.py scan your-db.firebaseio.com --config config.json

# Attempt takeover exploit + verify write
./firegun.py scan your-db.firebaseio.com --exploit

# Print DB data on read access
./firegun.py scan your-db.firebaseio.com --readout

# Combine all flags
./firegun.py scan your-db.firebaseio.com --config config.json --exploit --readout
```

> **config.json** example:
>
> ```json
> {
>   "idToken": "<FIREBASE_ID_TOKEN>"
> }
> ```

### 2. Dump Entire RTDB

```bash
./firegun.py dump-rtdb your-db.firebaseio.com --output rtdb_dump.json
```

### 3. Firestore Client Tests

```bash
./firegun.py fs-scan my-project --api-key YOUR_API_KEY
./firegun.py fs-scan my-project --api-key YOUR_API_KEY --exploit
```

### 4. Firestore Admin Export

```bash
./firegun.py admin-dump-fs --service-account service-account.json my-project --output fs_dump.json
```

### 5. Fuzz Security Rules

```bash
./firegun.py fuzz-rules firestore.rules my-project --api-key YOUR_API_KEY --script fuzz.js
```

### 6. Custom JS Extensions

```bash
./firegun.py script my_custom.js https://your-db.firebaseio.com
```

### 7. Authentication Helpers

```bash
# Sign up new user
./firegun.py signup --api-key YOUR_API_KEY user@example.com password123

# Sign in existing user
./firegun.py signin --api-key YOUR_API_KEY user@example.com password123
```

---

## ToDo List
- [ ] Finish the Scan Realtime Database with authentication
- [ ] Complete the Firestore Admin Export Module
- [ ] Complete the Fuzz Security Rules Module
- [ ] Complete the Custom JS Extensions Module
- [ ] Complete the Authentication Helpers Module

## License

GNUv3 © Marko Zivan (kurozy)

