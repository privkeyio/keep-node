#!/usr/bin/env python3
# Minimal headless Bitwarden/Vaultwarden client for the M0 test: register an account, store a
# login item, read it back -- implementing just enough of the client-side crypto to prove the vault
# is functionally usable (no browser, no bw/rbw agent). Stateless across invocations: every command
# re-derives the account keys from the email+password, so `read` works after a reboot with no saved
# state. Crypto per the Bitwarden spec: PBKDF2-SHA256 master key + password hash; HKDF-Expand to
# stretch the master key; AES-256-CBC + HMAC-SHA256 EncString (type 2) for the protected keys/ciphers.
import base64, json, os, sys, urllib.request, urllib.error, uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

KDF_ITERATIONS = 600000
b64 = lambda b: base64.b64encode(b).decode()
ub64 = lambda s: base64.b64decode(s)


def pbkdf2(password, salt, iterations, length=32):
    return PBKDF2HMAC(hashes.SHA256(), length, salt, iterations).derive(password)


def master_key(password, email):
    return pbkdf2(password.encode(), email.lower().encode(), KDF_ITERATIONS)


def password_hash(mk, password):
    return b64(pbkdf2(mk, password.encode(), 1))


def stretch(mk):
    enc = HKDFExpand(hashes.SHA256(), 32, b"enc").derive(mk)
    mac = HKDFExpand(hashes.SHA256(), 32, b"mac").derive(mk)
    return enc, mac


def enc_string(data, enc_key, mac_key):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(iv + ct)
    mac = h.finalize()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"


def dec_string(s, enc_key, mac_key):
    _, rest = s.split(".", 1)
    iv, ct, mac = (ub64(p) for p in rest.split("|"))
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(iv + ct)
    h.verify(mac)
    decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(pt) + unpadder.finalize()


def api(base, path, data=None, token=None, form=False):
    url = base + path
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if form:
        body = "&".join(f"{k}={urllib.request.quote(str(v))}" for k, v in data.items()).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    else:
        body = None
    req = urllib.request.Request(url, data=body, headers=headers, method="POST" if body else "GET")
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        sys.exit(f"HTTP {e.code} {path}: {e.read().decode(errors='replace')}")


def register(base, email, password, name):
    mk = master_key(password, email)
    enc_key, mac_key = stretch(mk)
    user_key = os.urandom(64)  # 32 enc + 32 mac
    protected_key = enc_string(user_key, enc_key, mac_key)
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_der = rsa_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    priv_der = rsa_key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    enc_priv = enc_string(priv_der, user_key[:32], user_key[32:])
    api(base, "/identity/accounts/register", {
        "email": email, "name": name,
        "masterPasswordHash": password_hash(mk, password),
        "masterPasswordHint": "",
        "key": protected_key,
        "kdf": 0, "kdfIterations": KDF_ITERATIONS,
        "keys": {"publicKey": b64(pub_der), "encryptedPrivateKey": enc_priv},
    })
    print("registered")


def login(base, email, password):
    mk = master_key(password, email)
    tok = api(base, "/identity/connect/token", data={
        "grant_type": "password", "username": email, "password": password_hash(mk, password),
        "scope": "api offline_access", "client_id": "cli",
        "deviceType": 14, "deviceIdentifier": str(uuid.uuid4()), "deviceName": "m0-test",
    }, form=True)
    enc_key, mac_key = stretch(mk)
    user_key = dec_string(tok.get("Key") or tok.get("key"), enc_key, mac_key)
    return tok["access_token"], user_key


def store(base, email, password, name, value):
    token, user_key = login(base, email, password)
    uk_enc, uk_mac = user_key[:32], user_key[32:]
    api(base, "/api/ciphers", {
        "type": 1,
        "name": enc_string(name.encode(), uk_enc, uk_mac),
        "login": {"password": enc_string(value.encode(), uk_enc, uk_mac)},
    }, token=token)
    print("stored")


def read(base, email, password, name):
    token, user_key = login(base, email, password)
    uk_enc, uk_mac = user_key[:32], user_key[32:]
    sync = api(base, "/api/sync", token=token)
    for c in sync.get("Ciphers", sync.get("ciphers", [])):
        cname = c.get("Name", c.get("name"))
        if not cname:
            continue
        try:
            if dec_string(cname, uk_enc, uk_mac).decode() != name:
                continue
        except (InvalidSignature, ValueError, UnicodeDecodeError):
            continue
        login_obj = c.get("Login", c.get("login"))
        pw = login_obj.get("Password", login_obj.get("password")) if login_obj else None
        if pw is None:
            continue
        print(dec_string(pw, uk_enc, uk_mac).decode())
        return
    sys.exit(f"item {name!r} not found in vault")


if __name__ == "__main__":
    # Secrets come from the environment (VW_PASSWORD, and VW_VALUE for store), not argv, so they
    # don't leak via /proc/<pid>/cmdline or CI logs.
    if len(sys.argv) != 5 or sys.argv[1] not in ("register", "store", "read"):
        sys.exit("usage: VW_PASSWORD=... [VW_VALUE=...] vw-client (register|store|read) BASE EMAIL NAME")
    cmd, base, email, name = sys.argv[1], sys.argv[2].rstrip("/"), sys.argv[3], sys.argv[4]
    password = os.environ.get("VW_PASSWORD")
    if not password:
        sys.exit("VW_PASSWORD must be set in the environment")
    if cmd == "register":
        register(base, email, password, name)
    elif cmd == "read":
        read(base, email, password, name)
    else:
        value = os.environ.get("VW_VALUE")
        if not value:
            sys.exit("VW_VALUE must be set in the environment for store")
        store(base, email, password, name, value)
