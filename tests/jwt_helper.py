#!/usr/bin/env python3
"""ES256 keys and JWTs with only the standard library and `openssl` (no PyJWT, no cryptography), so that the tests run on a plain CI machine.

  jwt_helper.py genkey <kid> <private.pem> <jwk-private.json> <jwk-public.json>
  jwt_helper.py sign <private.pem> <kid> <claims-json>            prints the JWT
  jwt_helper.py verify <jwks.json | jwk.json> <token>              exit 0 if a key in it verifies the signature (and prints the header and claims)
  jwt_helper.py decode <token>                                     prints the header and claims (no check)
"""
import base64
import json
import re
import subprocess
import sys
import tempfile
import os


def b64e(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def openssl(*args, stdin=None):
    result = subprocess.run(["openssl", *args], input=stdin, capture_output=True)
    if result.returncode != 0:
        raise SystemExit("openssl " + " ".join(args) + " failed: " + result.stderr.decode(errors="replace"))
    return result.stdout


def genkey(kid, private_pem, jwk_private, jwk_public):
    """A P-256 key: the PEM for signing, and the JWK of Auth's GOTRUE_JWT_KEYS (private) and the public one (verify only)."""
    openssl("ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", private_pem)
    text = openssl("ec", "-in", private_pem, "-text", "-noout").decode()

    def block(label, following):
        match = re.search(label + r":\s*((?:[0-9a-f]{2}:?\s*)+?)\s*" + following, text, re.S)
        return bytes.fromhex(re.sub(r"[^0-9a-f]", "", match.group(1)))

    private = block("priv", "pub:").lstrip(b"\x00").rjust(32, b"\x00")
    public = block("pub", "ASN1 OID")
    assert public[0] == 4 and len(public) == 65, "an uncompressed P-256 point"
    base = {"kty": "EC", "crv": "P-256", "alg": "ES256", "kid": kid, "use": "sig", "x": b64e(public[1:33]), "y": b64e(public[33:65])}
    with open(jwk_private, "w") as handle:
        json.dump({**base, "key_ops": ["sign", "verify"], "d": b64e(private)}, handle)
    with open(jwk_public, "w") as handle:
        json.dump({**base, "key_ops": ["verify"]}, handle)


def der_to_raw(der):
    """An ECDSA signature as DER (what openssl makes) to the 64 bytes R||S of a JWT."""
    assert der[0] == 0x30
    pos = 2 if der[1] < 0x80 else 2 + (der[1] & 0x7F)
    parts = []
    for _ in range(2):
        assert der[pos] == 0x02
        length = der[pos + 1]
        parts.append(der[pos + 2:pos + 2 + length].lstrip(b"\x00").rjust(32, b"\x00"))
        pos += 2 + length
    return parts[0] + parts[1]


def raw_to_der(raw):
    def integer(value):
        value = value.lstrip(b"\x00") or b"\x00"
        if value[0] & 0x80:
            value = b"\x00" + value
        return b"\x02" + bytes([len(value)]) + value
    body = integer(raw[:32]) + integer(raw[32:])
    return b"\x30" + bytes([len(body)]) + body


def sign(private_pem, kid, claims):
    header = b64e(json.dumps({"alg": "ES256", "typ": "JWT", "kid": kid}, separators=(",", ":")).encode())
    payload = b64e(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    der = openssl("dgst", "-sha256", "-sign", private_pem, stdin=signing_input)
    return f"{header}.{payload}.{b64e(der_to_raw(der))}"


SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")


def verify_with_jwk(jwk, token):
    header, payload, signature = token.split(".")
    point = b"\x04" + b64d(jwk["x"]) + b64d(jwk["y"])
    pem = "-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(SPKI_PREFIX + point).decode() + "\n-----END PUBLIC KEY-----\n"
    with tempfile.TemporaryDirectory() as directory:
        key_path, sig_path = os.path.join(directory, "key.pem"), os.path.join(directory, "sig.der")
        with open(key_path, "w") as handle:
            handle.write(pem)
        with open(sig_path, "wb") as handle:
            handle.write(raw_to_der(b64d(signature)))
        result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", key_path, "-signature", sig_path], input=f"{header}.{payload}".encode(), capture_output=True)
    return result.returncode == 0


def decode(token):
    header, payload, _ = token.split(".")
    return json.loads(b64d(header)), json.loads(b64d(payload))


def main(argv):
    command = argv[1]
    if command == "genkey":
        genkey(*argv[2:6])
    elif command == "sign":
        print(sign(argv[2], argv[3], json.loads(argv[4])))
    elif command == "verify":
        with open(argv[2]) as handle:
            document = json.load(handle)
        keys = document["keys"] if isinstance(document, dict) and "keys" in document else [document]
        token = argv[3]
        header, claims = decode(token)
        matching = [key for key in keys if key.get("kid") == header.get("kid")]
        if not matching or not any(verify_with_jwk(key, token) for key in matching):
            sys.exit(1)
        print(json.dumps({"header": header, "claims": claims}))
    elif command == "decode":
        header, claims = decode(argv[2])
        print(json.dumps({"header": header, "claims": claims}))
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
