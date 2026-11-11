#!/usr/bin/env python3
"""Generates TEST-ONLY certificates and private keys for the C2PA verifier tests.

Never use anything in test/certs for a real purpose: the private keys are published in this repo.
Re-run with:  python3 test/make-certs.py
"""
import datetime as dt
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
os.makedirs(OUT, exist_ok=True)
UTC = dt.timezone.utc
DOC_SIGNING = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.36")


def name(cn, org="Image Check Tests"):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def pem_cert(c):
    return c.public_bytes(serialization.Encoding.PEM)


def pem_key(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())


def write(fname, data):
    with open(os.path.join(OUT, fname), "wb") as f:
        f.write(data)


def make_ca(cn, key, **sign_kw):
    pub = key.public_key()
    return (x509.CertificateBuilder()
            .subject_name(name(cn)).issuer_name(name(cn)).public_key(pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime(2024, 1, 1, tzinfo=UTC))
            .not_valid_after(dt.datetime(2044, 1, 1, tzinfo=UTC))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=True, crl_sign=True,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
            .sign(key, hashes.SHA256(), **sign_kw))


def make_intermediate(cn, key, issuer_cert, issuer_key, key_cert_sign=True, path_len=None):
    pub = key.public_key()
    return (x509.CertificateBuilder()
            .subject_name(name(cn)).issuer_name(issuer_cert.subject).public_key(pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime(2024, 1, 1, tzinfo=UTC))
            .not_valid_after(dt.datetime(2040, 1, 1, tzinfo=UTC))
            .add_extension(x509.BasicConstraints(ca=True, path_length=path_len), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=key_cert_sign, crl_sign=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
            .sign(issuer_key, hashes.SHA256()))


DEFAULT_EKU = (ExtendedKeyUsageOID.EMAIL_PROTECTION, DOC_SIGNING)


def make_leaf(cn, leaf_key, issuer_cert, issuer_key, nb, na, self_signed=False, is_ca=False, can_sign=True,
              eku=DEFAULT_EKU, extra_ext=None, **sign_kw):
    pub = leaf_key.public_key()
    b = (x509.CertificateBuilder()
         .subject_name(name(cn, org="Example Newsroom"))
         .issuer_name(name(cn, org="Example Newsroom") if self_signed else issuer_cert.subject)
         .public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(nb).not_valid_after(na)
         .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=can_sign, content_commitment=False,
                                      key_encipherment=not can_sign, data_encipherment=False,
                                      key_agreement=False, key_cert_sign=False, crl_sign=False,
                                      encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False))
    if eku is not None:  # None = certificate without any extended key usage
        b = b.add_extension(x509.ExtendedKeyUsage(list(eku)), critical=False)
    if extra_ext is not None:
        b = b.add_extension(extra_ext, critical=True)
    if not self_signed:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
                            critical=False)
    return b.sign(leaf_key if self_signed else issuer_key, hashes.SHA256(), **sign_kw)


GOOD = (dt.datetime(2025, 1, 1, tzinfo=UTC), dt.datetime(2035, 1, 1, tzinfo=UTC))
OLD = (dt.datetime(2019, 1, 1, tzinfo=UTC), dt.datetime(2020, 1, 1, tzinfo=UTC))

# --- certificate authorities
ca_key = ec.generate_private_key(ec.SECP256R1())
ca = make_ca("Test C2PA Root CA", ca_key)
rogue_key = ec.generate_private_key(ec.SECP256R1())
rogue_ca = make_ca("Rogue Root CA", rogue_key)
rsa_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rsa_ca = make_ca("Test RSA Root CA (PKCS1)", rsa_ca_key)
pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
rsa_pss_ca = make_ca("Test RSA Root CA (PSS)", rsa_ca_key, rsa_padding=pss)
write("ca.pem", pem_cert(ca))
write("rogue-ca.pem", pem_cert(rogue_ca))
write("rsa-ca.pem", pem_cert(rsa_ca))
write("rsa-pss-ca.pem", pem_cert(rsa_pss_ca))


def emit(label, leaf_key, leaf_cert, issuer_cert=None):
    write(f"{label}.key.pem", pem_key(leaf_key))
    chain = pem_cert(leaf_cert) + (pem_cert(issuer_cert) if issuer_cert else b"")
    write(f"{label}.chain.pem", chain)


k = ec.generate_private_key(ec.SECP256R1())
emit("es256", k, make_leaf("Test Signer ES256", k, ca, ca_key, *GOOD), ca)
k = ec.generate_private_key(ec.SECP384R1())
emit("es384", k, make_leaf("Test Signer ES384", k, ca, ca_key, *GOOD), ca)
k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
emit("ps256", k, make_leaf("Test Signer PS256", k, ca, ca_key, *GOOD), ca)
k = ed25519.Ed25519PrivateKey.generate()
emit("ed25519", k, make_leaf("Test Signer Ed25519", k, ca, ca_key, *GOOD), ca)
k = ec.generate_private_key(ec.SECP256R1())
emit("expired", k, make_leaf("Test Signer Expired", k, ca, ca_key, *OLD), ca)
k = ec.generate_private_key(ec.SECP256R1())
emit("rogue", k, make_leaf("Rogue Signer", k, rogue_ca, rogue_key, *GOOD), rogue_ca)
k = ec.generate_private_key(ec.SECP256R1())
emit("selfsigned", k, make_leaf("Self Signed Signer", k, None, None, *GOOD, self_signed=True))
k = ec.generate_private_key(ec.SECP256R1())
emit("viarsa", k, make_leaf("Signer via RSA PKCS1 CA", k, rsa_ca, rsa_ca_key, *GOOD), rsa_ca)
k = ec.generate_private_key(ec.SECP256R1())
emit("viapss", k, make_leaf("Signer via RSA PSS CA", k, rsa_pss_ca, rsa_ca_key, *GOOD, rsa_padding=pss),
     rsa_pss_ca)
k = ec.generate_private_key(ec.SECP256R1())
emit("leafca", k, make_leaf("CA Used As Signer", k, ca, ca_key, *GOOD, is_ca=True), ca)
k = ec.generate_private_key(ec.SECP256R1())
emit("noksig", k, make_leaf("No Signature Usage", k, ca, ca_key, *GOOD, can_sign=False), ca)
# --- wrong-purpose certificates issued by a TRUSTED authority (regression tests for review findings)
def emit_chain(label, leaf_key, certs):
    write(f"{label}.key.pem", pem_key(leaf_key))
    write(f"{label}.chain.pem", b"".join(pem_cert(c) for c in certs))


k = ec.generate_private_key(ec.SECP256R1())
leaf = make_leaf("No Key Purpose", k, ca, ca_key, *GOOD, eku=None)
emit_chain("noeku", k, [leaf, ca])
k = ec.generate_private_key(ec.SECP256R1())
leaf = make_leaf("Web Server Only", k, ca, ca_key, *GOOD, eku=(ExtendedKeyUsageOID.SERVER_AUTH,))
emit_chain("serverauth", k, [leaf, ca])
inter_key = ec.generate_private_key(ec.SECP256R1())
inter = make_intermediate("Intermediate Without CertSign", inter_key, ca, ca_key, key_cert_sign=False)
k = ec.generate_private_key(ec.SECP256R1())
leaf = make_leaf("Signer Under Bad Intermediate", k, inter, inter_key, *GOOD)
emit_chain("nokcs", k, [leaf, inter, ca])
inter1_key = ec.generate_private_key(ec.SECP256R1())
inter1 = make_intermediate("Intermediate PathLen 0", inter1_key, ca, ca_key, path_len=0)
inter2_key = ec.generate_private_key(ec.SECP256R1())
inter2 = make_intermediate("Sub Intermediate", inter2_key, inter1, inter1_key)
k = ec.generate_private_key(ec.SECP256R1())
leaf = make_leaf("Signer Beyond PathLen", k, inter2, inter2_key, *GOOD)
emit_chain("pl0", k, [leaf, inter2, inter1, ca])
k = ec.generate_private_key(ec.SECP256R1())
leaf = make_leaf("Bidi \u202e\u2066Signer\u200b", k, ca, ca_key, *GOOD)
emit_chain("bidi", k, [leaf, ca])
k = ec.generate_private_key(ec.SECP256R1())
leaf = make_leaf("Unknown Critical Extension", k, ca, ca_key, *GOOD,
                 extra_ext=x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4.5"), b"\x05\x00"))
emit_chain("critext", k, [leaf, ca])
print("wrote", len(os.listdir(OUT)), "files to", OUT)
