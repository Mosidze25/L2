#!/usr/bin/env python3
import os
import ssl
import socket
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asy_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding


BASE_DIR = Path(__file__).resolve().parent
OUT_DIR = BASE_DIR / "outputs"
OUT_DIR.mkdir(exist_ok=True)

MESSAGE_FILE = BASE_DIR / "message.txt"
RSA_VS_AES_REPORT = BASE_DIR / "rsa_vs_aes.txt"
TLS_REPORT = BASE_DIR / "tls_report.txt"


# ---------- Utility ----------
def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_bytes(p: Path, data: bytes) -> None:
    p.write_bytes(data)

def write_text(p: Path, text: str) -> None:
    p.write_text(text, encoding="utf-8")

def read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8")

def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------- Task 1: RSA ----------
@dataclass
class RSAArtifacts:
    private_key_pem: Path
    public_key_pem: Path
    encrypted_bin: Path
    decrypted_txt: Path

def generate_rsa_keys(bits: int = 2048) -> RSAArtifacts:
    priv_path = OUT_DIR / "rsa_private.pem"
    pub_path = OUT_DIR / "rsa_public.pem"

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),  # keep simple for lab
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    write_bytes(priv_path, priv_pem)
    write_bytes(pub_path, pub_pem)

    return RSAArtifacts(
        private_key_pem=priv_path,
        public_key_pem=pub_path,
        encrypted_bin=OUT_DIR / "rsa_encrypted.bin",
        decrypted_txt=OUT_DIR / "rsa_decrypted.txt",
    )

def rsa_encrypt_file(pub_pem_path: Path, plaintext_path: Path, out_path: Path) -> None:
    public_key = serialization.load_pem_public_key(read_bytes(pub_pem_path))
    plaintext = read_bytes(plaintext_path)

    # RSA is not for large data; this lab uses a small message file.
    ciphertext = public_key.encrypt(
        plaintext,
        asy_padding.OAEP(
            mgf=asy_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    write_bytes(out_path, ciphertext)

def rsa_decrypt_file(priv_pem_path: Path, ciphertext_path: Path, out_path: Path) -> None:
    private_key = serialization.load_pem_private_key(read_bytes(priv_pem_path), password=None)
    ciphertext = read_bytes(ciphertext_path)

    plaintext = private_key.decrypt(
        ciphertext,
        asy_padding.OAEP(
            mgf=asy_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    write_bytes(out_path, plaintext)


# ---------- Task 1: AES ----------
@dataclass
class AESArtifacts:
    key_path: Path
    iv_path: Path
    encrypted_bin: Path
    decrypted_txt: Path

def generate_aes_key_iv() -> AESArtifacts:
    key = os.urandom(32)   # AES-256 key
    iv = os.urandom(16)    # CBC IV is 16 bytes

    key_path = OUT_DIR / "aes_key.bin"
    iv_path = OUT_DIR / "aes_iv.bin"
    write_bytes(key_path, key)
    write_bytes(iv_path, iv)

    return AESArtifacts(
        key_path=key_path,
        iv_path=iv_path,
        encrypted_bin=OUT_DIR / "aes_encrypted.bin",
        decrypted_txt=OUT_DIR / "aes_decrypted.txt",
    )

def aes_encrypt_file(key: bytes, iv: bytes, plaintext_path: Path, out_path: Path) -> None:
    plaintext = read_bytes(plaintext_path)

    padder = sym_padding.PKCS7(128).padder()  # AES block size = 128 bits
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()

    write_bytes(out_path, ciphertext)

def aes_decrypt_file(key: bytes, iv: bytes, ciphertext_path: Path, out_path: Path) -> None:
    ciphertext = read_bytes(ciphertext_path)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    write_bytes(out_path, plaintext)


# ---------- Task 2: TLS inspection ----------
@dataclass
class TLSInfo:
    host: str
    port: int
    protocol: str
    cipher: tuple
    subject: tuple
    issuer: tuple
    not_before: str
    not_after: str
    pem_cert_path: Path

def tls_inspect(host: str, port: int = 443) -> TLSInfo:
    ctx = ssl.create_default_context()
    # Enforce hostname verification + trusted CAs (default behavior)
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            protocol = ssock.version()
            cipher = ssock.cipher()  # (cipher_name, protocol, secret_bits)
            cert = ssock.getpeercert()  # parsed dict (subject/issuer/dates)
            der = ssock.getpeercert(binary_form=True)

    pem = ssl.DER_cert_to_PEM_cert(der)
    pem_path = OUT_DIR / "server_cert.pem"
    write_text(pem_path, pem)

    # Dates are strings in OpenSSL-ish format
    not_before = cert.get("notBefore", "")
    not_after = cert.get("notAfter", "")
    subject = cert.get("subject", ())
    issuer = cert.get("issuer", ())

    return TLSInfo(
        host=host,
        port=port,
        protocol=protocol or "",
        cipher=cipher,
        subject=subject,
        issuer=issuer,
        not_before=not_before,
        not_after=not_after,
        pem_cert_path=pem_path,
    )


# ---------- Reports ----------
def write_rsa_vs_aes_report() -> None:
    text = (
        f"{now_str()}\n\n"
        "This lab demonstrates asymmetric (RSA) and symmetric (AES) encryption on the same plaintext file.\n"
        "RSA uses a public key to encrypt and a private key to decrypt (two-key system). It is computationally expensive\n"
        "and is not designed for bulk file encryption; in real systems RSA (or ECDHE/RSA) is used mainly to authenticate\n"
        "and to establish or protect symmetric keys.\n\n"
        "AES is a symmetric cipher where the same secret key is used for encryption and decryption. AES-256 is fast and\n"
        "is the standard choice for encrypting files and large data. Real-world protocols (e.g., TLS/HTTPS) typically use\n"
        "public-key cryptography only during key exchange/authentication and then use AES (or ChaCha20) to encrypt data\n"
        "in transit or at rest.\n"
    )
    write_text(RSA_VS_AES_REPORT, text)

def write_tls_report(info: TLSInfo) -> None:
    cipher_name, cipher_proto, bits = info.cipher
    text = (
        f"{now_str()}\n\n"
        f"TLS/HTTPS inspection target: {info.host}:{info.port}\n"
        f"Negotiated TLS version: {info.protocol}\n"
        f"Cipher suite: {cipher_name} ({cipher_proto}, {bits} bits)\n"
        f"Certificate subject: {info.subject}\n"
        f"Certificate issuer: {info.issuer}\n"
        f"Certificate validity: {info.not_before}  ->  {info.not_after}\n"
        f"Saved server certificate (PEM): {info.pem_cert_path}\n\n"
        "How TLS helps prevent MITM:\n"
        "1) The server presents a certificate signed by a trusted CA (or a chain ending in a trusted root).\n"
        "2) The client validates the chain and checks that the certificate matches the hostname.\n"
        "3) During the handshake, key agreement establishes shared secrets; an attacker cannot decrypt traffic without\n"
        "   breaking key agreement or presenting a trusted certificate for the same hostname.\n"
        "4) TLS also provides integrity (tamper detection) using authenticated encryption/MAC.\n\n"
        "Result:\n"
        "HTTPS protects data in transit by encrypting it with session keys negotiated by TLS and by authenticating the\n"
        "server identity using certificates and the trust model.\n"
    )
    write_text(TLS_REPORT, text)


# ---------- Menu ----------
def ensure_message_file() -> None:
    if not MESSAGE_FILE.exists():
        write_text(MESSAGE_FILE, "Week 4 Lab: Real-world crypto test message.\n")

def run_task1_rsa() -> None:
    ensure_message_file()
    arts = generate_rsa_keys()
    rsa_encrypt_file(arts.public_key_pem, MESSAGE_FILE, arts.encrypted_bin)
    rsa_decrypt_file(arts.private_key_pem, arts.encrypted_bin, arts.decrypted_txt)
    ok = read_bytes(MESSAGE_FILE) == read_bytes(arts.decrypted_txt)
    print("\n[RSA] Done.")
    print("  Private key:", arts.private_key_pem)
    print("  Public key :", arts.public_key_pem)
    print("  Encrypted  :", arts.encrypted_bin)
    print("  Decrypted  :", arts.decrypted_txt)
    print("  Verified match:", ok)

def run_task1_aes() -> None:
    ensure_message_file()
    arts = generate_aes_key_iv()
    key = read_bytes(arts.key_path)
    iv = read_bytes(arts.iv_path)
    aes_encrypt_file(key, iv, MESSAGE_FILE, arts.encrypted_bin)
    aes_decrypt_file(key, iv, arts.encrypted_bin, arts.decrypted_txt)
    ok = read_bytes(MESSAGE_FILE) == read_bytes(arts.decrypted_txt)
    print("\n[AES] Done.")
    print("  Key:", arts.key_path)
    print("  IV :", arts.iv_path)
    print("  Encrypted:", arts.encrypted_bin)
    print("  Decrypted:", arts.decrypted_txt)
    print("  Verified match:", ok)

def run_task2_tls() -> None:
    host = input("Enter HTTPS host (e.g., example.com): ").strip()
    if not host:
        print("No host entered.")
        return
    info = tls_inspect(host)
    print("\n[TLS] Done.")
    print("  Protocol:", info.protocol)
    print("  Cipher  :", info.cipher)
    print("  Subject :", info.subject)
    print("  Issuer  :", info.issuer)
    print("  Validity:", info.not_before, "->", info.not_after)
    print("  Saved cert:", info.pem_cert_path)
    write_tls_report(info)
    print("  Wrote tls_report.txt")

def run_all() -> None:
    run_task1_rsa()
    run_task1_aes()
    write_rsa_vs_aes_report()
    print("\nWrote rsa_vs_aes.txt")
    run_task2_tls()

def menu() -> None:
    while True:
        print("\n==============================")
        print(" Week 4 Lab - Python Version")
        print("==============================")
        print("1) Task 1: RSA generate/encrypt/decrypt")
        print("2) Task 1: AES generate/encrypt/decrypt")
        print("3) Write rsa_vs_aes.txt")
        print("4) Task 2: TLS inspect + write tls_report.txt")
        print("5) Run ALL (RSA + AES + reports + TLS inspect)")
        print("0) Exit")
        choice = input("Select an option: ").strip()

        if choice == "1":
            run_task1_rsa()
        elif choice == "2":
            run_task1_aes()
        elif choice == "3":
            write_rsa_vs_aes_report()
            print("Wrote rsa_vs_aes.txt")
        elif choice == "4":
            run_task2_tls()
        elif choice == "5":
            run_all()
        elif choice == "0":
            print("Bye.")
            return
        else:
            print("Invalid option.")

if __name__ == "__main__":
    menu()

