import datetime
import ipaddress
import os
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from security_suite.crypto.primitive_dsa import DSAManager

OID_ML_DSA_65 = ObjectIdentifier("1.3.6.1.4.1.99999.1.1")


def _write_secure_bytes(path: Path, data: bytes) -> None:
    flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    finally:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def _cert_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "storage" / "certs"


def bootstrap_hospital_root_ca() -> x509.Certificate:
    """
    Generates a Self-Signed X.509 Root Certificate for the Hospital.
    Persists the ML-DSA-65 keypair alongside the cert for cross-restart consistency.
    """
    cert_dir = _cert_dir()
    cert_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(cert_dir, 0o700)
    except OSError:
        pass
    root_cert_path = cert_dir / "hospital_root_ca.pem"
    container_key_path = cert_dir / "hospital_root_ca.key"
    pqc_private_key_path = cert_dir / "hospital_root_ca_ml_dsa.key"

    if root_cert_path.exists() and container_key_path.exists() and pqc_private_key_path.exists():
        with open(root_cert_path, "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read())
        return root_cert

    # Generate a one-time PQC identity public key to embed in the CA cert extension.
    ephemeral_ca_identity = DSAManager(private_bytes=None)
    ephemeral_ca_identity.generate_keypair()
    pqc_private_key = ephemeral_ca_identity.get_private_bytes()

    # Create a lightweight classical key strictly to satisfy the X509 container
    container_key = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"VaultQ Central Hospital CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"VaultQ Root Authority"),
    ])

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
    builder = builder.serial_number(x509.random_serial_number())
    
    # Satisfy the builder with the container key
    builder = builder.public_key(container_key.public_key())
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)

    # Embed the ACTUAL VaultQ ML-DSA Key
    builder = builder.add_extension(
        x509.UnrecognizedExtension(OID_ML_DSA_65, ephemeral_ca_identity.pk),
        critical=False
    )

    # Sign the container
    root_cert = builder.sign(
        private_key=container_key, 
        algorithm=hashes.SHA256()
    )
    
    _write_secure_bytes(root_cert_path, root_cert.public_bytes(serialization.Encoding.PEM))
    _write_secure_bytes(
        container_key_path,
        container_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    _write_secure_bytes(pqc_private_key_path, pqc_private_key)
    
    return root_cert


def load_hospital_ca_signer() -> DSAManager:
    """
    Loads the CA signing material on demand.
    The returned DSAManager should be short-lived and discarded after use.
    """
    cert_dir = _cert_dir()
    root_cert_path = cert_dir / "hospital_root_ca.pem"
    container_key_path = cert_dir / "hospital_root_ca.key"
    pqc_private_key_path = cert_dir / "hospital_root_ca_ml_dsa.key"

    if not root_cert_path.exists() or not container_key_path.exists() or not pqc_private_key_path.exists():
        raise RuntimeError("Hospital CA artifacts are missing.")

    with open(root_cert_path, "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())
    with open(container_key_path, "rb") as f:
        container_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(pqc_private_key_path, "rb") as f:
        pqc_private_key = f.read()

    signer = DSAManager(private_bytes=pqc_private_key)
    signer.container_key = container_key
    try:
        ext = root_cert.extensions.get_extension_for_oid(OID_ML_DSA_65)
        signer.pk = ext.value.value
    except x509.ExtensionNotFound:
        signer.pk = None
    return signer


def ensure_server_tls_artifacts() -> bool:
    """
    Ensures server.key/server.crt exist under storage/certs.
    Generates a new server leaf cert signed by hospital_root_ca.key if missing.
    """
    cert_dir = _cert_dir()
    cert_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    root_cert_path = cert_dir / "hospital_root_ca.pem"
    root_key_path = cert_dir / "hospital_root_ca.key"
    server_cert_path = cert_dir / "server.crt"
    server_key_path = cert_dir / "server.key"

    if server_cert_path.exists() and server_key_path.exists():
        return True

    if not root_cert_path.exists() or not root_key_path.exists():
        return False

    with open(root_cert_path, "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())
    with open(root_key_path, "rb") as f:
        root_key = serialization.load_pem_private_key(f.read(), password=None)

    server_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"VaultQ Core Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"127.0.0.1"),
        ]
    )

    san = x509.SubjectAlternativeName(
        [
            x509.DNSName(u"localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]
    )

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(root_cert.subject)
    builder = builder.public_key(server_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=1))
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=825))
    builder = builder.add_extension(san, critical=False)
    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
        critical=False,
    )

    server_cert = builder.sign(private_key=root_key, algorithm=hashes.SHA256())

    with open(server_key_path, "wb") as f:
        f.write(
            server_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(server_cert_path, "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))

    return True
