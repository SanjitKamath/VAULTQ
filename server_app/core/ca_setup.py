import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from security_suite.crypto.primitive_dsa import DSAManager

OID_ML_DSA_65 = ObjectIdentifier("1.3.6.1.4.1.99999.1.1")

def bootstrap_hospital_root_ca(ca_key_manager: DSAManager) -> x509.Certificate:
    """
    Generates a Self-Signed X.509 Root Certificate for the Hospital.
    """
    cert_dir = Path(__file__).resolve().parents[1] / "storage" / "certs"
    cert_dir.mkdir(parents=True, exist_ok=True)
    root_cert_path = cert_dir / "hospital_root_ca.pem"
    container_key_path = cert_dir / "hospital_root_ca.key"

    if root_cert_path.exists() and container_key_path.exists():
        with open(root_cert_path, "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read())
        with open(container_key_path, "rb") as f:
            container_key = serialization.load_pem_private_key(f.read(), password=None)
        ca_key_manager.container_key = container_key
        try:
            ext = root_cert.extensions.get_extension_for_oid(OID_ML_DSA_65)
            ca_key_manager.pk = ext.value.value
        except Exception:
            ca_key_manager.pk = ca_key_manager.pk
        return root_cert

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
        x509.UnrecognizedExtension(OID_ML_DSA_65, ca_key_manager.pk),
        critical=False
    )

    # Sign the container
    root_cert = builder.sign(
        private_key=container_key, 
        algorithm=hashes.SHA256()
    )
    
    # ATTACH THE CONTAINER KEY so it can be used to issue doctor certs later
    ca_key_manager.container_key = container_key

    with open(root_cert_path, "wb") as f:
        f.write(root_cert.public_bytes(serialization.Encoding.PEM))
    with open(container_key_path, "wb") as f:
        f.write(
            container_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    
    return root_cert
