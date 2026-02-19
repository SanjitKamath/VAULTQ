import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from security_suite.crypto.primitive_dsa import DSAManager

OID_ML_DSA_65 = ObjectIdentifier("1.3.6.1.4.1.99999.1.1")

def bootstrap_hospital_root_ca(ca_key_manager: DSAManager) -> x509.Certificate:
    """
    Generates a Self-Signed X.509 Root Certificate for the Hospital.
    """
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
    
    return root_cert