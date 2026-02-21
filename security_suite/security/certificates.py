# security_suite/security/certificates.py
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from security_suite.crypto.primitive_dsa import DSAManager

OID_ML_DSA_65 = ObjectIdentifier("1.3.6.1.4.1.99999.1.1") 

class CertificateAuthority:
    @staticmethod
    def generate_doctor_certificate(
        doctor_pqc_public_bytes: bytes,
        doctor_tls_public_key, # <--- Pass the client's classical public key here
        doctor_details: dict,
        issuer_key: DSAManager,
        issuer_cert: x509.Certificate
    ) -> x509.Certificate:
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"VaultQ Hospital System"),
            x509.NameAttribute(NameOID.COMMON_NAME, doctor_details["name"]),
            x509.NameAttribute(NameOID.USER_ID, doctor_details["doctor_id"]),
        ])

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer_cert.subject)
        builder = builder.not_valid_before(datetime.datetime.utcnow())
        builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        builder = builder.serial_number(x509.random_serial_number())

        # Bind the client's classical key to the cert
        builder = builder.public_key(doctor_tls_public_key)

        # Embed the Doctor's ML-DSA public key
        builder = builder.add_extension(
            x509.UnrecognizedExtension(OID_ML_DSA_65, doctor_pqc_public_bytes),
            critical=False
        )

        return builder.sign(private_key=issuer_key.container_key, algorithm=hashes.SHA256())


def load_pem_certificate(pem_data: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem_data.encode("utf-8"))


def extract_pqc_public_key_from_cert(cert: x509.Certificate) -> bytes:
    ext = cert.extensions.get_extension_for_oid(OID_ML_DSA_65)
    return ext.value.value


def verify_cert_chain(cert: x509.Certificate, issuer_cert: x509.Certificate) -> bool:
    """
    Verifies doctor cert signature against issuer cert public key.
    """
    issuer_pub = issuer_cert.public_key()
    if isinstance(issuer_pub, ec.EllipticCurvePublicKey):
        issuer_pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        return True
    if isinstance(issuer_pub, rsa.RSAPublicKey):
        issuer_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    return False
