# security_suite/security/certificates.py
import datetime
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, ed25519, ed448
from security_suite.crypto.primitive_dsa import DSAManager

OID_ML_DSA_65 = ObjectIdentifier("1.3.6.1.4.1.99999.1.1")


class CertificateAuthority:
    @staticmethod
    def generate_doctor_certificate_from_csr(
        doctor_csr: x509.CertificateSigningRequest,
        issuer_key: DSAManager,
        issuer_cert: x509.Certificate,
    ) -> x509.Certificate:
        if not verify_csr_signature(doctor_csr):
            raise ValueError("Invalid CSR signature.")

        doctor_pqc_public_bytes = extract_pqc_public_key_from_csr(doctor_csr)
        now_utc = datetime.datetime.now(datetime.timezone.utc)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(doctor_csr.subject)
        builder = builder.issuer_name(issuer_cert.subject)
        builder = builder.not_valid_before(now_utc)
        builder = builder.not_valid_after(now_utc + datetime.timedelta(days=365))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(doctor_csr.public_key())
        builder = builder.add_extension(
            x509.UnrecognizedExtension(OID_ML_DSA_65, doctor_pqc_public_bytes),
            critical=True,
        )

        return builder.sign(private_key=issuer_key.container_key, algorithm=hashes.SHA256())


def generate_doctor_csr_pem(
    *,
    doctor_id: str,
    doctor_name: str,
    doctor_pqc_public_bytes: bytes,
    doctor_tls_private_key,
) -> str:
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"VaultQ Hospital System"),
            x509.NameAttribute(NameOID.COMMON_NAME, doctor_name),
            x509.NameAttribute(NameOID.USER_ID, doctor_id),
        ]
    )

    sign_algorithm = None if isinstance(
        doctor_tls_private_key,
        (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey),
    ) else hashes.SHA256()

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(
            x509.UnrecognizedExtension(OID_ML_DSA_65, doctor_pqc_public_bytes),
            critical=True,
        )
        .sign(doctor_tls_private_key, sign_algorithm)
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def load_pem_certificate(pem_data: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem_data.encode("utf-8"))


def load_pem_csr(pem_data: str) -> x509.CertificateSigningRequest:
    return x509.load_pem_x509_csr(pem_data.encode("utf-8"))


def extract_pqc_public_key_from_cert(cert: x509.Certificate) -> bytes:
    ext = cert.extensions.get_extension_for_oid(OID_ML_DSA_65)
    return ext.value.value


def extract_pqc_public_key_from_csr(csr: x509.CertificateSigningRequest) -> bytes:
    ext = csr.extensions.get_extension_for_oid(OID_ML_DSA_65)
    return ext.value.value


def verify_csr_signature(csr: x509.CertificateSigningRequest) -> bool:
    public_key = csr.public_key()
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        try:
            public_key.verify(csr.signature, csr.tbs_certrequest_bytes, ec.ECDSA(csr.signature_hash_algorithm))
            return True
        except InvalidSignature:
            return False
    if isinstance(public_key, rsa.RSAPublicKey):
        try:
            public_key.verify(
                csr.signature,
                csr.tbs_certrequest_bytes,
                padding.PKCS1v15(),
                csr.signature_hash_algorithm,
            )
            return True
        except InvalidSignature:
            return False
    if isinstance(public_key, ed25519.Ed25519PublicKey) or isinstance(public_key, ed448.Ed448PublicKey):
        try:
            public_key.verify(csr.signature, csr.tbs_certrequest_bytes)
            return True
        except InvalidSignature:
            return False
    return False


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
    if isinstance(issuer_pub, ed25519.Ed25519PublicKey) or isinstance(issuer_pub, ed448.Ed448PublicKey):
        issuer_pub.verify(cert.signature, cert.tbs_certificate_bytes)
        return True
    return False
