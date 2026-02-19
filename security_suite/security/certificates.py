import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from security_suite.crypto.primitive_dsa import DSAManager

OID_ML_DSA_65 = ObjectIdentifier("1.3.6.1.4.1.99999.1.1") 

class CertificateAuthority:
    @staticmethod
    def generate_doctor_certificate(
        doctor_public_key_bytes: bytes,
        doctor_details: dict,
        issuer_key: DSAManager,
        issuer_cert: x509.Certificate
    ) -> x509.Certificate:
        """
        Issues a unique X.509 Certificate for a doctor.
        """
        # Lightweight container key for the doctor's certificate
        doc_container_key = ec.generate_private_key(ec.SECP256R1())

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

        # Satisfy X509 public key requirement
        builder = builder.public_key(doc_container_key.public_key())

        # Embed the Doctor's ML-DSA public key into the custom extension
        builder = builder.add_extension(
            x509.UnrecognizedExtension(OID_ML_DSA_65, doctor_public_key_bytes),
            critical=False
        )

        # CRITICAL FIX: Sign using the Hospital's CA classical container key
        certificate = builder.sign(
            private_key=issuer_key.container_key, 
            algorithm=hashes.SHA256()
        )
        
        return certificate