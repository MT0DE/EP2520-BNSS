# Standrad libs
import base64
import time
import random

# Dedicated libs
import xmlrpc.client
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import interfaces_pb2


REQ_X509_CERT_REQ_VEHICLE_TO_LTCA_USING_PROTO_BUFF = 122
adress = "http://nsscore.ict.kth.se:30930/cgi-bin/ltca"
clientXML = xmlrpc.client.ServerProxy(uri=adress)

def get_x509_csr(hostname: str):
    # Create and write private key to file
    private_key = ec.generate_private_key(
        ec.SECP192R1()
    )
    with open("key.pem", "wb") as f:
        f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ACME"),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, "lannge@kth.se")
    ])

    san = x509.SubjectAlternativeName([x509.DNSName(hostname)])

    # CA should be true since this will be ACME's own signing certficate and pathlenght must be zero 
    # since this certifcate should not be able to sign other CA cerficates other then itself (will be done here)
    csr = x509.CertificateSigningRequestBuilder(subject_name=name).add_extension(san, False).sign(private_key=private_key, algorithm=hashes.SHA256())
    return csr
        
def cert_from_rpc_response(rpc_response):
    # Response is base64 encoded
    data = base64.b64decode(rpc_response)

    # Decoded data need to be parsed to Python ProtoBuf format
    msgX509CertRes_LTCA2V = interfaces_pb2.msgX509CertRes_LTCA2V()
    msgX509CertRes_LTCA2V.ParseFromString(data)

    # Take the cert
    return msgX509CertRes_LTCA2V.strX509Cert

def request_x509_cert(csr: str):
    # Create the proto buffer using proto3.proto
    msgX509CertReq_V2LTCA = interfaces_pb2.msgX509CertReq_V2LTCA()
    msgX509CertReq_V2LTCA.iReqType = 122
    msgX509CertReq_V2LTCA.iLTCAIdRange = 1002
    msgX509CertReq_V2LTCA.strProofOfPossessionVoucher = ""
    msgX509CertReq_V2LTCA.strKeyUsage = ""
    msgX509CertReq_V2LTCA.strExtendedKeyUsage = ""
    msgX509CertReq_V2LTCA.strX509CertReq = csr
    msgX509CertReq_V2LTCA.iNonce = random.randint(0, 65535)
    msgX509CertReq_V2LTCA.tTimeStamp = int(time.time())
    msgX509CertReq_V2LTCA.strDNSExtension = ""
    serialzed_to_string = msgX509CertReq_V2LTCA.SerializeToString()
    encoded_req = base64.b64encode(serialzed_to_string)
    str_req = encoded_req.decode("utf-8")
    # print("Raw: ")
    # print(serialzed_to_string)
    # print("\nEncoded: ")
    # print(str_req)
    return clientXML.ltca.operate(REQ_X509_CERT_REQ_VEHICLE_TO_LTCA_USING_PROTO_BUFF, str_req)

def main():
    x509_csr: x509.CertificateSigningRequest = get_x509_csr("www.acme.se")

    # The NSS RCEXML format requires a str version of the x509 cert
    x509_csr_string = x509_csr.public_bytes(serialization.Encoding.PEM).decode("UTF-8")

    # Send request
    response = request_x509_cert(x509_csr_string)

    # Process response
    cert = cert_from_rpc_response(response)
    print("XMLRPC replied with:")
    print(cert)

    # Save Certificate 
    with open("ltca-signed.crt", "w") as f:
        f.write(cert)

if __name__ == "__main__":
    main()