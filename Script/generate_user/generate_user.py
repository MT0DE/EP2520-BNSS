import os
import random
import argparse
from keycloak import KeycloakAdmin
from keycloak import KeycloakOpenIDConnection
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
import datetime
from dotenv import load_dotenv

from add_opnsense_user import add_opnsense_user_and_cert

'''
pip install -r requirements.txt

usage: generate_user.py [-h] -f FIRSTNAME -l LASTNAME -p PASSWORD [-c ROOTCERT] [-u USERNAME]

needs .env with the following to work (for the realm & specific client):
SERVER_URL="<url>"
CLIENT_SECRET_KEY=<client_secret>"
USERNAME_REALM="<username>"
PASSWORD_REALM="<password>"
'''


def generate_user(server_url, client_secret_key, username_realm, password_realm):
    user = {"email": email,
            "username": username,
            "enabled": True,
            "firstName": first_name,
            "lastName": last_name,
            "credentials": [{"value": "secret", "type": "password", }]}
    try:
        keycloak_connection_cert = KeycloakOpenIDConnection(
            server_url=server_url,
            username=username_realm,
            password=password_realm,
            realm_name="CertLogin",
            client_id="create-user",
            client_secret_key=client_secret_key,
            verify=False)

        keycloak_connection_actual_cert = KeycloakOpenIDConnection(
            server_url=server_url,
            username=username_realm,
            password=password_realm,
            realm_name="ActualCertLogin",
            client_id="create-user",
            client_secret_key=client_secret_key,
            verify=False)
        keycloak_cert = KeycloakAdmin(connection=keycloak_connection_cert)
        keycloak_actual_cert = KeycloakAdmin(connection=keycloak_connection_actual_cert)

        keycloak_cert.create_user(user)
        keycloak_actual_cert.create_user(user)

    except():
        print("error creating user")


def generate_private_key(key_file_path):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    os.makedirs(os.path.dirname(key_file_path), exist_ok=True)

    with open(key_file_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    return private_key


def generate_csr(private_key, email_address, common_name, country_name,
                 locality_name, state_or_province_name, organization_name,
                 organization_unit_name, csr_file, ca_cert):
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_address),
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organization_unit_name),
    ]))

    csr = csr_builder.sign(private_key, hashes.SHA256())

    os.makedirs(os.path.dirname(csr_file), exist_ok=True)

    with open(csr_file, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    return csr


def sign_csr_with_ca(csr_file_path, ca_cert_path, ca_key_path, cert_file_path, validity_days=365):
    with open(csr_file_path, "rb") as f:
        csr = x509.load_pem_x509_csr(f.read())

    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    serial_number = 10 #int.from_bytes(os.urandom(16), byteorder="big")
    now = datetime.datetime.now(datetime.UTC)

    cert_builder = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        serial_number
    ).not_valid_before(
        now
    ).not_valid_after(
        now + datetime.timedelta(days=validity_days)
    )

    for extension in csr.extensions:
        cert_builder = cert_builder.add_extension(extension.value, extension.critical)

    cert = cert_builder.sign(ca_key, hashes.SHA256())

    os.makedirs(os.path.dirname(cert_file_path), exist_ok=True)
    with open(cert_file_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def export_to_pkcs12(cert_file_path, key_file_path, p12_file_path, friendly_name, password=None):
    with open(cert_file_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    with open(key_file_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    p12 = pkcs12.serialize_key_and_certificates(
        name=friendly_name.encode('utf-8'),
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode('utf-8')) if password else serialization.NoEncryption()
    )

    os.makedirs(os.path.dirname(p12_file_path), exist_ok=True)

    with open(p12_file_path, "wb") as f:
        f.write(p12)


def create_and_sign_certificate(username, email, ca_cert_path="./rootCerts/rootCA.crt",
                                ca_key_path="./rootCerts/rootCA.key"):
    user_folder = f"./{username}"
    os.makedirs(user_folder, exist_ok=True)

    key_file = f"{user_folder}/{username}.key"
    csr_file = f"{user_folder}/{username}.csr"
    cert_file = f"{user_folder}/{username}.crt"
    p12_file = f"{user_folder}/{username}.p12"

    private_key = generate_private_key(key_file)
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    generate_csr(
        private_key=private_key,
        email_address=email,
        common_name=username,
        country_name="SE",
        locality_name="ACME",
        state_or_province_name="Stockholm",
        organization_name="ACME",
        organization_unit_name="ACME",
        csr_file=csr_file,
        ca_cert=ca_cert
    )

    sign_csr_with_ca(csr_file, ca_cert_path, ca_key_path, cert_file)
    export_to_pkcs12(cert_file, key_file, p12_file, username, password)
    print(f"Successfully created and signed certificate for {username}")
    print(f"Files created in folder: {user_folder}")
    print(f"Private key: {key_file}")
    print(f"CSR: {csr_file}")
    print(f"Certificate: {cert_file}")
    print(f"PKCS12 file: {p12_file}")


if __name__ == '__main__':
    load_dotenv()
    parser = argparse.ArgumentParser(description='Description of your program')
    parser.add_argument('-f', '--firstname', help='First name of user', required=True)
    parser.add_argument('-l', '--lastname', help='Last name of user', required=True)
    parser.add_argument('-p', '--password', help='Set password', required=True)
    parser.add_argument('-u', '--username', help="manually set username (OPTIONAL)", required=False)

    args = vars(parser.parse_args())
    cert_path = ""

    random = str(random.randint(1, 9999))

    if args["firstname"]:
        first_name = args["firstname"]
    if args["lastname"]:
        last_name = args["lastname"]
    if args["password"]:
        password = args["password"]
    if not args["username"]:
        username = first_name[0:3] + last_name[0:3] + random
    else:
        username = args["username"]
    if not args["rootcert"]:
        ca_cert_path = "./rootCerts/rootCA.crt"
        ca_key_path = "./rootCerts/rootCA.key"
    else:
        cert_path = args["rootcert"]
        ca_cert_path = cert_path + "/rootCA.crt"
        ca_key_path = cert_path + "/rootCA.key"

    email = username + "@acme.com"

    print(f"...Creating user {username} and generating certificate ")

    generate_user(username_realm=os.getenv("USERNAME_REALM"), password_realm=os.getenv("PASSWORD_REALM"),
                  client_secret_key=os.getenv("CLIENT_SECRET_KEY"), server_url=os.getenv("SERVER_URL"))
    create_and_sign_certificate(username, email, ca_cert_path=ca_cert_path, ca_key_path=ca_key_path)

    # Do all opensense shit
    add_opnsense_user_and_cert(username, email, password, f"./{username}/{username}.crt",
                               f"./{username}/{username}.key")
