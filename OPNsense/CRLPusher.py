# OPNsense lacks some BASIC features, including access to the CRL on an endpoint
# To allow this we have a python script thta extracts it and puts it in 
# an accessible place
import xml.etree.ElementTree as ET
import base64

def get_crl(path):
    xml = ET.parse(path)
    root = xml.getroot()
    crl_b64 = root.find("./crl/text").text
    crl_text = base64.b64decode(crl_b64)
    return crl_text

if __name__ == "__main__":
    crl = get_crl("/config/config.xml")
    # Save the CRL to the correct place
    with open("out.crl", "wb") as f:
        f.write(crl)