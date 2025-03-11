import xml.etree.ElementTree as ET
import uuid
import subprocess
import os
import base64
import random

def get_opnsense_last_uid(xml_root):
    user_tree = xml_root.find('system')
    user_elements = user_tree.findall('user')
    return max([int(u.find('uid').text) if u.find('uid') != None else 1 for u in user_elements])

def add_user_cert(xml_root, crt_path, prv_path):
    with open(crt_path, 'r') as f:
        crt = f.read()
    
    with open(prv_path, 'r') as f:
        prv = f.read()

    # B64 encode crt
    crt64 = base64.b64encode(crt.encode('utf-8')).decode('utf-8')
    prv64 = base64.b64encode(prv.encode('utf-8')).decode('utf-8')

    new_uuid = str(uuid.uuid4())
    cert_element = ET.SubElement(xml_root, "cert", uuid=new_uuid)
    refid_element = ET.SubElement(cert_element, "refid")
    hex_chars = "0123456789abcdef"
    rnd_id = ""
    for _ in range(13):
        rnd_id += hex_chars[random.randint(0, 15)]
    refid_element.text = rnd_id

    descr_element = ET.SubElement(cert_element, "descr")
    descr_element.text = "Automatically generated certificate"

    caref_element = ET.SubElement(cert_element, "caref")
    caref_element.text = "67b48a76ed935"

    crt_element = ET.SubElement(cert_element, "crt")
    crt_element.text = crt64

    csr_element = ET.SubElement(cert_element, "csr")

    prv_element = ET.SubElement(cert_element, "prv")
    prv_element.text = prv64

def get_hashed_password(user_name, password):
    command = ["htpasswd", "-i", "-B", "-c", "-C", "11", ".pwd", user_name]
    execute = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) #added text=True
    _, stderr = execute.communicate(input=password)
    if execute.returncode == 0:
        with open('.pwd', 'r') as file:
            return file.read().split(':')[1].strip()
    else:
        print(f"Error executing htpasswd: {stderr}") #Print the error if any.
        return None #Return None upon error.
    return None

def add_opnsense_user(xml_root, username, email, password):
    
    user_tree = xml_root.find('system')
    new_user = ET.SubElement(user_tree, 'user')
    new_uuid = str(uuid.uuid4())
    new_user.set('uuid', new_uuid)

    # Hash the password with 11 rounds of bcrypt
    password_hash = get_hashed_password(username, password)
    uid = get_opnsense_last_uid(xml_root) + 1
    ET.SubElement(new_user, 'uid').text = str(uid)
    ET.SubElement(new_user, 'name').text = username
    ET.SubElement(new_user, 'disabled').text = '0'
    ET.SubElement(new_user, 'scope').text = 'system'
    ET.SubElement(new_user, 'expires')
    ET.SubElement(new_user, 'authorizedkeys')
    ET.SubElement(new_user, 'otp_seed')
    ET.SubElement(new_user, 'shell')
    ET.SubElement(new_user, 'password').text = password_hash
    ET.SubElement(new_user, 'landing_page')
    ET.SubElement(new_user, 'comment')
    ET.SubElement(new_user, 'email').text = email
    ET.SubElement(new_user, 'apikeys')
    ET.SubElement(new_user, 'priv')
    ET.SubElement(new_user, 'language')
    ET.SubElement(new_user, 'descr').text = "Automatically generated user"
    ET.SubElement(new_user, 'dashboard')

def add_radius_user(xml_root, username, email, password):
    user_tree = xml_root.find('OPNsense/freeradius/user/users')
    new_user = ET.SubElement(user_tree, 'user')
    new_uuid = str(uuid.uuid4())
    new_user.set('uuid', new_uuid)

    ET.SubElement(new_user, "enabled").text = "1"
    ET.SubElement(new_user, "username").text = username
    ET.SubElement(new_user, "password").text = password
    ET.SubElement(new_user, "passwordencryption").text = "Cleartext-Password"
    ET.SubElement(new_user, "description").text = "Automatically generated user"
    ET.SubElement(new_user, "ip").text = "192.168.0.0"
    ET.SubElement(new_user, "subnet").text = "255.255.254.0"
    ET.SubElement(new_user, "route")
    ET.SubElement(new_user, "ip6")
    ET.SubElement(new_user, "vlan")
    ET.SubElement(new_user, "logintime")
    ET.SubElement(new_user, "simuse")
    ET.SubElement(new_user, "exos_vlan_untagged")
    ET.SubElement(new_user, "exos_vlan_tagged")
    ET.SubElement(new_user, "exos_policy")
    ET.SubElement(new_user, "wispr_bw_min_up")
    ET.SubElement(new_user, "wispr_bw_max_up")
    ET.SubElement(new_user, "wispr_bw_min_down")
    ET.SubElement(new_user, "wispr_bw_max_down")
    ET.SubElement(new_user, "chillispot_bw_max_up")
    ET.SubElement(new_user, "chillispot_bw_max_down")
    ET.SubElement(new_user, "mikrotik_vlan_id_number")
    ET.SubElement(new_user, "mikrotik_vlan_id_type")
    ET.SubElement(new_user, "sessionlimit_max_session_limit")
    ET.SubElement(new_user, "servicetype")
    ET.SubElement(new_user, "linkedAVPair")
    
def add_opnsense_user_and_cert(username, email, password, crt_path, prv_path):
    tree = ET.parse('/conf/config.xml')
    tree.write('/conf/config.xml.bak')
    root = tree.getroot()
    add_opnsense_user(root, username, email, password)
    add_radius_user(root, username, email, password)
    add_user_cert(root, crt_path, prv_path)
    tree.write('/conf/config_mod.xml')
    print("Saved the config")

def main():
    print("Username: ")
    username = input()
    print("Email: ")
    email = input()
    print("Password: ")
    password = input()

    tree = ET.parse('/conf/config.xml')
    tree.write('/conf/config.xml.bak')
    root = tree.getroot()
    add_opnsense_user(root, username, email, password)
    add_radius_user(root, username, email, password)
    tree.write('/conf/config.xml')



if __name__ == "__main__":
    main()