### EP2520-BNSS

###Login to OpenVPN on android
*For an employee to be able to connect to the stockholm network from an Android phone a number of steps must be taken.
*First, download the certificate of the root CA in PEM format in OPNsense (do not download the private key), this file is not confidential and can be stored publically. Then, in Android, go to the settings and search for “install certificate” and select the root CA’s certificate.
*Secondly, in OPNsense go to VPN ⇒ OpenVPN ⇒ Export clients and scroll to the bottom of the page. Update the IP address to the current public ip address of the Stockholm router and download the generic settings file as a .ovpn file and transfer it to the phone. 
*Finally, on the Android phone, install the OpenVPN app, open it and click import settings. Select the .ovpn file and insert the user's username and password. The VPN should now work and be able to access nextcloud.

###Revoking a user certificate in OPNsense
*To revoke a certificate go to the System ⇒ Trust ⇒ Revocation and update the CRL by adding the certificate that shold be revoked to it. After adding the certificate you must click on the apply button at the bottom. The revocation will be active after at most one minute of time.

###Creating a user and generating a x509 certificate
*A user is added to the system by  running the script  generate_user.py -f FIRSTNAME -l LASTNAME -p PASSWORD , this script adds the user to both OPNsense and keycloak, (which by implementation also includes nextcloud & the webserver) and generates a valid x509 certificate which can be used when authenticating via keycloak SSO.  

###Adding two factor authenticator
*2FA setup is forced on the first login to keycloak using username and password. Its simply added to the 2fa app by scanning a QRCode shown during login. 


###Wifi
To use certificate to access wifi:
*First, install the root CA’s certificate in the truststore on your computer/phone
In OPNsense, go to System ⇒ Trust ⇒ Certificates and export the certificate of the user. Transfer this file to the device.
Install the certificate on the device. This can be done simply by clicking on it in both windows and android.
*To access the wifi, use the following settings: 
**EAP method: EAP-TLS
**CA certificate: Internal truststore
**Client certificate: Select the installed certificate
**Username: the user’s username
**Password: The user’s password

###Assigning a domain name to a new server
Because of some security features in the DNS and firewall rules, a few OPNsense settings have to be modified to allow new servers on the network.
First, in OPNsense, go to Services ⇒ Unbound DNS ⇒ Overwrites, and add a domain name for a new server. Then go to the security settings in Unbound and add the domain name to the private domain names. If this is not done, the rebind-attack protection in the DNS server will not allow users to access it.

