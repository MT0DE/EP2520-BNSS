### EP2520-BNSS

## What is this project about?

## Setup (step-by-step)

## Snort 

## OPNsense 
* Install on VM follow ... (tutorial länk)
### FreeRadius in OPNsense

### OpenVPN in OPNsense 

### Wireguard in OPNsense

### Certificates in OPNsense
* Create a certificate by using GUI, go to System, Trust, and then Certificates.
* Create a new certificate by clicking on the + sign in the top right corner and add descriptors for who it is for and which CA should sign it.
* To revoke a certificate go to the Trust page again but choose Revocation this time, either update an existing CRL or create a new CRL based on the previous CRL, choose which certificate and under what reason for revocation. Update and Save.
## Wifi

### To use certificate to access wifi:
* First, install the root CA on your computer
* Install your cert with private key -p12 file.
* Use your cert when signing in to the wifi.

## Contributors
