#!/usr/bin/env python2.7

import interfaces_pb2
import random
import time
import base64
import xmlrpclib
import os
import ssl
import sys

REQ_VOUCHER_VEHICLE_TO_LTCA_USING_PROTO_BUFF = 120
RES_VOUCHER_LTCA_TO_VEHICLE_USING_PROTO_BUFF = 121
REQ_X509_CERT_REQ_VEHICLE_TO_LTCA_USING_PROTO_BUFF = 122
RES_ISSUE_X509_CERT_LTCA_TO_VEHICLE_USING_PROTO_BUFF = 123
REQ_X509_CERT_VALIDATION_VEHICLE_TO_LTCA_USING_PROTO_BUFF = 124
RES_X509_CERT_VALIDATION_LTCA_TO_VEHICLE_USING_PROTO_BUFF = 125
REQ_NATIVE_TICKET_VEHICLE_TO_LTCA_USING_PROTO_BUFF = 126
RES_NATIVE_TICKET_LTCA_TO_VEHICLE_USING_PROTO_BUFF = 127
REQ_FOREIGN_TICKET_VEHICLE_TO_LTCA_USING_PROTO_BUFF = 128
RES_FOREIGN_TICKET_LTCA_TO_VEHICLE_USING_PROTO_BUFF = 129

LTCA_SERVER_URL = "https://nsscore.ict.kth.se:30930/cgi-bin/ltca"

PKI = '/etc/pki'
#PKI = '.'


def init_variables():
    nonce = random.randrange(0, 65535)
    timestamp = int(time.time())
    return nonce, timestamp


def check(req, res, cert):
    if req.iNonce != (res.iNonce - 1):
        return False
    if req.tTimeStamp >= res.tTimeStamp:
        return False
    if cert == res.stSigner.strCertificate:
        return False
    if cert == res.stSigner.strCertificatesChain:
        return False
    if res.stErrInfo.strErrMsgDes != 'NO_ERROR':
        return False
    return True


def load_cert(username):
    return csr, cert, chain


def write_cert(username, cert):
        sys.exit()


def x509cert(csr):
    req = interfaces_pb2.msgX509CertReq_V2LTCA()
    res = interfaces_pb2.msgX509CertRes_LTCA2V()
    req.iReqType = REQ_X509_CERT_REQ_VEHICLE_TO_LTCA_USING_PROTO_BUFF
    req.iLTCAIdRange = 1002
    req.strProofOfPossessionVoucher = ""
    req.strX509CertReq = csr
    req.iNonce, req.tTimeStamp = init_variables()
    return req, res


def connection(req, res):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    context.verify_mode = ssl.CERT_NONE
    context.check_hostname = False
    context.load_default_certs()
    proxy = xmlrpclib.ServerProxy(LTCA_SERVER_URL, context=context)
    # Serialize
    sreq = req.SerializeToString()
    # base64 encode
    bsreq = base64.b64encode(sreq)
    try:
        rawdata = proxy.ltca.operate(req.iReqType, bsreq)
        res.ParseFromString(base64.b64decode(rawdata))
        return res
    except:
        print("Error, failed at xmlrpc")
        print(req)
        print(proxy)


def main():
    # Cert
    req, res = x509cert(csr)
    res = connection(req, res)
    if res.iReqType != RES_ISSUE_X509_CERT_LTCA_TO_VEHICLE_USING_PROTO_BUFF:
        print("Error, failed at %s" % req.iReqType)
    if not check(req, res, cert):
        print("Error, check failed")
        print(res)

if __name__ == "__main__":
    main()