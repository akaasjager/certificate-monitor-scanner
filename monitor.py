#!/usr/bin/env python


import sys, getopt, csv
import subprocess
import re
import time
import datetime
import pprint

def help():
    print "python monitor.py [-h] [-i <csv file>]"

def main(argv):
    conf = {}
    try:
        opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
    except getopt.GetoptError:
        help()
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            help()
            sys.exit(0)

        elif opt in ("-i", "--ifile"):
            conf['inputfile'] = arg

        else:
            conf['target'] = opt


    return conf


def parse_sslscan(out):
    results = {}

    try: subject = re.search('Subject: (.+?)[\n\r]+', out).group(1)
    except AttributeError: subject = ''
    results['subject'] = subject

    try: issuer = re.search('Issuer: (.+?)[\n\r]+', out).group(1)
    except AttributeError: issuer = ''
    results['issuer'] = issuer

    try: signature_algo = re.search('Signature Algorithm: (.+?)[\n\r]+', out).group(1)
    except AttributeError: signature_algo = ''
    results['signature_algo'] = signature_algo

    try: not_valid_before = re.search('Not valid before: (.+?)[\n\r]+', out).group(1)
    except AttributeError: not_valid_before = ''
    results['not_valid_before'] = not_valid_before

    try: not_valid_after = re.search('Not valid after: (.+?)[\n\r]+', out).group(1)
    except AttributeError: not_valid_after = ''
    results['not_valid_after'] = not_valid_after

    try: public_key_algo = re.search('Public Key Algorithm: (.+?)[\n\r]+', out).group(1)
    except AttributeError: public_key_algo = ''
    results['public_key_algo'] = public_key_algo

    try: modulus = re.search('Modulus \((.+?)\):', out).group(1)
    except AttributeError: modulus = ''
    results['modulus'] = modulus

    try: ca_issuers_uri = re.search('CA Issuers - URI:(.+?)[\n\r]+', out).group(1)
    except AttributeError: ca_issuers_uri = ''
    results['ca_issuers_uri'] = ca_issuers_uri

    try: ocsp_uri = re.search('OCSP - URI:(.+?)[\n\r]+', out).group(1)
    except AttributeError: ocsp_uri = ''
    results['ocsp_uri'] = ocsp_uri

    try: accepted = re.findall('Accepted  (.+?)[\n\r]+', out)
    except AttributeError: accepted = ''
    spl = []
    for hit in accepted: spl.append(hit.split())
    results['accepted'] = spl

    if "CA:FALSE" in out: results['basic_contrains_ca'] = True
    else: results['basic_contrains_ca'] = False


    # Parse it
    results['not_valid_before_dt'] = datetime.datetime.strptime(results['not_valid_before'], "%b %d %H:%M:%S %Y %Z")
    results['not_valid_after_dt'] = datetime.datetime.strptime(results['not_valid_after'], "%b %d %H:%M:%S %Y %Z")

    # Determine validity
    if datetime.datetime.now() > results['not_valid_before_dt'] and datetime.datetime.now() < results['not_valid_after_dt']:
        results['valid'] = True
    else:
        results['valid'] = False

    pos1 = out.find("Subject Alternative Name:") + len("Subject Alternative Name:") + 2
    if pos1 > 0:
        s = out[pos1:]
        pos2 = s.find('\n')
        SANS = s[0:pos2].replace(" ", "")
        #print SANS

        try:
            DNSS = re.findall('DNS:(.+?)[,\n\r]+', SANS)
            spl = []
            for hit in DNSS: spl.append(hit)
            results['SAN_DNS'] = spl
        except AttributeError: pass

        try:
            IPS = re.findall('IP:(.+?)[,\n\r]+', SANS)
            spl = []
            for hit in IPS: spl.append(hit)
            results['SAN_IP'] = spl
        except AttributeError: pass

        try:
            URIS = re.findall('URI:(.+?)[,\n\r]+', SANS)
            spl = []
            for hit in URIS: spl.append(hit)
            results['SAN_URI'] = spl
        except AttributeError: pass

    results['selfsigned'] = (subject == issuer)

    return results


def sslscan(host, port):
    p = subprocess.Popen(['sslscan', host], stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE)
    out, err = p.communicate()
    results = parse_sslscan(out)
    results['host'] = host
    results['port'] = port
    return results

def quotedstr(s):
    return "\"" + s + "\""

def verdict(results):
    if results['selfsigned']:
        print datetime.datetime.now().isoformat()
        print quotedstr(results['host']) + "," + str(results['port']) + "-" + str(results['selfsigned'])

##########################
if __name__ == "__main__":
    conf = main(sys.argv[1:])
    print conf

    if 'inputfile' not in conf:
        print "No inputfile provided"
        help()
        sys.exit(1)

    i = open(conf['inputfile'], "r")
    csvreader = csv.reader(i)

    for row in csvreader:
        print ', '.join(row)
        host = row[0]
        port = 443

        results = sslscan(host, port)
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(results)

        verdict(results)

        break


"""

                   _
           ___ ___| |___  ___ __ _ _ __
          / __/ __| / __|/ __/ _` | '_ \
          \__ \__ \ \__ \ (_| (_| | | | |
          |___/___/_|___/\___\__,_|_| |_|

                  Version 1.8.2
             http://www.titania.co.uk
        Copyright Ian Ventura-Whiting 2009

Testing SSL server www.kpn.com on port 443

  Supported Server Cipher(s):
    Failed    SSLv2  168 bits  DES-CBC3-MD5
    Failed    SSLv2  56 bits   DES-CBC-MD5
    Failed    SSLv2  40 bits   EXP-RC2-CBC-MD5
    Failed    SSLv2  128 bits  RC2-CBC-MD5
    Failed    SSLv2  40 bits   EXP-RC4-MD5
    Failed    SSLv2  128 bits  RC4-MD5
    Rejected  SSLv3  256 bits  ADH-AES256-SHA
    Rejected  SSLv3  256 bits  DHE-RSA-AES256-SHA
    Rejected  SSLv3  256 bits  DHE-DSS-AES256-SHA
    Rejected  SSLv3  256 bits  AES256-SHA
    Rejected  SSLv3  128 bits  ADH-AES128-SHA
    Rejected  SSLv3  128 bits  DHE-RSA-AES128-SHA
    Rejected  SSLv3  128 bits  DHE-DSS-AES128-SHA
    Rejected  SSLv3  128 bits  AES128-SHA
    Rejected  SSLv3  168 bits  ADH-DES-CBC3-SHA
    Rejected  SSLv3  56 bits   ADH-DES-CBC-SHA
    Rejected  SSLv3  40 bits   EXP-ADH-DES-CBC-SHA
    Rejected  SSLv3  128 bits  ADH-RC4-MD5
    Rejected  SSLv3  40 bits   EXP-ADH-RC4-MD5
    Rejected  SSLv3  168 bits  EDH-RSA-DES-CBC3-SHA
    Rejected  SSLv3  56 bits   EDH-RSA-DES-CBC-SHA
    Rejected  SSLv3  40 bits   EXP-EDH-RSA-DES-CBC-SHA
    Rejected  SSLv3  168 bits  EDH-DSS-DES-CBC3-SHA
    Rejected  SSLv3  56 bits   EDH-DSS-DES-CBC-SHA
    Rejected  SSLv3  40 bits   EXP-EDH-DSS-DES-CBC-SHA
    Rejected  SSLv3  168 bits  DES-CBC3-SHA
    Rejected  SSLv3  56 bits   DES-CBC-SHA
    Rejected  SSLv3  40 bits   EXP-DES-CBC-SHA
    Rejected  SSLv3  40 bits   EXP-RC2-CBC-MD5
    Rejected  SSLv3  128 bits  RC4-SHA
    Rejected  SSLv3  128 bits  RC4-MD5
    Rejected  SSLv3  40 bits   EXP-RC4-MD5
    Rejected  SSLv3  0 bits    NULL-SHA
    Rejected  SSLv3  0 bits    NULL-MD5
    Rejected  TLSv1  256 bits  ADH-AES256-SHA
    Rejected  TLSv1  256 bits  DHE-RSA-AES256-SHA
    Rejected  TLSv1  256 bits  DHE-DSS-AES256-SHA
    Accepted  TLSv1  256 bits  AES256-SHA
    Rejected  TLSv1  128 bits  ADH-AES128-SHA
    Rejected  TLSv1  128 bits  DHE-RSA-AES128-SHA
    Rejected  TLSv1  128 bits  DHE-DSS-AES128-SHA
    Accepted  TLSv1  128 bits  AES128-SHA
    Rejected  TLSv1  168 bits  ADH-DES-CBC3-SHA
    Rejected  TLSv1  56 bits   ADH-DES-CBC-SHA
    Rejected  TLSv1  40 bits   EXP-ADH-DES-CBC-SHA
    Rejected  TLSv1  128 bits  ADH-RC4-MD5
    Rejected  TLSv1  40 bits   EXP-ADH-RC4-MD5
    Accepted  TLSv1  168 bits  EDH-RSA-DES-CBC3-SHA
    Rejected  TLSv1  56 bits   EDH-RSA-DES-CBC-SHA
    Rejected  TLSv1  40 bits   EXP-EDH-RSA-DES-CBC-SHA
    Rejected  TLSv1  168 bits  EDH-DSS-DES-CBC3-SHA
    Rejected  TLSv1  56 bits   EDH-DSS-DES-CBC-SHA
    Rejected  TLSv1  40 bits   EXP-EDH-DSS-DES-CBC-SHA
    Accepted  TLSv1  168 bits  DES-CBC3-SHA
    Rejected  TLSv1  56 bits   DES-CBC-SHA
    Rejected  TLSv1  40 bits   EXP-DES-CBC-SHA
    Rejected  TLSv1  40 bits   EXP-RC2-CBC-MD5
    Accepted  TLSv1  128 bits  RC4-SHA
    Accepted  TLSv1  128 bits  RC4-MD5
    Rejected  TLSv1  40 bits   EXP-RC4-MD5
    Rejected  TLSv1  0 bits    NULL-SHA
    Rejected  TLSv1  0 bits    NULL-MD5

  Prefered Server Cipher(s):
    TLSv1  256 bits  AES256-SHA

  SSL Certificate:
    Version: 2
    Serial Number: 4294967295
    Signature Algorithm: sha256WithRSAEncryption
    Issuer: /C=BE/O=GlobalSign nv-sa/CN=GlobalSign Extended Validation CA - SHA256 - G2
    Not valid before: Aug 25 09:02:02 2015 GMT
    Not valid after: Jul 16 13:44:25 2017 GMT
    Subject: /2.5.4.15=Private Organization/serialNumber=27124701/1.3.6.1.4.1.311.60.2.1.3=NL/C=NL/ST=Zuid Holland/L=Den Haag/streetAddress=Maanplein 55/OU=ITNL/O=KPN B.V./CN=www.kpn.com
    Public Key Algorithm: rsaEncryption
    RSA Public Key: (2048 bit)
      Modulus (2048 bit):
          00:9d:8b:1f:b5:96:10:48:c2:12:ab:65:a6:ff:8a:
          8e:cf:53:16:87:0d:44:44:7f:f8:c7:6a:1a:2a:c3:
          8b:71:d1:8e:95:5f:e5:31:6f:5b:d9:b5:b5:55:bd:
          b8:dc:15:f8:0b:fd:3d:95:4f:c5:57:f9:b2:e2:71:
          54:2e:db:04:7a:54:72:22:20:54:5d:60:8f:19:c1:
          95:53:68:f4:ad:7a:74:3f:27:38:fb:9a:2f:9b:d5:
          04:b2:7c:ee:95:7e:a4:ff:e8:d2:07:fb:94:45:a5:
          92:c7:67:c0:26:81:ea:0e:40:47:b9:26:f9:56:b3:
          85:70:3f:64:a5:82:d0:1d:d2:79:ba:b9:92:e3:ce:
          57:65:9f:a1:09:4a:c8:66:e5:95:bd:cc:1a:44:5e:
          e3:4c:cc:08:cb:08:ce:88:3d:1c:e2:9f:04:3a:73:
          d8:d0:0a:a5:8a:6e:be:ff:fb:fb:29:f6:8d:ba:72:
          6b:e8:81:73:d8:38:97:45:e3:01:8e:44:cf:d0:04:
          71:ab:dd:85:a7:8c:54:44:71:4a:e1:f0:6b:ba:99:
          14:d4:89:23:cf:f0:d9:4d:e9:4a:16:92:87:3f:10:
          db:fc:28:d0:50:1a:4d:8a:a3:f3:45:2a:00:14:b7:
          43:36:23:c4:e9:2b:c7:1a:49:6e:25:2c:27:aa:21:
          9d:2f
      Exponent: 65537 (0x10001)
    X509v3 Extensions:
      X509v3 Key Usage: critical
        Digital Signature, Key Encipherment
      Authority Information Access:
        CA Issuers - URI:http://secure.globalsign.com/cacert/gsextendvalsha2g2r2.crt
        OCSP - URI:http://ocsp2.globalsign.com/gsextendvalsha2g2

      X509v3 Certificate Policies:
        Policy: 1.3.6.1.4.1.4146.1.1
          CPS: https://www.globalsign.com/repository/

      X509v3 Basic Constraints:
        CA:FALSE
      X509v3 CRL Distribution Points:
        URI:http://crl.globalsign.com/gs/gsextendvalsha2g2.crl

      X509v3 Subject Alternative Name:
        DNS:www.kpn.com, DNS:www.kpn.nl, DNS:inloggen.kpn.com, DNS:m.kpn.com, DNS:beta.kpn.com, DNS:kpn.nl, DNS:kpn.com
      X509v3 Extended Key Usage:
        TLS Web Server Authentication, TLS Web Client Authentication
      X509v3 Subject Key Identifier:
        AC:F9:FF:64:4A:90:E6:5C:86:E2:1B:4E:AE:72:59:4C:28:C2:BF:79
      X509v3 Authority Key Identifier:
        keyid:DA:40:77:43:65:1C:F8:FE:A7:E3:F4:64:82:3E:4D:43:13:22:31:02

      1.3.6.1.4.1.11129.2.4.2:
        ...Y.W.v.h....d..:...(.L.qQ]g..D.
g..OO.....Od........G0E.!..a...r.;....}.....!~..s....Q..... KR..X.....{5wH+a../......*.....l.v.......X......gp
.....Od..n.....G0E. .. .Z|.Dy....V...(.i.p5..#j...6..!........4....j....|OV.i:r$&.SB.Pu.v..K..u.`..Bi....f..~_.r....{.z......Od........G0E.!.....1...H..l.....s.....*.. .[.x.. ......"..;.4*v!.)y..3J.......2.........Q-.v.V.../.......D.>.Fv....\....U.......Od........G0E. 0..j..y.......|..R[...8.(.e.>i...!..$.4.6....n..&.Z.Y9..Z....FZ.3i.
  Verify Certificate:
    unable to get local issuer certificate

"""
