import 'dart:convert';
import 'dart:typed_data';
import 'package:asn1lib/asn1lib.dart';
import 'package:pointycastle/asymmetric/api.dart';

class RSAHelper
{
  static RSAPublicKey parsePublicKeyFromPem(String pemString) {
    List<int> publicKeyDER = _decodePEM(pemString);
    ASN1Parser asn1Parser = ASN1Parser(publicKeyDER as Uint8List);
    ASN1Sequence topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
    ASN1Integer modulus;
    ASN1Integer exponent;
    // Depending on the first element type, we either have PKCS1 or 2
    if (topLevelSeq.elements[0].runtimeType == ASN1Integer) {
      modulus = topLevelSeq.elements[0] as ASN1Integer;
      exponent = topLevelSeq.elements[1] as ASN1Integer;
    } else {
      ASN1Object publicKeyBitString = topLevelSeq.elements[1];
      ASN1Parser publicKeyAsn = ASN1Parser(publicKeyBitString.contentBytes()!);
      ASN1Sequence publicKeySeq = publicKeyAsn.nextObject() as ASN1Sequence;
      modulus = publicKeySeq.elements[0] as ASN1Integer;
      exponent = publicKeySeq.elements[1] as ASN1Integer;
    }
    RSAPublicKey rsaPublicKey =
    RSAPublicKey(modulus.valueAsBigInteger!, exponent.valueAsBigInteger!);
    return rsaPublicKey;
  }

  static RSAPrivateKey parsePrivateKeyFromPem(String pemString) {
    List<int> privateKeyDER = _decodePEM(pemString);
    ASN1Parser asn1Parser = ASN1Parser(privateKeyDER as Uint8List);
    ASN1Sequence topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    ASN1Integer modulus;
    ASN1Integer privateExponent;
    ASN1Integer p;
    ASN1Integer q;

    //Use either PKCS1 or PKCS8 depending on the number of ELEMENTS
    if (topLevelSeq.elements.length == 3) {
      ASN1Object privateKey = topLevelSeq.elements[2];

      asn1Parser = ASN1Parser(privateKey.contentBytes()!);
      ASN1Sequence pkSeq = asn1Parser.nextObject() as ASN1Sequence;

      modulus = pkSeq.elements[1] as ASN1Integer;
      privateExponent = pkSeq.elements[3] as ASN1Integer;
      p = pkSeq.elements[4] as ASN1Integer;
      q = pkSeq.elements[5] as ASN1Integer;
    } else {
      modulus = topLevelSeq.elements[1] as ASN1Integer;
      privateExponent = topLevelSeq.elements[3] as ASN1Integer;
      p = topLevelSeq.elements[4] as ASN1Integer;
      q = topLevelSeq.elements[5] as ASN1Integer;
    }

    RSAPrivateKey rsaPrivateKey = RSAPrivateKey(
        modulus.valueAsBigInteger!,
        privateExponent.valueAsBigInteger!,
        p.valueAsBigInteger,
        q.valueAsBigInteger);

    return rsaPrivateKey;
  }


  static List<int> _decodePEM(String pem) {
    return base64.decode(_removePemHeaderAndFooter(pem));
  }


  static String _removePemHeaderAndFooter(String pem) {
    List<String> startsWith = <String>[
      '-----BEGIN PUBLIC KEY-----',
      '-----BEGIN RSA PRIVATE KEY-----',
      '-----BEGIN RSA PUBLIC KEY-----',
      '-----BEGIN PRIVATE KEY-----',
      '-----BEGIN PGP PUBLIC KEY BLOCK-----\r\nVersion: React-Native-OpenPGP.js 0.1\r\nComment: http://openpgpjs.org\r\n\r\n',
      '-----BEGIN PGP PRIVATE KEY BLOCK-----\r\nVersion: React-Native-OpenPGP.js 0.1\r\nComment: http://openpgpjs.org\r\n\r\n',
    ];
    List<String> endsWith = <String>[
      '-----END PUBLIC KEY-----',
      '-----END PRIVATE KEY-----',
      '-----END RSA PRIVATE KEY-----',
      '-----END RSA PUBLIC KEY-----',
      '-----END PGP PUBLIC KEY BLOCK-----',
      '-----END PGP PRIVATE KEY BLOCK-----',
    ];
    bool isOpenPgp = pem.contains('BEGIN PGP');

    pem = pem.replaceAll(' ', '');
    pem = pem.replaceAll('\n', '');
    pem = pem.replaceAll('\r', '');

    for (String s in startsWith) {
      s = s.replaceAll(' ', '');
      if (pem.startsWith(s)) {
        pem = pem.substring(s.length);
      }
    }

    for (String s in endsWith) {
      s = s.replaceAll(' ', '');
      if (pem.endsWith(s)) {
        pem = pem.substring(0, pem.length - s.length);
      }
    }

    if (isOpenPgp) {
      int index = pem.indexOf('\r\n');
      pem = pem.substring(0, index);
    }

    return pem;
  }
}