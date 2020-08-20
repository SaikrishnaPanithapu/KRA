import { Component } from '@angular/core';
import { sha256 } from 'js-sha256';
import base64 from '@lapo/asn1js/base64';
import asn1js from '@lapo/asn1js';
import * as JsEncryptModule from 'jsencrypt';
import * as CryptoJS from 'crypto-js';
// declare var require;
// const Quassel = require('node-rsa/src/NodeRSA.js');
import * as forge from 'node-forge';


// import * as nodeRsa from 'node-rsa';
// import * as CryptoJS from 'crypto-js/aes';
// import * as CryptoJS from 'crypto-js/aes';
// import * as sha256Hash from 'crypto-js/sha256';
import utf8 from "utf8";
// import base64 from "base-64";
import { Certificate, RSAPublicKey, PublicKey } from "@fidm/x509";


@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent {
  name = 'Sai Krishna';
  testPublicKey = `-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhUkC8UT3QEFAPZ75FwaFUB+hvchMXaPHvWElw8p5+ilZgKoDXHpOxVOoFmE2clTzau0/OBj1T32rZmP7Km41Po0b22pkK8TByIz4Vi5IPczwZW251705ECh/FvKc4HbsgLIU6Am2zPznB5l0+BEAVcmvCDs1hnXwajZrC69ubTGLn1RcW4k/eOSwGEYb2/c7EJtW/BRyA0UvnixiO+7b4fyhF4wmilzMg6FukF9X3IL4HANj6Z+NqzyaNtbkGa/JQr/AEDLFLoDLp3Wx4Ea+7pd3sLTwftdsty9+7W2XndIv2Yt1k60j4MIM9NMKCxCuBTiIzUJVUkk/cnskRYaG9wIDAQAB-----END PUBLIC KEY-----`
  publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhUkC8UT3QEFAPZ75FwaFUB+hvchMXaPHvWElw8p5+ilZgKoDXHpOxVOoFmE2clTzau0/OBj1T32rZmP7Km41Po0b22pkK8TByIz4Vi5IPczwZW251705ECh/FvKc4HbsgLIU6Am2zPznB5l0+BEAVcmvCDs1hnXwajZrC69ubTGLn1RcW4k/eOSwGEYb2/c7EJtW/BRyA0UvnixiO+7b4fyhF4wmilzMg6FukF9X3IL4HANj6Z+NqzyaNtbkGa/JQr/AEDLFLoDLp3Wx4Ea+7pd3sLTwftdsty9+7W2XndIv2Yt1k60j4MIM9NMKCxCuBTiIzUJVUkk/cnskRYaG9wIDAQAB";
  hashValue = "";
  base64map
    = 'abcdefghijklmnopqrstuvwxyz0123456789';
  DIGITS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
  forge = forge;
  ngOnInit() {
    // console.log(asn1.decode);
    console.log(this.forge);


    // console.log(this.forge.pki.publicKeyFromPem(this.testPublicKey));
    this.hashValue = sha256('A2020-07-220P051505257JKRAMW563202007004955');
    const publicKeyFromPem = this.forge.pki.publicKeyFromPem(this.testPublicKey);
    // let ffdd = this.forge.pki.publicKeyToAsn1(this.testPublicKey)
    // const strss = publicKeyFromPem.n.data.toString().replace(/,/g, '');
    let encode = new TextEncoder();
    const bytesforge = encode.encode(this.hashValue);
    const options = {
      md: this.forge.md.sha256.create(),
      mgf1: {
        md: this.forge.md.sha1.create()
      }
    }
    var encrypted = publicKeyFromPem.encrypt(bytesforge, 'RSA-OAEP', options);
    console.log(encrypted);
    // const byteas: any = this.base64ToArrayBuffer(encrypted);
    // let sar = this.forge.util.createBuffer(encrypted)
    // const tt = this.forge.util.encode64(encrypted);
    console.log(new String(encrypted));
    let outss = new Array();
    // let encryptedBytes = encode.encode(encrypted);
    // const encryptedBytes: any = this.forge.util.format(encrypted);
    var encryptedBytes = this.forge.util.createBuffer(encrypted);
    
    // const encryptedBytes = [91, 78, 98, 42, 98, 48, -107, 113, -50, 25, -110, 98, 4, -13, 66, -86, -90, -121, 39, 72, 42, 7, 8, -103, -71, -109, -115, -73, -68, 68, 59, 72, -27, 92, 4, -40, 92, -39, 63, 8, 93, 22, -35, -53, 55, 16, 95, -57, 82, -89, -97, 101, 25, 0, 8, -26, 12, -51, 39, 21, -92, 73, 50, 120, -114, -94, 57, 26, 3, -50, 127, 16, -20, 49, -49, -35, -42, 124, -96, -126, -67, -122, 119, -94, -10, 107, -8, 48, -104, -113, 64, 42, -15, -66, -11, 62, 82, -67, 109, -10, 89, 121, 113, -89, 110, 29, 110, 13, 13, 123, 102, 13, -21, -105, -119, 104, -128, 127, -22, -90, 126, 69, -55, 6, -69, -10, 47, -12, 84, 46, 13, 98, -22, -57, 109, 98, 120, -5, -109, 25, 46, 36, 46, -71, -25, -82, -20, -14, -20, 18, -70, -78, -24, 43, -125, -122, -80, 76, 90, 63, -37, -51, 16, 99, 103, -30, -79, 33, -111, 3, -35, 14, 77, -27, 36, -124, -38, 2, 36, 28, -32, 31, 67, -3, -26, -86, 14, 64, 52, 32, -75, 90, 1, -112, 65, -86, 97, -24, 57, -66, -83, 99, 82, 43, -53, -123, 125, -82, 105, 58, -90, 76, -67, -94, 8, 88, 74, 1, 49, -45, 35, 2, -37, -64, -119, 117, 107, -37, -116, 91, 47, -58, 112, -32, 83, -75, -40, 115, 69, 32, -108, -75, -29, -101, -120, 32, -34, -71, 48, 124, 107, 83, -33, -49, 28, 109];
    for (let i = 0, j = 0; i < encryptedBytes.length; i++) {
      outss[j++] = this.DIGITS[(0xF0 & encryptedBytes[i]) >>> 4];
      outss[j++] = this.DIGITS[0x0F & encryptedBytes[i]];
    }
    const strs = outss.toString().replace(/,/g, '');
    console.log(strs);
    // var iv = CryptoJS.lib.WordArray.random(128 / 8).toString(CryptoJS.enc.Hex);
    // var salt = CryptoJS.lib.WordArray.random(128 / 8).toString(CryptoJS.enc.Hex);

    // const ss = CryptoJS.encrypt("Message", "Secret Passphrase")
    // this.hashValue = sha256('A2020-07-220P051505257JKRAMW563202007004955');
    // var ciphertext = CryptoJS.AES.encrypt(this.hashValue, this.publicKey).toString();
    // const bytesa = this.base64ToArrayBuffer(ciphertext);
    // let outs = new Array();

    // for (let i = 0, j = 0; i < bytesa.length; i++) {
    //   outs[j++] = this.DIGITS[(0xF0 & bytesa[i]) >>> 4];
    //   outs[j++] = this.DIGITS[0x0F & bytesa[i]];
    // }
    // const str1 = outs.toString().replace(/,/g, '');
    // console.log(str1);
    // const byteArray = utf8.encode(this.hashValue);
    // const bytes = base64.decode(this.publicKey)
    const spec = base64.unarmor(this.publicKey);
    const finalSpec = asn1js.decode(spec);
    // finalSpec.toPrettyString();
    // var encrypt = new JsEncryptModule.JSEncrypt();
    // encrypt.setPublicKey(this.publicKey);
    // var encrypted = encrypt.encrypt(this.hashValue);
    // console.log(encrypted);




    // var encrypt = new JsEncryptModule.JSEncrypt();
    // encrypt.setPublicKey(this.publicKey)
    // console.log(encrypt);
    // var encrypted = encrypt.encrypt(this.hashValue);
    // const arr = this.toUTF8Array(encrypted);
    let obj = {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: "SHA-256",
    }
    const encObj = {
      name: "RSA-OAEP",
      iv: crypto.getRandomValues(new Uint8Array(16))
    }
    const self = this;
    const key: any = {
      publickey: this.publicKey
    }
    const pem = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhUkC8UT3QEFAPZ75FwaFUB+hvchMXaPHvWElw8p5+ilZgKoDXHpOxVOoFmE2clTzau0/OBj1T32rZmP7Km41Po0b22pkK8TByIz4Vi5IPczwZW251705ECh/FvKc4HbsgLIU6Am2zPznB5l0+BEAVcmvCDs1hnXwajZrC69ubTGLn1RcW4k/eOSwGEYb2/c7EJtW/BRyA0UvnixiO+7b4fyhF4wmilzMg6FukF9X3IL4HANj6Z+NqzyaNtbkGa/JQr/AEDLFLoDLp3Wx4Ea+7pd3sLTwftdsty9+7W2XndIv2Yt1k60j4MIM9NMKCxCuBTiIzUJVUkk/cnskRYaG9wIDAQAB";
    // const pemHeader = "-----BEGIN PUBLIC KEY-----";
    // const pemFooter = "-----END PUBLIC KEY-----";
    // const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length);
    // base64 decode the string to get the binary data
    // convert from a binary string to an ArrayBuffer
    // const binaryDer = this.str2ab(pem);
    let enc = new TextEncoder();

    // const encoded = enc.encode(this.hashValue);
    // const encoded = this.base64ToArrayBuffer(this.hashValue);
    const encoded = enc.encode(this.hashValue);

    const bytes: any = this.base64ToArrayBuffer(pem);

    window.crypto.subtle.importKey(
      "spki",
      bytes,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      true,
      ["encrypt"]
    ).then(function (key) {
      return window.crypto.subtle.encrypt(encObj, key, encoded)
    })
      // window.crypto.subtle.generateKey(obj, true, ["encrypt"]).then(function (key: any) {
      //   console.log(key);
      //   const encObj = {
      //     name: "RSA-OAEP",
      //   }
      //   return window.crypto.subtle.encrypt(encObj, key.publicKey, self.strToArrayBuffer(self.hashValue));
      //   // return window.crypto.subtle.encrypt(algoEncrypt, key, strToArrayBuffer(plainText));
      // })

      // window.crypto.subtle.encrypt(encObj, key, self.strToArrayBuffer(self.hashValue))
      .then(function (cipherText) {
        console.log('Cipher Text: ' + cipherText);
        var finalArr = new Int8Array(cipherText);
        // const finalArr = [91, 78, 98, 42, 98, 48, -107, 113, -50, 25, -110, 98, 4, -13, 66, -86, -90, -121, 39, 72, 42, 7, 8, -103, -71, -109, -115, -73, -68, 68, 59, 72, -27, 92, 4, -40, 92, -39, 63, 8, 93, 22, -35, -53, 55, 16, 95, -57, 82, -89, -97, 101, 25, 0, 8, -26, 12, -51, 39, 21, -92, 73, 50, 120, -114, -94, 57, 26, 3, -50, 127, 16, -20, 49, -49, -35, -42, 124, -96, -126, -67, -122, 119, -94, -10, 107, -8, 48, -104, -113, 64, 42, -15, -66, -11, 62, 82, -67, 109, -10, 89, 121, 113, -89, 110, 29, 110, 13, 13, 123, 102, 13, -21, -105, -119, 104, -128, 127, -22, -90, 126, 69, -55, 6, -69, -10, 47, -12, 84, 46, 13, 98, -22, -57, 109, 98, 120, -5, -109, 25, 46, 36, 46, -71, -25, -82, -20, -14, -20, 18, -70, -78, -24, 43, -125, -122, -80, 76, 90, 63, -37, -51, 16, 99, 103, -30, -79, 33, -111, 3, -35, 14, 77, -27, 36, -124, -38, 2, 36, 28, -32, 31, 67, -3, -26, -86, 14, 64, 52, 32, -75, 90, 1, -112, 65, -86, 97, -24, 57, -66, -83, 99, 82, 43, -53, -123, 125, -82, 105, 58, -90, 76, -67, -94, 8, 88, 74, 1, 49, -45, 35, 2, -37, -64, -119, 117, 107, -37, -116, 91, 47, -58, 112, -32, 83, -75, -40, 115, 69, 32, -108, -75, -29, -101, -120, 32, -34, -71, 48, 124, 107, 83, -33, -49, 28, 109];
        let out = new Array();

        for (let i = 0, j = 0; i < finalArr.length; i++) {
          out[j++] = self.DIGITS[(0xF0 & finalArr[i]) >>> 4];
          out[j++] = self.DIGITS[0x0F & finalArr[i]];
        }
        const str = out.toString().replace(/,/g, '');
        console.log(str);
      })




    const arrFinal = [91, 78, 98, 42, 98, 48, -107, 113, -50, 25, -110, 98, 4, -13, 66, -86, -90, -121, 39, 72, 42, 7, 8, -103, -71, -109, -115, -73, -68, 68, 59, 72, -27, 92, 4, -40, 92, -39, 63, 8, 93, 22, -35, -53, 55, 16, 95, -57, 82, -89, -97, 101, 25, 0, 8, -26, 12, -51, 39, 21, -92, 73, 50, 120, -114, -94, 57, 26, 3, -50, 127, 16, -20, 49, -49, -35, -42, 124, -96, -126, -67, -122, 119, -94, -10, 107, -8, 48, -104, -113, 64, 42, -15, -66, -11, 62, 82, -67, 109, -10, 89, 121, 113, -89, 110, 29, 110, 13, 13, 123, 102, 13, -21, -105, -119, 104, -128, 127, -22, -90, 126, 69, -55, 6, -69, -10, 47, -12, 84, 46, 13, 98, -22, -57, 109, 98, 120, -5, -109, 25, 46, 36, 46, -71, -25, -82, -20, -14, -20, 18, -70, -78, -24, 43, -125, -122, -80, 76, 90, 63, -37, -51, 16, 99, 103, -30, -79, 33, -111, 3, -35, 14, 77, -27, 36, -124, -38, 2, 36, 28, -32, 31, 67, -3, -26, -86, 14, 64, 52, 32, -75, 90, 1, -112, 65, -86, 97, -24, 57, -66, -83, 99, 82, 43, -53, -123, 125, -82, 105, 58, -90, 76, -67, -94, 8, 88, 74, 1, 49, -45, 35, 2, -37, -64, -119, 117, 107, -37, -116, 91, 47, -58, 112, -32, 83, -75, -40, 115, 69, 32, -108, -75, -29, -101, -120, 32, -34, -71, 48, 124, 107, 83, -33, -49, 28, 109];
    
    let out = new Array();

    for (let i = 0, j = 0; i < 256; i++) {
      out[j++] = this.DIGITS[(0xF0 & arrFinal[i]) >>> 4];
      out[j++] = this.DIGITS[0x0F & arrFinal[i]];
    }
    const str = out.toString().replace(/,/g, '');
    console.log(str);

  }
  convertPemToBinary(pem) {
    var lines = pem.split('\n')
    var encoded = ''
    for (var i = 0; i < lines.length; i++) {
      if (lines[i].trim().length > 0 &&
        lines[i].indexOf('-BEGIN RSA PRIVATE KEY-') < 0 &&
        lines[i].indexOf('-BEGIN RSA PUBLIC KEY-') < 0 &&
        lines[i].indexOf('-END RSA PRIVATE KEY-') < 0 &&
        lines[i].indexOf('-END RSA PUBLIC KEY-') < 0) {
        encoded += lines[i].trim()
      }
    }
    return this.base64ToArrayBuffer(encoded)
  }
  b64DecodeUnicode(str) {
    return decodeURIComponent(Array.prototype.map.call(atob(str), function (c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
  }
  base64ToArrayBuffer(b64) {
    var byteString = window.atob(b64);
    var byteArray = new Int8Array(byteString.length);
    for (var i = 0; i < byteString.length; i++) {
      byteArray[i] = byteString.charCodeAt(i);
    }

    return byteArray;
  }
  str2ab(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Int8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  }
  strToArrayBuffer(str) {
    var buf = new ArrayBuffer(str.length * 2);
    var bufView = new Int8Array(buf);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  }
  bytesToBase64(bytes) {
    for (var base64 = [], i = 0; i < bytes.length; i += 3) {
      var triplet = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
      for (var j = 0; j < 4; j++)
        if (i * 8 + j * 6 <= bytes.length * 8)
          base64.push(this.base64map.charAt((triplet >>> 6 * (3 - j)) & 0x3F));
        else
          base64.push('=');
    }
    return base64.join('');
  };
  toUTF8Array(str) {
    var utf8 = [];
    for (var i = 0; i < str.length; i++) {
      var charcode = str.charCodeAt(i);
      if (charcode < 0x80) utf8.push(charcode);
      else if (charcode < 0x800) {
        utf8.push(0xc0 | (charcode >> 6),
          0x80 | (charcode & 0x3f));
      }
      else if (charcode < 0xd800 || charcode >= 0xe000) {
        utf8.push(0xe0 | (charcode >> 12),
          0x80 | ((charcode >> 6) & 0x3f),
          0x80 | (charcode & 0x3f));
      }
      // surrogate pair
      else {
        i++;
        // UTF-16 encodes 0x10000-0x10FFFF by
        // subtracting 0x10000 and splitting the
        // 20 bits of 0x0-0xFFFFF into two halves
        charcode = 0x10000 + (((charcode & 0x3ff) << 10)
          | (str.charCodeAt(i) & 0x3ff))
        utf8.push(0xf0 | (charcode >> 18),
          0x80 | ((charcode >> 12) & 0x3f),
          0x80 | ((charcode >> 6) & 0x3f),
          0x80 | (charcode & 0x3f));
      }
    }
    return utf8;
  }
}
