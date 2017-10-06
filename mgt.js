const forge = require('node-forge')
const dom = require('xmldom').DOMParser

function loadCert (certificateBase64, pass) {
  // let p12b64 = Buffer(certificateBase64).toString('base64')
  let p12Der = forge.util.decode64(certificateBase64)
  let p12Asn1 = forge.asn1.fromDer(p12Der)
  let p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, pass)

  const certBags = p12.getBags({bagType: forge.pki.oids.certBag})
  const certBag = certBags[forge.pki.oids.certBag][0]

  const keyBags = p12.getBags({bagType: forge.pki.oids.pkcs8ShroudedKeyBag})
  const keyBag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag][0]

  const cert = certBag.cert
  const publicKey = cert.publicKey
  const privateKey = keyBag.key

  let certPem = forge.pki.certificateToPem(cert)
  const privateKeyPem = forge.pki.privateKeyToPem(privateKey)
  const publicKeyPem = forge.pki.publicKeyToPem(publicKey)

  certPem = certPem.replace('-----BEGIN CERTIFICATE-----', '')
  certPem = certPem.replace('-----END CERTIFICATE-----', '')
  certPem = certPem.trim()

  return {certificate: certPem, privateKey: privateKey, publicKey: publicKey}
}

if (!String.prototype.splice) {
    String.prototype.splice = function(start, delCount, newSubStr) {
        return this.slice(0, start) + newSubStr + this.slice(start + Math.abs(delCount))
    }
}

function renderSignature (xml, id = '', certificatePem, privateKey) {

  let c14nXml = xml.replace(/\r\n/g, '\n')
  c14nXml = c14nXml.replace(/\sxmlns="http:\/\/www\.abrasf\.org\.br\/nfse\.xsd"/, '')
  c14nXml = c14nXml.splice(c14nXml.search('Id='), 0, 'xmlns="http://www.abrasf.org.br/nfse.xsd" ')

  const md = forge.md.sha1.create()
  md.update(c14nXml, 'utf8')
  const digestValue = forge.util.encode64(md.digest().data)

  const signedInfoContent =
    '<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315">'+
    '</CanonicalizationMethod>'+
    '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></SignatureMethod>'+
    '<Reference URI="'+id+'">'+
      '<Transforms>'+
        '<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></Transform>'+
        '<Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></Transform>'+
      '</Transforms>'+
      '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod>'+
      '<DigestValue>'+digestValue+'</DigestValue>'+
    '</Reference>'

  const unsignedInfoTag = '<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">'+signedInfoContent+'</SignedInfo>'

  const signAlgo = forge.md.sha1.create()
  signAlgo.update(unsignedInfoTag, 'utf-8')
  const signatureValue = forge.util.encode64(privateKey.sign(signAlgo))

  const signature = '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">' +
                      '<SignedInfo>' + signedInfoContent + '</SignedInfo>' +
                      '<SignatureValue>' + signatureValue + '</SignatureValue>' +
                      '<KeyInfo><X509Data><X509Certificate>' +
                        certificatePem +
                      '</X509Certificate></X509Data></KeyInfo>' +
                    '</Signature>'

  return signature
}

exports.sign = function (xml, cert, pass) {
  const { certificate, privateKey } = loadCert(cert, pass)

  xml = xml.replace(/>\s*</g, '><')
  xml = '<?xml version="1.0" encoding="UTF-8"?>' +
        '<EnviarLoteRpsEnvio xmlns="http://www.abrasf.org.br/nfse.xsd">'
        + xml +
        '</EnviarLoteRpsEnvio>'

  const doc = new dom().parseFromString(xml)

  const rpsDoc = doc.getElementsByTagName('InfRps')[0]
  const rpsId = rpsDoc.getAttribute('Id')
  const rpsSig = renderSignature(rpsDoc.toString(), `#${rpsId}`, certificate, privateKey)

  const loteDoc = doc.documentElement.getElementsByTagName('LoteRps')[0]
  const loteDocString = loteDoc.toString()
  const loteId = loteDoc.getAttribute('Id')
  const loteWithSignedRps = loteDocString.splice(loteDocString.search('</Rps>'), 0, rpsSig)
  const loteSig = renderSignature(loteWithSignedRps, `#${loteId}`)

  let finalXml = xml.splice(xml.search('</Rps>'), 0, rpsSig)
  finalXml = finalXml.splice(finalXml.search('</EnviarLoteRpsEnvio>'), 0, loteSig)
  const finalDoc = new dom().parseFromString(finalXml)
}
