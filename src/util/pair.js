
import { subtle } from './crypto';

export async function pair() {

  let ecdhSubtle = subtle;

  // First: ECDSA keys for signing/verifying...

  let sa = await subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256'
    },
    true,
    ['sign', 'verify']
  ).then(async (keys) => {
    // privateKey scope doesn't leak out from here!
    //const { d: priv } = await shim.subtle.exportKey('jwk', keys.privateKey)
    let key = {};
    key.priv = (await subtle.exportKey('jwk', keys.privateKey)).d;
    let pub = await subtle.exportKey('jwk', keys.publicKey);
    //const pub = Buff.from([ x, y ].join(':')).toString('base64') // old
    key.pub = pub.x+'.'+pub.y; // new
    // x and y are already base64
    // pub is UTF8 but filename/URL safe (https://www.ietf.org/rfc/rfc3986.txt)
    // but split on a non-base64 letter.
    return key;
  });

  // To include PGPv4 kind of keyId:
  // const pubId = await SEA.keyid(keys.pub)
  // Next: ECDH keys for encryption/decryption...
  let dh;

  try {
    dh = await ecdhSubtle.generateKey({name: 'ECDH', namedCurve: 'P-256'}, true, ['deriveKey'])
      .then(async (keys) => {
        // privateKey scope doesn't leak out from here!
        var key = {};
        key.epriv = (await ecdhSubtle.exportKey('jwk', keys.privateKey)).d;
        var pub = await ecdhSubtle.exportKey('jwk', keys.publicKey);
        //const epub = Buff.from([ ex, ey ].join(':')).toString('base64') // old
        key.epub = pub.x+'.'+pub.y; // new
        // ex and ey are already base64
        // epub is UTF8 but filename/URL safe (https://www.ietf.org/rfc/rfc3986.txt)
        // but split on a non-base64 letter.
        return key;
      });

  } catch(error) {
    if (error == 'Error: ECDH is not a supported algorithm') {
      console.log('Ignoring ECDH...')
    }
  }

  dh = dh || {};

  let r = {
    pub: sa.pub,
    priv: sa.priv,
    epub: dh.epub,
    epriv: dh.epriv
  };

  return r;
}
