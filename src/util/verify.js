
import { subtle } from './crypto';
import { sha256 } from './sha256';
import { getJwk } from './settings';

export async function verify(message, signature, publickey, options) {
  options = options || {};

  try {
    let key = await subtle.importKey('jwk', getJwk(publickey), {
      name: 'ECDSA',
      namedCurve: 'P-256'
    }, false, ['verify']);

    let hash = await sha256(message);

    let buf = Buffer.from(signature, options.encode || 'base64');
    let sig = new Uint8Array(buf);
    let check = await subtle.verify({
      name: 'ECDSA',
      hash: { name: 'SHA-256'}
    }, key, sig, new Uint8Array(hash));

    if (!check) {
      throw 'Signature did not match';
    }

    return check;
  } catch(error) {
    throw error;
  }
}
