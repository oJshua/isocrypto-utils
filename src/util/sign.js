
import { getJwk } from './settings';
import { sha256 } from './sha256';
import { subtle } from './crypto';

export async function sign(data, pair, options) {
  options = options || {};

  if (undefined === data) {
    throw '`undefined` not allowed.'
  }

  if (typeof data !== 'string') {
    data = JSON.stringify(data);
  }

  let jwk = getJwk(pair.pub, pair.priv);
  let hash = await sha256(data);
  let sig = await subtle.importKey(
    'jwk',
    jwk, {
      name: 'ECDSA',
      namedCurve: 'P-256'
    },
    false,
    ['sign']
  )
  .then((key) => subtle.sign(
    {
      name: 'ECDSA',
      hash: {
        name: 'SHA-256'
      }
    },
    key,
    new Uint8Array(hash)
  ));

  return Buffer.from(sig, 'binary').toString(options.encode || 'base64');
}
