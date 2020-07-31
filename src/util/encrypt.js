import { random } from './random';
import { aeskey } from './aeskey';
import { subtle } from './crypto';

export async function encrypt(data, key, options) {
  options = options || {};

  if (data === undefined) {
    throw '`undefined` not allowed.';
  }

  let msg = (typeof data === 'string') ? data : JSON.stringify(data);

  let rand = { // consider making this 9 and 15 or 18 or 12 to reduce == padding.
    s: random(9),
    iv: random(15)
  };

  let ct = await aeskey(key, rand.s).then(
    aes => subtle.encrypt(
      {
        name: options.name || 'AES-GCM',
        iv: new Uint8Array(rand.iv)
      },
      aes,
      new TextEncoder().encode(msg)
    )
  );

  let r = {
    ct: Buffer.from(ct, 'binary').toString(options.encode || 'base64'),
    iv: rand.iv.toString(options.encode || 'base64'),
    s: rand.s.toString(options.encode || 'base64')
  };

  return JSON.stringify(r);
}
