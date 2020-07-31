import { sha256 } from './sha256';
import { random } from './random';
import { TextEncoder } from 'text-encoding';
import { subtle } from './crypto';
import { pbkdf2 } from './settings';

export async function work(data, pair) {
  try {
    let salt = (pair||{}).epub || pair;
    let options = options || {};

    if (typeof data !== 'string') {
      data = JSON.stringify(data);
    }

    if ('sha' === (options.name||'').toLowerCase().slice(0, 3)) {
      let rsha = Buffer.from(await sha256(data, options.name), 'binary').toString(options.encode || 'base64');
      return rsha;
    }

    salt = salt || random(9);

    let key = await subtle.importKey(
      'raw',
      new TextEncoder().encode(data),
      {
        name: options.name || 'PBKDF2'
      },
      false,
      ['deriveBits']
    );

    let work = await subtle.deriveBits(
      {
        name: options.name || 'PBKDF2',
        iterations: options.iterations || pbkdf2.iter,
        salt: new TextEncoder().encode(options.salt || salt),
        hash: options.hash || pbkdf2.hash,
      },
      key,
      options.length || (pbkdf2.ks * 8)
    );

    data = random(data.length); // Erase data in case of passphrase

    let r = Buffer.from(work, 'binary').toString(options.encode || 'base64');

    return r;
  } catch(error) {
    throw error;
  }
}
