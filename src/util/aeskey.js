
import { keyToJwk } from './settings';
import { sha256 } from './sha256';
import { random } from './random';
import { subtle } from './crypto';

export async function aeskey(key, salt) {
  const combo = key + (salt || random(8)).toString('utf8');
  const hash = Buffer.from(await sha256(combo), 'binary');
  const jwkKey = keyToJwk(hash);

  try {
    let key = await subtle.importKey('jwk', jwkKey, { name:'AES-GCM' }, false, ['encrypt', 'decrypt']);
    return key;
  } catch(error) {
    throw error;
  }
}
