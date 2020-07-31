
import { subtle } from './crypto';
import { TextDecoder } from 'text-encoding';
import { aeskey } from './aeskey';

const TAGLENGTH = 128;

export async function decrypt(data, key, options) {
  options = options || {};

  try {
    let json = JSON.parse(data);

    let buf = Buffer.from(json.s, options.encode || 'base64');
    let bufiv = Buffer.from(json.iv, options.encode || 'base64');
    let bufct = Buffer.from(json.ct, options.encode || 'base64');

    let ct = await aeskey(key, buf).then(aes => subtle.decrypt({
      name: options.name || 'AES-GCM',
      iv: new Uint8Array(bufiv), tagLength: TAGLENGTH
    }, aes, new Uint8Array(bufct)));

    let r = new TextDecoder('utf8').decode(ct);

    return r;
  } catch(error) {
    if ('utf8' === options.encode) {
      throw 'Could not decrypt';
    }

    throw error;
  }
}
