import { crypto } from './crypto';

export function random(len) {
  let cont = new Uint32Array(len);
  let randomized = crypto.getRandomValues(cont);
  return Buffer.from(randomized);
}
