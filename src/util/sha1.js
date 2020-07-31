
import { sha } from './sha256';

export async function sha1(d) {
  return await sha(d, 'SHA-1');
}
