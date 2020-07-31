import { subtle } from "./crypto";
import { TextEncoder } from 'text-encoding';

export async function sha(d, o) {
  let t = (typeof d === 'string') ? d : JSON.stringify(d);
  let hash = await subtle.digest({ name: o || 'SHA-256' }, new TextEncoder().encode(t));
  return Buffer.from(hash);
}

export async function sha256(d, o) {
  return await sha(d, 'SHA-256');
}
