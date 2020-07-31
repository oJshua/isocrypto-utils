
export const pbkdf2 = {
  hash: {name : 'SHA-256'},
  iter: 100000,
  ks: 64
};

export const ecdsa = {
  pair: {name: 'ECDSA', namedCurve: 'P-256'},
  sign: {name: 'ECDSA', hash: {name: 'SHA-256'}}
};

export const ecdh = {
  name: 'ECDH', namedCurve: 'P-256'
};

// This creates Web Cryptography API compliant JWK for sign/verify purposes
export function getJwk(pub, d){
  pub = pub.split('.');
  var x = pub[0], y = pub[1];
  var jwk = {kty: "EC", crv: "P-256", x: x, y: y, ext: true};
  jwk.key_ops = d ? ['sign'] : ['verify'];
  if(d){ jwk.d = d }
  return jwk;
};

export function keyToJwk(keyBytes) {
  const keyB64 = keyBytes.toString('base64');
  const k = keyB64.replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
  return { kty: 'oct', k: k, ext: false, alg: 'A256GCM' };
}

export const recall = {
  validity: 12 * 60 * 60, // internally in seconds : 12 hours
  hook: function(props){ return props } // { iat, exp, alias, remember } // or return new Promise((resolve, reject) => resolve(props)
};
