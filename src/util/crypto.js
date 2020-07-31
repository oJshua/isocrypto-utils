import * as webcrypto from '@peculiar/webcrypto';

const { Crypto } = webcrypto;

export const crypto = new Crypto({ directory: 'ossl'});

export const subtle = crypto.subtle;
