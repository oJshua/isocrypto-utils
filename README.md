# isocrypto-utils

[![Build Status](https://travis-ci.com/oJshua/isocrypto-utils.svg?branch=master)](https://travis-ci.com/oJshua/isocrypto-utils) [![npm version](https://badge.fury.io/js/isocrypto-utils.svg)](https://www.npmjs.com/package/isocrypto-utils)

A simple set of cryptographic utility functions inspired/borrowed from the ones found in the [GUN](https://github.com/amark/gun) distributed database.

 - aeskey (generates a AES-GCM key)
 - encrypt (AES-GCM encryption)
 - decrypt (AES-GCM decryption)
 - pair (generates ECDSA keypair and ECDH keypair)
 - sha1 and sha256 hashing
 - sign (sign with ECDSA, SHA-256 hash)
 - verify (verify signature)
 - proof of work (PBKDF2 derivation)
