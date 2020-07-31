let sea = require('../build/bundle.js');
let chai = require('chai');
let assert = require('assert');
let crypto = require('crypto');

chai.should();

function sha(data, type) {
  var generator = crypto.createHash(type);
  generator.update(data)
  return generator.digest('buffer')
}

describe('SEA', function () {

  describe('sha1', () => {
    it('should generate a sha1 hash', async () => {
      let hash = await sea.sha1('foo');
      let nodehash = sha('foo', 'sha1');
      Buffer.compare(hash, nodehash).should.equal(0);
    });
  });

  describe('sha256', () => {
    it('should generate a sha256 hash', async () => {
      let hash = await sea.sha256('foo');
      let nodehash = sha('foo', 'sha256');
      Buffer.compare(hash, nodehash).should.equal(0);
    });
  });

  describe('pair', () => {
    it('should generate a keypair', async () => {
      let pair = await sea.pair();

      pair.should.have.property('pub');
      pair.should.have.property('priv');
      pair.should.have.property('epub');
      pair.should.have.property('epriv');
    });
  });

  describe('encrypt', () => {
    it('should encrypt data with a private key', async () => {
      let pair = await sea.pair();
      let encrypted = await sea.encrypt('Hello world', pair.epriv);
    });
  });

  describe('decrypt', () => {
    it('should decrypt data that has been encrypted', async () => {
      let pair = await sea.pair();
      let encrypted = await sea.encrypt('Hello world', pair.epriv);
      let decrypted = await sea.decrypt(encrypted, pair.epriv);
      decrypted.should.equal('Hello world');
    });
  });

  describe('sign messages', () => {
    it('should produce a signature', async () => {
      let pair = await sea.pair();
      let encrypted = await sea.encrypt('Hello world', pair.priv);
      let signature = await sea.sign(encrypted, pair);
      signature.should.be.a('string');
    });
  });

  describe('verify message', () => {
    it('should verify signature', async () => {
      let message = 'My message';
      let pair = await sea.pair();
      let signature = await sea.sign(message, pair);
      let check = await sea.verify(message, signature, pair.pub);
      check.should.equal(true);
    });

    it('should fail signature if signed by other', async () => {
      let message = 'My message';
      let mypair = await sea.pair();
      let otherpair = await sea.pair();
      let signature = await sea.sign(message, otherpair);
      try {
        await sea.verify(message, signature, mypair.pub);
      } catch(error) {
        assert(true);
        return;
      }
      assert(false);
    });
  });

});
