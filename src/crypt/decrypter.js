import AESCrypto from './aes-crypto';
import FastAESKey from './fast-aes-key';
import AESDecryptor from './aes-decryptor';

import { ErrorTypes, ErrorDetails } from '../errors';
import { logger } from '../utils/logger';

import Event from '../events';

import { getSelfScope } from '../utils/get-self-scope';

// see https://stackoverflow.com/a/11237259/589493
const global = getSelfScope(); // safeguard for code that might run both on worker and main thread

(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? factory() :
  typeof define === 'function' && define.amd ? define(factory) :
  (factory());
}(this, (function () { 'use strict';
/**
 * @this {Promise}
 */
function finallyConstructor(callback) {
  var constructor = this.constructor;
  return this.then(
    function(value) {
      return constructor.resolve(callback()).then(function() {
        return value;
      });
    },
    function(reason) {
      return constructor.resolve(callback()).then(function() {
        return constructor.reject(reason);
      });
    }
  );
}

// Store setTimeout reference so promise-polyfill will be unaffected by
// other code modifying setTimeout (like sinon.useFakeTimers())
var setTimeoutFunc = setTimeout;

function noop() {}

// Polyfill for Function.prototype.bind
function bind(fn, thisArg) {
  return function() {
    fn.apply(thisArg, arguments);
  };
}

/**
 * @constructor
 * @param {Function} fn
 */
function Promise(fn) {
  if (!(this instanceof Promise))
    throw new TypeError('Promises must be constructed via new');
  if (typeof fn !== 'function') throw new TypeError('not a function');
  /** @type {!number} */
  this._state = 0;
  /** @type {!boolean} */
  this._handled = false;
  /** @type {Promise|undefined} */
  this._value = undefined;
  /** @type {!Array<!Function>} */
  this._deferreds = [];

  doResolve(fn, this);
}

function handle(self, deferred) {
  while (self._state === 3) {
    self = self._value;
  }
  if (self._state === 0) {
    self._deferreds.push(deferred);
    return;
  }
  self._handled = true;
  Promise._immediateFn(function() {
    var cb = self._state === 1 ? deferred.onFulfilled : deferred.onRejected;
    if (cb === null) {
      (self._state === 1 ? resolve : reject)(deferred.promise, self._value);
      return;
    }
    var ret;
    try {
      ret = cb(self._value);
    } catch (e) {
      reject(deferred.promise, e);
      return;
    }
    resolve(deferred.promise, ret);
  });
}

function resolve(self, newValue) {
  try {
    // Promise Resolution Procedure: https://github.com/promises-aplus/promises-spec#the-promise-resolution-procedure
    if (newValue === self)
      throw new TypeError('A promise cannot be resolved with itself.');
    if (
      newValue &&
      (typeof newValue === 'object' || typeof newValue === 'function')
    ) {
      var then = newValue.then;
      if (newValue instanceof Promise) {
        self._state = 3;
        self._value = newValue;
        finale(self);
        return;
      } else if (typeof then === 'function') {
        doResolve(bind(then, newValue), self);
        return;
      }
    }
    self._state = 1;
    self._value = newValue;
    finale(self);
  } catch (e) {
    reject(self, e);
  }
}

function reject(self, newValue) {
  self._state = 2;
  self._value = newValue;
  finale(self);
}

function finale(self) {
  if (self._state === 2 && self._deferreds.length === 0) {
    Promise._immediateFn(function() {
      if (!self._handled) {
        Promise._unhandledRejectionFn(self._value);
      }
    });
  }

  for (var i = 0, len = self._deferreds.length; i < len; i++) {
    handle(self, self._deferreds[i]);
  }
  self._deferreds = null;
}

/**
 * @constructor
 */
function Handler(onFulfilled, onRejected, promise) {
  this.onFulfilled = typeof onFulfilled === 'function' ? onFulfilled : null;
  this.onRejected = typeof onRejected === 'function' ? onRejected : null;
  this.promise = promise;
}

/**
 * Take a potentially misbehaving resolver function and make sure
 * onFulfilled and onRejected are only called once.
 *
 * Makes no guarantees about asynchrony.
 */
function doResolve(fn, self) {
  var done = false;
  try {
    fn(
      function(value) {
        if (done) return;
        done = true;
        resolve(self, value);
      },
      function(reason) {
        if (done) return;
        done = true;
        reject(self, reason);
      }
    );
  } catch (ex) {
    if (done) return;
    done = true;
    reject(self, ex);
  }
}

Promise.prototype['catch'] = function(onRejected) {
  return this.then(null, onRejected);
};

Promise.prototype.then = function(onFulfilled, onRejected) {
  // @ts-ignore
  var prom = new this.constructor(noop);

  handle(this, new Handler(onFulfilled, onRejected, prom));
  return prom;
};

Promise.prototype['finally'] = finallyConstructor;

Promise.all = function(arr) {
  return new Promise(function(resolve, reject) {
    if (!arr || typeof arr.length === 'undefined')
      throw new TypeError('Promise.all accepts an array');
    var args = Array.prototype.slice.call(arr);
    if (args.length === 0) return resolve([]);
    var remaining = args.length;

    function res(i, val) {
      try {
        if (val && (typeof val === 'object' || typeof val === 'function')) {
          var then = val.then;
          if (typeof then === 'function') {
            then.call(
              val,
              function(val) {
                res(i, val);
              },
              reject
            );
            return;
          }
        }
        args[i] = val;
        if (--remaining === 0) {
          resolve(args);
        }
      } catch (ex) {
        reject(ex);
      }
    }

    for (var i = 0; i < args.length; i++) {
      res(i, args[i]);
    }
  });
};

Promise.resolve = function(value) {
  if (value && typeof value === 'object' && value.constructor === Promise) {
    return value;
  }

  return new Promise(function(resolve) {
    resolve(value);
  });
};

Promise.reject = function(value) {
  return new Promise(function(resolve, reject) {
    reject(value);
  });
};

Promise.race = function(values) {
  return new Promise(function(resolve, reject) {
    for (var i = 0, len = values.length; i < len; i++) {
      values[i].then(resolve, reject);
    }
  });
};

// Use polyfill for setImmediate for performance gains
Promise._immediateFn =
  (typeof setImmediate === 'function' &&
    function(fn) {
      setImmediate(fn);
    }) ||
  function(fn) {
    setTimeoutFunc(fn, 0);
  };

Promise._unhandledRejectionFn = function _unhandledRejectionFn(err) {
  if (typeof console !== 'undefined' && console) {
    console.warn('Possible Unhandled Promise Rejection:', err); // eslint-disable-line no-console
  }
};

/** @suppress {undefinedVars} */
var globalNS = (function() {
  // the only reliable means to get the global object is
  // `Function('return this')()`
  // However, this causes CSP violations in Chrome apps.
  if (typeof self !== 'undefined') {
    return self;
  }
  if (typeof window !== 'undefined') {
    return window;
  }
  if (typeof global !== 'undefined') {
    return global;
  }
  throw new Error('unable to locate global object');
})();

if (!('Promise' in globalNS)) {
  globalNS['Promise'] = Promise;
} else if (!globalNS.Promise.prototype['finally']) {
  globalNS.Promise.prototype['finally'] = finallyConstructor;
}

})));
(function (global, factory) {
  if (typeof define === 'function' && define.amd) {
      // AMD. Register as an anonymous module.
      define([], function () {
          return factory(global);
      });
  } else if (typeof module === 'object' && module.exports) {
      // CommonJS-like environments that support module.exports
      module.exports = factory(global);
  } else {
      factory(global);
  }
}(typeof self !== 'undefined' ? self : this, function (global) {
  'use strict';
  
  if ( typeof Promise !== 'function' )
      throw "Promise support required";

  var _crypto = global.crypto || global.msCrypto;
  if ( !_crypto ) return;

  var _subtle = _crypto.subtle || _crypto.webkitSubtle;
  if ( !_subtle ) return;

  var _Crypto     = global.Crypto || _crypto.constructor || Object,
      _SubtleCrypto = global.SubtleCrypto || _subtle.constructor || Object,
      _CryptoKey  = global.CryptoKey || global.Key || Object;

  var isEdge = false;// global.navigator.userAgent.indexOf('Edge/') > -1;
  var isIE    = true;//!!global.msCrypto && !isEdge;
  var isWebkit = !_crypto.subtle && !!_crypto.webkitSubtle;
  if ( !isIE && !isWebkit ) return;

  function s2a ( s ) {
      return btoa(s).replace(/\=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  }

  function a2s ( s ) {
      s += '===', s = s.slice( 0, -s.length % 4 );
      return atob( s.replace(/-/g, '+').replace(/_/g, '/') );
  }

  function s2b ( s ) {
      var b = new Uint8Array(s.length);
      for ( var i = 0; i < s.length; i++ ) b[i] = s.charCodeAt(i);
      return b;
  }

  function b2s ( b ) {
      if ( b instanceof ArrayBuffer ) b = new Uint8Array(b);
      return String.fromCharCode.apply( String, b );
  }

  function alg ( a ) {
      var r = { 'name': (a.name || a || '').toUpperCase().replace('V','v') };
      switch ( r.name ) {
          case 'SHA-1':
          case 'SHA-256':
          case 'SHA-384':
          case 'SHA-512':
              break;
          case 'AES-CBC':
          case 'AES-GCM':
          case 'AES-KW':
              if ( a.length ) r['length'] = a.length;
              break;
          case 'HMAC':
              if ( a.hash ) r['hash'] = alg(a.hash);
              if ( a.length ) r['length'] = a.length;
              break;
          case 'RSAES-PKCS1-v1_5':
              if ( a.publicExponent ) r['publicExponent'] = new Uint8Array(a.publicExponent);
              if ( a.modulusLength ) r['modulusLength'] = a.modulusLength;
              break;
          case 'RSASSA-PKCS1-v1_5':
          case 'RSA-OAEP':
              if ( a.hash ) r['hash'] = alg(a.hash);
              if ( a.publicExponent ) r['publicExponent'] = new Uint8Array(a.publicExponent);
              if ( a.modulusLength ) r['modulusLength'] = a.modulusLength;
              break;
          default:
              throw new SyntaxError("Bad algorithm name");
      }
      return r;
  };

  function jwkAlg ( a ) {
      return {
          'HMAC': {
              'SHA-1': 'HS1',
              'SHA-256': 'HS256',
              'SHA-384': 'HS384',
              'SHA-512': 'HS512',
          },
          'RSASSA-PKCS1-v1_5': {
              'SHA-1': 'RS1',
              'SHA-256': 'RS256',
              'SHA-384': 'RS384',
              'SHA-512': 'RS512',
          },
          'RSAES-PKCS1-v1_5': {
              '': 'RSA1_5',
          },
          'RSA-OAEP': {
              'SHA-1': 'RSA-OAEP',
              'SHA-256': 'RSA-OAEP-256',
          },
          'AES-KW': {
              '128': 'A128KW',
              '192': 'A192KW',
              '256': 'A256KW',
          },
          'AES-GCM': {
              '128': 'A128GCM',
              '192': 'A192GCM',
              '256': 'A256GCM',
          },
          'AES-CBC': {
              '128': 'A128CBC',
              '192': 'A192CBC',
              '256': 'A256CBC',
          },
      }[a.name][ ( a.hash || {} ).name || a.length || '' ];
  }

  function b2jwk ( k ) {
      if ( k instanceof ArrayBuffer || k instanceof Uint8Array ) k = JSON.parse( decodeURIComponent( escape( b2s(k) ) ) );
      var jwk = { 'kty': k.kty, 'alg': k.alg, 'ext': k.ext || k.extractable };
      switch ( jwk.kty ) {
          case 'oct':
              jwk.k = k.k;
          case 'RSA':
              [ 'n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi', 'oth' ].forEach( function ( x ) { if ( x in k ) jwk[x] = k[x] } );
              break;
          default:
              throw new TypeError("Unsupported key type");
      }
      return jwk;
  }

  function jwk2b ( k ) {
      var jwk = b2jwk(k);
      if ( isIE ) jwk['extractable'] = jwk.ext, delete jwk.ext;
      return s2b( unescape( encodeURIComponent( JSON.stringify(jwk) ) ) ).buffer;
  }

  function pkcs2jwk ( k ) {
      var info = b2der(k), prv = false;
      if ( info.length > 2 ) prv = true, info.shift(); // remove version from PKCS#8 PrivateKeyInfo structure
      var jwk = { 'ext': true };
      switch ( info[0][0] ) {
          case '1.2.840.113549.1.1.1':
              var rsaComp = [ 'n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi' ],
                  rsaKey  = b2der( info[1] );
              if ( prv ) rsaKey.shift(); // remove version from PKCS#1 RSAPrivateKey structure
              for ( var i = 0; i < rsaKey.length; i++ ) {
                  if ( !rsaKey[i][0] ) rsaKey[i] = rsaKey[i].subarray(1);
                  jwk[ rsaComp[i] ] = s2a( b2s( rsaKey[i] ) );
              }
              jwk['kty'] = 'RSA';
              break;
          default:
              throw new TypeError("Unsupported key type");
      }
      return jwk;
  }

  function jwk2pkcs ( k ) {
      var key, info = [ [ '', null ] ], prv = false;
      switch ( k.kty ) {
          case 'RSA':
              var rsaComp = [ 'n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi' ],
                  rsaKey = [];
              for ( var i = 0; i < rsaComp.length; i++ ) {
                  if ( !( rsaComp[i] in k ) ) break;
                  var b = rsaKey[i] = s2b( a2s( k[ rsaComp[i] ] ) );
                  if ( b[0] & 0x80 ) rsaKey[i] = new Uint8Array(b.length + 1), rsaKey[i].set( b, 1 );
              }
              if ( rsaKey.length > 2 ) prv = true, rsaKey.unshift( new Uint8Array([0]) ); // add version to PKCS#1 RSAPrivateKey structure
              info[0][0] = '1.2.840.113549.1.1.1';
              key = rsaKey;
              break;
          default:
              throw new TypeError("Unsupported key type");
      }
      info.push( new Uint8Array( der2b(key) ).buffer );
      if ( !prv ) info[1] = { 'tag': 0x03, 'value': info[1] };
      else info.unshift( new Uint8Array([0]) ); // add version to PKCS#8 PrivateKeyInfo structure
      return new Uint8Array( der2b(info) ).buffer;
  }

  var oid2str = { 'KoZIhvcNAQEB': '1.2.840.113549.1.1.1' },
      str2oid = { '1.2.840.113549.1.1.1': 'KoZIhvcNAQEB' };

  function b2der ( buf, ctx ) {
      if ( buf instanceof ArrayBuffer ) buf = new Uint8Array(buf);
      if ( !ctx ) ctx = { pos: 0, end: buf.length };

      if ( ctx.end - ctx.pos < 2 || ctx.end > buf.length ) throw new RangeError("Malformed DER");

      var tag = buf[ctx.pos++],
          len = buf[ctx.pos++];

      if ( len >= 0x80 ) {
          len &= 0x7f;
          if ( ctx.end - ctx.pos < len ) throw new RangeError("Malformed DER");
          for ( var xlen = 0; len--; ) xlen <<= 8, xlen |= buf[ctx.pos++];
          len = xlen;
      }

      if ( ctx.end - ctx.pos < len ) throw new RangeError("Malformed DER");

      var rv;

      switch ( tag ) {
          case 0x02: // Universal Primitive INTEGER
              rv = buf.subarray( ctx.pos, ctx.pos += len );
              break;
          case 0x03: // Universal Primitive BIT STRING
              if ( buf[ctx.pos++] ) throw new Error( "Unsupported bit string" );
              len--;
          case 0x04: // Universal Primitive OCTET STRING
              rv = new Uint8Array( buf.subarray( ctx.pos, ctx.pos += len ) ).buffer;
              break;
          case 0x05: // Universal Primitive NULL
              rv = null;
              break;
          case 0x06: // Universal Primitive OBJECT IDENTIFIER
              var oid = btoa( b2s( buf.subarray( ctx.pos, ctx.pos += len ) ) );
              if ( !( oid in oid2str ) ) throw new Error( "Unsupported OBJECT ID " + oid );
              rv = oid2str[oid];
              break;
          case 0x30: // Universal Constructed SEQUENCE
              rv = [];
              for ( var end = ctx.pos + len; ctx.pos < end; ) rv.push( b2der( buf, ctx ) );
              break;
          default:
              throw new Error( "Unsupported DER tag 0x" + tag.toString(16) );
      }

      return rv;
  }

  function der2b ( val, buf ) {
      if ( !buf ) buf = [];

      var tag = 0, len = 0,
          pos = buf.length + 2;

      buf.push( 0, 0 ); // placeholder

      if ( val instanceof Uint8Array ) {  // Universal Primitive INTEGER
          tag = 0x02, len = val.length;
          for ( var i = 0; i < len; i++ ) buf.push( val[i] );
      }
      else if ( val instanceof ArrayBuffer ) { // Universal Primitive OCTET STRING
          tag = 0x04, len = val.byteLength, val = new Uint8Array(val);
          for ( var i = 0; i < len; i++ ) buf.push( val[i] );
      }
      else if ( val === null ) { // Universal Primitive NULL
          tag = 0x05, len = 0;
      }
      else if ( typeof val === 'string' && val in str2oid ) { // Universal Primitive OBJECT IDENTIFIER
          var oid = s2b( atob( str2oid[val] ) );
          tag = 0x06, len = oid.length;
          for ( var i = 0; i < len; i++ ) buf.push( oid[i] );
      }
      else if ( val instanceof Array ) { // Universal Constructed SEQUENCE
          for ( var i = 0; i < val.length; i++ ) der2b( val[i], buf );
          tag = 0x30, len = buf.length - pos;
      }
      else if ( typeof val === 'object' && val.tag === 0x03 && val.value instanceof ArrayBuffer ) { // Tag hint
          val = new Uint8Array(val.value), tag = 0x03, len = val.byteLength;
          buf.push(0); for ( var i = 0; i < len; i++ ) buf.push( val[i] );
          len++;
      }
      else {
          throw new Error( "Unsupported DER value " + val );
      }

      if ( len >= 0x80 ) {
          var xlen = len, len = 4;
          buf.splice( pos, 0, (xlen >> 24) & 0xff, (xlen >> 16) & 0xff, (xlen >> 8) & 0xff, xlen & 0xff );
          while ( len > 1 && !(xlen >> 24) ) xlen <<= 8, len--;
          if ( len < 4 ) buf.splice( pos, 4 - len );
          len |= 0x80;
      }

      buf.splice( pos - 2, 2, tag, len );

      return buf;
  }

  function CryptoKey ( key, alg, ext, use ) {
      Object.defineProperties( this, {
          _key: {
              value: key
          },
          type: {
              value: key.type,
              enumerable: true,
          },
          extractable: {
              value: (ext === undefined) ? key.extractable : ext,
              enumerable: true,
          },
          algorithm: {
              value: (alg === undefined) ? key.algorithm : alg,
              enumerable: true,
          },
          usages: {
              value: (use === undefined) ? key.usages : use,
              enumerable: true,
          },
      });
  }

  function isPubKeyUse ( u ) {
      return u === 'verify' || u === 'encrypt' || u === 'wrapKey';
  }

  function isPrvKeyUse ( u ) {
      return u === 'sign' || u === 'decrypt' || u === 'unwrapKey';
  }

  [ 'generateKey', 'importKey', 'unwrapKey' ]
      .forEach( function ( m ) {
          var _fn = _subtle[m];

          _subtle[m] = function ( a, b, c ) {
              var args = [].slice.call(arguments),
                  ka, kx, ku;

              switch ( m ) {
                  case 'generateKey':
                      ka = alg(a), kx = b, ku = c;
                      break;
                  case 'importKey':
                      ka = alg(c), kx = args[3], ku = args[4];
                      if ( a === 'jwk' ) {
                          b = b2jwk(b);
                          if ( !b.alg ) b.alg = jwkAlg(ka);
                          if ( !b.key_ops ) b.key_ops = ( b.kty !== 'oct' ) ? ( 'd' in b ) ? ku.filter(isPrvKeyUse) : ku.filter(isPubKeyUse) : ku.slice();
                          args[1] = jwk2b(b);
                      }
                      break;
                  case 'unwrapKey':
                      ka = args[4], kx = args[5], ku = args[6];
                      args[2] = c._key;
                      break;
              }

              if ( m === 'generateKey' && ka.name === 'HMAC' && ka.hash ) {
                  ka.length = ka.length || { 'SHA-1': 512, 'SHA-256': 512, 'SHA-384': 1024, 'SHA-512': 1024 }[ka.hash.name];
                  return _subtle.importKey( 'raw', _crypto.getRandomValues( new Uint8Array( (ka.length+7)>>3 ) ), ka, kx, ku );
              }

              if ( isWebkit && m === 'generateKey' && ka.name === 'RSASSA-PKCS1-v1_5' && ( !ka.modulusLength || ka.modulusLength >= 2048 ) ) {
                  a = alg(a), a.name = 'RSAES-PKCS1-v1_5', delete a.hash;
                  return _subtle.generateKey( a, true, [ 'encrypt', 'decrypt' ] )
                      .then( function ( k ) {
                          return Promise.all([
                              _subtle.exportKey( 'jwk', k.publicKey ),
                              _subtle.exportKey( 'jwk', k.privateKey ),
                          ]);
                      })
                      .then( function ( keys ) {
                          keys[0].alg = keys[1].alg = jwkAlg(ka);
                          keys[0].key_ops = ku.filter(isPubKeyUse), keys[1].key_ops = ku.filter(isPrvKeyUse);
                          return Promise.all([
                              _subtle.importKey( 'jwk', keys[0], ka, true, keys[0].key_ops ),
                              _subtle.importKey( 'jwk', keys[1], ka, kx, keys[1].key_ops ),
                          ]);
                      })
                      .then( function ( keys ) {
                          return {
                              publicKey: keys[0],
                              privateKey: keys[1],
                          };
                      });
              }

              if ( ( isWebkit || ( isIE && ( ka.hash || {} ).name === 'SHA-1' ) )
                      && m === 'importKey' && a === 'jwk' && ka.name === 'HMAC' && b.kty === 'oct' ) {
                  return _subtle.importKey( 'raw', s2b( a2s(b.k) ), c, args[3], args[4] );
              }

              if ( isWebkit && m === 'importKey' && ( a === 'spki' || a === 'pkcs8' ) ) {
                  return _subtle.importKey( 'jwk', pkcs2jwk(b), c, args[3], args[4] );
              }

              if ( isIE && m === 'unwrapKey' ) {
                  return _subtle.decrypt( args[3], c, b )
                      .then( function ( k ) {
                          return _subtle.importKey( a, k, args[4], args[5], args[6] );
                      });
              }

              var op;
              try {
                  op = _fn.apply( _subtle, args );
              }
              catch ( e ) {
                  return Promise.reject(e);
              }

              if ( isIE ) {
                  op = new Promise( function ( res, rej ) {
                      op.onabort =
                      op.onerror =    function ( e ) { rej(e)               };
                      op.oncomplete = function ( r ) { res(r.target.result) };
                  });
              }

              op = op.then( function ( k ) {
                  if ( ka.name === 'HMAC' ) {
                      if ( !ka.length ) ka.length = 8 * k.algorithm.length;
                  }
                  if ( ka.name.search('RSA') == 0 ) {
                      if ( !ka.modulusLength ) ka.modulusLength = (k.publicKey || k).algorithm.modulusLength;
                      if ( !ka.publicExponent ) ka.publicExponent = (k.publicKey || k).algorithm.publicExponent;
                  }
                  if ( k.publicKey && k.privateKey ) {
                      k = {
                          publicKey: new CryptoKey( k.publicKey, ka, kx, ku.filter(isPubKeyUse) ),
                          privateKey: new CryptoKey( k.privateKey, ka, kx, ku.filter(isPrvKeyUse) ),
                      };
                  }
                  else {
                      k = new CryptoKey( k, ka, kx, ku );
                  }
                  return k;
              });

              return op;
          }
      });

  [ 'exportKey', 'wrapKey' ]
      .forEach( function ( m ) {
          var _fn = _subtle[m];

          _subtle[m] = function ( a, b, c ) {
              var args = [].slice.call(arguments);

              switch ( m ) {
                  case 'exportKey':
                      args[1] = b._key;
                      break;
                  case 'wrapKey':
                      args[1] = b._key, args[2] = c._key;
                      break;
              }

              if ( ( isWebkit || ( isIE && ( b.algorithm.hash || {} ).name === 'SHA-1' ) )
                      && m === 'exportKey' && a === 'jwk' && b.algorithm.name === 'HMAC' ) {
                  args[0] = 'raw';
              }

              if ( isWebkit && m === 'exportKey' && ( a === 'spki' || a === 'pkcs8' ) ) {
                  args[0] = 'jwk';
              }

              if ( isIE && m === 'wrapKey' ) {
                  return _subtle.exportKey( a, b )
                      .then( function ( k ) {
                          if ( a === 'jwk' ) k = s2b( unescape( encodeURIComponent( JSON.stringify( b2jwk(k) ) ) ) );
                          return  _subtle.encrypt( args[3], c, k );
                      });
              }

              var op;
              try {
                  op = _fn.apply( _subtle, args );
              }
              catch ( e ) {
                  return Promise.reject(e);
              }

              if ( isIE ) {
                  op = new Promise( function ( res, rej ) {
                      op.onabort =
                      op.onerror =    function ( e ) { rej(e)               };
                      op.oncomplete = function ( r ) { res(r.target.result) };
                  });
              }

              if ( m === 'exportKey' && a === 'jwk' ) {
                  op = op.then( function ( k ) {
                      if ( ( isWebkit || ( isIE && ( b.algorithm.hash || {} ).name === 'SHA-1' ) )
                              && b.algorithm.name === 'HMAC') {
                          return { 'kty': 'oct', 'alg': jwkAlg(b.algorithm), 'key_ops': b.usages.slice(), 'ext': true, 'k': s2a( b2s(k) ) };
                      }
                      k = b2jwk(k);
                      if ( !k.alg ) k['alg'] = jwkAlg(b.algorithm);
                      if ( !k.key_ops ) k['key_ops'] = ( b.type === 'public' ) ? b.usages.filter(isPubKeyUse) : ( b.type === 'private' ) ? b.usages.filter(isPrvKeyUse) : b.usages.slice();
                      return k;
                  });
              }

              if ( isWebkit && m === 'exportKey' && ( a === 'spki' || a === 'pkcs8' ) ) {
                  op = op.then( function ( k ) {
                      k = jwk2pkcs( b2jwk(k) );
                      return k;
                  });
              }

              return op;
          }
      });

  [ 'encrypt', 'decrypt', 'sign', 'verify' ]
      .forEach( function ( m ) {
          var _fn = _subtle[m];

          _subtle[m] = function ( a, b, c, d ) {
              if ( isIE && ( !c.byteLength || ( d && !d.byteLength ) ) )
                  throw new Error("Empy input is not allowed");

              var args = [].slice.call(arguments),
                  ka = alg(a);

              if ( isIE && ( m === 'encrypt' || m === 'decrypt' ) && ka.name === 'RSA-OAEP' ) {
                  args[0].hash = b.hash;
              }

              if ( isIE && m === 'decrypt' && ka.name === 'AES-GCM' ) {
                  var tl = a.tagLength >> 3;
                  args[2] = (c.buffer || c).slice( 0, c.byteLength - tl ),
                  a.tag = (c.buffer || c).slice( c.byteLength - tl );
              }

              args[1] = b._key;

              var op;
              try {
                  op = _fn.apply( _subtle, args );
              }
              catch ( e ) {
                  return Promise.reject(e);
              }

              if ( isIE ) {
                  op = new Promise( function ( res, rej ) {
                      op.onabort =
                      op.onerror = function ( e ) {
                          rej(e);
                      };

                      op.oncomplete = function ( r ) {
                          var r = r.target.result;

                          if ( m === 'encrypt' && r instanceof AesGcmEncryptResult ) {
                              var c = r.ciphertext, t = r.tag;
                              r = new Uint8Array( c.byteLength + t.byteLength );
                              r.set( new Uint8Array(c), 0 );
                              r.set( new Uint8Array(t), c.byteLength );
                              r = r.buffer;
                          }

                          res(r);
                      };
                  });
              }

              return op;
          }
      });

  if ( isIE ) {
      var _digest = _subtle.digest;

      _subtle['digest'] = function ( a, b ) {
          if ( !b.byteLength )
              throw new Error("Empy input is not allowed");

          var op;
          try {
              op = _digest.call( _subtle, a, b );
          }
          catch ( e ) {
              return Promise.reject(e);
          }

          op = new Promise( function ( res, rej ) {
              op.onabort =
              op.onerror =    function ( e ) { rej(e)               };
              op.oncomplete = function ( r ) { res(r.target.result) };
          });

          return op;
      };

      global.crypto = Object.create( _crypto, {
          getRandomValues: { value: function ( a ) { return _crypto.getRandomValues(a) } },
          subtle:          { value: _subtle },
      });
      global.CryptoKey = CryptoKey;
  }

  if ( isWebkit ) {
      _crypto.subtle = _subtle;

      global.Crypto = _Crypto;
      global.SubtleCrypto = _SubtleCrypto;
      global.CryptoKey = CryptoKey;
  }
}));
class Decrypter {
  constructor (observer, config, { removePKCS7Padding = true } = {}) {
    this.logEnabled = true;
    this.observer = observer;
    this.config = config;
    this.removePKCS7Padding = removePKCS7Padding;


    // built in decryptor expects PKCS7 padding
    if (removePKCS7Padding) {
      try {
        const browserCrypto = global.crypto;
        if (browserCrypto) {
          this.subtle = browserCrypto.subtle || browserCrypto.webkitSubtle;
        }
      } catch (e) {}
    }
    this.disableWebCrypto = !this.subtle;
  }

  isSync () {
    return (this.disableWebCrypto && this.config.enableSoftwareAES);
  }

  decrypt (data, key, iv, callback) {
    if (this.disableWebCrypto && this.config.enableSoftwareAES) {
      if (this.logEnabled) {
        logger.log('JS AES decrypt');
        this.logEnabled = false;
      }
      let decryptor = this.decryptor;
      if (!decryptor) {
        this.decryptor = decryptor = new AESDecryptor();
      }

      decryptor.expandKey(key);
      callback(decryptor.decrypt(data, 0, iv, this.removePKCS7Padding));
    } else {
      if (this.logEnabled) {
        logger.log('WebCrypto AES decrypt');
        this.logEnabled = false;
      }
      const subtle = this.subtle;
      if (this.key !== key) {
        this.key = key;
        this.fastAesKey = new FastAESKey(subtle, key);
      }

      this.fastAesKey.expandKey()
        .then((aesKey) => {
          // decrypt using web crypto
          let crypto = new AESCrypto(subtle, iv);
          crypto.decrypt(data, aesKey)
            .catch((err) => {
              this.onWebCryptoError(err, data, key, iv, callback);
            })
            .then((result) => {
              callback(result);
            });
        })
        .catch((err) => {
          this.onWebCryptoError(err, data, key, iv, callback);
        });
    }
  }

  onWebCryptoError (err, data, key, iv, callback) {
    if (this.config.enableSoftwareAES) {
      logger.log('WebCrypto Error, disable WebCrypto API');
      this.disableWebCrypto = true;
      this.logEnabled = true;
      this.decrypt(data, key, iv, callback);
    } else {
      logger.error(`decrypting error : ${err.message}`);
      this.observer.trigger(Event.ERROR, { type: ErrorTypes.MEDIA_ERROR, details: ErrorDetails.FRAG_DECRYPT_ERROR, fatal: true, reason: err.message });
    }
  }

  destroy () {
    let decryptor = this.decryptor;
    if (decryptor) {
      decryptor.destroy();
      this.decryptor = undefined;
    }
  }
}

export default Decrypter;
