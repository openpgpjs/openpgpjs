(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.openpgp = f()}})(function(){var define,module,exports;return (function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(_dereq_,module,exports){
/*! asmCrypto Lite v1.1.0, (c) 2013 Artem S Vybornov, opensource.org/licenses/MIT */
(function ( exports, global ) {

function IllegalStateError () { var err = Error.apply( this, arguments ); this.message = err.message, this.stack = err.stack; }
IllegalStateError.prototype = Object.create( Error.prototype, { name: { value: 'IllegalStateError' } } );

function IllegalArgumentError () { var err = Error.apply( this, arguments ); this.message = err.message, this.stack = err.stack; }
IllegalArgumentError.prototype = Object.create( Error.prototype, { name: { value: 'IllegalArgumentError' } } );

function SecurityError () { var err = Error.apply( this, arguments ); this.message = err.message, this.stack = err.stack; }
SecurityError.prototype = Object.create( Error.prototype, { name: { value: 'SecurityError' } } );

var FloatArray = global.Float64Array || global.Float32Array; // make PhantomJS happy

function string_to_bytes ( str, utf8 ) {
    utf8 = !!utf8;

    var len = str.length,
        bytes = new Uint8Array( utf8 ? 4*len : len );

    for ( var i = 0, j = 0; i < len; i++ ) {
        var c = str.charCodeAt(i);

        if ( utf8 && 0xd800 <= c && c <= 0xdbff ) {
            if ( ++i >= len ) throw new Error( "Malformed string, low surrogate expected at position " + i );
            c = ( (c ^ 0xd800) << 10 ) | 0x10000 | ( str.charCodeAt(i) ^ 0xdc00 );
        }
        else if ( !utf8 && c >>> 8 ) {
            throw new Error("Wide characters are not allowed.");
        }

        if ( !utf8 || c <= 0x7f ) {
            bytes[j++] = c;
        }
        else if ( c <= 0x7ff ) {
            bytes[j++] = 0xc0 | (c >> 6);
            bytes[j++] = 0x80 | (c & 0x3f);
        }
        else if ( c <= 0xffff ) {
            bytes[j++] = 0xe0 | (c >> 12);
            bytes[j++] = 0x80 | (c >> 6 & 0x3f);
            bytes[j++] = 0x80 | (c & 0x3f);
        }
        else {
            bytes[j++] = 0xf0 | (c >> 18);
            bytes[j++] = 0x80 | (c >> 12 & 0x3f);
            bytes[j++] = 0x80 | (c >> 6 & 0x3f);
            bytes[j++] = 0x80 | (c & 0x3f);
        }
    }

    return bytes.subarray(0, j);
}

function hex_to_bytes ( str ) {
    var len = str.length;
    if ( len & 1 ) {
        str = '0'+str;
        len++;
    }
    var bytes = new Uint8Array(len>>1);
    for ( var i = 0; i < len; i += 2 ) {
        bytes[i>>1] = parseInt( str.substr( i, 2), 16 );
    }
    return bytes;
}

function base64_to_bytes ( str ) {
    return string_to_bytes( atob( str ) );
}

function bytes_to_string ( bytes, utf8 ) {
    utf8 = !!utf8;

    var len = bytes.length,
        chars = new Array(len);

    for ( var i = 0, j = 0; i < len; i++ ) {
        var b = bytes[i];
        if ( !utf8 || b < 128 ) {
            chars[j++] = b;
        }
        else if ( b >= 192 && b < 224 && i+1 < len ) {
            chars[j++] = ( (b & 0x1f) << 6 ) | (bytes[++i] & 0x3f);
        }
        else if ( b >= 224 && b < 240 && i+2 < len ) {
            chars[j++] = ( (b & 0xf) << 12 ) | ( (bytes[++i] & 0x3f) << 6 ) | (bytes[++i] & 0x3f);
        }
        else if ( b >= 240 && b < 248 && i+3 < len ) {
            var c = ( (b & 7) << 18 ) | ( (bytes[++i] & 0x3f) << 12 ) | ( (bytes[++i] & 0x3f) << 6 ) | (bytes[++i] & 0x3f);
            if ( c <= 0xffff ) {
                chars[j++] = c;
            }
            else {
                c ^= 0x10000;
                chars[j++] = 0xd800 | (c >> 10);
                chars[j++] = 0xdc00 | (c & 0x3ff);
            }
        }
        else {
            throw new Error("Malformed UTF8 character at byte offset " + i);
        }
    }

    var str = '',
        bs = 16384;
    for ( var i = 0; i < j; i += bs ) {
        str += String.fromCharCode.apply( String, chars.slice( i, i+bs <= j ? i+bs : j ) );
    }

    return str;
}

function bytes_to_hex ( arr ) {
    var str = '';
    for ( var i = 0; i < arr.length; i++ ) {
        var h = ( arr[i] & 0xff ).toString(16);
        if ( h.length < 2 ) str += '0';
        str += h;
    }
    return str;
}

function bytes_to_base64 ( arr ) {
    return btoa( bytes_to_string(arr) );
}

function pow2_ceil ( a ) {
    a -= 1;
    a |= a >>> 1;
    a |= a >>> 2;
    a |= a >>> 4;
    a |= a >>> 8;
    a |= a >>> 16;
    a += 1;
    return a;
}

function is_number ( a ) {
    return ( typeof a === 'number' );
}

function is_string ( a ) {
    return ( typeof a === 'string' );
}

function is_buffer ( a ) {
    return ( a instanceof ArrayBuffer );
}

function is_bytes ( a ) {
    return ( a instanceof Uint8Array );
}

function is_typed_array ( a ) {
    return ( a instanceof Int8Array ) || ( a instanceof Uint8Array )
        || ( a instanceof Int16Array ) || ( a instanceof Uint16Array )
        || ( a instanceof Int32Array ) || ( a instanceof Uint32Array )
        || ( a instanceof Float32Array )
        || ( a instanceof Float64Array );
}

function _heap_init ( constructor, options ) {
    var heap = options.heap,
        size = heap ? heap.byteLength : options.heapSize || 65536;

    if ( size & 0xfff || size <= 0 )
        throw new Error("heap size must be a positive integer and a multiple of 4096");

    heap = heap || new constructor( new ArrayBuffer(size) );

    return heap;
}

function _heap_write ( heap, hpos, data, dpos, dlen ) {
    var hlen = heap.length - hpos,
        wlen = ( hlen < dlen ) ? hlen : dlen;

    heap.set( data.subarray( dpos, dpos+wlen ), hpos );

    return wlen;
}

/**
 * Error definitions
 */

global.IllegalStateError = IllegalStateError;
global.IllegalArgumentError = IllegalArgumentError;
global.SecurityError = SecurityError;

/**
 * @file {@link http://asmjs.org Asm.js} implementation of the {@link https://en.wikipedia.org/wiki/Advanced_Encryption_Standard Advanced Encryption Standard}.
 * @author Artem S Vybornov <vybornov@gmail.com>
 * @license MIT
 */
var AES_asm = function () {
    "use strict";

    /**
     * Galois Field stuff init flag
     */
    var ginit_done = false;

    /**
     * Galois Field exponentiation and logarithm tables for 3 (the generator)
     */
    var gexp3, glog3;

    /**
     * Init Galois Field tables
     */
    function ginit () {
        gexp3 = [],
        glog3 = [];

        var a = 1, c, d;
        for ( c = 0; c < 255; c++ ) {
            gexp3[c] = a;

            // Multiply by three
            d = a & 0x80, a <<= 1, a &= 255;
            if ( d === 0x80 ) a ^= 0x1b;
            a ^= gexp3[c];

            // Set the log table value
            glog3[gexp3[c]] = c;
        }
        gexp3[255] = gexp3[0];
        glog3[0] = 0;

        ginit_done = true;
    }

    /**
     * Galois Field multiplication
     * @param {int} a
     * @param {int} b
     * @return {int}
     */
    function gmul ( a, b ) {
        var c = gexp3[ ( glog3[a] + glog3[b] ) % 255 ];
        if ( a === 0 || b === 0 ) c = 0;
        return c;
    }

    /**
     * Galois Field reciprocal
     * @param {int} a
     * @return {int}
     */
    function ginv ( a ) {
        var i = gexp3[ 255 - glog3[a] ];
        if ( a === 0 ) i = 0;
        return i;
    }

    /**
     * AES stuff init flag
     */
    var aes_init_done = false;

    /**
     * Encryption, Decryption, S-Box and KeyTransform tables
     */
    var aes_sbox, aes_sinv, aes_enc, aes_dec;

    /**
     * Init AES tables
     */
    function aes_init () {
        if ( !ginit_done ) ginit();

        // Calculates AES S-Box value
        function _s ( a ) {
            var c, s, x;
            s = x = ginv(a);
            for ( c = 0; c < 4; c++ ) {
                s = ( (s << 1) | (s >>> 7) ) & 255;
                x ^= s;
            }
            x ^= 99;
            return x;
        }

        // Tables
        aes_sbox = [],
        aes_sinv = [],
        aes_enc = [ [], [], [], [] ],
        aes_dec = [ [], [], [], [] ];

        for ( var i = 0; i < 256; i++ ) {
            var s = _s(i);

            // S-Box and its inverse
            aes_sbox[i]  = s;
            aes_sinv[s]  = i;

            // Ecryption and Decryption tables
            aes_enc[0][i] = ( gmul( 2, s ) << 24 )  | ( s << 16 )            | ( s << 8 )             | gmul( 3, s );
            aes_dec[0][s] = ( gmul( 14, i ) << 24 ) | ( gmul( 9, i ) << 16 ) | ( gmul( 13, i ) << 8 ) | gmul( 11, i );
            // Rotate tables
            for ( var t = 1; t < 4; t++ ) {
                aes_enc[t][i] = ( aes_enc[t-1][i] >>> 8 ) | ( aes_enc[t-1][i] << 24 );
                aes_dec[t][s] = ( aes_dec[t-1][s] >>> 8 ) | ( aes_dec[t-1][s] << 24 );
            }
        }
    }

    /**
     * Asm.js module constructor.
     *
     * <p>
     * Heap buffer layout by offset:
     * <pre>
     * 0x0000   encryption key schedule
     * 0x0400   decryption key schedule
     * 0x0800   sbox
     * 0x0c00   inv sbox
     * 0x1000   encryption tables
     * 0x2000   decryption tables
     * 0x3000   reserved (future GCM multiplication lookup table)
     * 0x4000   data
     * </pre>
     * Don't touch anything before <code>0x400</code>.
     * </p>
     *
     * @alias AES_asm
     * @class
     * @param {GlobalScope} stdlib - global scope object (e.g. <code>window</code>)
     * @param {Object} foreign - <i>ignored</i>
     * @param {ArrayBuffer} buffer - heap buffer to link with
     */
    var wrapper = function ( stdlib, foreign, buffer ) {
        // Init AES stuff for the first time
        if ( !aes_init_done ) aes_init();

        // Fill up AES tables
        var heap = new Uint32Array(buffer);
        heap.set( aes_sbox, 0x0800>>2 );
        heap.set( aes_sinv, 0x0c00>>2 );
        for ( var i = 0; i < 4; i++ ) {
            heap.set( aes_enc[i], ( 0x1000 + 0x400 * i )>>2 );
            heap.set( aes_dec[i], ( 0x2000 + 0x400 * i )>>2 );
        }

        /**
         * Calculate AES key schedules.
         * @instance
         * @memberof AES_asm
         * @param {int} ks - key size, 4/6/8 (for 128/192/256-bit key correspondingly)
         * @param {int} k0..k7 - key vector components
         */
        function set_key ( ks, k0, k1, k2, k3, k4, k5, k6, k7 ) {
            var ekeys = heap.subarray( 0x000, 60 ),
                dkeys = heap.subarray( 0x100, 0x100+60 );

            // Encryption key schedule
            ekeys.set( [ k0, k1, k2, k3, k4, k5, k6, k7 ] );
            for ( var i = ks, rcon = 1; i < 4*ks+28; i++ ) {
                var k = ekeys[i-1];
                if ( ( i % ks === 0 ) || ( ks === 8 && i % ks === 4 ) ) {
                    k = aes_sbox[k>>>24]<<24 ^ aes_sbox[k>>>16&255]<<16 ^ aes_sbox[k>>>8&255]<<8 ^ aes_sbox[k&255];
                }
                if ( i % ks === 0 ) {
                    k = (k << 8) ^ (k >>> 24) ^ (rcon << 24);
                    rcon = (rcon << 1) ^ ( (rcon & 0x80) ? 0x1b : 0 );
                }
                ekeys[i] = ekeys[i-ks] ^ k;
            }

            // Decryption key schedule
            for ( var j = 0; j < i; j += 4 ) {
                for ( var jj = 0; jj < 4; jj++ ) {
                    var k = ekeys[i-(4+j)+(4-jj)%4];
                    if ( j < 4 || j >= i-4 ) {
                        dkeys[j+jj] = k;
                    } else {
                        dkeys[j+jj] = aes_dec[0][aes_sbox[k>>>24]]
                                    ^ aes_dec[1][aes_sbox[k>>>16&255]]
                                    ^ aes_dec[2][aes_sbox[k>>>8&255]]
                                    ^ aes_dec[3][aes_sbox[k&255]];
                    }
                }
            }

            // Set rounds number
            asm.set_rounds( ks + 5 );
        }

        var asm = function ( stdlib, foreign, buffer ) {
            "use asm";

            var S0 = 0, S1 = 0, S2 = 0, S3 = 0,
                I0 = 0, I1 = 0, I2 = 0, I3 = 0,
                N0 = 0, N1 = 0, N2 = 0, N3 = 0,
                M0 = 0, M1 = 0, M2 = 0, M3 = 0,
                H0 = 0, H1 = 0, H2 = 0, H3 = 0,
                R = 0;

            var HEAP = new stdlib.Uint32Array(buffer),
                DATA = new stdlib.Uint8Array(buffer);

            /**
             * AES core
             * @param {int} k - precomputed key schedule offset
             * @param {int} s - precomputed sbox table offset
             * @param {int} t - precomputed round table offset
             * @param {int} r - number of inner rounds to perform
             * @param {int} x0..x3 - 128-bit input block vector
             */
            function _core ( k, s, t, r, x0, x1, x2, x3 ) {
                k = k|0;
                s = s|0;
                t = t|0;
                r = r|0;
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                var t1 = 0, t2 = 0, t3 = 0,
                    y0 = 0, y1 = 0, y2 = 0, y3 = 0,
                    i = 0;

                t1 = t|0x400, t2 = t|0x800, t3 = t|0xc00;

                // round 0
                x0 = x0 ^ HEAP[(k|0)>>2],
                x1 = x1 ^ HEAP[(k|4)>>2],
                x2 = x2 ^ HEAP[(k|8)>>2],
                x3 = x3 ^ HEAP[(k|12)>>2];

                // round 1..r
                for ( i = 16; (i|0) <= (r<<4); i = (i+16)|0 ) {
                    y0 = HEAP[(t|x0>>22&1020)>>2] ^ HEAP[(t1|x1>>14&1020)>>2] ^ HEAP[(t2|x2>>6&1020)>>2] ^ HEAP[(t3|x3<<2&1020)>>2] ^ HEAP[(k|i|0)>>2],
                    y1 = HEAP[(t|x1>>22&1020)>>2] ^ HEAP[(t1|x2>>14&1020)>>2] ^ HEAP[(t2|x3>>6&1020)>>2] ^ HEAP[(t3|x0<<2&1020)>>2] ^ HEAP[(k|i|4)>>2],
                    y2 = HEAP[(t|x2>>22&1020)>>2] ^ HEAP[(t1|x3>>14&1020)>>2] ^ HEAP[(t2|x0>>6&1020)>>2] ^ HEAP[(t3|x1<<2&1020)>>2] ^ HEAP[(k|i|8)>>2],
                    y3 = HEAP[(t|x3>>22&1020)>>2] ^ HEAP[(t1|x0>>14&1020)>>2] ^ HEAP[(t2|x1>>6&1020)>>2] ^ HEAP[(t3|x2<<2&1020)>>2] ^ HEAP[(k|i|12)>>2];
                    x0 = y0, x1 = y1, x2 = y2, x3 = y3;
                }

                // final round
                S0 = HEAP[(s|x0>>22&1020)>>2]<<24 ^ HEAP[(s|x1>>14&1020)>>2]<<16 ^ HEAP[(s|x2>>6&1020)>>2]<<8 ^ HEAP[(s|x3<<2&1020)>>2] ^ HEAP[(k|i|0)>>2],
                S1 = HEAP[(s|x1>>22&1020)>>2]<<24 ^ HEAP[(s|x2>>14&1020)>>2]<<16 ^ HEAP[(s|x3>>6&1020)>>2]<<8 ^ HEAP[(s|x0<<2&1020)>>2] ^ HEAP[(k|i|4)>>2],
                S2 = HEAP[(s|x2>>22&1020)>>2]<<24 ^ HEAP[(s|x3>>14&1020)>>2]<<16 ^ HEAP[(s|x0>>6&1020)>>2]<<8 ^ HEAP[(s|x1<<2&1020)>>2] ^ HEAP[(k|i|8)>>2],
                S3 = HEAP[(s|x3>>22&1020)>>2]<<24 ^ HEAP[(s|x0>>14&1020)>>2]<<16 ^ HEAP[(s|x1>>6&1020)>>2]<<8 ^ HEAP[(s|x2<<2&1020)>>2] ^ HEAP[(k|i|12)>>2];
            }

            /**
             * ECB mode encryption
             * @param {int} x0..x3 - 128-bit input block vector
             */
            function _ecb_enc ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                _core(
                    0x0000, 0x0800, 0x1000,
                    R,
                    x0,
                    x1,
                    x2,
                    x3
                );
            }

            /**
             * ECB mode decryption
             * @param {int} x0..x3 - 128-bit input block vector
             */
            function _ecb_dec ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                var t = 0;

                _core(
                    0x0400, 0x0c00, 0x2000,
                    R,
                    x0,
                    x3,
                    x2,
                    x1
                );

                t = S1, S1 = S3, S3 = t;
            }


            /**
             * CBC mode encryption
             * @param {int} x0..x3 - 128-bit input block vector
             */
            function _cbc_enc ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                _core(
                    0x0000, 0x0800, 0x1000,
                    R,
                    I0 ^ x0,
                    I1 ^ x1,
                    I2 ^ x2,
                    I3 ^ x3
                );

                I0 = S0,
                I1 = S1,
                I2 = S2,
                I3 = S3;
            }

            /**
             * CBC mode decryption
             * @param {int} x0..x3 - 128-bit input block vector
             */
            function _cbc_dec ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                var t = 0;

                _core(
                    0x0400, 0x0c00, 0x2000,
                    R,
                    x0,
                    x3,
                    x2,
                    x1
                );

                t = S1, S1 = S3, S3 = t;

                S0 = S0 ^ I0,
                S1 = S1 ^ I1,
                S2 = S2 ^ I2,
                S3 = S3 ^ I3;

                I0 = x0,
                I1 = x1,
                I2 = x2,
                I3 = x3;
            }

            /**
             * CFB mode encryption
             * @param {int} x0..x3 - 128-bit input block vector
             */
            function _cfb_enc ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                _core(
                    0x0000, 0x0800, 0x1000,
                    R,
                    I0,
                    I1,
                    I2,
                    I3
                );

                I0 = S0 = S0 ^ x0,
                I1 = S1 = S1 ^ x1,
                I2 = S2 = S2 ^ x2,
                I3 = S3 = S3 ^ x3;
            }


            /**
             * CFB mode decryption
             * @param {int} x0..x3 - 128-bit input block vector
             */
            function _cfb_dec ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                _core(
                    0x0000, 0x0800, 0x1000,
                    R,
                    I0,
                    I1,
                    I2,
                    I3
                );

                S0 = S0 ^ x0,
                S1 = S1 ^ x1,
                S2 = S2 ^ x2,
                S3 = S3 ^ x3;

                I0 = x0,
                I1 = x1,
                I2 = x2,
                I3 = x3;
            }

            /**
             * OFB mode encryption / decryption
             * @param {int} x0..x3 - 128-bit input block vector
             */
            function _ofb ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                _core(
                    0x0000, 0x0800, 0x1000,
                    R,
                    I0,
                    I1,
                    I2,
                    I3
                );

                I0 = S0,
                I1 = S1,
                I2 = S2,
                I3 = S3;

                S0 = S0 ^ x0,
                S1 = S1 ^ x1,
                S2 = S2 ^ x2,
                S3 = S3 ^ x3;
            }

            /**
             * CTR mode encryption / decryption
             * @param {int} x0..x3 - 128-bit input block vector
             */
            function _ctr ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                _core(
                    0x0000, 0x0800, 0x1000,
                    R,
                    N0,
                    N1,
                    N2,
                    N3
                );

                N3 = ( ~M3 & N3 ) | M3 & ( N3 + 1 ),
                N2 = ( ~M2 & N2 ) | M2 & ( N2 + ( (N3|0) == 0 ) ),
                N1 = ( ~M1 & N1 ) | M1 & ( N1 + ( (N2|0) == 0 ) ),
                N0 = ( ~M0 & N0 ) | M0 & ( N0 + ( (N1|0) == 0 ) );

                S0 = S0 ^ x0,
                S1 = S1 ^ x1,
                S2 = S2 ^ x2,
                S3 = S3 ^ x3;
            }

            /**
             * GCM mode MAC calculation
             * @param {int} x0..x3 - 128-bit input block vector
             */
            function _gcm_mac ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                var y0 = 0, y1 = 0, y2 = 0, y3 = 0,
                    z0 = 0, z1 = 0, z2 = 0, z3 = 0,
                    i = 0, c = 0;

                x0 = x0 ^ I0,
                x1 = x1 ^ I1,
                x2 = x2 ^ I2,
                x3 = x3 ^ I3;

                y0 = H0|0,
                y1 = H1|0,
                y2 = H2|0,
                y3 = H3|0;

                for ( ; (i|0) < 128; i = (i + 1)|0 ) {
                    if ( y0 >>> 31 ) {
                        z0 = z0 ^ x0,
                        z1 = z1 ^ x1,
                        z2 = z2 ^ x2,
                        z3 = z3 ^ x3;
                    }

                    y0 = (y0 << 1) | (y1 >>> 31),
                    y1 = (y1 << 1) | (y2 >>> 31),
                    y2 = (y2 << 1) | (y3 >>> 31),
                    y3 = (y3 << 1);

                    c = x3 & 1;

                    x3 = (x3 >>> 1) | (x2 << 31),
                    x2 = (x2 >>> 1) | (x1 << 31),
                    x1 = (x1 >>> 1) | (x0 << 31),
                    x0 = (x0 >>> 1);

                    if ( c ) x0 = x0 ^ 0xe1000000;
                }

                I0 = z0,
                I1 = z1,
                I2 = z2,
                I3 = z3;
            }

            /**
             * Set the internal rounds number.
             * @instance
             * @memberof AES_asm
             * @param {int} r - number if inner AES rounds
             */
            function set_rounds ( r ) {
                r = r|0;
                R = r;
            }

            /**
             * Populate the internal state of the module.
             * @instance
             * @memberof AES_asm
             * @param {int} s0...s3 - state vector
             */
            function set_state ( s0, s1, s2, s3 ) {
                s0 = s0|0;
                s1 = s1|0;
                s2 = s2|0;
                s3 = s3|0;

                S0 = s0,
                S1 = s1,
                S2 = s2,
                S3 = s3;
            }

            /**
             * Populate the internal iv of the module.
             * @instance
             * @memberof AES_asm
             * @param {int} i0...i3 - iv vector
             */
            function set_iv ( i0, i1, i2, i3 ) {
                i0 = i0|0;
                i1 = i1|0;
                i2 = i2|0;
                i3 = i3|0;

                I0 = i0,
                I1 = i1,
                I2 = i2,
                I3 = i3;
            }

            /**
             * Set nonce for CTR-family modes.
             * @instance
             * @memberof AES_asm
             * @param {int} n0..n3 - nonce vector
             */
            function set_nonce ( n0, n1, n2, n3 ) {
                n0 = n0|0;
                n1 = n1|0;
                n2 = n2|0;
                n3 = n3|0;

                N0 = n0,
                N1 = n1,
                N2 = n2,
                N3 = n3;
            }

            /**
             * Set counter mask for CTR-family modes.
             * @instance
             * @memberof AES_asm
             * @param {int} m0...m3 - counter mask vector
             */
            function set_mask ( m0, m1, m2, m3 ) {
                m0 = m0|0;
                m1 = m1|0;
                m2 = m2|0;
                m3 = m3|0;

                M0 = m0,
                M1 = m1,
                M2 = m2,
                M3 = m3;
            }

            /**
             * Set counter for CTR-family modes.
             * @instance
             * @memberof AES_asm
             * @param {int} c0...c3 - counter vector
             */
            function set_counter ( c0, c1, c2, c3 ) {
                c0 = c0|0;
                c1 = c1|0;
                c2 = c2|0;
                c3 = c3|0;

                N3 = ( ~M3 & N3 ) | M3 & c3,
                N2 = ( ~M2 & N2 ) | M2 & c2,
                N1 = ( ~M1 & N1 ) | M1 & c1,
                N0 = ( ~M0 & N0 ) | M0 & c0;
            }

            /**
             * Store the internal state vector into the heap.
             * @instance
             * @memberof AES_asm
             * @param {int} pos - offset where to put the data
             * @return {int} The number of bytes have been written into the heap, always 16.
             */
            function get_state ( pos ) {
                pos = pos|0;

                if ( pos & 15 ) return -1;

                DATA[pos|0] = S0>>>24,
                DATA[pos|1] = S0>>>16&255,
                DATA[pos|2] = S0>>>8&255,
                DATA[pos|3] = S0&255,
                DATA[pos|4] = S1>>>24,
                DATA[pos|5] = S1>>>16&255,
                DATA[pos|6] = S1>>>8&255,
                DATA[pos|7] = S1&255,
                DATA[pos|8] = S2>>>24,
                DATA[pos|9] = S2>>>16&255,
                DATA[pos|10] = S2>>>8&255,
                DATA[pos|11] = S2&255,
                DATA[pos|12] = S3>>>24,
                DATA[pos|13] = S3>>>16&255,
                DATA[pos|14] = S3>>>8&255,
                DATA[pos|15] = S3&255;

                return 16;
            }

            /**
             * Store the internal iv vector into the heap.
             * @instance
             * @memberof AES_asm
             * @param {int} pos - offset where to put the data
             * @return {int} The number of bytes have been written into the heap, always 16.
             */
            function get_iv ( pos ) {
                pos = pos|0;

                if ( pos & 15 ) return -1;

                DATA[pos|0] = I0>>>24,
                DATA[pos|1] = I0>>>16&255,
                DATA[pos|2] = I0>>>8&255,
                DATA[pos|3] = I0&255,
                DATA[pos|4] = I1>>>24,
                DATA[pos|5] = I1>>>16&255,
                DATA[pos|6] = I1>>>8&255,
                DATA[pos|7] = I1&255,
                DATA[pos|8] = I2>>>24,
                DATA[pos|9] = I2>>>16&255,
                DATA[pos|10] = I2>>>8&255,
                DATA[pos|11] = I2&255,
                DATA[pos|12] = I3>>>24,
                DATA[pos|13] = I3>>>16&255,
                DATA[pos|14] = I3>>>8&255,
                DATA[pos|15] = I3&255;

                return 16;
            }

            /**
             * GCM initialization.
             * @instance
             * @memberof AES_asm
             */
            function gcm_init ( ) {
                _ecb_enc( 0, 0, 0, 0 );
                H0 = S0,
                H1 = S1,
                H2 = S2,
                H3 = S3;
            }

            /**
             * Perform ciphering operation on the supplied data.
             * @instance
             * @memberof AES_asm
             * @param {int} mode - block cipher mode (see {@link AES_asm} mode constants)
             * @param {int} pos - offset of the data being processed
             * @param {int} len - length of the data being processed
             * @return {int} Actual amount of data have been processed.
             */
            function cipher ( mode, pos, len ) {
                mode = mode|0;
                pos = pos|0;
                len = len|0;

                var ret = 0;

                if ( pos & 15 ) return -1;

                while ( (len|0) >= 16 ) {
                    _cipher_modes[mode&7](
                        DATA[pos|0]<<24 | DATA[pos|1]<<16 | DATA[pos|2]<<8 | DATA[pos|3],
                        DATA[pos|4]<<24 | DATA[pos|5]<<16 | DATA[pos|6]<<8 | DATA[pos|7],
                        DATA[pos|8]<<24 | DATA[pos|9]<<16 | DATA[pos|10]<<8 | DATA[pos|11],
                        DATA[pos|12]<<24 | DATA[pos|13]<<16 | DATA[pos|14]<<8 | DATA[pos|15]
                    );

                    DATA[pos|0] = S0>>>24,
                    DATA[pos|1] = S0>>>16&255,
                    DATA[pos|2] = S0>>>8&255,
                    DATA[pos|3] = S0&255,
                    DATA[pos|4] = S1>>>24,
                    DATA[pos|5] = S1>>>16&255,
                    DATA[pos|6] = S1>>>8&255,
                    DATA[pos|7] = S1&255,
                    DATA[pos|8] = S2>>>24,
                    DATA[pos|9] = S2>>>16&255,
                    DATA[pos|10] = S2>>>8&255,
                    DATA[pos|11] = S2&255,
                    DATA[pos|12] = S3>>>24,
                    DATA[pos|13] = S3>>>16&255,
                    DATA[pos|14] = S3>>>8&255,
                    DATA[pos|15] = S3&255;

                    ret = (ret + 16)|0,
                    pos = (pos + 16)|0,
                    len = (len - 16)|0;
                }

                return ret|0;
            }

            /**
             * Calculates MAC of the supplied data.
             * @instance
             * @memberof AES_asm
             * @param {int} mode - block cipher mode (see {@link AES_asm} mode constants)
             * @param {int} pos - offset of the data being processed
             * @param {int} len - length of the data being processed
             * @return {int} Actual amount of data have been processed.
             */
            function mac ( mode, pos, len ) {
                mode = mode|0;
                pos = pos|0;
                len = len|0;

                var ret = 0;

                if ( pos & 15 ) return -1;

                while ( (len|0) >= 16 ) {
                    _mac_modes[mode&1](
                        DATA[pos|0]<<24 | DATA[pos|1]<<16 | DATA[pos|2]<<8 | DATA[pos|3],
                        DATA[pos|4]<<24 | DATA[pos|5]<<16 | DATA[pos|6]<<8 | DATA[pos|7],
                        DATA[pos|8]<<24 | DATA[pos|9]<<16 | DATA[pos|10]<<8 | DATA[pos|11],
                        DATA[pos|12]<<24 | DATA[pos|13]<<16 | DATA[pos|14]<<8 | DATA[pos|15]
                    );

                    ret = (ret + 16)|0,
                    pos = (pos + 16)|0,
                    len = (len - 16)|0;
                }

                return ret|0;
            }

            /**
             * AES cipher modes table (virual methods)
             */
            var _cipher_modes = [ _ecb_enc, _ecb_dec, _cbc_enc, _cbc_dec, _cfb_enc, _cfb_dec, _ofb, _ctr ];

            /**
             * AES MAC modes table (virual methods)
             */
            var _mac_modes = [ _cbc_enc, _gcm_mac ];

            /**
             * Asm.js module exports
             */
            return {
                set_rounds: set_rounds,
                set_state:  set_state,
                set_iv:     set_iv,
                set_nonce:  set_nonce,
                set_mask:   set_mask,
                set_counter:set_counter,
                get_state:  get_state,
                get_iv:     get_iv,
                gcm_init:   gcm_init,
                cipher:     cipher,
                mac:        mac
            };
        }( stdlib, foreign, buffer );

        asm.set_key = set_key;

        return asm;
    };

    /**
     * AES enciphering mode constants
     * @enum {int}
     * @const
     */
    wrapper.ENC = {
        ECB: 0,
        CBC: 2,
        CFB: 4,
        OFB: 6,
        CTR: 7
    },

    /**
     * AES deciphering mode constants
     * @enum {int}
     * @const
     */
    wrapper.DEC = {
        ECB: 1,
        CBC: 3,
        CFB: 5,
        OFB: 6,
        CTR: 7
    },

    /**
     * AES MAC mode constants
     * @enum {int}
     * @const
     */
    wrapper.MAC = {
        CBC: 0,
        GCM: 1
    };

    /**
     * Heap data offset
     * @type {int}
     * @const
     */
    wrapper.HEAP_DATA = 0x4000;

    return wrapper;
}();

function AES ( options ) {
    options = options || {};

    this.heap = _heap_init( Uint8Array, options ).subarray( AES_asm.HEAP_DATA );
    this.asm = options.asm || AES_asm( global, null, this.heap.buffer );
    this.mode = null;
    this.key = null;

    this.reset( options );
}

function AES_set_key ( key ) {
    if ( key !== undefined ) {
        if ( is_buffer(key) || is_bytes(key) ) {
            key = new Uint8Array(key);
        }
        else if ( is_string(key) ) {
            key = string_to_bytes(key);
        }
        else {
            throw new TypeError("unexpected key type");
        }

        var keylen = key.length;
        if ( keylen !== 16 && keylen !== 24 && keylen !== 32 )
            throw new IllegalArgumentError("illegal key size");

        var keyview = new DataView( key.buffer, key.byteOffset, key.byteLength );
        this.asm.set_key(
            keylen >> 2,
            keyview.getUint32(0),
            keyview.getUint32(4),
            keyview.getUint32(8),
            keyview.getUint32(12),
            keylen > 16 ? keyview.getUint32(16) : 0,
            keylen > 16 ? keyview.getUint32(20) : 0,
            keylen > 24 ? keyview.getUint32(24) : 0,
            keylen > 24 ? keyview.getUint32(28) : 0
        );

        this.key = key;
    }
    else if ( !this.key ) {
        throw new Error("key is required");
    }
}

function AES_set_iv ( iv ) {
    if ( iv !== undefined ) {
        if ( is_buffer(iv) || is_bytes(iv) ) {
            iv = new Uint8Array(iv);
        }
        else if ( is_string(iv) ) {
            iv = string_to_bytes(iv);
        }
        else {
            throw new TypeError("unexpected iv type");
        }

        if ( iv.length !== 16 )
            throw new IllegalArgumentError("illegal iv size");

        var ivview = new DataView( iv.buffer, iv.byteOffset, iv.byteLength );

        this.iv = iv;
        this.asm.set_iv( ivview.getUint32(0), ivview.getUint32(4), ivview.getUint32(8), ivview.getUint32(12) );
    }
    else {
        this.iv = null;
        this.asm.set_iv( 0, 0, 0, 0 );
    }
}

function AES_set_padding ( padding ) {
    if ( padding !== undefined ) {
        this.padding = !!padding;
    }
    else {
        this.padding = true;
    }
}

function AES_reset ( options ) {
    options = options || {};

    this.result = null;
    this.pos = 0;
    this.len = 0;

    AES_set_key.call( this, options.key );
    if ( this.hasOwnProperty('iv') ) AES_set_iv.call( this, options.iv );
    if ( this.hasOwnProperty('padding') ) AES_set_padding.call( this, options.padding );

    return this;
}

function AES_Encrypt_process ( data ) {
    if ( is_string(data) )
        data = string_to_bytes(data);

    if ( is_buffer(data) )
        data = new Uint8Array(data);

    if ( !is_bytes(data) )
        throw new TypeError("data isn't of expected type");

    var asm = this.asm,
        heap = this.heap,
        amode = AES_asm.ENC[this.mode],
        hpos = AES_asm.HEAP_DATA,
        pos = this.pos,
        len = this.len,
        dpos = 0,
        dlen = data.length || 0,
        rpos = 0,
        rlen = (len + dlen) & -16,
        wlen = 0;

    var result = new Uint8Array(rlen);

    while ( dlen > 0 ) {
        wlen = _heap_write( heap, pos+len, data, dpos, dlen );
        len  += wlen;
        dpos += wlen;
        dlen -= wlen;

        wlen = asm.cipher( amode, hpos + pos, len );

        if ( wlen ) result.set( heap.subarray( pos, pos + wlen ), rpos );
        rpos += wlen;

        if ( wlen < len ) {
            pos += wlen;
            len -= wlen;
        } else {
            pos = 0;
            len = 0;
        }
    }

    this.result = result;
    this.pos = pos;
    this.len = len;

    return this;
}

function AES_Encrypt_finish ( data ) {
    var presult = null,
        prlen = 0;

    if ( data !== undefined ) {
        presult = AES_Encrypt_process.call( this, data ).result;
        prlen = presult.length;
    }

    var asm = this.asm,
        heap = this.heap,
        amode = AES_asm.ENC[this.mode],
        hpos = AES_asm.HEAP_DATA,
        pos = this.pos,
        len = this.len,
        plen = 16 - len % 16,
        rlen = len;

    if ( this.hasOwnProperty('padding') ) {
        if ( this.padding ) {
            for ( var p = 0; p < plen; ++p ) heap[ pos + len + p ] = plen;
            len += plen;
            rlen = len;
        }
        else if ( len % 16 ) {
            throw new IllegalArgumentError("data length must be a multiple of the block size");
        }
    }
    else {
        len += plen;
    }

    var result = new Uint8Array( prlen + rlen );

    if ( prlen ) result.set( presult );

    if ( len ) asm.cipher( amode, hpos + pos, len );

    if ( rlen ) result.set( heap.subarray( pos, pos + rlen ), prlen );

    this.result = result;
    this.pos = 0;
    this.len = 0;

    return this;
}

function AES_Decrypt_process ( data ) {
    if ( is_string(data) )
        data = string_to_bytes(data);

    if ( is_buffer(data) )
        data = new Uint8Array(data);

    if ( !is_bytes(data) )
        throw new TypeError("data isn't of expected type");

    var asm = this.asm,
        heap = this.heap,
        amode = AES_asm.DEC[this.mode],
        hpos = AES_asm.HEAP_DATA,
        pos = this.pos,
        len = this.len,
        dpos = 0,
        dlen = data.length || 0,
        rpos = 0,
        rlen = (len + dlen) & -16,
        plen = 0,
        wlen = 0;

    if ( this.hasOwnProperty('padding') && this.padding ) {
        plen = len + dlen - rlen || 16;
        rlen -= plen;
    }

    var result = new Uint8Array(rlen);

    while ( dlen > 0 ) {
        wlen = _heap_write( heap, pos+len, data, dpos, dlen );
        len  += wlen;
        dpos += wlen;
        dlen -= wlen;

        wlen = asm.cipher( amode, hpos + pos, len - ( !dlen ? plen : 0 ) );

        if ( wlen ) result.set( heap.subarray( pos, pos + wlen ), rpos );
        rpos += wlen;

        if ( wlen < len ) {
            pos += wlen;
            len -= wlen;
        } else {
            pos = 0;
            len = 0;
        }
    }

    this.result = result;
    this.pos = pos;
    this.len = len;

    return this;
}

function AES_Decrypt_finish ( data ) {
    var presult = null,
        prlen = 0;

    if ( data !== undefined ) {
        presult = AES_Decrypt_process.call( this, data ).result;
        prlen = presult.length;
    }

    var asm = this.asm,
        heap = this.heap,
        amode = AES_asm.DEC[this.mode],
        hpos = AES_asm.HEAP_DATA,
        pos = this.pos,
        len = this.len,
        rlen = len;

    if ( len > 0 ) {
        if ( len % 16 ) {
            if ( this.hasOwnProperty('padding') ) {
                throw new IllegalArgumentError("data length must be a multiple of the block size");
            } else {
                len += 16 - len % 16;
            }
        }

        asm.cipher( amode, hpos + pos, len );

        if ( this.hasOwnProperty('padding') && this.padding ) {
            var pad = heap[ pos + rlen - 1 ];
            if ( pad < 1 || pad > 16 || pad > rlen )
                throw new SecurityError("bad padding");

            var pcheck = 0;
            for ( var i = pad; i > 1; i-- ) pcheck |= pad ^ heap[ pos + rlen - i ];
            if ( pcheck )
                throw new SecurityError("bad padding");

            rlen -= pad;
        }
    }

    var result = new Uint8Array( prlen + rlen );

    if ( prlen > 0 ) {
        result.set( presult );
    }

    if ( rlen > 0 ) {
        result.set( heap.subarray( pos, pos + rlen ), prlen );
    }

    this.result = result;
    this.pos = 0;
    this.len = 0;

    return this;
}

/**
 * Cipher Feedback Mode (CFB)
 */

function AES_CFB ( options ) {
    this.iv = null;

    AES.call( this, options );

    this.mode = 'CFB';
}

var AES_CFB_prototype = AES_CFB.prototype;
AES_CFB_prototype.BLOCK_SIZE = 16;
AES_CFB_prototype.reset = AES_reset;
AES_CFB_prototype.encrypt = AES_Encrypt_finish;
AES_CFB_prototype.decrypt = AES_Decrypt_finish;

function AES_CFB_Encrypt ( options ) {
    AES_CFB.call( this, options );
}

var AES_CFB_Encrypt_prototype = AES_CFB_Encrypt.prototype;
AES_CFB_Encrypt_prototype.BLOCK_SIZE = 16;
AES_CFB_Encrypt_prototype.reset = AES_reset;
AES_CFB_Encrypt_prototype.process = AES_Encrypt_process;
AES_CFB_Encrypt_prototype.finish = AES_Encrypt_finish;

function AES_CFB_Decrypt ( options ) {
    AES_CFB.call( this, options );
}

var AES_CFB_Decrypt_prototype = AES_CFB_Decrypt.prototype;
AES_CFB_Decrypt_prototype.BLOCK_SIZE = 16;
AES_CFB_Decrypt_prototype.reset = AES_reset;
AES_CFB_Decrypt_prototype.process = AES_Decrypt_process;
AES_CFB_Decrypt_prototype.finish = AES_Decrypt_finish;

/**
 * Counter Mode (CTR)
 */

function AES_CTR ( options ) {
    this.nonce = null,
    this.counter = 0,
    this.counterSize = 0;

    AES.call( this, options );

    this.mode = 'CTR';
}

function AES_CTR_Crypt ( options ) {
    AES_CTR.call( this, options );
}

function AES_CTR_set_options ( nonce, counter, size ) {
    if ( size !== undefined ) {
        if ( size < 8 || size > 48 )
            throw new IllegalArgumentError("illegal counter size");

        this.counterSize = size;

        var mask = Math.pow( 2, size ) - 1;
        this.asm.set_mask( 0, 0, (mask / 0x100000000)|0, mask|0 );
    }
    else {
        this.counterSize = size = 48;
        this.asm.set_mask( 0, 0, 0xffff, 0xffffffff );
    }

    if ( nonce !== undefined ) {
        if ( is_buffer(nonce) || is_bytes(nonce) ) {
            nonce = new Uint8Array(nonce);
        }
        else if ( is_string(nonce) ) {
            nonce = string_to_bytes(nonce);
        }
        else {
            throw new TypeError("unexpected nonce type");
        }

        var len = nonce.length;
        if ( !len || len > 16 )
            throw new IllegalArgumentError("illegal nonce size");

        this.nonce = nonce;

        var view = new DataView( new ArrayBuffer(16) );
        new Uint8Array(view.buffer).set(nonce);

        this.asm.set_nonce( view.getUint32(0), view.getUint32(4), view.getUint32(8), view.getUint32(12) );
    }
    else {
        throw new Error("nonce is required");
    }

    if ( counter !== undefined ) {
        if ( !is_number(counter) )
            throw new TypeError("unexpected counter type");

        if ( counter < 0 || counter >= Math.pow( 2, size ) )
            throw new IllegalArgumentError("illegal counter value");

        this.counter = counter;

        this.asm.set_counter( 0, 0, (counter / 0x100000000)|0, counter|0 );
    }
    else {
        this.counter = counter = 0;
    }
}

function AES_CTR_reset ( options ) {
    options = options || {};

    AES_reset.call( this, options );

    AES_CTR_set_options.call( this, options.nonce, options.counter, options.counterSize );

    return this;
}

var AES_CTR_prototype = AES_CTR.prototype;
AES_CTR_prototype.BLOCK_SIZE = 16;
AES_CTR_prototype.reset = AES_CTR_reset;
AES_CTR_prototype.encrypt = AES_Encrypt_finish;
AES_CTR_prototype.decrypt = AES_Encrypt_finish;

var AES_CTR_Crypt_prototype = AES_CTR_Crypt.prototype;
AES_CTR_Crypt_prototype.BLOCK_SIZE = 16;
AES_CTR_Crypt_prototype.reset = AES_CTR_reset;
AES_CTR_Crypt_prototype.process = AES_Encrypt_process;
AES_CTR_Crypt_prototype.finish = AES_Encrypt_finish;

/**
 * Galois/Counter mode
 */

var _AES_GCM_data_maxLength = 68719476704;  // 2^36 - 2^5

function _gcm_mac_process ( data ) {
    var heap = this.heap,
        asm  = this.asm,
        dpos = 0,
        dlen = data.length || 0,
        wlen = 0;

    while ( dlen > 0 ) {
        wlen = _heap_write( heap, 0, data, dpos, dlen );
        dpos += wlen;
        dlen -= wlen;

        while ( wlen & 15 ) heap[ wlen++ ] = 0;

        asm.mac( AES_asm.MAC.GCM, AES_asm.HEAP_DATA, wlen );
    }
}

function AES_GCM ( options ) {
    this.nonce      = null;
    this.adata      = null;
    this.iv         = null;
    this.counter    = 1;
    this.tagSize    = 16;

    AES.call( this, options );

    this.mode       = 'GCM';
}

function AES_GCM_Encrypt ( options ) {
    AES_GCM.call( this, options );
}

function AES_GCM_Decrypt ( options ) {
    AES_GCM.call( this, options );
}

function AES_GCM_reset ( options ) {
    options = options || {};

    AES_reset.call( this, options );

    var asm = this.asm,
        heap = this.heap;

    asm.gcm_init();

    var tagSize = options.tagSize;
    if ( tagSize !== undefined ) {
        if ( !is_number(tagSize) )
            throw new TypeError("tagSize must be a number");

        if ( tagSize < 4 || tagSize > 16 )
            throw new IllegalArgumentError("illegal tagSize value");

        this.tagSize = tagSize;
    }
    else {
        this.tagSize = 16;
    }

    var nonce = options.nonce;
    if ( nonce !== undefined ) {
        if ( is_bytes(nonce) || is_buffer(nonce) ) {
            nonce = new Uint8Array(nonce);
        }
        else if ( is_string(nonce) ) {
            nonce = string_to_bytes(nonce);
        }
        else {
            throw new TypeError("unexpected nonce type");
        }

        this.nonce = nonce;

        var noncelen = nonce.length || 0,
            noncebuf = new Uint8Array(16);
        if ( noncelen !== 12 ) {
            _gcm_mac_process.call( this, nonce );

            heap[0] = heap[1] = heap[2] = heap[3] = heap[4] = heap[5] = heap[6] = heap[7] = heap[8] = heap[9] = heap[10] = 0,
            heap[11] = noncelen>>>29,
            heap[12] = noncelen>>>21&255,
            heap[13] = noncelen>>>13&255,
            heap[14] = noncelen>>>5&255,
            heap[15] = noncelen<<3&255;
            asm.mac( AES_asm.MAC.GCM, AES_asm.HEAP_DATA, 16 );

            asm.get_iv( AES_asm.HEAP_DATA );
            asm.set_iv();

            noncebuf.set( heap.subarray( 0, 16 ) );
        }
        else {
            noncebuf.set(nonce);
            noncebuf[15] = 1;
        }

        var nonceview = new DataView( noncebuf.buffer );
        this.gamma0 = nonceview.getUint32(12);

        asm.set_nonce( nonceview.getUint32(0), nonceview.getUint32(4), nonceview.getUint32(8), 0 );
        asm.set_mask( 0, 0, 0, 0xffffffff );
    }
    else {
        throw new Error("nonce is required");
    }

    var adata = options.adata;
    if ( adata !== undefined && adata !== null ) {
        if ( is_bytes(adata) || is_buffer(adata) ) {
            adata = new Uint8Array(adata);
        }
        else if ( is_string(adata) ) {
            adata = string_to_bytes(adata);
        }
        else {
            throw new TypeError("unexpected adata type");
        }

        if ( adata.length > _AES_GCM_data_maxLength )
            throw new IllegalArgumentError("illegal adata length");

        if ( adata.length ) {
            this.adata = adata;
            _gcm_mac_process.call( this, adata );
        }
        else {
            this.adata = null;
        }
    }
    else {
        this.adata = null;
    }

    var counter = options.counter;
    if ( counter !== undefined ) {
        if ( !is_number(counter) )
            throw new TypeError("counter must be a number");

        if ( counter < 1 || counter > 0xffffffff )
            throw new RangeError("counter must be a positive 32-bit integer");

        this.counter = counter;
        asm.set_counter( 0, 0, 0, this.gamma0+counter|0 );
    }
    else {
        this.counter = 1;
        asm.set_counter( 0, 0, 0, this.gamma0+1|0 );
    }

    var iv = options.iv;
    if ( iv !== undefined ) {
        if ( !is_number(counter) )
            throw new TypeError("counter must be a number");

        this.iv = iv;

        AES_set_iv.call( this, iv );
    }

    return this;
}

function AES_GCM_Encrypt_process ( data ) {
    if ( is_string(data) )
        data = string_to_bytes(data);

    if ( is_buffer(data) )
        data = new Uint8Array(data);

    if ( !is_bytes(data) )
        throw new TypeError("data isn't of expected type");

    var dpos = 0,
        dlen = data.length || 0,
        asm = this.asm,
        heap = this.heap,
        counter = this.counter,
        pos = this.pos,
        len = this.len,
        rpos = 0,
        rlen = ( len + dlen ) & -16,
        wlen = 0;

    if ( ((counter-1)<<4) + len + dlen > _AES_GCM_data_maxLength )
        throw new RangeError("counter overflow");

    var result = new Uint8Array(rlen);

    while ( dlen > 0 ) {
        wlen = _heap_write( heap, pos+len, data, dpos, dlen );
        len  += wlen;
        dpos += wlen;
        dlen -= wlen;

        wlen = asm.cipher( AES_asm.ENC.CTR, AES_asm.HEAP_DATA + pos, len );
        wlen = asm.mac( AES_asm.MAC.GCM, AES_asm.HEAP_DATA + pos, wlen );

        if ( wlen ) result.set( heap.subarray( pos, pos + wlen ), rpos );
        counter += (wlen>>>4);
        rpos += wlen;

        if ( wlen < len ) {
            pos += wlen;
            len -= wlen;
        } else {
            pos = 0;
            len = 0;
        }
    }

    this.result = result;
    this.counter = counter;
    this.pos = pos;
    this.len = len;

    return this;
}

function AES_GCM_Encrypt_finish () {
    var asm = this.asm,
        heap = this.heap,
        counter = this.counter,
        tagSize = this.tagSize,
        adata = this.adata,
        pos = this.pos,
        len = this.len;

    var result = new Uint8Array( len + tagSize );

    asm.cipher( AES_asm.ENC.CTR, AES_asm.HEAP_DATA + pos, (len + 15) & -16 );
    if ( len ) result.set( heap.subarray( pos, pos + len ) );

    for ( var i = len; i & 15; i++ ) heap[ pos + i ] = 0;
    asm.mac( AES_asm.MAC.GCM, AES_asm.HEAP_DATA + pos, i );

    var alen = ( adata !== null ) ? adata.length : 0,
        clen = ( (counter-1) << 4) + len;
    heap[0] = heap[1] = heap[2] = 0,
    heap[3] = alen>>>29,
    heap[4] = alen>>>21,
    heap[5] = alen>>>13&255,
    heap[6] = alen>>>5&255,
    heap[7] = alen<<3&255,
    heap[8] = heap[9] = heap[10] = 0,
    heap[11] = clen>>>29,
    heap[12] = clen>>>21&255,
    heap[13] = clen>>>13&255,
    heap[14] = clen>>>5&255,
    heap[15] = clen<<3&255;
    asm.mac( AES_asm.MAC.GCM, AES_asm.HEAP_DATA, 16 );
    asm.get_iv( AES_asm.HEAP_DATA );

    asm.set_counter( 0, 0, 0, this.gamma0 );
    asm.cipher( AES_asm.ENC.CTR, AES_asm.HEAP_DATA, 16 );
    result.set( heap.subarray( 0, tagSize ), len );

    this.result = result;
    this.counter = 1;
    this.pos = 0;
    this.len = 0;

    return this;
}

function AES_GCM_encrypt ( data ) {
    var result1 = AES_GCM_Encrypt_process.call( this, data ).result,
        result2 = AES_GCM_Encrypt_finish.call(this).result;

    var result = new Uint8Array( result1.length + result2.length );
    if ( result1.length ) result.set( result1 );
    if ( result2.length ) result.set( result2, result1.length );
    this.result = result;

    return this;
}

function AES_GCM_Decrypt_process ( data ) {
    if ( is_string(data) )
        data = string_to_bytes(data);

    if ( is_buffer(data) )
        data = new Uint8Array(data);

    if ( !is_bytes(data) )
        throw new TypeError("data isn't of expected type");

    var dpos = 0,
        dlen = data.length || 0,
        asm = this.asm,
        heap = this.heap,
        counter = this.counter,
        tagSize = this.tagSize,
        pos = this.pos,
        len = this.len,
        rpos = 0,
        rlen = len + dlen > tagSize ? ( len + dlen - tagSize ) & -16 : 0,
        tlen = len + dlen - rlen,
        wlen = 0;

    if ( ((counter-1)<<4) + len + dlen > _AES_GCM_data_maxLength )
        throw new RangeError("counter overflow");

    var result = new Uint8Array(rlen);

    while ( dlen > tlen ) {
        wlen = _heap_write( heap, pos+len, data, dpos, dlen-tlen );
        len  += wlen;
        dpos += wlen;
        dlen -= wlen;

        wlen = asm.mac( AES_asm.MAC.GCM, AES_asm.HEAP_DATA + pos, wlen );
        wlen = asm.cipher( AES_asm.DEC.CTR, AES_asm.HEAP_DATA + pos, wlen );

        if ( wlen ) result.set( heap.subarray( pos, pos+wlen ), rpos );
        counter += (wlen>>>4);
        rpos += wlen;

        pos = 0;
        len = 0;
    }

    if ( dlen > 0 ) {
        len += _heap_write( heap, 0, data, dpos, dlen );
    }

    this.result = result;
    this.counter = counter;
    this.pos = pos;
    this.len = len;

    return this;
}

function AES_GCM_Decrypt_finish () {
    var asm = this.asm,
        heap = this.heap,
        tagSize = this.tagSize,
        adata = this.adata,
        counter = this.counter,
        pos = this.pos,
        len = this.len,
        rlen = len - tagSize,
        wlen = 0;

    if ( len < tagSize )
        throw new IllegalStateError("authentication tag not found");

    var result = new Uint8Array(rlen),
        atag = new Uint8Array( heap.subarray( pos+rlen, pos+len ) );

    for ( var i = rlen; i & 15; i++ ) heap[ pos + i ] = 0;

    wlen = asm.mac( AES_asm.MAC.GCM, AES_asm.HEAP_DATA + pos, i );
    wlen = asm.cipher( AES_asm.DEC.CTR, AES_asm.HEAP_DATA + pos, i );
    if ( rlen ) result.set( heap.subarray( pos, pos+rlen ) );

    var alen = ( adata !== null ) ? adata.length : 0,
        clen = ( (counter-1) << 4) + len - tagSize;
    heap[0] = heap[1] = heap[2] = 0,
    heap[3] = alen>>>29,
    heap[4] = alen>>>21,
    heap[5] = alen>>>13&255,
    heap[6] = alen>>>5&255,
    heap[7] = alen<<3&255,
    heap[8] = heap[9] = heap[10] = 0,
    heap[11] = clen>>>29,
    heap[12] = clen>>>21&255,
    heap[13] = clen>>>13&255,
    heap[14] = clen>>>5&255,
    heap[15] = clen<<3&255;
    asm.mac( AES_asm.MAC.GCM, AES_asm.HEAP_DATA, 16 );
    asm.get_iv( AES_asm.HEAP_DATA );

    asm.set_counter( 0, 0, 0, this.gamma0 );
    asm.cipher( AES_asm.ENC.CTR, AES_asm.HEAP_DATA, 16 );

    var acheck = 0;
    for ( var i = 0; i < tagSize; ++i ) acheck |= atag[i] ^ heap[i];
    if ( acheck )
        throw new SecurityError("data integrity check failed");

    this.result = result;
    this.counter = 1;
    this.pos = 0;
    this.len = 0;

    return this;
}

function AES_GCM_decrypt ( data ) {
    var result1 = AES_GCM_Decrypt_process.call( this, data ).result,
        result2 = AES_GCM_Decrypt_finish.call( this ).result;

    var result = new Uint8Array( result1.length + result2.length );
    if ( result1.length ) result.set( result1 );
    if ( result2.length ) result.set( result2, result1.length );
    this.result = result;

    return this;
}

var AES_GCM_prototype = AES_GCM.prototype;
AES_GCM_prototype.BLOCK_SIZE = 16;
AES_GCM_prototype.reset = AES_GCM_reset;
AES_GCM_prototype.encrypt = AES_GCM_encrypt;
AES_GCM_prototype.decrypt = AES_GCM_decrypt;

var AES_GCM_Encrypt_prototype = AES_GCM_Encrypt.prototype;
AES_GCM_Encrypt_prototype.BLOCK_SIZE = 16;
AES_GCM_Encrypt_prototype.reset = AES_GCM_reset;
AES_GCM_Encrypt_prototype.process = AES_GCM_Encrypt_process;
AES_GCM_Encrypt_prototype.finish = AES_GCM_Encrypt_finish;

var AES_GCM_Decrypt_prototype = AES_GCM_Decrypt.prototype;
AES_GCM_Decrypt_prototype.BLOCK_SIZE = 16;
AES_GCM_Decrypt_prototype.reset = AES_GCM_reset;
AES_GCM_Decrypt_prototype.process = AES_GCM_Decrypt_process;
AES_GCM_Decrypt_prototype.finish = AES_GCM_Decrypt_finish;

// shared asm.js module and heap
var _AES_heap_instance = new Uint8Array(0x100000),
    _AES_asm_instance  = AES_asm( global, null, _AES_heap_instance.buffer );

/**
 * AES-CFB exports
 */

function AES_CFB_encrypt_bytes ( data, key, iv ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return new AES_CFB( { heap: _AES_heap_instance, asm: _AES_asm_instance, key: key, iv: iv } ).encrypt(data).result;
}

function AES_CFB_decrypt_bytes ( data, key, iv ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return new AES_CFB( { heap: _AES_heap_instance, asm: _AES_asm_instance, key: key, iv: iv } ).decrypt(data).result;
}

exports.AES_CFB = AES_CFB;
exports.AES_CFB.encrypt = AES_CFB_encrypt_bytes;
exports.AES_CFB.decrypt = AES_CFB_decrypt_bytes;

exports.AES_CFB.Encrypt = AES_CFB_Encrypt;
exports.AES_CFB.Decrypt = AES_CFB_Decrypt;

/**
 * AES-GCM exports
 */

function AES_GCM_encrypt_bytes ( data, key, nonce, adata, tagSize ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    if ( nonce === undefined ) throw new SyntaxError("nonce required");
    return new AES_GCM( { heap: _AES_heap_instance, asm: _AES_asm_instance, key: key, nonce: nonce, adata: adata, tagSize: tagSize } ).encrypt(data).result;
}

function AES_GCM_decrypt_bytes ( data, key, nonce, adata, tagSize ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    if ( nonce === undefined ) throw new SyntaxError("nonce required");
    return new AES_GCM( { heap: _AES_heap_instance, asm: _AES_asm_instance, key: key, nonce: nonce, adata: adata, tagSize: tagSize } ).decrypt(data).result;
}

exports.AES_GCM = AES_GCM;
exports.AES_GCM.encrypt = AES_GCM_encrypt_bytes;
exports.AES_GCM.decrypt = AES_GCM_decrypt_bytes;

exports.AES_GCM.Encrypt = AES_GCM_Encrypt;
exports.AES_GCM.Decrypt = AES_GCM_Decrypt;

function hash_reset () {
    this.result = null;
    this.pos = 0;
    this.len = 0;

    this.asm.reset();

    return this;
}

function hash_process ( data ) {
    if ( this.result !== null )
        throw new IllegalStateError("state must be reset before processing new data");

    if ( is_string(data) )
        data = string_to_bytes(data);

    if ( is_buffer(data) )
        data = new Uint8Array(data);

    if ( !is_bytes(data) )
        throw new TypeError("data isn't of expected type");

    var asm = this.asm,
        heap = this.heap,
        hpos = this.pos,
        hlen = this.len,
        dpos = 0,
        dlen = data.length,
        wlen = 0;

    while ( dlen > 0 ) {
        wlen = _heap_write( heap, hpos+hlen, data, dpos, dlen );
        hlen += wlen;
        dpos += wlen;
        dlen -= wlen;

        wlen = asm.process( hpos, hlen );

        hpos += wlen;
        hlen -= wlen;

        if ( !hlen ) hpos = 0;
    }

    this.pos = hpos;
    this.len = hlen;

    return this;
}

function hash_finish () {
    if ( this.result !== null )
        throw new IllegalStateError("state must be reset before processing new data");

    this.asm.finish( this.pos, this.len, 0 );

    this.result = new Uint8Array(this.HASH_SIZE);
    this.result.set( this.heap.subarray( 0, this.HASH_SIZE ) );

    this.pos = 0;
    this.len = 0;

    return this;
}

function sha256_asm ( stdlib, foreign, buffer ) {
    "use asm";

    // SHA256 state
    var H0 = 0, H1 = 0, H2 = 0, H3 = 0, H4 = 0, H5 = 0, H6 = 0, H7 = 0,
        TOTAL0 = 0, TOTAL1 = 0;

    // HMAC state
    var I0 = 0, I1 = 0, I2 = 0, I3 = 0, I4 = 0, I5 = 0, I6 = 0, I7 = 0,
        O0 = 0, O1 = 0, O2 = 0, O3 = 0, O4 = 0, O5 = 0, O6 = 0, O7 = 0;

    // I/O buffer
    var HEAP = new stdlib.Uint8Array(buffer);

    function _core ( w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15 ) {
        w0 = w0|0;
        w1 = w1|0;
        w2 = w2|0;
        w3 = w3|0;
        w4 = w4|0;
        w5 = w5|0;
        w6 = w6|0;
        w7 = w7|0;
        w8 = w8|0;
        w9 = w9|0;
        w10 = w10|0;
        w11 = w11|0;
        w12 = w12|0;
        w13 = w13|0;
        w14 = w14|0;
        w15 = w15|0;

        var a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, h = 0,
            t = 0;

        a = H0;
        b = H1;
        c = H2;
        d = H3;
        e = H4;
        f = H5;
        g = H6;
        h = H7;

        // 0
        t = ( w0 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x428a2f98 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 1
        t = ( w1 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x71374491 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 2
        t = ( w2 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xb5c0fbcf )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 3
        t = ( w3 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xe9b5dba5 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 4
        t = ( w4 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x3956c25b )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 5
        t = ( w5 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x59f111f1 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 6
        t = ( w6 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x923f82a4 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 7
        t = ( w7 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xab1c5ed5 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 8
        t = ( w8 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xd807aa98 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 9
        t = ( w9 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x12835b01 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 10
        t = ( w10 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x243185be )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 11
        t = ( w11 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x550c7dc3 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 12
        t = ( w12 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x72be5d74 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 13
        t = ( w13 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x80deb1fe )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 14
        t = ( w14 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x9bdc06a7 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 15
        t = ( w15 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xc19bf174 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 16
        w0 = t = ( ( w1>>>7  ^ w1>>>18 ^ w1>>>3  ^ w1<<25 ^ w1<<14 ) + ( w14>>>17 ^ w14>>>19 ^ w14>>>10 ^ w14<<15 ^ w14<<13 ) + w0 + w9 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xe49b69c1 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 17
        w1 = t = ( ( w2>>>7  ^ w2>>>18 ^ w2>>>3  ^ w2<<25 ^ w2<<14 ) + ( w15>>>17 ^ w15>>>19 ^ w15>>>10 ^ w15<<15 ^ w15<<13 ) + w1 + w10 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xefbe4786 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 18
        w2 = t = ( ( w3>>>7  ^ w3>>>18 ^ w3>>>3  ^ w3<<25 ^ w3<<14 ) + ( w0>>>17 ^ w0>>>19 ^ w0>>>10 ^ w0<<15 ^ w0<<13 ) + w2 + w11 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x0fc19dc6 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 19
        w3 = t = ( ( w4>>>7  ^ w4>>>18 ^ w4>>>3  ^ w4<<25 ^ w4<<14 ) + ( w1>>>17 ^ w1>>>19 ^ w1>>>10 ^ w1<<15 ^ w1<<13 ) + w3 + w12 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x240ca1cc )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 20
        w4 = t = ( ( w5>>>7  ^ w5>>>18 ^ w5>>>3  ^ w5<<25 ^ w5<<14 ) + ( w2>>>17 ^ w2>>>19 ^ w2>>>10 ^ w2<<15 ^ w2<<13 ) + w4 + w13 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x2de92c6f )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 21
        w5 = t = ( ( w6>>>7  ^ w6>>>18 ^ w6>>>3  ^ w6<<25 ^ w6<<14 ) + ( w3>>>17 ^ w3>>>19 ^ w3>>>10 ^ w3<<15 ^ w3<<13 ) + w5 + w14 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x4a7484aa )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 22
        w6 = t = ( ( w7>>>7  ^ w7>>>18 ^ w7>>>3  ^ w7<<25 ^ w7<<14 ) + ( w4>>>17 ^ w4>>>19 ^ w4>>>10 ^ w4<<15 ^ w4<<13 ) + w6 + w15 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x5cb0a9dc )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 23
        w7 = t = ( ( w8>>>7  ^ w8>>>18 ^ w8>>>3  ^ w8<<25 ^ w8<<14 ) + ( w5>>>17 ^ w5>>>19 ^ w5>>>10 ^ w5<<15 ^ w5<<13 ) + w7 + w0 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x76f988da )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 24
        w8 = t = ( ( w9>>>7  ^ w9>>>18 ^ w9>>>3  ^ w9<<25 ^ w9<<14 ) + ( w6>>>17 ^ w6>>>19 ^ w6>>>10 ^ w6<<15 ^ w6<<13 ) + w8 + w1 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x983e5152 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 25
        w9 = t = ( ( w10>>>7  ^ w10>>>18 ^ w10>>>3  ^ w10<<25 ^ w10<<14 ) + ( w7>>>17 ^ w7>>>19 ^ w7>>>10 ^ w7<<15 ^ w7<<13 ) + w9 + w2 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xa831c66d )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 26
        w10 = t = ( ( w11>>>7  ^ w11>>>18 ^ w11>>>3  ^ w11<<25 ^ w11<<14 ) + ( w8>>>17 ^ w8>>>19 ^ w8>>>10 ^ w8<<15 ^ w8<<13 ) + w10 + w3 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xb00327c8 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 27
        w11 = t = ( ( w12>>>7  ^ w12>>>18 ^ w12>>>3  ^ w12<<25 ^ w12<<14 ) + ( w9>>>17 ^ w9>>>19 ^ w9>>>10 ^ w9<<15 ^ w9<<13 ) + w11 + w4 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xbf597fc7 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 28
        w12 = t = ( ( w13>>>7  ^ w13>>>18 ^ w13>>>3  ^ w13<<25 ^ w13<<14 ) + ( w10>>>17 ^ w10>>>19 ^ w10>>>10 ^ w10<<15 ^ w10<<13 ) + w12 + w5 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xc6e00bf3 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 29
        w13 = t = ( ( w14>>>7  ^ w14>>>18 ^ w14>>>3  ^ w14<<25 ^ w14<<14 ) + ( w11>>>17 ^ w11>>>19 ^ w11>>>10 ^ w11<<15 ^ w11<<13 ) + w13 + w6 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xd5a79147 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 30
        w14 = t = ( ( w15>>>7  ^ w15>>>18 ^ w15>>>3  ^ w15<<25 ^ w15<<14 ) + ( w12>>>17 ^ w12>>>19 ^ w12>>>10 ^ w12<<15 ^ w12<<13 ) + w14 + w7 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x06ca6351 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 31
        w15 = t = ( ( w0>>>7  ^ w0>>>18 ^ w0>>>3  ^ w0<<25 ^ w0<<14 ) + ( w13>>>17 ^ w13>>>19 ^ w13>>>10 ^ w13<<15 ^ w13<<13 ) + w15 + w8 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x14292967 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 32
        w0 = t = ( ( w1>>>7  ^ w1>>>18 ^ w1>>>3  ^ w1<<25 ^ w1<<14 ) + ( w14>>>17 ^ w14>>>19 ^ w14>>>10 ^ w14<<15 ^ w14<<13 ) + w0 + w9 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x27b70a85 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 33
        w1 = t = ( ( w2>>>7  ^ w2>>>18 ^ w2>>>3  ^ w2<<25 ^ w2<<14 ) + ( w15>>>17 ^ w15>>>19 ^ w15>>>10 ^ w15<<15 ^ w15<<13 ) + w1 + w10 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x2e1b2138 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 34
        w2 = t = ( ( w3>>>7  ^ w3>>>18 ^ w3>>>3  ^ w3<<25 ^ w3<<14 ) + ( w0>>>17 ^ w0>>>19 ^ w0>>>10 ^ w0<<15 ^ w0<<13 ) + w2 + w11 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x4d2c6dfc )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 35
        w3 = t = ( ( w4>>>7  ^ w4>>>18 ^ w4>>>3  ^ w4<<25 ^ w4<<14 ) + ( w1>>>17 ^ w1>>>19 ^ w1>>>10 ^ w1<<15 ^ w1<<13 ) + w3 + w12 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x53380d13 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 36
        w4 = t = ( ( w5>>>7  ^ w5>>>18 ^ w5>>>3  ^ w5<<25 ^ w5<<14 ) + ( w2>>>17 ^ w2>>>19 ^ w2>>>10 ^ w2<<15 ^ w2<<13 ) + w4 + w13 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x650a7354 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 37
        w5 = t = ( ( w6>>>7  ^ w6>>>18 ^ w6>>>3  ^ w6<<25 ^ w6<<14 ) + ( w3>>>17 ^ w3>>>19 ^ w3>>>10 ^ w3<<15 ^ w3<<13 ) + w5 + w14 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x766a0abb )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 38
        w6 = t = ( ( w7>>>7  ^ w7>>>18 ^ w7>>>3  ^ w7<<25 ^ w7<<14 ) + ( w4>>>17 ^ w4>>>19 ^ w4>>>10 ^ w4<<15 ^ w4<<13 ) + w6 + w15 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x81c2c92e )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 39
        w7 = t = ( ( w8>>>7  ^ w8>>>18 ^ w8>>>3  ^ w8<<25 ^ w8<<14 ) + ( w5>>>17 ^ w5>>>19 ^ w5>>>10 ^ w5<<15 ^ w5<<13 ) + w7 + w0 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x92722c85 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 40
        w8 = t = ( ( w9>>>7  ^ w9>>>18 ^ w9>>>3  ^ w9<<25 ^ w9<<14 ) + ( w6>>>17 ^ w6>>>19 ^ w6>>>10 ^ w6<<15 ^ w6<<13 ) + w8 + w1 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xa2bfe8a1 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 41
        w9 = t = ( ( w10>>>7  ^ w10>>>18 ^ w10>>>3  ^ w10<<25 ^ w10<<14 ) + ( w7>>>17 ^ w7>>>19 ^ w7>>>10 ^ w7<<15 ^ w7<<13 ) + w9 + w2 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xa81a664b )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 42
        w10 = t = ( ( w11>>>7  ^ w11>>>18 ^ w11>>>3  ^ w11<<25 ^ w11<<14 ) + ( w8>>>17 ^ w8>>>19 ^ w8>>>10 ^ w8<<15 ^ w8<<13 ) + w10 + w3 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xc24b8b70 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 43
        w11 = t = ( ( w12>>>7  ^ w12>>>18 ^ w12>>>3  ^ w12<<25 ^ w12<<14 ) + ( w9>>>17 ^ w9>>>19 ^ w9>>>10 ^ w9<<15 ^ w9<<13 ) + w11 + w4 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xc76c51a3 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 44
        w12 = t = ( ( w13>>>7  ^ w13>>>18 ^ w13>>>3  ^ w13<<25 ^ w13<<14 ) + ( w10>>>17 ^ w10>>>19 ^ w10>>>10 ^ w10<<15 ^ w10<<13 ) + w12 + w5 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xd192e819 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 45
        w13 = t = ( ( w14>>>7  ^ w14>>>18 ^ w14>>>3  ^ w14<<25 ^ w14<<14 ) + ( w11>>>17 ^ w11>>>19 ^ w11>>>10 ^ w11<<15 ^ w11<<13 ) + w13 + w6 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xd6990624 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 46
        w14 = t = ( ( w15>>>7  ^ w15>>>18 ^ w15>>>3  ^ w15<<25 ^ w15<<14 ) + ( w12>>>17 ^ w12>>>19 ^ w12>>>10 ^ w12<<15 ^ w12<<13 ) + w14 + w7 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xf40e3585 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 47
        w15 = t = ( ( w0>>>7  ^ w0>>>18 ^ w0>>>3  ^ w0<<25 ^ w0<<14 ) + ( w13>>>17 ^ w13>>>19 ^ w13>>>10 ^ w13<<15 ^ w13<<13 ) + w15 + w8 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x106aa070 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 48
        w0 = t = ( ( w1>>>7  ^ w1>>>18 ^ w1>>>3  ^ w1<<25 ^ w1<<14 ) + ( w14>>>17 ^ w14>>>19 ^ w14>>>10 ^ w14<<15 ^ w14<<13 ) + w0 + w9 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x19a4c116 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 49
        w1 = t = ( ( w2>>>7  ^ w2>>>18 ^ w2>>>3  ^ w2<<25 ^ w2<<14 ) + ( w15>>>17 ^ w15>>>19 ^ w15>>>10 ^ w15<<15 ^ w15<<13 ) + w1 + w10 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x1e376c08 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 50
        w2 = t = ( ( w3>>>7  ^ w3>>>18 ^ w3>>>3  ^ w3<<25 ^ w3<<14 ) + ( w0>>>17 ^ w0>>>19 ^ w0>>>10 ^ w0<<15 ^ w0<<13 ) + w2 + w11 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x2748774c )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 51
        w3 = t = ( ( w4>>>7  ^ w4>>>18 ^ w4>>>3  ^ w4<<25 ^ w4<<14 ) + ( w1>>>17 ^ w1>>>19 ^ w1>>>10 ^ w1<<15 ^ w1<<13 ) + w3 + w12 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x34b0bcb5 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 52
        w4 = t = ( ( w5>>>7  ^ w5>>>18 ^ w5>>>3  ^ w5<<25 ^ w5<<14 ) + ( w2>>>17 ^ w2>>>19 ^ w2>>>10 ^ w2<<15 ^ w2<<13 ) + w4 + w13 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x391c0cb3 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 53
        w5 = t = ( ( w6>>>7  ^ w6>>>18 ^ w6>>>3  ^ w6<<25 ^ w6<<14 ) + ( w3>>>17 ^ w3>>>19 ^ w3>>>10 ^ w3<<15 ^ w3<<13 ) + w5 + w14 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x4ed8aa4a )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 54
        w6 = t = ( ( w7>>>7  ^ w7>>>18 ^ w7>>>3  ^ w7<<25 ^ w7<<14 ) + ( w4>>>17 ^ w4>>>19 ^ w4>>>10 ^ w4<<15 ^ w4<<13 ) + w6 + w15 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x5b9cca4f )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 55
        w7 = t = ( ( w8>>>7  ^ w8>>>18 ^ w8>>>3  ^ w8<<25 ^ w8<<14 ) + ( w5>>>17 ^ w5>>>19 ^ w5>>>10 ^ w5<<15 ^ w5<<13 ) + w7 + w0 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x682e6ff3 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 56
        w8 = t = ( ( w9>>>7  ^ w9>>>18 ^ w9>>>3  ^ w9<<25 ^ w9<<14 ) + ( w6>>>17 ^ w6>>>19 ^ w6>>>10 ^ w6<<15 ^ w6<<13 ) + w8 + w1 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x748f82ee )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 57
        w9 = t = ( ( w10>>>7  ^ w10>>>18 ^ w10>>>3  ^ w10<<25 ^ w10<<14 ) + ( w7>>>17 ^ w7>>>19 ^ w7>>>10 ^ w7<<15 ^ w7<<13 ) + w9 + w2 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x78a5636f )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 58
        w10 = t = ( ( w11>>>7  ^ w11>>>18 ^ w11>>>3  ^ w11<<25 ^ w11<<14 ) + ( w8>>>17 ^ w8>>>19 ^ w8>>>10 ^ w8<<15 ^ w8<<13 ) + w10 + w3 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x84c87814 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 59
        w11 = t = ( ( w12>>>7  ^ w12>>>18 ^ w12>>>3  ^ w12<<25 ^ w12<<14 ) + ( w9>>>17 ^ w9>>>19 ^ w9>>>10 ^ w9<<15 ^ w9<<13 ) + w11 + w4 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x8cc70208 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 60
        w12 = t = ( ( w13>>>7  ^ w13>>>18 ^ w13>>>3  ^ w13<<25 ^ w13<<14 ) + ( w10>>>17 ^ w10>>>19 ^ w10>>>10 ^ w10<<15 ^ w10<<13 ) + w12 + w5 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x90befffa )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 61
        w13 = t = ( ( w14>>>7  ^ w14>>>18 ^ w14>>>3  ^ w14<<25 ^ w14<<14 ) + ( w11>>>17 ^ w11>>>19 ^ w11>>>10 ^ w11<<15 ^ w11<<13 ) + w13 + w6 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xa4506ceb )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 62
        w14 = t = ( ( w15>>>7  ^ w15>>>18 ^ w15>>>3  ^ w15<<25 ^ w15<<14 ) + ( w12>>>17 ^ w12>>>19 ^ w12>>>10 ^ w12<<15 ^ w12<<13 ) + w14 + w7 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xbef9a3f7 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 63
        w15 = t = ( ( w0>>>7  ^ w0>>>18 ^ w0>>>3  ^ w0<<25 ^ w0<<14 ) + ( w13>>>17 ^ w13>>>19 ^ w13>>>10 ^ w13<<15 ^ w13<<13 ) + w15 + w8 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xc67178f2 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        H0 = ( H0 + a )|0;
        H1 = ( H1 + b )|0;
        H2 = ( H2 + c )|0;
        H3 = ( H3 + d )|0;
        H4 = ( H4 + e )|0;
        H5 = ( H5 + f )|0;
        H6 = ( H6 + g )|0;
        H7 = ( H7 + h )|0;
    }

    function _core_heap ( offset ) {
        offset = offset|0;

        _core(
            HEAP[offset|0]<<24 | HEAP[offset|1]<<16 | HEAP[offset|2]<<8 | HEAP[offset|3],
            HEAP[offset|4]<<24 | HEAP[offset|5]<<16 | HEAP[offset|6]<<8 | HEAP[offset|7],
            HEAP[offset|8]<<24 | HEAP[offset|9]<<16 | HEAP[offset|10]<<8 | HEAP[offset|11],
            HEAP[offset|12]<<24 | HEAP[offset|13]<<16 | HEAP[offset|14]<<8 | HEAP[offset|15],
            HEAP[offset|16]<<24 | HEAP[offset|17]<<16 | HEAP[offset|18]<<8 | HEAP[offset|19],
            HEAP[offset|20]<<24 | HEAP[offset|21]<<16 | HEAP[offset|22]<<8 | HEAP[offset|23],
            HEAP[offset|24]<<24 | HEAP[offset|25]<<16 | HEAP[offset|26]<<8 | HEAP[offset|27],
            HEAP[offset|28]<<24 | HEAP[offset|29]<<16 | HEAP[offset|30]<<8 | HEAP[offset|31],
            HEAP[offset|32]<<24 | HEAP[offset|33]<<16 | HEAP[offset|34]<<8 | HEAP[offset|35],
            HEAP[offset|36]<<24 | HEAP[offset|37]<<16 | HEAP[offset|38]<<8 | HEAP[offset|39],
            HEAP[offset|40]<<24 | HEAP[offset|41]<<16 | HEAP[offset|42]<<8 | HEAP[offset|43],
            HEAP[offset|44]<<24 | HEAP[offset|45]<<16 | HEAP[offset|46]<<8 | HEAP[offset|47],
            HEAP[offset|48]<<24 | HEAP[offset|49]<<16 | HEAP[offset|50]<<8 | HEAP[offset|51],
            HEAP[offset|52]<<24 | HEAP[offset|53]<<16 | HEAP[offset|54]<<8 | HEAP[offset|55],
            HEAP[offset|56]<<24 | HEAP[offset|57]<<16 | HEAP[offset|58]<<8 | HEAP[offset|59],
            HEAP[offset|60]<<24 | HEAP[offset|61]<<16 | HEAP[offset|62]<<8 | HEAP[offset|63]
        );
    }

    // offset — multiple of 32
    function _state_to_heap ( output ) {
        output = output|0;

        HEAP[output|0] = H0>>>24;
        HEAP[output|1] = H0>>>16&255;
        HEAP[output|2] = H0>>>8&255;
        HEAP[output|3] = H0&255;
        HEAP[output|4] = H1>>>24;
        HEAP[output|5] = H1>>>16&255;
        HEAP[output|6] = H1>>>8&255;
        HEAP[output|7] = H1&255;
        HEAP[output|8] = H2>>>24;
        HEAP[output|9] = H2>>>16&255;
        HEAP[output|10] = H2>>>8&255;
        HEAP[output|11] = H2&255;
        HEAP[output|12] = H3>>>24;
        HEAP[output|13] = H3>>>16&255;
        HEAP[output|14] = H3>>>8&255;
        HEAP[output|15] = H3&255;
        HEAP[output|16] = H4>>>24;
        HEAP[output|17] = H4>>>16&255;
        HEAP[output|18] = H4>>>8&255;
        HEAP[output|19] = H4&255;
        HEAP[output|20] = H5>>>24;
        HEAP[output|21] = H5>>>16&255;
        HEAP[output|22] = H5>>>8&255;
        HEAP[output|23] = H5&255;
        HEAP[output|24] = H6>>>24;
        HEAP[output|25] = H6>>>16&255;
        HEAP[output|26] = H6>>>8&255;
        HEAP[output|27] = H6&255;
        HEAP[output|28] = H7>>>24;
        HEAP[output|29] = H7>>>16&255;
        HEAP[output|30] = H7>>>8&255;
        HEAP[output|31] = H7&255;
    }

    function reset () {
        H0 = 0x6a09e667;
        H1 = 0xbb67ae85;
        H2 = 0x3c6ef372;
        H3 = 0xa54ff53a;
        H4 = 0x510e527f;
        H5 = 0x9b05688c;
        H6 = 0x1f83d9ab;
        H7 = 0x5be0cd19;
        TOTAL0 = TOTAL1 = 0;
    }

    function init ( h0, h1, h2, h3, h4, h5, h6, h7, total0, total1 ) {
        h0 = h0|0;
        h1 = h1|0;
        h2 = h2|0;
        h3 = h3|0;
        h4 = h4|0;
        h5 = h5|0;
        h6 = h6|0;
        h7 = h7|0;
        total0 = total0|0;
        total1 = total1|0;

        H0 = h0;
        H1 = h1;
        H2 = h2;
        H3 = h3;
        H4 = h4;
        H5 = h5;
        H6 = h6;
        H7 = h7;
        TOTAL0 = total0;
        TOTAL1 = total1;
    }

    // offset — multiple of 64
    function process ( offset, length ) {
        offset = offset|0;
        length = length|0;

        var hashed = 0;

        if ( offset & 63 )
            return -1;

        while ( (length|0) >= 64 ) {
            _core_heap(offset);

            offset = ( offset + 64 )|0;
            length = ( length - 64 )|0;

            hashed = ( hashed + 64 )|0;
        }

        TOTAL0 = ( TOTAL0 + hashed )|0;
        if ( TOTAL0>>>0 < hashed>>>0 ) TOTAL1 = ( TOTAL1 + 1 )|0;

        return hashed|0;
    }

    // offset — multiple of 64
    // output — multiple of 32
    function finish ( offset, length, output ) {
        offset = offset|0;
        length = length|0;
        output = output|0;

        var hashed = 0,
            i = 0;

        if ( offset & 63 )
            return -1;

        if ( ~output )
            if ( output & 31 )
                return -1;

        if ( (length|0) >= 64 ) {
            hashed = process( offset, length )|0;
            if ( (hashed|0) == -1 )
                return -1;

            offset = ( offset + hashed )|0;
            length = ( length - hashed )|0;
        }

        hashed = ( hashed + length )|0;
        TOTAL0 = ( TOTAL0 + length )|0;
        if ( TOTAL0>>>0 < length>>>0 ) TOTAL1 = ( TOTAL1 + 1 )|0;

        HEAP[offset|length] = 0x80;

        if ( (length|0) >= 56 ) {
            for ( i = (length+1)|0; (i|0) < 64; i = (i+1)|0 )
                HEAP[offset|i] = 0x00;

            _core_heap(offset);

            length = 0;

            HEAP[offset|0] = 0;
        }

        for ( i = (length+1)|0; (i|0) < 59; i = (i+1)|0 )
            HEAP[offset|i] = 0;

        HEAP[offset|56] = TOTAL1>>>21&255;
        HEAP[offset|57] = TOTAL1>>>13&255;
        HEAP[offset|58] = TOTAL1>>>5&255;
        HEAP[offset|59] = TOTAL1<<3&255 | TOTAL0>>>29;
        HEAP[offset|60] = TOTAL0>>>21&255;
        HEAP[offset|61] = TOTAL0>>>13&255;
        HEAP[offset|62] = TOTAL0>>>5&255;
        HEAP[offset|63] = TOTAL0<<3&255;
        _core_heap(offset);

        if ( ~output )
            _state_to_heap(output);

        return hashed|0;
    }

    function hmac_reset () {
        H0 = I0;
        H1 = I1;
        H2 = I2;
        H3 = I3;
        H4 = I4;
        H5 = I5;
        H6 = I6;
        H7 = I7;
        TOTAL0 = 64;
        TOTAL1 = 0;
    }

    function _hmac_opad () {
        H0 = O0;
        H1 = O1;
        H2 = O2;
        H3 = O3;
        H4 = O4;
        H5 = O5;
        H6 = O6;
        H7 = O7;
        TOTAL0 = 64;
        TOTAL1 = 0;
    }

    function hmac_init ( p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13, p14, p15 ) {
        p0 = p0|0;
        p1 = p1|0;
        p2 = p2|0;
        p3 = p3|0;
        p4 = p4|0;
        p5 = p5|0;
        p6 = p6|0;
        p7 = p7|0;
        p8 = p8|0;
        p9 = p9|0;
        p10 = p10|0;
        p11 = p11|0;
        p12 = p12|0;
        p13 = p13|0;
        p14 = p14|0;
        p15 = p15|0;

        // opad
        reset();
        _core(
            p0 ^ 0x5c5c5c5c,
            p1 ^ 0x5c5c5c5c,
            p2 ^ 0x5c5c5c5c,
            p3 ^ 0x5c5c5c5c,
            p4 ^ 0x5c5c5c5c,
            p5 ^ 0x5c5c5c5c,
            p6 ^ 0x5c5c5c5c,
            p7 ^ 0x5c5c5c5c,
            p8 ^ 0x5c5c5c5c,
            p9 ^ 0x5c5c5c5c,
            p10 ^ 0x5c5c5c5c,
            p11 ^ 0x5c5c5c5c,
            p12 ^ 0x5c5c5c5c,
            p13 ^ 0x5c5c5c5c,
            p14 ^ 0x5c5c5c5c,
            p15 ^ 0x5c5c5c5c
        );
        O0 = H0;
        O1 = H1;
        O2 = H2;
        O3 = H3;
        O4 = H4;
        O5 = H5;
        O6 = H6;
        O7 = H7;

        // ipad
        reset();
        _core(
            p0 ^ 0x36363636,
            p1 ^ 0x36363636,
            p2 ^ 0x36363636,
            p3 ^ 0x36363636,
            p4 ^ 0x36363636,
            p5 ^ 0x36363636,
            p6 ^ 0x36363636,
            p7 ^ 0x36363636,
            p8 ^ 0x36363636,
            p9 ^ 0x36363636,
            p10 ^ 0x36363636,
            p11 ^ 0x36363636,
            p12 ^ 0x36363636,
            p13 ^ 0x36363636,
            p14 ^ 0x36363636,
            p15 ^ 0x36363636
        );
        I0 = H0;
        I1 = H1;
        I2 = H2;
        I3 = H3;
        I4 = H4;
        I5 = H5;
        I6 = H6;
        I7 = H7;

        TOTAL0 = 64;
        TOTAL1 = 0;
    }

    // offset — multiple of 64
    // output — multiple of 32
    function hmac_finish ( offset, length, output ) {
        offset = offset|0;
        length = length|0;
        output = output|0;

        var t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0,
            hashed = 0;

        if ( offset & 63 )
            return -1;

        if ( ~output )
            if ( output & 31 )
                return -1;

        hashed = finish( offset, length, -1 )|0;
        t0 = H0, t1 = H1, t2 = H2, t3 = H3, t4 = H4, t5 = H5, t6 = H6, t7 = H7;

        _hmac_opad();
        _core( t0, t1, t2, t3, t4, t5, t6, t7, 0x80000000, 0, 0, 0, 0, 0, 0, 768 );

        if ( ~output )
            _state_to_heap(output);

        return hashed|0;
    }

    // salt is assumed to be already processed
    // offset — multiple of 64
    // output — multiple of 32
    function pbkdf2_generate_block ( offset, length, block, count, output ) {
        offset = offset|0;
        length = length|0;
        block = block|0;
        count = count|0;
        output = output|0;

        var h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0, h5 = 0, h6 = 0, h7 = 0,
            t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0;

        if ( offset & 63 )
            return -1;

        if ( ~output )
            if ( output & 31 )
                return -1;

        // pad block number into heap
        // FIXME probable OOB write
        HEAP[(offset+length)|0]   = block>>>24;
        HEAP[(offset+length+1)|0] = block>>>16&255;
        HEAP[(offset+length+2)|0] = block>>>8&255;
        HEAP[(offset+length+3)|0] = block&255;

        // finish first iteration
        hmac_finish( offset, (length+4)|0, -1 )|0;
        h0 = t0 = H0, h1 = t1 = H1, h2 = t2 = H2, h3 = t3 = H3, h4 = t4 = H4, h5 = t5 = H5, h6 = t6 = H6, h7 = t7 = H7;
        count = (count-1)|0;

        // perform the rest iterations
        while ( (count|0) > 0 ) {
            hmac_reset();
            _core( t0, t1, t2, t3, t4, t5, t6, t7, 0x80000000, 0, 0, 0, 0, 0, 0, 768 );
            t0 = H0, t1 = H1, t2 = H2, t3 = H3, t4 = H4, t5 = H5, t6 = H6, t7 = H7;

            _hmac_opad();
            _core( t0, t1, t2, t3, t4, t5, t6, t7, 0x80000000, 0, 0, 0, 0, 0, 0, 768 );
            t0 = H0, t1 = H1, t2 = H2, t3 = H3, t4 = H4, t5 = H5, t6 = H6, t7 = H7;

            h0 = h0 ^ H0;
            h1 = h1 ^ H1;
            h2 = h2 ^ H2;
            h3 = h3 ^ H3;
            h4 = h4 ^ H4;
            h5 = h5 ^ H5;
            h6 = h6 ^ H6;
            h7 = h7 ^ H7;

            count = (count-1)|0;
        }

        H0 = h0;
        H1 = h1;
        H2 = h2;
        H3 = h3;
        H4 = h4;
        H5 = h5;
        H6 = h6;
        H7 = h7;

        if ( ~output )
            _state_to_heap(output);

        return 0;
    }

    return {
        // SHA256
        reset: reset,
        init: init,
        process: process,
        finish: finish,

        // HMAC-SHA256
        hmac_reset: hmac_reset,
        hmac_init: hmac_init,
        hmac_finish: hmac_finish,

        // PBKDF2-HMAC-SHA256
        pbkdf2_generate_block: pbkdf2_generate_block
    }
}

var _sha256_block_size = 64,
    _sha256_hash_size = 32;

function sha256_constructor ( options ) {
    options = options || {};

    this.heap = _heap_init( Uint8Array, options );
    this.asm = options.asm || sha256_asm( global, null, this.heap.buffer );

    this.BLOCK_SIZE = _sha256_block_size;
    this.HASH_SIZE = _sha256_hash_size;

    this.reset();
}

sha256_constructor.BLOCK_SIZE = _sha256_block_size;
sha256_constructor.HASH_SIZE = _sha256_hash_size;
var sha256_prototype = sha256_constructor.prototype;
sha256_prototype.reset =   hash_reset;
sha256_prototype.process = hash_process;
sha256_prototype.finish =  hash_finish;

var sha256_instance = null;

function get_sha256_instance () {
    if ( sha256_instance === null ) sha256_instance = new sha256_constructor( { heapSize: 0x100000 } );
    return sha256_instance;
}

/**
 * SHA256 exports
 */

function sha256_bytes ( data ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    return get_sha256_instance().reset().process(data).finish().result;
}

function sha256_hex ( data ) {
    var result = sha256_bytes(data);
    return bytes_to_hex(result);
}

function sha256_base64 ( data ) {
    var result = sha256_bytes(data);
    return bytes_to_base64(result);
}

sha256_constructor.bytes = sha256_bytes;
sha256_constructor.hex = sha256_hex;
sha256_constructor.base64 = sha256_base64;

exports.SHA256 = sha256_constructor;


'function'==typeof define&&define.amd?define([],function(){return exports}):'object'==typeof module&&module.exports?module.exports=exports:global.asmCrypto=exports;

return exports;
})( {}, function(){return this}() );
},{}],2:[function(_dereq_,module,exports){
(function (process,global){
/*!
 * @overview es6-promise - a tiny implementation of Promises/A+.
 * @copyright Copyright (c) 2014 Yehuda Katz, Tom Dale, Stefan Penner and contributors (Conversion to ES6 API by Jake Archibald)
 * @license   Licensed under MIT license
 *            See https://raw.githubusercontent.com/jakearchibald/es6-promise/master/LICENSE
 * @version   3.2.1
 */

(function() {
    "use strict";
    function lib$es6$promise$utils$$objectOrFunction(x) {
      return typeof x === 'function' || (typeof x === 'object' && x !== null);
    }

    function lib$es6$promise$utils$$isFunction(x) {
      return typeof x === 'function';
    }

    function lib$es6$promise$utils$$isMaybeThenable(x) {
      return typeof x === 'object' && x !== null;
    }

    var lib$es6$promise$utils$$_isArray;
    if (!Array.isArray) {
      lib$es6$promise$utils$$_isArray = function (x) {
        return Object.prototype.toString.call(x) === '[object Array]';
      };
    } else {
      lib$es6$promise$utils$$_isArray = Array.isArray;
    }

    var lib$es6$promise$utils$$isArray = lib$es6$promise$utils$$_isArray;
    var lib$es6$promise$asap$$len = 0;
    var lib$es6$promise$asap$$vertxNext;
    var lib$es6$promise$asap$$customSchedulerFn;

    var lib$es6$promise$asap$$asap = function asap(callback, arg) {
      lib$es6$promise$asap$$queue[lib$es6$promise$asap$$len] = callback;
      lib$es6$promise$asap$$queue[lib$es6$promise$asap$$len + 1] = arg;
      lib$es6$promise$asap$$len += 2;
      if (lib$es6$promise$asap$$len === 2) {
        // If len is 2, that means that we need to schedule an async flush.
        // If additional callbacks are queued before the queue is flushed, they
        // will be processed by this flush that we are scheduling.
        if (lib$es6$promise$asap$$customSchedulerFn) {
          lib$es6$promise$asap$$customSchedulerFn(lib$es6$promise$asap$$flush);
        } else {
          lib$es6$promise$asap$$scheduleFlush();
        }
      }
    }

    function lib$es6$promise$asap$$setScheduler(scheduleFn) {
      lib$es6$promise$asap$$customSchedulerFn = scheduleFn;
    }

    function lib$es6$promise$asap$$setAsap(asapFn) {
      lib$es6$promise$asap$$asap = asapFn;
    }

    var lib$es6$promise$asap$$browserWindow = (typeof window !== 'undefined') ? window : undefined;
    var lib$es6$promise$asap$$browserGlobal = lib$es6$promise$asap$$browserWindow || {};
    var lib$es6$promise$asap$$BrowserMutationObserver = lib$es6$promise$asap$$browserGlobal.MutationObserver || lib$es6$promise$asap$$browserGlobal.WebKitMutationObserver;
    var lib$es6$promise$asap$$isNode = typeof self === 'undefined' && typeof process !== 'undefined' && {}.toString.call(process) === '[object process]';

    // test for web worker but not in IE10
    var lib$es6$promise$asap$$isWorker = typeof Uint8ClampedArray !== 'undefined' &&
      typeof importScripts !== 'undefined' &&
      typeof MessageChannel !== 'undefined';

    // node
    function lib$es6$promise$asap$$useNextTick() {
      // node version 0.10.x displays a deprecation warning when nextTick is used recursively
      // see https://github.com/cujojs/when/issues/410 for details
      return function() {
        process.nextTick(lib$es6$promise$asap$$flush);
      };
    }

    // vertx
    function lib$es6$promise$asap$$useVertxTimer() {
      return function() {
        lib$es6$promise$asap$$vertxNext(lib$es6$promise$asap$$flush);
      };
    }

    function lib$es6$promise$asap$$useMutationObserver() {
      var iterations = 0;
      var observer = new lib$es6$promise$asap$$BrowserMutationObserver(lib$es6$promise$asap$$flush);
      var node = document.createTextNode('');
      observer.observe(node, { characterData: true });

      return function() {
        node.data = (iterations = ++iterations % 2);
      };
    }

    // web worker
    function lib$es6$promise$asap$$useMessageChannel() {
      var channel = new MessageChannel();
      channel.port1.onmessage = lib$es6$promise$asap$$flush;
      return function () {
        channel.port2.postMessage(0);
      };
    }

    function lib$es6$promise$asap$$useSetTimeout() {
      return function() {
        setTimeout(lib$es6$promise$asap$$flush, 1);
      };
    }

    var lib$es6$promise$asap$$queue = new Array(1000);
    function lib$es6$promise$asap$$flush() {
      for (var i = 0; i < lib$es6$promise$asap$$len; i+=2) {
        var callback = lib$es6$promise$asap$$queue[i];
        var arg = lib$es6$promise$asap$$queue[i+1];

        callback(arg);

        lib$es6$promise$asap$$queue[i] = undefined;
        lib$es6$promise$asap$$queue[i+1] = undefined;
      }

      lib$es6$promise$asap$$len = 0;
    }

    function lib$es6$promise$asap$$attemptVertx() {
      try {
        var r = _dereq_;
        var vertx = r('vertx');
        lib$es6$promise$asap$$vertxNext = vertx.runOnLoop || vertx.runOnContext;
        return lib$es6$promise$asap$$useVertxTimer();
      } catch(e) {
        return lib$es6$promise$asap$$useSetTimeout();
      }
    }

    var lib$es6$promise$asap$$scheduleFlush;
    // Decide what async method to use to triggering processing of queued callbacks:
    if (lib$es6$promise$asap$$isNode) {
      lib$es6$promise$asap$$scheduleFlush = lib$es6$promise$asap$$useNextTick();
    } else if (lib$es6$promise$asap$$BrowserMutationObserver) {
      lib$es6$promise$asap$$scheduleFlush = lib$es6$promise$asap$$useMutationObserver();
    } else if (lib$es6$promise$asap$$isWorker) {
      lib$es6$promise$asap$$scheduleFlush = lib$es6$promise$asap$$useMessageChannel();
    } else if (lib$es6$promise$asap$$browserWindow === undefined && typeof _dereq_ === 'function') {
      lib$es6$promise$asap$$scheduleFlush = lib$es6$promise$asap$$attemptVertx();
    } else {
      lib$es6$promise$asap$$scheduleFlush = lib$es6$promise$asap$$useSetTimeout();
    }
    function lib$es6$promise$then$$then(onFulfillment, onRejection) {
      var parent = this;

      var child = new this.constructor(lib$es6$promise$$internal$$noop);

      if (child[lib$es6$promise$$internal$$PROMISE_ID] === undefined) {
        lib$es6$promise$$internal$$makePromise(child);
      }

      var state = parent._state;

      if (state) {
        var callback = arguments[state - 1];
        lib$es6$promise$asap$$asap(function(){
          lib$es6$promise$$internal$$invokeCallback(state, child, callback, parent._result);
        });
      } else {
        lib$es6$promise$$internal$$subscribe(parent, child, onFulfillment, onRejection);
      }

      return child;
    }
    var lib$es6$promise$then$$default = lib$es6$promise$then$$then;
    function lib$es6$promise$promise$resolve$$resolve(object) {
      /*jshint validthis:true */
      var Constructor = this;

      if (object && typeof object === 'object' && object.constructor === Constructor) {
        return object;
      }

      var promise = new Constructor(lib$es6$promise$$internal$$noop);
      lib$es6$promise$$internal$$resolve(promise, object);
      return promise;
    }
    var lib$es6$promise$promise$resolve$$default = lib$es6$promise$promise$resolve$$resolve;
    var lib$es6$promise$$internal$$PROMISE_ID = Math.random().toString(36).substring(16);

    function lib$es6$promise$$internal$$noop() {}

    var lib$es6$promise$$internal$$PENDING   = void 0;
    var lib$es6$promise$$internal$$FULFILLED = 1;
    var lib$es6$promise$$internal$$REJECTED  = 2;

    var lib$es6$promise$$internal$$GET_THEN_ERROR = new lib$es6$promise$$internal$$ErrorObject();

    function lib$es6$promise$$internal$$selfFulfillment() {
      return new TypeError("You cannot resolve a promise with itself");
    }

    function lib$es6$promise$$internal$$cannotReturnOwn() {
      return new TypeError('A promises callback cannot return that same promise.');
    }

    function lib$es6$promise$$internal$$getThen(promise) {
      try {
        return promise.then;
      } catch(error) {
        lib$es6$promise$$internal$$GET_THEN_ERROR.error = error;
        return lib$es6$promise$$internal$$GET_THEN_ERROR;
      }
    }

    function lib$es6$promise$$internal$$tryThen(then, value, fulfillmentHandler, rejectionHandler) {
      try {
        then.call(value, fulfillmentHandler, rejectionHandler);
      } catch(e) {
        return e;
      }
    }

    function lib$es6$promise$$internal$$handleForeignThenable(promise, thenable, then) {
       lib$es6$promise$asap$$asap(function(promise) {
        var sealed = false;
        var error = lib$es6$promise$$internal$$tryThen(then, thenable, function(value) {
          if (sealed) { return; }
          sealed = true;
          if (thenable !== value) {
            lib$es6$promise$$internal$$resolve(promise, value);
          } else {
            lib$es6$promise$$internal$$fulfill(promise, value);
          }
        }, function(reason) {
          if (sealed) { return; }
          sealed = true;

          lib$es6$promise$$internal$$reject(promise, reason);
        }, 'Settle: ' + (promise._label || ' unknown promise'));

        if (!sealed && error) {
          sealed = true;
          lib$es6$promise$$internal$$reject(promise, error);
        }
      }, promise);
    }

    function lib$es6$promise$$internal$$handleOwnThenable(promise, thenable) {
      if (thenable._state === lib$es6$promise$$internal$$FULFILLED) {
        lib$es6$promise$$internal$$fulfill(promise, thenable._result);
      } else if (thenable._state === lib$es6$promise$$internal$$REJECTED) {
        lib$es6$promise$$internal$$reject(promise, thenable._result);
      } else {
        lib$es6$promise$$internal$$subscribe(thenable, undefined, function(value) {
          lib$es6$promise$$internal$$resolve(promise, value);
        }, function(reason) {
          lib$es6$promise$$internal$$reject(promise, reason);
        });
      }
    }

    function lib$es6$promise$$internal$$handleMaybeThenable(promise, maybeThenable, then) {
      if (maybeThenable.constructor === promise.constructor &&
          then === lib$es6$promise$then$$default &&
          constructor.resolve === lib$es6$promise$promise$resolve$$default) {
        lib$es6$promise$$internal$$handleOwnThenable(promise, maybeThenable);
      } else {
        if (then === lib$es6$promise$$internal$$GET_THEN_ERROR) {
          lib$es6$promise$$internal$$reject(promise, lib$es6$promise$$internal$$GET_THEN_ERROR.error);
        } else if (then === undefined) {
          lib$es6$promise$$internal$$fulfill(promise, maybeThenable);
        } else if (lib$es6$promise$utils$$isFunction(then)) {
          lib$es6$promise$$internal$$handleForeignThenable(promise, maybeThenable, then);
        } else {
          lib$es6$promise$$internal$$fulfill(promise, maybeThenable);
        }
      }
    }

    function lib$es6$promise$$internal$$resolve(promise, value) {
      if (promise === value) {
        lib$es6$promise$$internal$$reject(promise, lib$es6$promise$$internal$$selfFulfillment());
      } else if (lib$es6$promise$utils$$objectOrFunction(value)) {
        lib$es6$promise$$internal$$handleMaybeThenable(promise, value, lib$es6$promise$$internal$$getThen(value));
      } else {
        lib$es6$promise$$internal$$fulfill(promise, value);
      }
    }

    function lib$es6$promise$$internal$$publishRejection(promise) {
      if (promise._onerror) {
        promise._onerror(promise._result);
      }

      lib$es6$promise$$internal$$publish(promise);
    }

    function lib$es6$promise$$internal$$fulfill(promise, value) {
      if (promise._state !== lib$es6$promise$$internal$$PENDING) { return; }

      promise._result = value;
      promise._state = lib$es6$promise$$internal$$FULFILLED;

      if (promise._subscribers.length !== 0) {
        lib$es6$promise$asap$$asap(lib$es6$promise$$internal$$publish, promise);
      }
    }

    function lib$es6$promise$$internal$$reject(promise, reason) {
      if (promise._state !== lib$es6$promise$$internal$$PENDING) { return; }
      promise._state = lib$es6$promise$$internal$$REJECTED;
      promise._result = reason;

      lib$es6$promise$asap$$asap(lib$es6$promise$$internal$$publishRejection, promise);
    }

    function lib$es6$promise$$internal$$subscribe(parent, child, onFulfillment, onRejection) {
      var subscribers = parent._subscribers;
      var length = subscribers.length;

      parent._onerror = null;

      subscribers[length] = child;
      subscribers[length + lib$es6$promise$$internal$$FULFILLED] = onFulfillment;
      subscribers[length + lib$es6$promise$$internal$$REJECTED]  = onRejection;

      if (length === 0 && parent._state) {
        lib$es6$promise$asap$$asap(lib$es6$promise$$internal$$publish, parent);
      }
    }

    function lib$es6$promise$$internal$$publish(promise) {
      var subscribers = promise._subscribers;
      var settled = promise._state;

      if (subscribers.length === 0) { return; }

      var child, callback, detail = promise._result;

      for (var i = 0; i < subscribers.length; i += 3) {
        child = subscribers[i];
        callback = subscribers[i + settled];

        if (child) {
          lib$es6$promise$$internal$$invokeCallback(settled, child, callback, detail);
        } else {
          callback(detail);
        }
      }

      promise._subscribers.length = 0;
    }

    function lib$es6$promise$$internal$$ErrorObject() {
      this.error = null;
    }

    var lib$es6$promise$$internal$$TRY_CATCH_ERROR = new lib$es6$promise$$internal$$ErrorObject();

    function lib$es6$promise$$internal$$tryCatch(callback, detail) {
      try {
        return callback(detail);
      } catch(e) {
        lib$es6$promise$$internal$$TRY_CATCH_ERROR.error = e;
        return lib$es6$promise$$internal$$TRY_CATCH_ERROR;
      }
    }

    function lib$es6$promise$$internal$$invokeCallback(settled, promise, callback, detail) {
      var hasCallback = lib$es6$promise$utils$$isFunction(callback),
          value, error, succeeded, failed;

      if (hasCallback) {
        value = lib$es6$promise$$internal$$tryCatch(callback, detail);

        if (value === lib$es6$promise$$internal$$TRY_CATCH_ERROR) {
          failed = true;
          error = value.error;
          value = null;
        } else {
          succeeded = true;
        }

        if (promise === value) {
          lib$es6$promise$$internal$$reject(promise, lib$es6$promise$$internal$$cannotReturnOwn());
          return;
        }

      } else {
        value = detail;
        succeeded = true;
      }

      if (promise._state !== lib$es6$promise$$internal$$PENDING) {
        // noop
      } else if (hasCallback && succeeded) {
        lib$es6$promise$$internal$$resolve(promise, value);
      } else if (failed) {
        lib$es6$promise$$internal$$reject(promise, error);
      } else if (settled === lib$es6$promise$$internal$$FULFILLED) {
        lib$es6$promise$$internal$$fulfill(promise, value);
      } else if (settled === lib$es6$promise$$internal$$REJECTED) {
        lib$es6$promise$$internal$$reject(promise, value);
      }
    }

    function lib$es6$promise$$internal$$initializePromise(promise, resolver) {
      try {
        resolver(function resolvePromise(value){
          lib$es6$promise$$internal$$resolve(promise, value);
        }, function rejectPromise(reason) {
          lib$es6$promise$$internal$$reject(promise, reason);
        });
      } catch(e) {
        lib$es6$promise$$internal$$reject(promise, e);
      }
    }

    var lib$es6$promise$$internal$$id = 0;
    function lib$es6$promise$$internal$$nextId() {
      return lib$es6$promise$$internal$$id++;
    }

    function lib$es6$promise$$internal$$makePromise(promise) {
      promise[lib$es6$promise$$internal$$PROMISE_ID] = lib$es6$promise$$internal$$id++;
      promise._state = undefined;
      promise._result = undefined;
      promise._subscribers = [];
    }

    function lib$es6$promise$promise$all$$all(entries) {
      return new lib$es6$promise$enumerator$$default(this, entries).promise;
    }
    var lib$es6$promise$promise$all$$default = lib$es6$promise$promise$all$$all;
    function lib$es6$promise$promise$race$$race(entries) {
      /*jshint validthis:true */
      var Constructor = this;

      if (!lib$es6$promise$utils$$isArray(entries)) {
        return new Constructor(function(resolve, reject) {
          reject(new TypeError('You must pass an array to race.'));
        });
      } else {
        return new Constructor(function(resolve, reject) {
          var length = entries.length;
          for (var i = 0; i < length; i++) {
            Constructor.resolve(entries[i]).then(resolve, reject);
          }
        });
      }
    }
    var lib$es6$promise$promise$race$$default = lib$es6$promise$promise$race$$race;
    function lib$es6$promise$promise$reject$$reject(reason) {
      /*jshint validthis:true */
      var Constructor = this;
      var promise = new Constructor(lib$es6$promise$$internal$$noop);
      lib$es6$promise$$internal$$reject(promise, reason);
      return promise;
    }
    var lib$es6$promise$promise$reject$$default = lib$es6$promise$promise$reject$$reject;


    function lib$es6$promise$promise$$needsResolver() {
      throw new TypeError('You must pass a resolver function as the first argument to the promise constructor');
    }

    function lib$es6$promise$promise$$needsNew() {
      throw new TypeError("Failed to construct 'Promise': Please use the 'new' operator, this object constructor cannot be called as a function.");
    }

    var lib$es6$promise$promise$$default = lib$es6$promise$promise$$Promise;
    /**
      Promise objects represent the eventual result of an asynchronous operation. The
      primary way of interacting with a promise is through its `then` method, which
      registers callbacks to receive either a promise's eventual value or the reason
      why the promise cannot be fulfilled.

      Terminology
      -----------

      - `promise` is an object or function with a `then` method whose behavior conforms to this specification.
      - `thenable` is an object or function that defines a `then` method.
      - `value` is any legal JavaScript value (including undefined, a thenable, or a promise).
      - `exception` is a value that is thrown using the throw statement.
      - `reason` is a value that indicates why a promise was rejected.
      - `settled` the final resting state of a promise, fulfilled or rejected.

      A promise can be in one of three states: pending, fulfilled, or rejected.

      Promises that are fulfilled have a fulfillment value and are in the fulfilled
      state.  Promises that are rejected have a rejection reason and are in the
      rejected state.  A fulfillment value is never a thenable.

      Promises can also be said to *resolve* a value.  If this value is also a
      promise, then the original promise's settled state will match the value's
      settled state.  So a promise that *resolves* a promise that rejects will
      itself reject, and a promise that *resolves* a promise that fulfills will
      itself fulfill.


      Basic Usage:
      ------------

      ```js
      var promise = new Promise(function(resolve, reject) {
        // on success
        resolve(value);

        // on failure
        reject(reason);
      });

      promise.then(function(value) {
        // on fulfillment
      }, function(reason) {
        // on rejection
      });
      ```

      Advanced Usage:
      ---------------

      Promises shine when abstracting away asynchronous interactions such as
      `XMLHttpRequest`s.

      ```js
      function getJSON(url) {
        return new Promise(function(resolve, reject){
          var xhr = new XMLHttpRequest();

          xhr.open('GET', url);
          xhr.onreadystatechange = handler;
          xhr.responseType = 'json';
          xhr.setRequestHeader('Accept', 'application/json');
          xhr.send();

          function handler() {
            if (this.readyState === this.DONE) {
              if (this.status === 200) {
                resolve(this.response);
              } else {
                reject(new Error('getJSON: `' + url + '` failed with status: [' + this.status + ']'));
              }
            }
          };
        });
      }

      getJSON('/posts.json').then(function(json) {
        // on fulfillment
      }, function(reason) {
        // on rejection
      });
      ```

      Unlike callbacks, promises are great composable primitives.

      ```js
      Promise.all([
        getJSON('/posts'),
        getJSON('/comments')
      ]).then(function(values){
        values[0] // => postsJSON
        values[1] // => commentsJSON

        return values;
      });
      ```

      @class Promise
      @param {function} resolver
      Useful for tooling.
      @constructor
    */
    function lib$es6$promise$promise$$Promise(resolver) {
      this[lib$es6$promise$$internal$$PROMISE_ID] = lib$es6$promise$$internal$$nextId();
      this._result = this._state = undefined;
      this._subscribers = [];

      if (lib$es6$promise$$internal$$noop !== resolver) {
        typeof resolver !== 'function' && lib$es6$promise$promise$$needsResolver();
        this instanceof lib$es6$promise$promise$$Promise ? lib$es6$promise$$internal$$initializePromise(this, resolver) : lib$es6$promise$promise$$needsNew();
      }
    }

    lib$es6$promise$promise$$Promise.all = lib$es6$promise$promise$all$$default;
    lib$es6$promise$promise$$Promise.race = lib$es6$promise$promise$race$$default;
    lib$es6$promise$promise$$Promise.resolve = lib$es6$promise$promise$resolve$$default;
    lib$es6$promise$promise$$Promise.reject = lib$es6$promise$promise$reject$$default;
    lib$es6$promise$promise$$Promise._setScheduler = lib$es6$promise$asap$$setScheduler;
    lib$es6$promise$promise$$Promise._setAsap = lib$es6$promise$asap$$setAsap;
    lib$es6$promise$promise$$Promise._asap = lib$es6$promise$asap$$asap;

    lib$es6$promise$promise$$Promise.prototype = {
      constructor: lib$es6$promise$promise$$Promise,

    /**
      The primary way of interacting with a promise is through its `then` method,
      which registers callbacks to receive either a promise's eventual value or the
      reason why the promise cannot be fulfilled.

      ```js
      findUser().then(function(user){
        // user is available
      }, function(reason){
        // user is unavailable, and you are given the reason why
      });
      ```

      Chaining
      --------

      The return value of `then` is itself a promise.  This second, 'downstream'
      promise is resolved with the return value of the first promise's fulfillment
      or rejection handler, or rejected if the handler throws an exception.

      ```js
      findUser().then(function (user) {
        return user.name;
      }, function (reason) {
        return 'default name';
      }).then(function (userName) {
        // If `findUser` fulfilled, `userName` will be the user's name, otherwise it
        // will be `'default name'`
      });

      findUser().then(function (user) {
        throw new Error('Found user, but still unhappy');
      }, function (reason) {
        throw new Error('`findUser` rejected and we're unhappy');
      }).then(function (value) {
        // never reached
      }, function (reason) {
        // if `findUser` fulfilled, `reason` will be 'Found user, but still unhappy'.
        // If `findUser` rejected, `reason` will be '`findUser` rejected and we're unhappy'.
      });
      ```
      If the downstream promise does not specify a rejection handler, rejection reasons will be propagated further downstream.

      ```js
      findUser().then(function (user) {
        throw new PedagogicalException('Upstream error');
      }).then(function (value) {
        // never reached
      }).then(function (value) {
        // never reached
      }, function (reason) {
        // The `PedgagocialException` is propagated all the way down to here
      });
      ```

      Assimilation
      ------------

      Sometimes the value you want to propagate to a downstream promise can only be
      retrieved asynchronously. This can be achieved by returning a promise in the
      fulfillment or rejection handler. The downstream promise will then be pending
      until the returned promise is settled. This is called *assimilation*.

      ```js
      findUser().then(function (user) {
        return findCommentsByAuthor(user);
      }).then(function (comments) {
        // The user's comments are now available
      });
      ```

      If the assimliated promise rejects, then the downstream promise will also reject.

      ```js
      findUser().then(function (user) {
        return findCommentsByAuthor(user);
      }).then(function (comments) {
        // If `findCommentsByAuthor` fulfills, we'll have the value here
      }, function (reason) {
        // If `findCommentsByAuthor` rejects, we'll have the reason here
      });
      ```

      Simple Example
      --------------

      Synchronous Example

      ```javascript
      var result;

      try {
        result = findResult();
        // success
      } catch(reason) {
        // failure
      }
      ```

      Errback Example

      ```js
      findResult(function(result, err){
        if (err) {
          // failure
        } else {
          // success
        }
      });
      ```

      Promise Example;

      ```javascript
      findResult().then(function(result){
        // success
      }, function(reason){
        // failure
      });
      ```

      Advanced Example
      --------------

      Synchronous Example

      ```javascript
      var author, books;

      try {
        author = findAuthor();
        books  = findBooksByAuthor(author);
        // success
      } catch(reason) {
        // failure
      }
      ```

      Errback Example

      ```js

      function foundBooks(books) {

      }

      function failure(reason) {

      }

      findAuthor(function(author, err){
        if (err) {
          failure(err);
          // failure
        } else {
          try {
            findBoooksByAuthor(author, function(books, err) {
              if (err) {
                failure(err);
              } else {
                try {
                  foundBooks(books);
                } catch(reason) {
                  failure(reason);
                }
              }
            });
          } catch(error) {
            failure(err);
          }
          // success
        }
      });
      ```

      Promise Example;

      ```javascript
      findAuthor().
        then(findBooksByAuthor).
        then(function(books){
          // found books
      }).catch(function(reason){
        // something went wrong
      });
      ```

      @method then
      @param {Function} onFulfilled
      @param {Function} onRejected
      Useful for tooling.
      @return {Promise}
    */
      then: lib$es6$promise$then$$default,

    /**
      `catch` is simply sugar for `then(undefined, onRejection)` which makes it the same
      as the catch block of a try/catch statement.

      ```js
      function findAuthor(){
        throw new Error('couldn't find that author');
      }

      // synchronous
      try {
        findAuthor();
      } catch(reason) {
        // something went wrong
      }

      // async with promises
      findAuthor().catch(function(reason){
        // something went wrong
      });
      ```

      @method catch
      @param {Function} onRejection
      Useful for tooling.
      @return {Promise}
    */
      'catch': function(onRejection) {
        return this.then(null, onRejection);
      }
    };
    var lib$es6$promise$enumerator$$default = lib$es6$promise$enumerator$$Enumerator;
    function lib$es6$promise$enumerator$$Enumerator(Constructor, input) {
      this._instanceConstructor = Constructor;
      this.promise = new Constructor(lib$es6$promise$$internal$$noop);

      if (!this.promise[lib$es6$promise$$internal$$PROMISE_ID]) {
        lib$es6$promise$$internal$$makePromise(this.promise);
      }

      if (lib$es6$promise$utils$$isArray(input)) {
        this._input     = input;
        this.length     = input.length;
        this._remaining = input.length;

        this._result = new Array(this.length);

        if (this.length === 0) {
          lib$es6$promise$$internal$$fulfill(this.promise, this._result);
        } else {
          this.length = this.length || 0;
          this._enumerate();
          if (this._remaining === 0) {
            lib$es6$promise$$internal$$fulfill(this.promise, this._result);
          }
        }
      } else {
        lib$es6$promise$$internal$$reject(this.promise, lib$es6$promise$enumerator$$validationError());
      }
    }

    function lib$es6$promise$enumerator$$validationError() {
      return new Error('Array Methods must be provided an Array');
    }

    lib$es6$promise$enumerator$$Enumerator.prototype._enumerate = function() {
      var length  = this.length;
      var input   = this._input;

      for (var i = 0; this._state === lib$es6$promise$$internal$$PENDING && i < length; i++) {
        this._eachEntry(input[i], i);
      }
    };

    lib$es6$promise$enumerator$$Enumerator.prototype._eachEntry = function(entry, i) {
      var c = this._instanceConstructor;
      var resolve = c.resolve;

      if (resolve === lib$es6$promise$promise$resolve$$default) {
        var then = lib$es6$promise$$internal$$getThen(entry);

        if (then === lib$es6$promise$then$$default &&
            entry._state !== lib$es6$promise$$internal$$PENDING) {
          this._settledAt(entry._state, i, entry._result);
        } else if (typeof then !== 'function') {
          this._remaining--;
          this._result[i] = entry;
        } else if (c === lib$es6$promise$promise$$default) {
          var promise = new c(lib$es6$promise$$internal$$noop);
          lib$es6$promise$$internal$$handleMaybeThenable(promise, entry, then);
          this._willSettleAt(promise, i);
        } else {
          this._willSettleAt(new c(function(resolve) { resolve(entry); }), i);
        }
      } else {
        this._willSettleAt(resolve(entry), i);
      }
    };

    lib$es6$promise$enumerator$$Enumerator.prototype._settledAt = function(state, i, value) {
      var promise = this.promise;

      if (promise._state === lib$es6$promise$$internal$$PENDING) {
        this._remaining--;

        if (state === lib$es6$promise$$internal$$REJECTED) {
          lib$es6$promise$$internal$$reject(promise, value);
        } else {
          this._result[i] = value;
        }
      }

      if (this._remaining === 0) {
        lib$es6$promise$$internal$$fulfill(promise, this._result);
      }
    };

    lib$es6$promise$enumerator$$Enumerator.prototype._willSettleAt = function(promise, i) {
      var enumerator = this;

      lib$es6$promise$$internal$$subscribe(promise, undefined, function(value) {
        enumerator._settledAt(lib$es6$promise$$internal$$FULFILLED, i, value);
      }, function(reason) {
        enumerator._settledAt(lib$es6$promise$$internal$$REJECTED, i, reason);
      });
    };
    function lib$es6$promise$polyfill$$polyfill() {
      var local;

      if (typeof global !== 'undefined') {
          local = global;
      } else if (typeof self !== 'undefined') {
          local = self;
      } else {
          try {
              local = Function('return this')();
          } catch (e) {
              throw new Error('polyfill failed because global object is unavailable in this environment');
          }
      }

      var P = local.Promise;

      if (P && Object.prototype.toString.call(P.resolve()) === '[object Promise]' && !P.cast) {
        return;
      }

      local.Promise = lib$es6$promise$promise$$default;
    }
    var lib$es6$promise$polyfill$$default = lib$es6$promise$polyfill$$polyfill;

    var lib$es6$promise$umd$$ES6Promise = {
      'Promise': lib$es6$promise$promise$$default,
      'polyfill': lib$es6$promise$polyfill$$default
    };

    /* global define:true module:true window: true */
    if (typeof define === 'function' && define['amd']) {
      define(function() { return lib$es6$promise$umd$$ES6Promise; });
    } else if (typeof module !== 'undefined' && module['exports']) {
      module['exports'] = lib$es6$promise$umd$$ES6Promise;
    } else if (typeof this !== 'undefined') {
      this['ES6Promise'] = lib$es6$promise$umd$$ES6Promise;
    }

    lib$es6$promise$polyfill$$default();
}).call(this);


}).call(this,_dereq_('_process'),typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"_process":3}],3:[function(_dereq_,module,exports){
// shim for using process in browser

var process = module.exports = {};

// cached from whatever global is present so that test runners that stub it
// don't break things.  But we need to wrap it in a try catch in case it is
// wrapped in strict mode code which doesn't define any globals.  It's inside a
// function because try/catches deoptimize in certain engines.

var cachedSetTimeout;
var cachedClearTimeout;

(function () {
  try {
    cachedSetTimeout = setTimeout;
  } catch (e) {
    cachedSetTimeout = function () {
      throw new Error('setTimeout is not defined');
    }
  }
  try {
    cachedClearTimeout = clearTimeout;
  } catch (e) {
    cachedClearTimeout = function () {
      throw new Error('clearTimeout is not defined');
    }
  }
} ())
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    if (!draining || !currentQueue) {
        return;
    }
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = cachedSetTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    cachedClearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        cachedSetTimeout(drainQueue, 0);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };

},{}],4:[function(_dereq_,module,exports){
(function (global){
/*
 * Rusha, a JavaScript implementation of the Secure Hash Algorithm, SHA-1,
 * as defined in FIPS PUB 180-1, tuned for high performance with large inputs.
 * (http://github.com/srijs/rusha)
 *
 * Inspired by Paul Johnstons implementation (http://pajhome.org.uk/crypt/md5).
 *
 * Copyright (c) 2013 Sam Rijs (http://awesam.de).
 * Released under the terms of the MIT license as follows:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
(function () {
    var util = {
            getDataType: function (data) {
                if (typeof data === 'string') {
                    return 'string';
                }
                if (data instanceof Array) {
                    return 'array';
                }
                if (typeof global !== 'undefined' && global.Buffer && global.Buffer.isBuffer(data)) {
                    return 'buffer';
                }
                if (data instanceof ArrayBuffer) {
                    return 'arraybuffer';
                }
                if (data.buffer instanceof ArrayBuffer) {
                    return 'view';
                }
                if (data instanceof Blob) {
                    return 'blob';
                }
                throw new Error('Unsupported data type.');
            }
        };
    // The Rusha object is a wrapper around the low-level RushaCore.
    // It provides means of converting different inputs to the
    // format accepted by RushaCore as well as other utility methods.
    function Rusha(chunkSize) {
        'use strict';
        // Private object structure.
        var self$2 = { fill: 0 };
        // Calculate the length of buffer that the sha1 routine uses
        // including the padding.
        var padlen = function (len) {
            for (len += 9; len % 64 > 0; len += 1);
            return len;
        };
        var padZeroes = function (bin, len) {
            for (var i = len >> 2; i < bin.length; i++)
                bin[i] = 0;
        };
        var padData = function (bin, chunkLen, msgLen) {
            bin[chunkLen >> 2] |= 128 << 24 - (chunkLen % 4 << 3);
            bin[((chunkLen >> 2) + 2 & ~15) + 14] = msgLen >> 29;
            bin[((chunkLen >> 2) + 2 & ~15) + 15] = msgLen << 3;
        };
        // Convert a binary string and write it to the heap.
        // A binary string is expected to only contain char codes < 256.
        var convStr = function (H8, H32, start, len, off) {
            var str = this, i, om = off % 4, lm = len % 4, j = len - lm;
            if (j > 0) {
                switch (om) {
                case 0:
                    H8[off + 3 | 0] = str.charCodeAt(start);
                case 1:
                    H8[off + 2 | 0] = str.charCodeAt(start + 1);
                case 2:
                    H8[off + 1 | 0] = str.charCodeAt(start + 2);
                case 3:
                    H8[off | 0] = str.charCodeAt(start + 3);
                }
            }
            for (i = om; i < j; i = i + 4 | 0) {
                H32[off + i >> 2] = str.charCodeAt(start + i) << 24 | str.charCodeAt(start + i + 1) << 16 | str.charCodeAt(start + i + 2) << 8 | str.charCodeAt(start + i + 3);
            }
            switch (lm) {
            case 3:
                H8[off + j + 1 | 0] = str.charCodeAt(start + j + 2);
            case 2:
                H8[off + j + 2 | 0] = str.charCodeAt(start + j + 1);
            case 1:
                H8[off + j + 3 | 0] = str.charCodeAt(start + j);
            }
        };
        // Convert a buffer or array and write it to the heap.
        // The buffer or array is expected to only contain elements < 256.
        var convBuf = function (H8, H32, start, len, off) {
            var buf = this, i, om = off % 4, lm = len % 4, j = len - lm;
            if (j > 0) {
                switch (om) {
                case 0:
                    H8[off + 3 | 0] = buf[start];
                case 1:
                    H8[off + 2 | 0] = buf[start + 1];
                case 2:
                    H8[off + 1 | 0] = buf[start + 2];
                case 3:
                    H8[off | 0] = buf[start + 3];
                }
            }
            for (i = 4 - om; i < j; i = i += 4 | 0) {
                H32[off + i >> 2] = buf[start + i] << 24 | buf[start + i + 1] << 16 | buf[start + i + 2] << 8 | buf[start + i + 3];
            }
            switch (lm) {
            case 3:
                H8[off + j + 1 | 0] = buf[start + j + 2];
            case 2:
                H8[off + j + 2 | 0] = buf[start + j + 1];
            case 1:
                H8[off + j + 3 | 0] = buf[start + j];
            }
        };
        var convBlob = function (H8, H32, start, len, off) {
            var blob = this, i, om = off % 4, lm = len % 4, j = len - lm;
            var buf = new Uint8Array(reader.readAsArrayBuffer(blob.slice(start, start + len)));
            if (j > 0) {
                switch (om) {
                case 0:
                    H8[off + 3 | 0] = buf[0];
                case 1:
                    H8[off + 2 | 0] = buf[1];
                case 2:
                    H8[off + 1 | 0] = buf[2];
                case 3:
                    H8[off | 0] = buf[3];
                }
            }
            for (i = 4 - om; i < j; i = i += 4 | 0) {
                H32[off + i >> 2] = buf[i] << 24 | buf[i + 1] << 16 | buf[i + 2] << 8 | buf[i + 3];
            }
            switch (lm) {
            case 3:
                H8[off + j + 1 | 0] = buf[j + 2];
            case 2:
                H8[off + j + 2 | 0] = buf[j + 1];
            case 1:
                H8[off + j + 3 | 0] = buf[j];
            }
        };
        var convFn = function (data) {
            switch (util.getDataType(data)) {
            case 'string':
                return convStr.bind(data);
            case 'array':
                return convBuf.bind(data);
            case 'buffer':
                return convBuf.bind(data);
            case 'arraybuffer':
                return convBuf.bind(new Uint8Array(data));
            case 'view':
                return convBuf.bind(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
            case 'blob':
                return convBlob.bind(data);
            }
        };
        var slice = function (data, offset) {
            switch (util.getDataType(data)) {
            case 'string':
                return data.slice(offset);
            case 'array':
                return data.slice(offset);
            case 'buffer':
                return data.slice(offset);
            case 'arraybuffer':
                return data.slice(offset);
            case 'view':
                return data.buffer.slice(offset);
            }
        };
        // Convert an ArrayBuffer into its hexadecimal string representation.
        var hex = function (arrayBuffer) {
            var i, x, hex_tab = '0123456789abcdef', res = [], binarray = new Uint8Array(arrayBuffer);
            for (i = 0; i < binarray.length; i++) {
                x = binarray[i];
                res[i] = hex_tab.charAt(x >> 4 & 15) + hex_tab.charAt(x >> 0 & 15);
            }
            return res.join('');
        };
        var ceilHeapSize = function (v) {
            // The asm.js spec says:
            // The heap object's byteLength must be either
            // 2^n for n in [12, 24) or 2^24 * n for n ≥ 1.
            // Also, byteLengths smaller than 2^16 are deprecated.
            var p;
            // If v is smaller than 2^16, the smallest possible solution
            // is 2^16.
            if (v <= 65536)
                return 65536;
            // If v < 2^24, we round up to 2^n,
            // otherwise we round up to 2^24 * n.
            if (v < 16777216) {
                for (p = 1; p < v; p = p << 1);
            } else {
                for (p = 16777216; p < v; p += 16777216);
            }
            return p;
        };
        // Initialize the internal data structures to a new capacity.
        var init = function (size) {
            if (size % 64 > 0) {
                throw new Error('Chunk size must be a multiple of 128 bit');
            }
            self$2.maxChunkLen = size;
            self$2.padMaxChunkLen = padlen(size);
            // The size of the heap is the sum of:
            // 1. The padded input message size
            // 2. The extended space the algorithm needs (320 byte)
            // 3. The 160 bit state the algoritm uses
            self$2.heap = new ArrayBuffer(ceilHeapSize(self$2.padMaxChunkLen + 320 + 20));
            self$2.h32 = new Int32Array(self$2.heap);
            self$2.h8 = new Int8Array(self$2.heap);
            self$2.core = new Rusha._core({
                Int32Array: Int32Array,
                DataView: DataView
            }, {}, self$2.heap);
            self$2.buffer = null;
        };
        // Iinitializethe datastructures according
        // to a chunk siyze.
        init(chunkSize || 64 * 1024);
        var initState = function (heap, padMsgLen) {
            var io = new Int32Array(heap, padMsgLen + 320, 5);
            io[0] = 1732584193;
            io[1] = -271733879;
            io[2] = -1732584194;
            io[3] = 271733878;
            io[4] = -1009589776;
        };
        var padChunk = function (chunkLen, msgLen) {
            var padChunkLen = padlen(chunkLen);
            var view = new Int32Array(self$2.heap, 0, padChunkLen >> 2);
            padZeroes(view, chunkLen);
            padData(view, chunkLen, msgLen);
            return padChunkLen;
        };
        // Write data to the heap.
        var write = function (data, chunkOffset, chunkLen) {
            convFn(data)(self$2.h8, self$2.h32, chunkOffset, chunkLen, 0);
        };
        // Initialize and call the RushaCore,
        // assuming an input buffer of length len * 4.
        var coreCall = function (data, chunkOffset, chunkLen, msgLen, finalize) {
            var padChunkLen = chunkLen;
            if (finalize) {
                padChunkLen = padChunk(chunkLen, msgLen);
            }
            write(data, chunkOffset, chunkLen);
            self$2.core.hash(padChunkLen, self$2.padMaxChunkLen);
        };
        var getRawDigest = function (heap, padMaxChunkLen) {
            var io = new Int32Array(heap, padMaxChunkLen + 320, 5);
            var out = new Int32Array(5);
            var arr = new DataView(out.buffer);
            arr.setInt32(0, io[0], false);
            arr.setInt32(4, io[1], false);
            arr.setInt32(8, io[2], false);
            arr.setInt32(12, io[3], false);
            arr.setInt32(16, io[4], false);
            return out;
        };
        // Calculate the hash digest as an array of 5 32bit integers.
        var rawDigest = this.rawDigest = function (str) {
                var msgLen = str.byteLength || str.length || str.size || 0;
                initState(self$2.heap, self$2.padMaxChunkLen);
                var chunkOffset = 0, chunkLen = self$2.maxChunkLen, last;
                for (chunkOffset = 0; msgLen > chunkOffset + chunkLen; chunkOffset += chunkLen) {
                    coreCall(str, chunkOffset, chunkLen, msgLen, false);
                }
                coreCall(str, chunkOffset, msgLen - chunkOffset, msgLen, true);
                return getRawDigest(self$2.heap, self$2.padMaxChunkLen);
            };
        // The digest and digestFrom* interface returns the hash digest
        // as a hex string.
        this.digest = this.digestFromString = this.digestFromBuffer = this.digestFromArrayBuffer = function (str) {
            return hex(rawDigest(str).buffer);
        };
    }
    ;
    // The low-level RushCore module provides the heart of Rusha,
    // a high-speed sha1 implementation working on an Int32Array heap.
    // At first glance, the implementation seems complicated, however
    // with the SHA1 spec at hand, it is obvious this almost a textbook
    // implementation that has a few functions hand-inlined and a few loops
    // hand-unrolled.
    Rusha._core = function RushaCore(stdlib, foreign, heap) {
        'use asm';
        var H = new stdlib.Int32Array(heap);
        function hash(k, x) {
            // k in bytes
            k = k | 0;
            x = x | 0;
            var i = 0, j = 0, y0 = 0, z0 = 0, y1 = 0, z1 = 0, y2 = 0, z2 = 0, y3 = 0, z3 = 0, y4 = 0, z4 = 0, t0 = 0, t1 = 0;
            y0 = H[x + 320 >> 2] | 0;
            y1 = H[x + 324 >> 2] | 0;
            y2 = H[x + 328 >> 2] | 0;
            y3 = H[x + 332 >> 2] | 0;
            y4 = H[x + 336 >> 2] | 0;
            for (i = 0; (i | 0) < (k | 0); i = i + 64 | 0) {
                z0 = y0;
                z1 = y1;
                z2 = y2;
                z3 = y3;
                z4 = y4;
                for (j = 0; (j | 0) < 64; j = j + 4 | 0) {
                    t1 = H[i + j >> 2] | 0;
                    t0 = ((y0 << 5 | y0 >>> 27) + (y1 & y2 | ~y1 & y3) | 0) + ((t1 + y4 | 0) + 1518500249 | 0) | 0;
                    y4 = y3;
                    y3 = y2;
                    y2 = y1 << 30 | y1 >>> 2;
                    y1 = y0;
                    y0 = t0;
                    H[k + j >> 2] = t1;
                }
                for (j = k + 64 | 0; (j | 0) < (k + 80 | 0); j = j + 4 | 0) {
                    t1 = (H[j - 12 >> 2] ^ H[j - 32 >> 2] ^ H[j - 56 >> 2] ^ H[j - 64 >> 2]) << 1 | (H[j - 12 >> 2] ^ H[j - 32 >> 2] ^ H[j - 56 >> 2] ^ H[j - 64 >> 2]) >>> 31;
                    t0 = ((y0 << 5 | y0 >>> 27) + (y1 & y2 | ~y1 & y3) | 0) + ((t1 + y4 | 0) + 1518500249 | 0) | 0;
                    y4 = y3;
                    y3 = y2;
                    y2 = y1 << 30 | y1 >>> 2;
                    y1 = y0;
                    y0 = t0;
                    H[j >> 2] = t1;
                }
                for (j = k + 80 | 0; (j | 0) < (k + 160 | 0); j = j + 4 | 0) {
                    t1 = (H[j - 12 >> 2] ^ H[j - 32 >> 2] ^ H[j - 56 >> 2] ^ H[j - 64 >> 2]) << 1 | (H[j - 12 >> 2] ^ H[j - 32 >> 2] ^ H[j - 56 >> 2] ^ H[j - 64 >> 2]) >>> 31;
                    t0 = ((y0 << 5 | y0 >>> 27) + (y1 ^ y2 ^ y3) | 0) + ((t1 + y4 | 0) + 1859775393 | 0) | 0;
                    y4 = y3;
                    y3 = y2;
                    y2 = y1 << 30 | y1 >>> 2;
                    y1 = y0;
                    y0 = t0;
                    H[j >> 2] = t1;
                }
                for (j = k + 160 | 0; (j | 0) < (k + 240 | 0); j = j + 4 | 0) {
                    t1 = (H[j - 12 >> 2] ^ H[j - 32 >> 2] ^ H[j - 56 >> 2] ^ H[j - 64 >> 2]) << 1 | (H[j - 12 >> 2] ^ H[j - 32 >> 2] ^ H[j - 56 >> 2] ^ H[j - 64 >> 2]) >>> 31;
                    t0 = ((y0 << 5 | y0 >>> 27) + (y1 & y2 | y1 & y3 | y2 & y3) | 0) + ((t1 + y4 | 0) - 1894007588 | 0) | 0;
                    y4 = y3;
                    y3 = y2;
                    y2 = y1 << 30 | y1 >>> 2;
                    y1 = y0;
                    y0 = t0;
                    H[j >> 2] = t1;
                }
                for (j = k + 240 | 0; (j | 0) < (k + 320 | 0); j = j + 4 | 0) {
                    t1 = (H[j - 12 >> 2] ^ H[j - 32 >> 2] ^ H[j - 56 >> 2] ^ H[j - 64 >> 2]) << 1 | (H[j - 12 >> 2] ^ H[j - 32 >> 2] ^ H[j - 56 >> 2] ^ H[j - 64 >> 2]) >>> 31;
                    t0 = ((y0 << 5 | y0 >>> 27) + (y1 ^ y2 ^ y3) | 0) + ((t1 + y4 | 0) - 899497514 | 0) | 0;
                    y4 = y3;
                    y3 = y2;
                    y2 = y1 << 30 | y1 >>> 2;
                    y1 = y0;
                    y0 = t0;
                    H[j >> 2] = t1;
                }
                y0 = y0 + z0 | 0;
                y1 = y1 + z1 | 0;
                y2 = y2 + z2 | 0;
                y3 = y3 + z3 | 0;
                y4 = y4 + z4 | 0;
            }
            H[x + 320 >> 2] = y0;
            H[x + 324 >> 2] = y1;
            H[x + 328 >> 2] = y2;
            H[x + 332 >> 2] = y3;
            H[x + 336 >> 2] = y4;
        }
        return { hash: hash };
    };
    // If we'e running in Node.JS, export a module.
    if (typeof module !== 'undefined') {
        module.exports = Rusha;
    } else if (typeof window !== 'undefined') {
        window.Rusha = Rusha;
    }
    // If we're running in a webworker, accept
    // messages containing a jobid and a buffer
    // or blob object, and return the hash result.
    if (typeof FileReaderSync !== 'undefined') {
        var reader = new FileReaderSync(), hasher = new Rusha(4 * 1024 * 1024);
        self.onmessage = function onMessage(event) {
            var hash, data = event.data.data;
            try {
                hash = hasher.digest(data);
                self.postMessage({
                    id: event.data.id,
                    hash: hash
                });
            } catch (e) {
                self.postMessage({
                    id: event.data.id,
                    error: e.name
                });
            }
        };
    }
}());
}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}],5:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @requires config
 * @requires encoding/armor
 * @requires enums
 * @requires packet
 * @module cleartext
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.CleartextMessage = CleartextMessage;
exports.readArmored = readArmored;

var _config = _dereq_('./config');

var _config2 = _interopRequireDefault(_config);

var _packet = _dereq_('./packet');

var _packet2 = _interopRequireDefault(_packet);

var _enums = _dereq_('./enums.js');

var _enums2 = _interopRequireDefault(_enums);

var _armor = _dereq_('./encoding/armor.js');

var _armor2 = _interopRequireDefault(_armor);

var _signature = _dereq_('./signature.js');

var sigModule = _interopRequireWildcard(_signature);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @class
 * @classdesc Class that represents an OpenPGP cleartext signed message.
 * See {@link http://tools.ietf.org/html/rfc4880#section-7}
 * @param  {String}     text       The cleartext of the signed message
 * @param  {module:signature} signature       The detached signature or an empty signature if message not yet signed
 */

function CleartextMessage(text, signature) {
  if (!(this instanceof CleartextMessage)) {
    return new CleartextMessage(text, signature);
  }
  // normalize EOL to canonical form <CR><LF>
  this.text = text.replace(/\r/g, '').replace(/[\t ]+\n/g, "\n").replace(/\n/g, "\r\n");
  if (signature && !(signature instanceof sigModule.Signature)) {
    throw new Error('Invalid signature input');
  }
  this.signature = signature || new sigModule.Signature(new _packet2.default.List());
}

/**
 * Returns the key IDs of the keys that signed the cleartext message
 * @return {Array<module:type/keyid>} array of keyid objects
 */
CleartextMessage.prototype.getSigningKeyIds = function () {
  var keyIds = [];
  var signatureList = this.signature.packets;
  signatureList.forEach(function (packet) {
    keyIds.push(packet.issuerKeyId);
  });
  return keyIds;
};

/**
 * Sign the cleartext message
 * @param  {Array<module:key~Key>} privateKeys private keys with decrypted secret key data for signing
 * @return {module:message~CleartextMessage} new cleartext message with signed content
 */
CleartextMessage.prototype.sign = function (privateKeys) {
  return new CleartextMessage(this.text, this.signDetached(privateKeys));
};

/**
 * Sign the cleartext message
 * @param  {Array<module:key~Key>} privateKeys private keys with decrypted secret key data for signing
 * @return {module:signature~Signature}      new detached signature of message content
 */
CleartextMessage.prototype.signDetached = function (privateKeys) {
  var packetlist = new _packet2.default.List();
  var literalDataPacket = new _packet2.default.Literal();
  literalDataPacket.setText(this.text);
  for (var i = 0; i < privateKeys.length; i++) {
    if (privateKeys[i].isPublic()) {
      throw new Error('Need private key for signing');
    }
    var signaturePacket = new _packet2.default.Signature();
    signaturePacket.signatureType = _enums2.default.signature.text;
    signaturePacket.hashAlgorithm = _config2.default.prefer_hash_algorithm;
    var signingKeyPacket = privateKeys[i].getSigningKeyPacket();
    signaturePacket.publicKeyAlgorithm = signingKeyPacket.algorithm;
    if (!signingKeyPacket.isDecrypted) {
      throw new Error('Private key is not decrypted.');
    }
    signaturePacket.sign(signingKeyPacket, literalDataPacket);
    packetlist.push(signaturePacket);
  }
  return new sigModule.Signature(packetlist);
};

/**
 * Verify signatures of cleartext signed message
 * @param {Array<module:key~Key>} keys array of keys to verify signatures
 * @return {Array<{keyid: module:type/keyid, valid: Boolean}>} list of signer's keyid and validity of signature
 */
CleartextMessage.prototype.verify = function (keys) {
  return this.verifyDetached(this.signature, keys);
};

/**
 * Verify signatures of cleartext signed message
 * @param {Array<module:key~Key>} keys array of keys to verify signatures
 * @return {Array<{keyid: module:type/keyid, valid: Boolean}>} list of signer's keyid and validity of signature
 */
CleartextMessage.prototype.verifyDetached = function (signature, keys) {
  var result = [];
  var signatureList = signature.packets;
  var literalDataPacket = new _packet2.default.Literal();
  // we assume that cleartext signature is generated based on UTF8 cleartext
  literalDataPacket.setText(this.text);
  for (var i = 0; i < signatureList.length; i++) {
    var keyPacket = null;
    for (var j = 0; j < keys.length; j++) {
      keyPacket = keys[j].getSigningKeyPacket(signatureList[i].issuerKeyId);
      if (keyPacket) {
        break;
      }
    }

    var verifiedSig = {};
    if (keyPacket) {
      verifiedSig.keyid = signatureList[i].issuerKeyId;
      verifiedSig.valid = signatureList[i].verify(keyPacket, literalDataPacket);
    } else {
      verifiedSig.keyid = signatureList[i].issuerKeyId;
      verifiedSig.valid = null;
    }

    var packetlist = new _packet2.default.List();
    packetlist.push(signatureList[i]);
    verifiedSig.signature = new sigModule.Signature(packetlist);

    result.push(verifiedSig);
  }
  return result;
};

/**
 * Get cleartext
 * @return {String} cleartext of message
 */
CleartextMessage.prototype.getText = function () {
  // normalize end of line to \n
  return this.text.replace(/\r\n/g, "\n");
};

/**
 * Returns ASCII armored text of cleartext signed message
 * @return {String} ASCII armor
 */
CleartextMessage.prototype.armor = function () {
  var body = {
    hash: _enums2.default.read(_enums2.default.hash, _config2.default.prefer_hash_algorithm).toUpperCase(),
    text: this.text,
    data: this.signature.packets.write()
  };
  return _armor2.default.encode(_enums2.default.armor.signed, body);
};

/**
 * reads an OpenPGP cleartext signed message and returns a CleartextMessage object
 * @param {String} armoredText text to be parsed
 * @return {module:cleartext~CleartextMessage} new cleartext message object
 * @static
 */
function readArmored(armoredText) {
  var input = _armor2.default.decode(armoredText);
  if (input.type !== _enums2.default.armor.signed) {
    throw new Error('No cleartext signed message.');
  }
  var packetlist = new _packet2.default.List();
  packetlist.read(input.data);
  verifyHeaders(input.headers, packetlist);
  var signature = new sigModule.Signature(packetlist);
  var newMessage = new CleartextMessage(input.text, signature);
  return newMessage;
}

/**
 * Compare hash algorithm specified in the armor header with signatures
 * @private
 * @param  {Array<String>} headers    Armor headers
 * @param  {module:packet/packetlist} packetlist The packetlist with signature packets
 */
function verifyHeaders(headers, packetlist) {
  var checkHashAlgos = function checkHashAlgos(hashAlgos) {
    function check(algo) {
      return packetlist[i].hashAlgorithm === algo;
    }
    for (var i = 0; i < packetlist.length; i++) {
      if (packetlist[i].tag === _enums2.default.packet.signature && !hashAlgos.some(check)) {
        return false;
      }
    }
    return true;
  };
  var oneHeader = null;
  var hashAlgos = [];
  headers.forEach(function (header) {
    oneHeader = header.match(/Hash: (.+)/); // get header value
    if (oneHeader) {
      oneHeader = oneHeader[1].replace(/\s/g, ''); // remove whitespace
      oneHeader = oneHeader.split(',');
      oneHeader = oneHeader.map(function (hash) {
        hash = hash.toLowerCase();
        try {
          return _enums2.default.write(_enums2.default.hash, hash);
        } catch (e) {
          throw new Error('Unknown hash algorithm in armor header: ' + hash);
        }
      });
      hashAlgos = hashAlgos.concat(oneHeader);
    } else {
      throw new Error('Only "Hash" header allowed in cleartext signed message');
    }
  });
  if (!hashAlgos.length && !checkHashAlgos([_enums2.default.hash.md5])) {
    throw new Error('If no "Hash" header in cleartext signed message, then only MD5 signatures allowed');
  } else if (!checkHashAlgos(hashAlgos)) {
    throw new Error('Hash algorithm mismatch in armor header and signature');
  }
}

},{"./config":10,"./encoding/armor.js":33,"./enums.js":35,"./packet":47,"./signature.js":66}],6:[function(_dereq_,module,exports){
/** @license zlib.js 2012 - imaya [ https://github.com/imaya/zlib.js ] The MIT License */(function() {'use strict';var n=void 0,u=!0,aa=this;function ba(e,d){var c=e.split("."),f=aa;!(c[0]in f)&&f.execScript&&f.execScript("var "+c[0]);for(var a;c.length&&(a=c.shift());)!c.length&&d!==n?f[a]=d:f=f[a]?f[a]:f[a]={}};var C="undefined"!==typeof Uint8Array&&"undefined"!==typeof Uint16Array&&"undefined"!==typeof Uint32Array&&"undefined"!==typeof DataView;function K(e,d){this.index="number"===typeof d?d:0;this.d=0;this.buffer=e instanceof(C?Uint8Array:Array)?e:new (C?Uint8Array:Array)(32768);if(2*this.buffer.length<=this.index)throw Error("invalid index");this.buffer.length<=this.index&&ca(this)}function ca(e){var d=e.buffer,c,f=d.length,a=new (C?Uint8Array:Array)(f<<1);if(C)a.set(d);else for(c=0;c<f;++c)a[c]=d[c];return e.buffer=a}
K.prototype.a=function(e,d,c){var f=this.buffer,a=this.index,b=this.d,k=f[a],m;c&&1<d&&(e=8<d?(L[e&255]<<24|L[e>>>8&255]<<16|L[e>>>16&255]<<8|L[e>>>24&255])>>32-d:L[e]>>8-d);if(8>d+b)k=k<<d|e,b+=d;else for(m=0;m<d;++m)k=k<<1|e>>d-m-1&1,8===++b&&(b=0,f[a++]=L[k],k=0,a===f.length&&(f=ca(this)));f[a]=k;this.buffer=f;this.d=b;this.index=a};K.prototype.finish=function(){var e=this.buffer,d=this.index,c;0<this.d&&(e[d]<<=8-this.d,e[d]=L[e[d]],d++);C?c=e.subarray(0,d):(e.length=d,c=e);return c};
var ga=new (C?Uint8Array:Array)(256),M;for(M=0;256>M;++M){for(var R=M,S=R,ha=7,R=R>>>1;R;R>>>=1)S<<=1,S|=R&1,--ha;ga[M]=(S<<ha&255)>>>0}var L=ga;function ja(e){this.buffer=new (C?Uint16Array:Array)(2*e);this.length=0}ja.prototype.getParent=function(e){return 2*((e-2)/4|0)};ja.prototype.push=function(e,d){var c,f,a=this.buffer,b;c=this.length;a[this.length++]=d;for(a[this.length++]=e;0<c;)if(f=this.getParent(c),a[c]>a[f])b=a[c],a[c]=a[f],a[f]=b,b=a[c+1],a[c+1]=a[f+1],a[f+1]=b,c=f;else break;return this.length};
ja.prototype.pop=function(){var e,d,c=this.buffer,f,a,b;d=c[0];e=c[1];this.length-=2;c[0]=c[this.length];c[1]=c[this.length+1];for(b=0;;){a=2*b+2;if(a>=this.length)break;a+2<this.length&&c[a+2]>c[a]&&(a+=2);if(c[a]>c[b])f=c[b],c[b]=c[a],c[a]=f,f=c[b+1],c[b+1]=c[a+1],c[a+1]=f;else break;b=a}return{index:e,value:d,length:this.length}};function ka(e,d){this.e=ma;this.f=0;this.input=C&&e instanceof Array?new Uint8Array(e):e;this.c=0;d&&(d.lazy&&(this.f=d.lazy),"number"===typeof d.compressionType&&(this.e=d.compressionType),d.outputBuffer&&(this.b=C&&d.outputBuffer instanceof Array?new Uint8Array(d.outputBuffer):d.outputBuffer),"number"===typeof d.outputIndex&&(this.c=d.outputIndex));this.b||(this.b=new (C?Uint8Array:Array)(32768))}var ma=2,T=[],U;
for(U=0;288>U;U++)switch(u){case 143>=U:T.push([U+48,8]);break;case 255>=U:T.push([U-144+400,9]);break;case 279>=U:T.push([U-256+0,7]);break;case 287>=U:T.push([U-280+192,8]);break;default:throw"invalid literal: "+U;}
ka.prototype.h=function(){var e,d,c,f,a=this.input;switch(this.e){case 0:c=0;for(f=a.length;c<f;){d=C?a.subarray(c,c+65535):a.slice(c,c+65535);c+=d.length;var b=d,k=c===f,m=n,g=n,p=n,v=n,x=n,l=this.b,h=this.c;if(C){for(l=new Uint8Array(this.b.buffer);l.length<=h+b.length+5;)l=new Uint8Array(l.length<<1);l.set(this.b)}m=k?1:0;l[h++]=m|0;g=b.length;p=~g+65536&65535;l[h++]=g&255;l[h++]=g>>>8&255;l[h++]=p&255;l[h++]=p>>>8&255;if(C)l.set(b,h),h+=b.length,l=l.subarray(0,h);else{v=0;for(x=b.length;v<x;++v)l[h++]=
b[v];l.length=h}this.c=h;this.b=l}break;case 1:var q=new K(C?new Uint8Array(this.b.buffer):this.b,this.c);q.a(1,1,u);q.a(1,2,u);var t=na(this,a),w,da,z;w=0;for(da=t.length;w<da;w++)if(z=t[w],K.prototype.a.apply(q,T[z]),256<z)q.a(t[++w],t[++w],u),q.a(t[++w],5),q.a(t[++w],t[++w],u);else if(256===z)break;this.b=q.finish();this.c=this.b.length;break;case ma:var B=new K(C?new Uint8Array(this.b.buffer):this.b,this.c),ra,J,N,O,P,Ia=[16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15],W,sa,X,ta,ea,ia=Array(19),
ua,Q,fa,y,va;ra=ma;B.a(1,1,u);B.a(ra,2,u);J=na(this,a);W=oa(this.j,15);sa=pa(W);X=oa(this.i,7);ta=pa(X);for(N=286;257<N&&0===W[N-1];N--);for(O=30;1<O&&0===X[O-1];O--);var wa=N,xa=O,F=new (C?Uint32Array:Array)(wa+xa),r,G,s,Y,E=new (C?Uint32Array:Array)(316),D,A,H=new (C?Uint8Array:Array)(19);for(r=G=0;r<wa;r++)F[G++]=W[r];for(r=0;r<xa;r++)F[G++]=X[r];if(!C){r=0;for(Y=H.length;r<Y;++r)H[r]=0}r=D=0;for(Y=F.length;r<Y;r+=G){for(G=1;r+G<Y&&F[r+G]===F[r];++G);s=G;if(0===F[r])if(3>s)for(;0<s--;)E[D++]=0,
H[0]++;else for(;0<s;)A=138>s?s:138,A>s-3&&A<s&&(A=s-3),10>=A?(E[D++]=17,E[D++]=A-3,H[17]++):(E[D++]=18,E[D++]=A-11,H[18]++),s-=A;else if(E[D++]=F[r],H[F[r]]++,s--,3>s)for(;0<s--;)E[D++]=F[r],H[F[r]]++;else for(;0<s;)A=6>s?s:6,A>s-3&&A<s&&(A=s-3),E[D++]=16,E[D++]=A-3,H[16]++,s-=A}e=C?E.subarray(0,D):E.slice(0,D);ea=oa(H,7);for(y=0;19>y;y++)ia[y]=ea[Ia[y]];for(P=19;4<P&&0===ia[P-1];P--);ua=pa(ea);B.a(N-257,5,u);B.a(O-1,5,u);B.a(P-4,4,u);for(y=0;y<P;y++)B.a(ia[y],3,u);y=0;for(va=e.length;y<va;y++)if(Q=
e[y],B.a(ua[Q],ea[Q],u),16<=Q){y++;switch(Q){case 16:fa=2;break;case 17:fa=3;break;case 18:fa=7;break;default:throw"invalid code: "+Q;}B.a(e[y],fa,u)}var ya=[sa,W],za=[ta,X],I,Aa,Z,la,Ba,Ca,Da,Ea;Ba=ya[0];Ca=ya[1];Da=za[0];Ea=za[1];I=0;for(Aa=J.length;I<Aa;++I)if(Z=J[I],B.a(Ba[Z],Ca[Z],u),256<Z)B.a(J[++I],J[++I],u),la=J[++I],B.a(Da[la],Ea[la],u),B.a(J[++I],J[++I],u);else if(256===Z)break;this.b=B.finish();this.c=this.b.length;break;default:throw"invalid compression type";}return this.b};
function qa(e,d){this.length=e;this.g=d}
var Fa=function(){function e(a){switch(u){case 3===a:return[257,a-3,0];case 4===a:return[258,a-4,0];case 5===a:return[259,a-5,0];case 6===a:return[260,a-6,0];case 7===a:return[261,a-7,0];case 8===a:return[262,a-8,0];case 9===a:return[263,a-9,0];case 10===a:return[264,a-10,0];case 12>=a:return[265,a-11,1];case 14>=a:return[266,a-13,1];case 16>=a:return[267,a-15,1];case 18>=a:return[268,a-17,1];case 22>=a:return[269,a-19,2];case 26>=a:return[270,a-23,2];case 30>=a:return[271,a-27,2];case 34>=a:return[272,
a-31,2];case 42>=a:return[273,a-35,3];case 50>=a:return[274,a-43,3];case 58>=a:return[275,a-51,3];case 66>=a:return[276,a-59,3];case 82>=a:return[277,a-67,4];case 98>=a:return[278,a-83,4];case 114>=a:return[279,a-99,4];case 130>=a:return[280,a-115,4];case 162>=a:return[281,a-131,5];case 194>=a:return[282,a-163,5];case 226>=a:return[283,a-195,5];case 257>=a:return[284,a-227,5];case 258===a:return[285,a-258,0];default:throw"invalid length: "+a;}}var d=[],c,f;for(c=3;258>=c;c++)f=e(c),d[c]=f[2]<<24|
f[1]<<16|f[0];return d}(),Ga=C?new Uint32Array(Fa):Fa;
function na(e,d){function c(a,c){var b=a.g,d=[],f=0,e;e=Ga[a.length];d[f++]=e&65535;d[f++]=e>>16&255;d[f++]=e>>24;var g;switch(u){case 1===b:g=[0,b-1,0];break;case 2===b:g=[1,b-2,0];break;case 3===b:g=[2,b-3,0];break;case 4===b:g=[3,b-4,0];break;case 6>=b:g=[4,b-5,1];break;case 8>=b:g=[5,b-7,1];break;case 12>=b:g=[6,b-9,2];break;case 16>=b:g=[7,b-13,2];break;case 24>=b:g=[8,b-17,3];break;case 32>=b:g=[9,b-25,3];break;case 48>=b:g=[10,b-33,4];break;case 64>=b:g=[11,b-49,4];break;case 96>=b:g=[12,b-
65,5];break;case 128>=b:g=[13,b-97,5];break;case 192>=b:g=[14,b-129,6];break;case 256>=b:g=[15,b-193,6];break;case 384>=b:g=[16,b-257,7];break;case 512>=b:g=[17,b-385,7];break;case 768>=b:g=[18,b-513,8];break;case 1024>=b:g=[19,b-769,8];break;case 1536>=b:g=[20,b-1025,9];break;case 2048>=b:g=[21,b-1537,9];break;case 3072>=b:g=[22,b-2049,10];break;case 4096>=b:g=[23,b-3073,10];break;case 6144>=b:g=[24,b-4097,11];break;case 8192>=b:g=[25,b-6145,11];break;case 12288>=b:g=[26,b-8193,12];break;case 16384>=
b:g=[27,b-12289,12];break;case 24576>=b:g=[28,b-16385,13];break;case 32768>=b:g=[29,b-24577,13];break;default:throw"invalid distance";}e=g;d[f++]=e[0];d[f++]=e[1];d[f++]=e[2];var k,m;k=0;for(m=d.length;k<m;++k)l[h++]=d[k];t[d[0]]++;w[d[3]]++;q=a.length+c-1;x=null}var f,a,b,k,m,g={},p,v,x,l=C?new Uint16Array(2*d.length):[],h=0,q=0,t=new (C?Uint32Array:Array)(286),w=new (C?Uint32Array:Array)(30),da=e.f,z;if(!C){for(b=0;285>=b;)t[b++]=0;for(b=0;29>=b;)w[b++]=0}t[256]=1;f=0;for(a=d.length;f<a;++f){b=
m=0;for(k=3;b<k&&f+b!==a;++b)m=m<<8|d[f+b];g[m]===n&&(g[m]=[]);p=g[m];if(!(0<q--)){for(;0<p.length&&32768<f-p[0];)p.shift();if(f+3>=a){x&&c(x,-1);b=0;for(k=a-f;b<k;++b)z=d[f+b],l[h++]=z,++t[z];break}0<p.length?(v=Ha(d,f,p),x?x.length<v.length?(z=d[f-1],l[h++]=z,++t[z],c(v,0)):c(x,-1):v.length<da?x=v:c(v,0)):x?c(x,-1):(z=d[f],l[h++]=z,++t[z])}p.push(f)}l[h++]=256;t[256]++;e.j=t;e.i=w;return C?l.subarray(0,h):l}
function Ha(e,d,c){var f,a,b=0,k,m,g,p,v=e.length;m=0;p=c.length;a:for(;m<p;m++){f=c[p-m-1];k=3;if(3<b){for(g=b;3<g;g--)if(e[f+g-1]!==e[d+g-1])continue a;k=b}for(;258>k&&d+k<v&&e[f+k]===e[d+k];)++k;k>b&&(a=f,b=k);if(258===k)break}return new qa(b,d-a)}
function oa(e,d){var c=e.length,f=new ja(572),a=new (C?Uint8Array:Array)(c),b,k,m,g,p;if(!C)for(g=0;g<c;g++)a[g]=0;for(g=0;g<c;++g)0<e[g]&&f.push(g,e[g]);b=Array(f.length/2);k=new (C?Uint32Array:Array)(f.length/2);if(1===b.length)return a[f.pop().index]=1,a;g=0;for(p=f.length/2;g<p;++g)b[g]=f.pop(),k[g]=b[g].value;m=Ja(k,k.length,d);g=0;for(p=b.length;g<p;++g)a[b[g].index]=m[g];return a}
function Ja(e,d,c){function f(a){var b=g[a][p[a]];b===d?(f(a+1),f(a+1)):--k[b];++p[a]}var a=new (C?Uint16Array:Array)(c),b=new (C?Uint8Array:Array)(c),k=new (C?Uint8Array:Array)(d),m=Array(c),g=Array(c),p=Array(c),v=(1<<c)-d,x=1<<c-1,l,h,q,t,w;a[c-1]=d;for(h=0;h<c;++h)v<x?b[h]=0:(b[h]=1,v-=x),v<<=1,a[c-2-h]=(a[c-1-h]/2|0)+d;a[0]=b[0];m[0]=Array(a[0]);g[0]=Array(a[0]);for(h=1;h<c;++h)a[h]>2*a[h-1]+b[h]&&(a[h]=2*a[h-1]+b[h]),m[h]=Array(a[h]),g[h]=Array(a[h]);for(l=0;l<d;++l)k[l]=c;for(q=0;q<a[c-1];++q)m[c-
1][q]=e[q],g[c-1][q]=q;for(l=0;l<c;++l)p[l]=0;1===b[c-1]&&(--k[0],++p[c-1]);for(h=c-2;0<=h;--h){t=l=0;w=p[h+1];for(q=0;q<a[h];q++)t=m[h+1][w]+m[h+1][w+1],t>e[l]?(m[h][q]=t,g[h][q]=d,w+=2):(m[h][q]=e[l],g[h][q]=l,++l);p[h]=0;1===b[h]&&f(h)}return k}
function pa(e){var d=new (C?Uint16Array:Array)(e.length),c=[],f=[],a=0,b,k,m,g;b=0;for(k=e.length;b<k;b++)c[e[b]]=(c[e[b]]|0)+1;b=1;for(k=16;b<=k;b++)f[b]=a,a+=c[b]|0,a<<=1;b=0;for(k=e.length;b<k;b++){a=f[e[b]];f[e[b]]+=1;m=d[b]=0;for(g=e[b];m<g;m++)d[b]=d[b]<<1|a&1,a>>>=1}return d};ba("Zlib.RawDeflate",ka);ba("Zlib.RawDeflate.prototype.compress",ka.prototype.h);var Ka={NONE:0,FIXED:1,DYNAMIC:ma},V,La,$,Ma;if(Object.keys)V=Object.keys(Ka);else for(La in V=[],$=0,Ka)V[$++]=La;$=0;for(Ma=V.length;$<Ma;++$)La=V[$],ba("Zlib.RawDeflate.CompressionType."+La,Ka[La]);}).call(this); 

},{}],7:[function(_dereq_,module,exports){
/** @license zlib.js 2012 - imaya [ https://github.com/imaya/zlib.js ] The MIT License */(function() {'use strict';var l=this;function p(b,e){var a=b.split("."),c=l;!(a[0]in c)&&c.execScript&&c.execScript("var "+a[0]);for(var d;a.length&&(d=a.shift());)!a.length&&void 0!==e?c[d]=e:c=c[d]?c[d]:c[d]={}};var q="undefined"!==typeof Uint8Array&&"undefined"!==typeof Uint16Array&&"undefined"!==typeof Uint32Array&&"undefined"!==typeof DataView;function t(b){var e=b.length,a=0,c=Number.POSITIVE_INFINITY,d,f,g,h,k,m,r,n,s,J;for(n=0;n<e;++n)b[n]>a&&(a=b[n]),b[n]<c&&(c=b[n]);d=1<<a;f=new (q?Uint32Array:Array)(d);g=1;h=0;for(k=2;g<=a;){for(n=0;n<e;++n)if(b[n]===g){m=0;r=h;for(s=0;s<g;++s)m=m<<1|r&1,r>>=1;J=g<<16|n;for(s=m;s<d;s+=k)f[s]=J;++h}++g;h<<=1;k<<=1}return[f,a,c]};function u(b,e){this.g=[];this.h=32768;this.c=this.f=this.d=this.k=0;this.input=q?new Uint8Array(b):b;this.l=!1;this.i=v;this.q=!1;if(e||!(e={}))e.index&&(this.d=e.index),e.bufferSize&&(this.h=e.bufferSize),e.bufferType&&(this.i=e.bufferType),e.resize&&(this.q=e.resize);switch(this.i){case w:this.a=32768;this.b=new (q?Uint8Array:Array)(32768+this.h+258);break;case v:this.a=0;this.b=new (q?Uint8Array:Array)(this.h);this.e=this.v;this.m=this.s;this.j=this.t;break;default:throw Error("invalid inflate mode");
}}var w=0,v=1;
u.prototype.u=function(){for(;!this.l;){var b=x(this,3);b&1&&(this.l=!0);b>>>=1;switch(b){case 0:var e=this.input,a=this.d,c=this.b,d=this.a,f=e.length,g=void 0,h=void 0,k=c.length,m=void 0;this.c=this.f=0;if(a+1>=f)throw Error("invalid uncompressed block header: LEN");g=e[a++]|e[a++]<<8;if(a+1>=f)throw Error("invalid uncompressed block header: NLEN");h=e[a++]|e[a++]<<8;if(g===~h)throw Error("invalid uncompressed block header: length verify");if(a+g>e.length)throw Error("input buffer is broken");switch(this.i){case w:for(;d+
g>c.length;){m=k-d;g-=m;if(q)c.set(e.subarray(a,a+m),d),d+=m,a+=m;else for(;m--;)c[d++]=e[a++];this.a=d;c=this.e();d=this.a}break;case v:for(;d+g>c.length;)c=this.e({o:2});break;default:throw Error("invalid inflate mode");}if(q)c.set(e.subarray(a,a+g),d),d+=g,a+=g;else for(;g--;)c[d++]=e[a++];this.d=a;this.a=d;this.b=c;break;case 1:this.j(y,z);break;case 2:A(this);break;default:throw Error("unknown BTYPE: "+b);}}return this.m()};
var B=[16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15],C=q?new Uint16Array(B):B,D=[3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258,258,258],E=q?new Uint16Array(D):D,F=[0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0,0,0],G=q?new Uint8Array(F):F,H=[1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577],I=q?new Uint16Array(H):H,K=[0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,
13],L=q?new Uint8Array(K):K,M=new (q?Uint8Array:Array)(288),N,O;N=0;for(O=M.length;N<O;++N)M[N]=143>=N?8:255>=N?9:279>=N?7:8;var y=t(M),P=new (q?Uint8Array:Array)(30),Q,R;Q=0;for(R=P.length;Q<R;++Q)P[Q]=5;var z=t(P);function x(b,e){for(var a=b.f,c=b.c,d=b.input,f=b.d,g=d.length,h;c<e;){if(f>=g)throw Error("input buffer is broken");a|=d[f++]<<c;c+=8}h=a&(1<<e)-1;b.f=a>>>e;b.c=c-e;b.d=f;return h}
function S(b,e){for(var a=b.f,c=b.c,d=b.input,f=b.d,g=d.length,h=e[0],k=e[1],m,r;c<k&&!(f>=g);)a|=d[f++]<<c,c+=8;m=h[a&(1<<k)-1];r=m>>>16;b.f=a>>r;b.c=c-r;b.d=f;return m&65535}
function A(b){function e(a,b,c){var e,d=this.p,f,g;for(g=0;g<a;)switch(e=S(this,b),e){case 16:for(f=3+x(this,2);f--;)c[g++]=d;break;case 17:for(f=3+x(this,3);f--;)c[g++]=0;d=0;break;case 18:for(f=11+x(this,7);f--;)c[g++]=0;d=0;break;default:d=c[g++]=e}this.p=d;return c}var a=x(b,5)+257,c=x(b,5)+1,d=x(b,4)+4,f=new (q?Uint8Array:Array)(C.length),g,h,k,m;for(m=0;m<d;++m)f[C[m]]=x(b,3);if(!q){m=d;for(d=f.length;m<d;++m)f[C[m]]=0}g=t(f);h=new (q?Uint8Array:Array)(a);k=new (q?Uint8Array:Array)(c);b.p=0;
b.j(t(e.call(b,a,g,h)),t(e.call(b,c,g,k)))}u.prototype.j=function(b,e){var a=this.b,c=this.a;this.n=b;for(var d=a.length-258,f,g,h,k;256!==(f=S(this,b));)if(256>f)c>=d&&(this.a=c,a=this.e(),c=this.a),a[c++]=f;else{g=f-257;k=E[g];0<G[g]&&(k+=x(this,G[g]));f=S(this,e);h=I[f];0<L[f]&&(h+=x(this,L[f]));c>=d&&(this.a=c,a=this.e(),c=this.a);for(;k--;)a[c]=a[c++-h]}for(;8<=this.c;)this.c-=8,this.d--;this.a=c};
u.prototype.t=function(b,e){var a=this.b,c=this.a;this.n=b;for(var d=a.length,f,g,h,k;256!==(f=S(this,b));)if(256>f)c>=d&&(a=this.e(),d=a.length),a[c++]=f;else{g=f-257;k=E[g];0<G[g]&&(k+=x(this,G[g]));f=S(this,e);h=I[f];0<L[f]&&(h+=x(this,L[f]));c+k>d&&(a=this.e(),d=a.length);for(;k--;)a[c]=a[c++-h]}for(;8<=this.c;)this.c-=8,this.d--;this.a=c};
u.prototype.e=function(){var b=new (q?Uint8Array:Array)(this.a-32768),e=this.a-32768,a,c,d=this.b;if(q)b.set(d.subarray(32768,b.length));else{a=0;for(c=b.length;a<c;++a)b[a]=d[a+32768]}this.g.push(b);this.k+=b.length;if(q)d.set(d.subarray(e,e+32768));else for(a=0;32768>a;++a)d[a]=d[e+a];this.a=32768;return d};
u.prototype.v=function(b){var e,a=this.input.length/this.d+1|0,c,d,f,g=this.input,h=this.b;b&&("number"===typeof b.o&&(a=b.o),"number"===typeof b.r&&(a+=b.r));2>a?(c=(g.length-this.d)/this.n[2],f=258*(c/2)|0,d=f<h.length?h.length+f:h.length<<1):d=h.length*a;q?(e=new Uint8Array(d),e.set(h)):e=h;return this.b=e};
u.prototype.m=function(){var b=0,e=this.b,a=this.g,c,d=new (q?Uint8Array:Array)(this.k+(this.a-32768)),f,g,h,k;if(0===a.length)return q?this.b.subarray(32768,this.a):this.b.slice(32768,this.a);f=0;for(g=a.length;f<g;++f){c=a[f];h=0;for(k=c.length;h<k;++h)d[b++]=c[h]}f=32768;for(g=this.a;f<g;++f)d[b++]=e[f];this.g=[];return this.buffer=d};
u.prototype.s=function(){var b,e=this.a;q?this.q?(b=new Uint8Array(e),b.set(this.b.subarray(0,e))):b=this.b.subarray(0,e):(this.b.length>e&&(this.b.length=e),b=this.b);return this.buffer=b};p("Zlib.RawInflate",u);p("Zlib.RawInflate.prototype.decompress",u.prototype.u);var T={ADAPTIVE:v,BLOCK:w},U,V,W,X;if(Object.keys)U=Object.keys(T);else for(V in U=[],W=0,T)U[W++]=V;W=0;for(X=U.length;W<X;++W)V=U[W],p("Zlib.RawInflate.BufferType."+V,T[V]);}).call(this); 

},{}],8:[function(_dereq_,module,exports){
/** @license zlib.js 2012 - imaya [ https://github.com/imaya/zlib.js ] The MIT License */(function() {'use strict';function l(d){throw d;}var v=void 0,x=!0,aa=this;function D(d,a){var c=d.split("."),e=aa;!(c[0]in e)&&e.execScript&&e.execScript("var "+c[0]);for(var b;c.length&&(b=c.shift());)!c.length&&a!==v?e[b]=a:e=e[b]?e[b]:e[b]={}};var F="undefined"!==typeof Uint8Array&&"undefined"!==typeof Uint16Array&&"undefined"!==typeof Uint32Array&&"undefined"!==typeof DataView;function H(d,a){this.index="number"===typeof a?a:0;this.i=0;this.buffer=d instanceof(F?Uint8Array:Array)?d:new (F?Uint8Array:Array)(32768);2*this.buffer.length<=this.index&&l(Error("invalid index"));this.buffer.length<=this.index&&this.f()}H.prototype.f=function(){var d=this.buffer,a,c=d.length,e=new (F?Uint8Array:Array)(c<<1);if(F)e.set(d);else for(a=0;a<c;++a)e[a]=d[a];return this.buffer=e};
H.prototype.d=function(d,a,c){var e=this.buffer,b=this.index,f=this.i,g=e[b],h;c&&1<a&&(d=8<a?(N[d&255]<<24|N[d>>>8&255]<<16|N[d>>>16&255]<<8|N[d>>>24&255])>>32-a:N[d]>>8-a);if(8>a+f)g=g<<a|d,f+=a;else for(h=0;h<a;++h)g=g<<1|d>>a-h-1&1,8===++f&&(f=0,e[b++]=N[g],g=0,b===e.length&&(e=this.f()));e[b]=g;this.buffer=e;this.i=f;this.index=b};H.prototype.finish=function(){var d=this.buffer,a=this.index,c;0<this.i&&(d[a]<<=8-this.i,d[a]=N[d[a]],a++);F?c=d.subarray(0,a):(d.length=a,c=d);return c};
var fa=new (F?Uint8Array:Array)(256),O;for(O=0;256>O;++O){for(var P=O,Q=P,ga=7,P=P>>>1;P;P>>>=1)Q<<=1,Q|=P&1,--ga;fa[O]=(Q<<ga&255)>>>0}var N=fa;function ha(d){this.buffer=new (F?Uint16Array:Array)(2*d);this.length=0}ha.prototype.getParent=function(d){return 2*((d-2)/4|0)};ha.prototype.push=function(d,a){var c,e,b=this.buffer,f;c=this.length;b[this.length++]=a;for(b[this.length++]=d;0<c;)if(e=this.getParent(c),b[c]>b[e])f=b[c],b[c]=b[e],b[e]=f,f=b[c+1],b[c+1]=b[e+1],b[e+1]=f,c=e;else break;return this.length};
ha.prototype.pop=function(){var d,a,c=this.buffer,e,b,f;a=c[0];d=c[1];this.length-=2;c[0]=c[this.length];c[1]=c[this.length+1];for(f=0;;){b=2*f+2;if(b>=this.length)break;b+2<this.length&&c[b+2]>c[b]&&(b+=2);if(c[b]>c[f])e=c[f],c[f]=c[b],c[b]=e,e=c[f+1],c[f+1]=c[b+1],c[b+1]=e;else break;f=b}return{index:d,value:a,length:this.length}};function R(d){var a=d.length,c=0,e=Number.POSITIVE_INFINITY,b,f,g,h,k,n,q,r,p,m;for(r=0;r<a;++r)d[r]>c&&(c=d[r]),d[r]<e&&(e=d[r]);b=1<<c;f=new (F?Uint32Array:Array)(b);g=1;h=0;for(k=2;g<=c;){for(r=0;r<a;++r)if(d[r]===g){n=0;q=h;for(p=0;p<g;++p)n=n<<1|q&1,q>>=1;m=g<<16|r;for(p=n;p<b;p+=k)f[p]=m;++h}++g;h<<=1;k<<=1}return[f,c,e]};function ia(d,a){this.h=ma;this.w=0;this.input=F&&d instanceof Array?new Uint8Array(d):d;this.b=0;a&&(a.lazy&&(this.w=a.lazy),"number"===typeof a.compressionType&&(this.h=a.compressionType),a.outputBuffer&&(this.a=F&&a.outputBuffer instanceof Array?new Uint8Array(a.outputBuffer):a.outputBuffer),"number"===typeof a.outputIndex&&(this.b=a.outputIndex));this.a||(this.a=new (F?Uint8Array:Array)(32768))}var ma=2,na={NONE:0,r:1,k:ma,O:3},oa=[],S;
for(S=0;288>S;S++)switch(x){case 143>=S:oa.push([S+48,8]);break;case 255>=S:oa.push([S-144+400,9]);break;case 279>=S:oa.push([S-256+0,7]);break;case 287>=S:oa.push([S-280+192,8]);break;default:l("invalid literal: "+S)}
ia.prototype.j=function(){var d,a,c,e,b=this.input;switch(this.h){case 0:c=0;for(e=b.length;c<e;){a=F?b.subarray(c,c+65535):b.slice(c,c+65535);c+=a.length;var f=a,g=c===e,h=v,k=v,n=v,q=v,r=v,p=this.a,m=this.b;if(F){for(p=new Uint8Array(this.a.buffer);p.length<=m+f.length+5;)p=new Uint8Array(p.length<<1);p.set(this.a)}h=g?1:0;p[m++]=h|0;k=f.length;n=~k+65536&65535;p[m++]=k&255;p[m++]=k>>>8&255;p[m++]=n&255;p[m++]=n>>>8&255;if(F)p.set(f,m),m+=f.length,p=p.subarray(0,m);else{q=0;for(r=f.length;q<r;++q)p[m++]=
f[q];p.length=m}this.b=m;this.a=p}break;case 1:var s=new H(F?new Uint8Array(this.a.buffer):this.a,this.b);s.d(1,1,x);s.d(1,2,x);var w=pa(this,b),y,ja,A;y=0;for(ja=w.length;y<ja;y++)if(A=w[y],H.prototype.d.apply(s,oa[A]),256<A)s.d(w[++y],w[++y],x),s.d(w[++y],5),s.d(w[++y],w[++y],x);else if(256===A)break;this.a=s.finish();this.b=this.a.length;break;case ma:var C=new H(F?new Uint8Array(this.a.buffer):this.a,this.b),Ea,M,U,V,W,gb=[16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15],ba,Fa,ca,Ga,ka,ra=Array(19),
Ha,X,la,z,Ia;Ea=ma;C.d(1,1,x);C.d(Ea,2,x);M=pa(this,b);ba=qa(this.M,15);Fa=sa(ba);ca=qa(this.L,7);Ga=sa(ca);for(U=286;257<U&&0===ba[U-1];U--);for(V=30;1<V&&0===ca[V-1];V--);var Ja=U,Ka=V,I=new (F?Uint32Array:Array)(Ja+Ka),t,J,u,da,G=new (F?Uint32Array:Array)(316),E,B,K=new (F?Uint8Array:Array)(19);for(t=J=0;t<Ja;t++)I[J++]=ba[t];for(t=0;t<Ka;t++)I[J++]=ca[t];if(!F){t=0;for(da=K.length;t<da;++t)K[t]=0}t=E=0;for(da=I.length;t<da;t+=J){for(J=1;t+J<da&&I[t+J]===I[t];++J);u=J;if(0===I[t])if(3>u)for(;0<
u--;)G[E++]=0,K[0]++;else for(;0<u;)B=138>u?u:138,B>u-3&&B<u&&(B=u-3),10>=B?(G[E++]=17,G[E++]=B-3,K[17]++):(G[E++]=18,G[E++]=B-11,K[18]++),u-=B;else if(G[E++]=I[t],K[I[t]]++,u--,3>u)for(;0<u--;)G[E++]=I[t],K[I[t]]++;else for(;0<u;)B=6>u?u:6,B>u-3&&B<u&&(B=u-3),G[E++]=16,G[E++]=B-3,K[16]++,u-=B}d=F?G.subarray(0,E):G.slice(0,E);ka=qa(K,7);for(z=0;19>z;z++)ra[z]=ka[gb[z]];for(W=19;4<W&&0===ra[W-1];W--);Ha=sa(ka);C.d(U-257,5,x);C.d(V-1,5,x);C.d(W-4,4,x);for(z=0;z<W;z++)C.d(ra[z],3,x);z=0;for(Ia=d.length;z<
Ia;z++)if(X=d[z],C.d(Ha[X],ka[X],x),16<=X){z++;switch(X){case 16:la=2;break;case 17:la=3;break;case 18:la=7;break;default:l("invalid code: "+X)}C.d(d[z],la,x)}var La=[Fa,ba],Ma=[Ga,ca],L,Na,ea,ua,Oa,Pa,Qa,Ra;Oa=La[0];Pa=La[1];Qa=Ma[0];Ra=Ma[1];L=0;for(Na=M.length;L<Na;++L)if(ea=M[L],C.d(Oa[ea],Pa[ea],x),256<ea)C.d(M[++L],M[++L],x),ua=M[++L],C.d(Qa[ua],Ra[ua],x),C.d(M[++L],M[++L],x);else if(256===ea)break;this.a=C.finish();this.b=this.a.length;break;default:l("invalid compression type")}return this.a};
function ta(d,a){this.length=d;this.H=a}
var va=function(){function d(b){switch(x){case 3===b:return[257,b-3,0];case 4===b:return[258,b-4,0];case 5===b:return[259,b-5,0];case 6===b:return[260,b-6,0];case 7===b:return[261,b-7,0];case 8===b:return[262,b-8,0];case 9===b:return[263,b-9,0];case 10===b:return[264,b-10,0];case 12>=b:return[265,b-11,1];case 14>=b:return[266,b-13,1];case 16>=b:return[267,b-15,1];case 18>=b:return[268,b-17,1];case 22>=b:return[269,b-19,2];case 26>=b:return[270,b-23,2];case 30>=b:return[271,b-27,2];case 34>=b:return[272,
b-31,2];case 42>=b:return[273,b-35,3];case 50>=b:return[274,b-43,3];case 58>=b:return[275,b-51,3];case 66>=b:return[276,b-59,3];case 82>=b:return[277,b-67,4];case 98>=b:return[278,b-83,4];case 114>=b:return[279,b-99,4];case 130>=b:return[280,b-115,4];case 162>=b:return[281,b-131,5];case 194>=b:return[282,b-163,5];case 226>=b:return[283,b-195,5];case 257>=b:return[284,b-227,5];case 258===b:return[285,b-258,0];default:l("invalid length: "+b)}}var a=[],c,e;for(c=3;258>=c;c++)e=d(c),a[c]=e[2]<<24|e[1]<<
16|e[0];return a}(),wa=F?new Uint32Array(va):va;
function pa(d,a){function c(b,c){var a=b.H,d=[],e=0,f;f=wa[b.length];d[e++]=f&65535;d[e++]=f>>16&255;d[e++]=f>>24;var g;switch(x){case 1===a:g=[0,a-1,0];break;case 2===a:g=[1,a-2,0];break;case 3===a:g=[2,a-3,0];break;case 4===a:g=[3,a-4,0];break;case 6>=a:g=[4,a-5,1];break;case 8>=a:g=[5,a-7,1];break;case 12>=a:g=[6,a-9,2];break;case 16>=a:g=[7,a-13,2];break;case 24>=a:g=[8,a-17,3];break;case 32>=a:g=[9,a-25,3];break;case 48>=a:g=[10,a-33,4];break;case 64>=a:g=[11,a-49,4];break;case 96>=a:g=[12,a-
65,5];break;case 128>=a:g=[13,a-97,5];break;case 192>=a:g=[14,a-129,6];break;case 256>=a:g=[15,a-193,6];break;case 384>=a:g=[16,a-257,7];break;case 512>=a:g=[17,a-385,7];break;case 768>=a:g=[18,a-513,8];break;case 1024>=a:g=[19,a-769,8];break;case 1536>=a:g=[20,a-1025,9];break;case 2048>=a:g=[21,a-1537,9];break;case 3072>=a:g=[22,a-2049,10];break;case 4096>=a:g=[23,a-3073,10];break;case 6144>=a:g=[24,a-4097,11];break;case 8192>=a:g=[25,a-6145,11];break;case 12288>=a:g=[26,a-8193,12];break;case 16384>=
a:g=[27,a-12289,12];break;case 24576>=a:g=[28,a-16385,13];break;case 32768>=a:g=[29,a-24577,13];break;default:l("invalid distance")}f=g;d[e++]=f[0];d[e++]=f[1];d[e++]=f[2];var h,k;h=0;for(k=d.length;h<k;++h)p[m++]=d[h];w[d[0]]++;y[d[3]]++;s=b.length+c-1;r=null}var e,b,f,g,h,k={},n,q,r,p=F?new Uint16Array(2*a.length):[],m=0,s=0,w=new (F?Uint32Array:Array)(286),y=new (F?Uint32Array:Array)(30),ja=d.w,A;if(!F){for(f=0;285>=f;)w[f++]=0;for(f=0;29>=f;)y[f++]=0}w[256]=1;e=0;for(b=a.length;e<b;++e){f=h=0;
for(g=3;f<g&&e+f!==b;++f)h=h<<8|a[e+f];k[h]===v&&(k[h]=[]);n=k[h];if(!(0<s--)){for(;0<n.length&&32768<e-n[0];)n.shift();if(e+3>=b){r&&c(r,-1);f=0;for(g=b-e;f<g;++f)A=a[e+f],p[m++]=A,++w[A];break}0<n.length?(q=xa(a,e,n),r?r.length<q.length?(A=a[e-1],p[m++]=A,++w[A],c(q,0)):c(r,-1):q.length<ja?r=q:c(q,0)):r?c(r,-1):(A=a[e],p[m++]=A,++w[A])}n.push(e)}p[m++]=256;w[256]++;d.M=w;d.L=y;return F?p.subarray(0,m):p}
function xa(d,a,c){var e,b,f=0,g,h,k,n,q=d.length;h=0;n=c.length;a:for(;h<n;h++){e=c[n-h-1];g=3;if(3<f){for(k=f;3<k;k--)if(d[e+k-1]!==d[a+k-1])continue a;g=f}for(;258>g&&a+g<q&&d[e+g]===d[a+g];)++g;g>f&&(b=e,f=g);if(258===g)break}return new ta(f,a-b)}
function qa(d,a){var c=d.length,e=new ha(572),b=new (F?Uint8Array:Array)(c),f,g,h,k,n;if(!F)for(k=0;k<c;k++)b[k]=0;for(k=0;k<c;++k)0<d[k]&&e.push(k,d[k]);f=Array(e.length/2);g=new (F?Uint32Array:Array)(e.length/2);if(1===f.length)return b[e.pop().index]=1,b;k=0;for(n=e.length/2;k<n;++k)f[k]=e.pop(),g[k]=f[k].value;h=ya(g,g.length,a);k=0;for(n=f.length;k<n;++k)b[f[k].index]=h[k];return b}
function ya(d,a,c){function e(b){var c=k[b][n[b]];c===a?(e(b+1),e(b+1)):--g[c];++n[b]}var b=new (F?Uint16Array:Array)(c),f=new (F?Uint8Array:Array)(c),g=new (F?Uint8Array:Array)(a),h=Array(c),k=Array(c),n=Array(c),q=(1<<c)-a,r=1<<c-1,p,m,s,w,y;b[c-1]=a;for(m=0;m<c;++m)q<r?f[m]=0:(f[m]=1,q-=r),q<<=1,b[c-2-m]=(b[c-1-m]/2|0)+a;b[0]=f[0];h[0]=Array(b[0]);k[0]=Array(b[0]);for(m=1;m<c;++m)b[m]>2*b[m-1]+f[m]&&(b[m]=2*b[m-1]+f[m]),h[m]=Array(b[m]),k[m]=Array(b[m]);for(p=0;p<a;++p)g[p]=c;for(s=0;s<b[c-1];++s)h[c-
1][s]=d[s],k[c-1][s]=s;for(p=0;p<c;++p)n[p]=0;1===f[c-1]&&(--g[0],++n[c-1]);for(m=c-2;0<=m;--m){w=p=0;y=n[m+1];for(s=0;s<b[m];s++)w=h[m+1][y]+h[m+1][y+1],w>d[p]?(h[m][s]=w,k[m][s]=a,y+=2):(h[m][s]=d[p],k[m][s]=p,++p);n[m]=0;1===f[m]&&e(m)}return g}
function sa(d){var a=new (F?Uint16Array:Array)(d.length),c=[],e=[],b=0,f,g,h,k;f=0;for(g=d.length;f<g;f++)c[d[f]]=(c[d[f]]|0)+1;f=1;for(g=16;f<=g;f++)e[f]=b,b+=c[f]|0,b<<=1;f=0;for(g=d.length;f<g;f++){b=e[d[f]];e[d[f]]+=1;h=a[f]=0;for(k=d[f];h<k;h++)a[f]=a[f]<<1|b&1,b>>>=1}return a};function T(d,a){this.l=[];this.m=32768;this.e=this.g=this.c=this.q=0;this.input=F?new Uint8Array(d):d;this.s=!1;this.n=za;this.C=!1;if(a||!(a={}))a.index&&(this.c=a.index),a.bufferSize&&(this.m=a.bufferSize),a.bufferType&&(this.n=a.bufferType),a.resize&&(this.C=a.resize);switch(this.n){case Aa:this.b=32768;this.a=new (F?Uint8Array:Array)(32768+this.m+258);break;case za:this.b=0;this.a=new (F?Uint8Array:Array)(this.m);this.f=this.K;this.t=this.I;this.o=this.J;break;default:l(Error("invalid inflate mode"))}}
var Aa=0,za=1,Ba={F:Aa,D:za};
T.prototype.p=function(){for(;!this.s;){var d=Y(this,3);d&1&&(this.s=x);d>>>=1;switch(d){case 0:var a=this.input,c=this.c,e=this.a,b=this.b,f=a.length,g=v,h=v,k=e.length,n=v;this.e=this.g=0;c+1>=f&&l(Error("invalid uncompressed block header: LEN"));g=a[c++]|a[c++]<<8;c+1>=f&&l(Error("invalid uncompressed block header: NLEN"));h=a[c++]|a[c++]<<8;g===~h&&l(Error("invalid uncompressed block header: length verify"));c+g>a.length&&l(Error("input buffer is broken"));switch(this.n){case Aa:for(;b+g>e.length;){n=
k-b;g-=n;if(F)e.set(a.subarray(c,c+n),b),b+=n,c+=n;else for(;n--;)e[b++]=a[c++];this.b=b;e=this.f();b=this.b}break;case za:for(;b+g>e.length;)e=this.f({v:2});break;default:l(Error("invalid inflate mode"))}if(F)e.set(a.subarray(c,c+g),b),b+=g,c+=g;else for(;g--;)e[b++]=a[c++];this.c=c;this.b=b;this.a=e;break;case 1:this.o(Ca,Da);break;case 2:Sa(this);break;default:l(Error("unknown BTYPE: "+d))}}return this.t()};
var Ta=[16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15],Ua=F?new Uint16Array(Ta):Ta,Va=[3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258,258,258],Wa=F?new Uint16Array(Va):Va,Xa=[0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0,0,0],Ya=F?new Uint8Array(Xa):Xa,Za=[1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577],$a=F?new Uint16Array(Za):Za,ab=[0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,
10,11,11,12,12,13,13],bb=F?new Uint8Array(ab):ab,cb=new (F?Uint8Array:Array)(288),Z,db;Z=0;for(db=cb.length;Z<db;++Z)cb[Z]=143>=Z?8:255>=Z?9:279>=Z?7:8;var Ca=R(cb),eb=new (F?Uint8Array:Array)(30),fb,hb;fb=0;for(hb=eb.length;fb<hb;++fb)eb[fb]=5;var Da=R(eb);function Y(d,a){for(var c=d.g,e=d.e,b=d.input,f=d.c,g=b.length,h;e<a;)f>=g&&l(Error("input buffer is broken")),c|=b[f++]<<e,e+=8;h=c&(1<<a)-1;d.g=c>>>a;d.e=e-a;d.c=f;return h}
function ib(d,a){for(var c=d.g,e=d.e,b=d.input,f=d.c,g=b.length,h=a[0],k=a[1],n,q;e<k&&!(f>=g);)c|=b[f++]<<e,e+=8;n=h[c&(1<<k)-1];q=n>>>16;d.g=c>>q;d.e=e-q;d.c=f;return n&65535}
function Sa(d){function a(a,b,c){var d,e=this.z,f,g;for(g=0;g<a;)switch(d=ib(this,b),d){case 16:for(f=3+Y(this,2);f--;)c[g++]=e;break;case 17:for(f=3+Y(this,3);f--;)c[g++]=0;e=0;break;case 18:for(f=11+Y(this,7);f--;)c[g++]=0;e=0;break;default:e=c[g++]=d}this.z=e;return c}var c=Y(d,5)+257,e=Y(d,5)+1,b=Y(d,4)+4,f=new (F?Uint8Array:Array)(Ua.length),g,h,k,n;for(n=0;n<b;++n)f[Ua[n]]=Y(d,3);if(!F){n=b;for(b=f.length;n<b;++n)f[Ua[n]]=0}g=R(f);h=new (F?Uint8Array:Array)(c);k=new (F?Uint8Array:Array)(e);
d.z=0;d.o(R(a.call(d,c,g,h)),R(a.call(d,e,g,k)))}T.prototype.o=function(d,a){var c=this.a,e=this.b;this.u=d;for(var b=c.length-258,f,g,h,k;256!==(f=ib(this,d));)if(256>f)e>=b&&(this.b=e,c=this.f(),e=this.b),c[e++]=f;else{g=f-257;k=Wa[g];0<Ya[g]&&(k+=Y(this,Ya[g]));f=ib(this,a);h=$a[f];0<bb[f]&&(h+=Y(this,bb[f]));e>=b&&(this.b=e,c=this.f(),e=this.b);for(;k--;)c[e]=c[e++-h]}for(;8<=this.e;)this.e-=8,this.c--;this.b=e};
T.prototype.J=function(d,a){var c=this.a,e=this.b;this.u=d;for(var b=c.length,f,g,h,k;256!==(f=ib(this,d));)if(256>f)e>=b&&(c=this.f(),b=c.length),c[e++]=f;else{g=f-257;k=Wa[g];0<Ya[g]&&(k+=Y(this,Ya[g]));f=ib(this,a);h=$a[f];0<bb[f]&&(h+=Y(this,bb[f]));e+k>b&&(c=this.f(),b=c.length);for(;k--;)c[e]=c[e++-h]}for(;8<=this.e;)this.e-=8,this.c--;this.b=e};
T.prototype.f=function(){var d=new (F?Uint8Array:Array)(this.b-32768),a=this.b-32768,c,e,b=this.a;if(F)d.set(b.subarray(32768,d.length));else{c=0;for(e=d.length;c<e;++c)d[c]=b[c+32768]}this.l.push(d);this.q+=d.length;if(F)b.set(b.subarray(a,a+32768));else for(c=0;32768>c;++c)b[c]=b[a+c];this.b=32768;return b};
T.prototype.K=function(d){var a,c=this.input.length/this.c+1|0,e,b,f,g=this.input,h=this.a;d&&("number"===typeof d.v&&(c=d.v),"number"===typeof d.G&&(c+=d.G));2>c?(e=(g.length-this.c)/this.u[2],f=258*(e/2)|0,b=f<h.length?h.length+f:h.length<<1):b=h.length*c;F?(a=new Uint8Array(b),a.set(h)):a=h;return this.a=a};
T.prototype.t=function(){var d=0,a=this.a,c=this.l,e,b=new (F?Uint8Array:Array)(this.q+(this.b-32768)),f,g,h,k;if(0===c.length)return F?this.a.subarray(32768,this.b):this.a.slice(32768,this.b);f=0;for(g=c.length;f<g;++f){e=c[f];h=0;for(k=e.length;h<k;++h)b[d++]=e[h]}f=32768;for(g=this.b;f<g;++f)b[d++]=a[f];this.l=[];return this.buffer=b};
T.prototype.I=function(){var d,a=this.b;F?this.C?(d=new Uint8Array(a),d.set(this.a.subarray(0,a))):d=this.a.subarray(0,a):(this.a.length>a&&(this.a.length=a),d=this.a);return this.buffer=d};function jb(d){if("string"===typeof d){var a=d.split(""),c,e;c=0;for(e=a.length;c<e;c++)a[c]=(a[c].charCodeAt(0)&255)>>>0;d=a}for(var b=1,f=0,g=d.length,h,k=0;0<g;){h=1024<g?1024:g;g-=h;do b+=d[k++],f+=b;while(--h);b%=65521;f%=65521}return(f<<16|b)>>>0};function kb(d,a){var c,e;this.input=d;this.c=0;if(a||!(a={}))a.index&&(this.c=a.index),a.verify&&(this.N=a.verify);c=d[this.c++];e=d[this.c++];switch(c&15){case lb:this.method=lb;break;default:l(Error("unsupported compression method"))}0!==((c<<8)+e)%31&&l(Error("invalid fcheck flag:"+((c<<8)+e)%31));e&32&&l(Error("fdict flag is not supported"));this.B=new T(d,{index:this.c,bufferSize:a.bufferSize,bufferType:a.bufferType,resize:a.resize})}
kb.prototype.p=function(){var d=this.input,a,c;a=this.B.p();this.c=this.B.c;this.N&&(c=(d[this.c++]<<24|d[this.c++]<<16|d[this.c++]<<8|d[this.c++])>>>0,c!==jb(a)&&l(Error("invalid adler-32 checksum")));return a};var lb=8;function mb(d,a){this.input=d;this.a=new (F?Uint8Array:Array)(32768);this.h=$.k;var c={},e;if((a||!(a={}))&&"number"===typeof a.compressionType)this.h=a.compressionType;for(e in a)c[e]=a[e];c.outputBuffer=this.a;this.A=new ia(this.input,c)}var $=na;
mb.prototype.j=function(){var d,a,c,e,b,f,g,h=0;g=this.a;d=lb;switch(d){case lb:a=Math.LOG2E*Math.log(32768)-8;break;default:l(Error("invalid compression method"))}c=a<<4|d;g[h++]=c;switch(d){case lb:switch(this.h){case $.NONE:b=0;break;case $.r:b=1;break;case $.k:b=2;break;default:l(Error("unsupported compression type"))}break;default:l(Error("invalid compression method"))}e=b<<6|0;g[h++]=e|31-(256*c+e)%31;f=jb(this.input);this.A.b=h;g=this.A.j();h=g.length;F&&(g=new Uint8Array(g.buffer),g.length<=
h+4&&(this.a=new Uint8Array(g.length+4),this.a.set(g),g=this.a),g=g.subarray(0,h+4));g[h++]=f>>24&255;g[h++]=f>>16&255;g[h++]=f>>8&255;g[h++]=f&255;return g};function nb(d,a){var c,e,b,f;if(Object.keys)c=Object.keys(a);else for(e in c=[],b=0,a)c[b++]=e;b=0;for(f=c.length;b<f;++b)e=c[b],D(d+"."+e,a[e])};D("Zlib.Inflate",kb);D("Zlib.Inflate.prototype.decompress",kb.prototype.p);nb("Zlib.Inflate.BufferType",{ADAPTIVE:Ba.D,BLOCK:Ba.F});D("Zlib.Deflate",mb);D("Zlib.Deflate.compress",function(d,a){return(new mb(d,a)).j()});D("Zlib.Deflate.prototype.compress",mb.prototype.j);nb("Zlib.Deflate.CompressionType",{NONE:$.NONE,FIXED:$.r,DYNAMIC:$.k});}).call(this); 

},{}],9:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * This object contains configuration values.
 * @requires enums
 * @property {Integer} prefer_hash_algorithm
 * @property {Integer} encryption_cipher
 * @property {Integer} compression
 * @property {Boolean} show_version
 * @property {Boolean} show_comment
 * @property {Boolean} integrity_protect
 * @property {String} keyserver
 * @property {Boolean} debug If enabled, debug messages will be printed
 * @module config/config
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _enums = _dereq_('../enums.js');

var _enums2 = _interopRequireDefault(_enums);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = {
  prefer_hash_algorithm: _enums2.default.hash.sha256,
  encryption_cipher: _enums2.default.symmetric.aes256,
  compression: _enums2.default.compression.zip,
  aead_protect: false, // use Authenticated Encryption with Additional Data (AEAD) protection for symmetric encryption
  integrity_protect: true, // use integrity protection for symmetric encryption
  ignore_mdc_error: false, // fail on decrypt if message is not integrity protected
  checksum_required: false, // do not throw error when armor is missing a checksum
  rsa_blinding: true,
  use_native: true, // use native node.js crypto and Web Crypto apis (if available)
  zero_copy: false, // use transferable objects between the Web Worker and main thread
  debug: false,
  tolerant: true, // ignore unsupported/unrecognizable packets instead of throwing an error
  show_version: true,
  show_comment: true,
  versionstring: "OpenPGP.js v2.5.13",
  commentstring: "https://openpgpjs.org",
  keyserver: "https://keyserver.ubuntu.com",
  node_store: './openpgp.store'
};

},{"../enums.js":35}],10:[function(_dereq_,module,exports){
/**
 * @see module:config/config
 * @module config
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _config = _dereq_('./config.js');

Object.defineProperty(exports, 'default', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_config).default;
  }
});

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

},{"./config.js":9}],11:[function(_dereq_,module,exports){
// Modified by ProtonTech AG

// Modified by Recurity Labs GmbH

// modified version of http://www.hanewin.net/encrypt/PGdecode.js:

/* OpenPGP encryption using RSA/AES
 * Copyright 2005-2006 Herbert Hanewinkel, www.haneWIN.de
 * version 2.0, check www.haneWIN.de for the latest version

 * This software is provided as-is, without express or implied warranty.
 * Permission to use, copy, modify, distribute or sell this software, with or
 * without fee, for any purpose and by any individual or organization, is hereby
 * granted, provided that the above copyright notice and this paragraph appear
 * in all copies. Distribution as a part of an application or binary must
 * include the above copyright notice in the documentation and/or other
 * materials provided with the application or distribution.
 */

/**
 * @requires crypto/cipher
 * @module crypto/cfb
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _cipher = _dereq_('./cipher');

var _cipher2 = _interopRequireDefault(_cipher);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = {

  /**
   * This function encrypts a given with the specified prefixrandom
   * using the specified blockcipher to encrypt a message
   * @param {Uint8Array} prefixrandom random bytes of block_size length
   *  to be used in prefixing the data
   * @param {String} cipherfn the algorithm cipher class to encrypt
   *  data in one block_size encryption, {@link module:crypto/cipher}.
   * @param {Uint8Array} plaintext data to be encrypted
   * @param {Uint8Array} key key to be used to encrypt the plaintext.
   * This will be passed to the cipherfn
   * @param {Boolean} resync a boolean value specifying if a resync of the
   *  IV should be used or not. The encrypteddatapacket uses the
   *  "old" style with a resync. Encryption within an
   *  encryptedintegrityprotecteddata packet is not resyncing the IV.
   * @return {Uint8Array} encrypted data
   */
  encrypt: function encrypt(prefixrandom, cipherfn, plaintext, key, resync) {
    cipherfn = new _cipher2.default[cipherfn](key);
    var block_size = cipherfn.blockSize;

    var FR = new Uint8Array(block_size);
    var FRE = new Uint8Array(block_size);

    var new_prefix = new Uint8Array(prefixrandom.length + 2);
    new_prefix.set(prefixrandom);
    new_prefix[prefixrandom.length] = prefixrandom[block_size - 2];
    new_prefix[prefixrandom.length + 1] = prefixrandom[block_size - 1];
    prefixrandom = new_prefix;

    var ciphertext = new Uint8Array(plaintext.length + 2 + block_size * 2);
    var i, n, begin;
    var offset = resync ? 0 : 2;

    // 1.  The feedback register (FR) is set to the IV, which is all zeros.
    for (i = 0; i < block_size; i++) {
      FR[i] = 0;
    }

    // 2.  FR is encrypted to produce FRE (FR Encrypted).  This is the
    //     encryption of an all-zero value.
    FRE = cipherfn.encrypt(FR);
    // 3.  FRE is xored with the first BS octets of random data prefixed to
    //     the plaintext to produce C[1] through C[BS], the first BS octets
    //     of ciphertext.
    for (i = 0; i < block_size; i++) {
      ciphertext[i] = FRE[i] ^ prefixrandom[i];
    }

    // 4.  FR is loaded with C[1] through C[BS].
    FR.set(ciphertext.subarray(0, block_size));

    // 5.  FR is encrypted to produce FRE, the encryption of the first BS
    //     octets of ciphertext.
    FRE = cipherfn.encrypt(FR);

    // 6.  The left two octets of FRE get xored with the next two octets of
    //     data that were prefixed to the plaintext.  This produces C[BS+1]
    //     and C[BS+2], the next two octets of ciphertext.
    ciphertext[block_size] = FRE[0] ^ prefixrandom[block_size];
    ciphertext[block_size + 1] = FRE[1] ^ prefixrandom[block_size + 1];

    if (resync) {
      // 7.  (The resync step) FR is loaded with C[3] through C[BS+2].
      FR.set(ciphertext.subarray(2, block_size + 2));
    } else {
      FR.set(ciphertext.subarray(0, block_size));
    }
    // 8.  FR is encrypted to produce FRE.
    FRE = cipherfn.encrypt(FR);

    // 9.  FRE is xored with the first BS octets of the given plaintext, now
    //     that we have finished encrypting the BS+2 octets of prefixed
    //     data.  This produces C[BS+3] through C[BS+(BS+2)], the next BS
    //     octets of ciphertext.
    for (i = 0; i < block_size; i++) {
      ciphertext[block_size + 2 + i] = FRE[i + offset] ^ plaintext[i];
    }
    for (n = block_size; n < plaintext.length + offset; n += block_size) {
      // 10. FR is loaded with C[BS+3] to C[BS + (BS+2)] (which is C11-C18 for
      // an 8-octet block).
      begin = n + 2 - offset;
      FR.set(ciphertext.subarray(begin, begin + block_size));

      // 11. FR is encrypted to produce FRE.
      FRE = cipherfn.encrypt(FR);

      // 12. FRE is xored with the next BS octets of plaintext, to produce
      // the next BS octets of ciphertext.  These are loaded into FR, and
      // the process is repeated until the plaintext is used up.
      for (i = 0; i < block_size; i++) {
        ciphertext[block_size + begin + i] = FRE[i] ^ plaintext[n + i - offset];
      }
    }

    ciphertext = ciphertext.subarray(0, plaintext.length + 2 + block_size);
    return ciphertext;
  },

  /**
   * Decrypts the prefixed data for the Modification Detection Code (MDC) computation
   * @param {String} cipherfn.encrypt Cipher function to use,
   *  @see module:crypto/cipher.
   * @param {Uint8Array} key Uint8Array representation of key to be used to check the mdc
   * This will be passed to the cipherfn
   * @param {Uint8Array} ciphertext The encrypted data
   * @return {Uint8Array} plaintext Data of D(ciphertext) with blocksize length +2
   */
  mdc: function mdc(cipherfn, key, ciphertext) {
    cipherfn = new _cipher2.default[cipherfn](key);
    var block_size = cipherfn.blockSize;

    var iblock = new Uint8Array(block_size);
    var ablock = new Uint8Array(block_size);
    var i;

    // initialisation vector
    for (i = 0; i < block_size; i++) {
      iblock[i] = 0;
    }

    iblock = cipherfn.encrypt(iblock);
    for (i = 0; i < block_size; i++) {
      ablock[i] = ciphertext[i];
      iblock[i] ^= ablock[i];
    }

    ablock = cipherfn.encrypt(ablock);

    var result = new Uint8Array(iblock.length + 2);
    result.set(iblock);
    result[iblock.length] = ablock[0] ^ ciphertext[block_size];
    result[iblock.length + 1] = ablock[1] ^ ciphertext[block_size + 1];
    return result;
  },
  /**
   * This function decrypts a given plaintext using the specified
   * blockcipher to decrypt a message
   * @param {String} cipherfn the algorithm cipher class to decrypt
   *  data in one block_size encryption, {@link module:crypto/cipher}.
   * @param {Uint8Array} key Uint8Array representation of key to be used to decrypt the ciphertext.
   * This will be passed to the cipherfn
   * @param {Uint8Array} ciphertext to be decrypted
   * @param {Boolean} resync a boolean value specifying if a resync of the
   *  IV should be used or not. The encrypteddatapacket uses the
   *  "old" style with a resync. Decryption within an
   *  encryptedintegrityprotecteddata packet is not resyncing the IV.
   * @return {Uint8Array} the plaintext data
   */

  decrypt: function decrypt(cipherfn, key, ciphertext, resync) {
    cipherfn = new _cipher2.default[cipherfn](key);
    var block_size = cipherfn.blockSize;

    var iblock = new Uint8Array(block_size);
    var ablock = new Uint8Array(block_size);

    var i, j, n;
    var text = new Uint8Array(ciphertext.length - block_size);

    // initialisation vector
    for (i = 0; i < block_size; i++) {
      iblock[i] = 0;
    }

    iblock = cipherfn.encrypt(iblock);
    for (i = 0; i < block_size; i++) {
      ablock[i] = ciphertext[i];
      iblock[i] ^= ablock[i];
    }

    ablock = cipherfn.encrypt(ablock);

    // test check octets
    if (iblock[block_size - 2] !== (ablock[0] ^ ciphertext[block_size]) || iblock[block_size - 1] !== (ablock[1] ^ ciphertext[block_size + 1])) {
      throw new Error('CFB decrypt: invalid key');
    }

    /*  RFC4880: Tag 18 and Resync:
     *  [...] Unlike the Symmetrically Encrypted Data Packet, no
     *  special CFB resynchronization is done after encrypting this prefix
     *  data.  See "OpenPGP CFB Mode" below for more details.
      */

    j = 0;
    if (resync) {
      for (i = 0; i < block_size; i++) {
        iblock[i] = ciphertext[i + 2];
      }
      for (n = block_size + 2; n < ciphertext.length; n += block_size) {
        ablock = cipherfn.encrypt(iblock);

        for (i = 0; i < block_size && i + n < ciphertext.length; i++) {
          iblock[i] = ciphertext[n + i];
          if (j < text.length) {
            text[j] = ablock[i] ^ iblock[i];
            j++;
          }
        }
      }
    } else {
      for (i = 0; i < block_size; i++) {
        iblock[i] = ciphertext[i];
      }
      for (n = block_size; n < ciphertext.length; n += block_size) {
        ablock = cipherfn.encrypt(iblock);
        for (i = 0; i < block_size && i + n < ciphertext.length; i++) {
          iblock[i] = ciphertext[n + i];
          if (j < text.length) {
            text[j] = ablock[i] ^ iblock[i];
            j++;
          }
        }
      }
    }

    n = resync ? 0 : 2;

    text = text.subarray(n, ciphertext.length - block_size - 2 + n);

    return text;
  },

  normalEncrypt: function normalEncrypt(cipherfn, key, plaintext, iv) {
    cipherfn = new _cipher2.default[cipherfn](key);
    var block_size = cipherfn.blockSize;

    var blocki = new Uint8Array(block_size);
    var blockc = new Uint8Array(block_size);
    var pos = 0;
    var cyphertext = new Uint8Array(plaintext.length);
    var i,
        j = 0;

    if (iv === null) {
      for (i = 0; i < block_size; i++) {
        blockc[i] = 0;
      }
    } else {
      for (i = 0; i < block_size; i++) {
        blockc[i] = iv[i];
      }
    }
    while (plaintext.length > block_size * pos) {
      var encblock = cipherfn.encrypt(blockc);
      blocki = plaintext.subarray(pos * block_size, pos * block_size + block_size);
      for (i = 0; i < blocki.length; i++) {
        blockc[i] = blocki[i] ^ encblock[i];
        cyphertext[j++] = blockc[i];
      }
      pos++;
    }
    return cyphertext;
  },

  normalDecrypt: function normalDecrypt(cipherfn, key, ciphertext, iv) {
    cipherfn = new _cipher2.default[cipherfn](key);
    var block_size = cipherfn.blockSize;

    var blockp;
    var pos = 0;
    var plaintext = new Uint8Array(ciphertext.length);
    var offset = 0;
    var i,
        j = 0;

    if (iv === null) {
      blockp = new Uint8Array(block_size);
      for (i = 0; i < block_size; i++) {
        blockp[i] = 0;
      }
    } else {
      blockp = iv.subarray(0, block_size);
    }
    while (ciphertext.length > block_size * pos) {
      var decblock = cipherfn.encrypt(blockp);
      blockp = ciphertext.subarray(pos * block_size + offset, pos * block_size + block_size + offset);
      for (i = 0; i < blockp.length; i++) {
        plaintext[j++] = blockp[i] ^ decblock[i];
      }
      pos++;
    }

    return plaintext;
  }
};

},{"./cipher":16}],12:[function(_dereq_,module,exports){
/* Rijndael (AES) Encryption
 * Copyright 2005 Herbert Hanewinkel, www.haneWIN.de
 * version 1.1, check www.haneWIN.de for the latest version

 * This software is provided as-is, without express or implied warranty.
 * Permission to use, copy, modify, distribute or sell this software, with or
 * without fee, for any purpose and by any individual or organization, is hereby
 * granted, provided that the above copyright notice and this paragraph appear
 * in all copies. Distribution as a part of an application or binary must
 * include the above copyright notice in the documentation and/or other
 * materials provided with the application or distribution.
 */

/**
 * @module crypto/cipher/aes
 */

'use strict';

// The round constants used in subkey expansion

Object.defineProperty(exports, "__esModule", {
  value: true
});
var Rcon = new Uint8Array([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91]);

// Precomputed lookup table for the SBox
var S = new Uint8Array([99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22]);

var T1 = new Uint32Array([0xa56363c6, 0x847c7cf8, 0x997777ee, 0x8d7b7bf6, 0x0df2f2ff, 0xbd6b6bd6, 0xb16f6fde, 0x54c5c591, 0x50303060, 0x03010102, 0xa96767ce, 0x7d2b2b56, 0x19fefee7, 0x62d7d7b5, 0xe6abab4d, 0x9a7676ec, 0x45caca8f, 0x9d82821f, 0x40c9c989, 0x877d7dfa, 0x15fafaef, 0xeb5959b2, 0xc947478e, 0x0bf0f0fb, 0xecadad41, 0x67d4d4b3, 0xfda2a25f, 0xeaafaf45, 0xbf9c9c23, 0xf7a4a453, 0x967272e4, 0x5bc0c09b, 0xc2b7b775, 0x1cfdfde1, 0xae93933d, 0x6a26264c, 0x5a36366c, 0x413f3f7e, 0x02f7f7f5, 0x4fcccc83, 0x5c343468, 0xf4a5a551, 0x34e5e5d1, 0x08f1f1f9, 0x937171e2, 0x73d8d8ab, 0x53313162, 0x3f15152a, 0x0c040408, 0x52c7c795, 0x65232346, 0x5ec3c39d, 0x28181830, 0xa1969637, 0x0f05050a, 0xb59a9a2f, 0x0907070e, 0x36121224, 0x9b80801b, 0x3de2e2df, 0x26ebebcd, 0x6927274e, 0xcdb2b27f, 0x9f7575ea, 0x1b090912, 0x9e83831d, 0x742c2c58, 0x2e1a1a34, 0x2d1b1b36, 0xb26e6edc, 0xee5a5ab4, 0xfba0a05b, 0xf65252a4, 0x4d3b3b76, 0x61d6d6b7, 0xceb3b37d, 0x7b292952, 0x3ee3e3dd, 0x712f2f5e, 0x97848413, 0xf55353a6, 0x68d1d1b9, 0x00000000, 0x2cededc1, 0x60202040, 0x1ffcfce3, 0xc8b1b179, 0xed5b5bb6, 0xbe6a6ad4, 0x46cbcb8d, 0xd9bebe67, 0x4b393972, 0xde4a4a94, 0xd44c4c98, 0xe85858b0, 0x4acfcf85, 0x6bd0d0bb, 0x2aefefc5, 0xe5aaaa4f, 0x16fbfbed, 0xc5434386, 0xd74d4d9a, 0x55333366, 0x94858511, 0xcf45458a, 0x10f9f9e9, 0x06020204, 0x817f7ffe, 0xf05050a0, 0x443c3c78, 0xba9f9f25, 0xe3a8a84b, 0xf35151a2, 0xfea3a35d, 0xc0404080, 0x8a8f8f05, 0xad92923f, 0xbc9d9d21, 0x48383870, 0x04f5f5f1, 0xdfbcbc63, 0xc1b6b677, 0x75dadaaf, 0x63212142, 0x30101020, 0x1affffe5, 0x0ef3f3fd, 0x6dd2d2bf, 0x4ccdcd81, 0x140c0c18, 0x35131326, 0x2fececc3, 0xe15f5fbe, 0xa2979735, 0xcc444488, 0x3917172e, 0x57c4c493, 0xf2a7a755, 0x827e7efc, 0x473d3d7a, 0xac6464c8, 0xe75d5dba, 0x2b191932, 0x957373e6, 0xa06060c0, 0x98818119, 0xd14f4f9e, 0x7fdcdca3, 0x66222244, 0x7e2a2a54, 0xab90903b, 0x8388880b, 0xca46468c, 0x29eeeec7, 0xd3b8b86b, 0x3c141428, 0x79dedea7, 0xe25e5ebc, 0x1d0b0b16, 0x76dbdbad, 0x3be0e0db, 0x56323264, 0x4e3a3a74, 0x1e0a0a14, 0xdb494992, 0x0a06060c, 0x6c242448, 0xe45c5cb8, 0x5dc2c29f, 0x6ed3d3bd, 0xefacac43, 0xa66262c4, 0xa8919139, 0xa4959531, 0x37e4e4d3, 0x8b7979f2, 0x32e7e7d5, 0x43c8c88b, 0x5937376e, 0xb76d6dda, 0x8c8d8d01, 0x64d5d5b1, 0xd24e4e9c, 0xe0a9a949, 0xb46c6cd8, 0xfa5656ac, 0x07f4f4f3, 0x25eaeacf, 0xaf6565ca, 0x8e7a7af4, 0xe9aeae47, 0x18080810, 0xd5baba6f, 0x887878f0, 0x6f25254a, 0x722e2e5c, 0x241c1c38, 0xf1a6a657, 0xc7b4b473, 0x51c6c697, 0x23e8e8cb, 0x7cdddda1, 0x9c7474e8, 0x211f1f3e, 0xdd4b4b96, 0xdcbdbd61, 0x868b8b0d, 0x858a8a0f, 0x907070e0, 0x423e3e7c, 0xc4b5b571, 0xaa6666cc, 0xd8484890, 0x05030306, 0x01f6f6f7, 0x120e0e1c, 0xa36161c2, 0x5f35356a, 0xf95757ae, 0xd0b9b969, 0x91868617, 0x58c1c199, 0x271d1d3a, 0xb99e9e27, 0x38e1e1d9, 0x13f8f8eb, 0xb398982b, 0x33111122, 0xbb6969d2, 0x70d9d9a9, 0x898e8e07, 0xa7949433, 0xb69b9b2d, 0x221e1e3c, 0x92878715, 0x20e9e9c9, 0x49cece87, 0xff5555aa, 0x78282850, 0x7adfdfa5, 0x8f8c8c03, 0xf8a1a159, 0x80898909, 0x170d0d1a, 0xdabfbf65, 0x31e6e6d7, 0xc6424284, 0xb86868d0, 0xc3414182, 0xb0999929, 0x772d2d5a, 0x110f0f1e, 0xcbb0b07b, 0xfc5454a8, 0xd6bbbb6d, 0x3a16162c]);

var T2 = new Uint32Array([0x6363c6a5, 0x7c7cf884, 0x7777ee99, 0x7b7bf68d, 0xf2f2ff0d, 0x6b6bd6bd, 0x6f6fdeb1, 0xc5c59154, 0x30306050, 0x01010203, 0x6767cea9, 0x2b2b567d, 0xfefee719, 0xd7d7b562, 0xabab4de6, 0x7676ec9a, 0xcaca8f45, 0x82821f9d, 0xc9c98940, 0x7d7dfa87, 0xfafaef15, 0x5959b2eb, 0x47478ec9, 0xf0f0fb0b, 0xadad41ec, 0xd4d4b367, 0xa2a25ffd, 0xafaf45ea, 0x9c9c23bf, 0xa4a453f7, 0x7272e496, 0xc0c09b5b, 0xb7b775c2, 0xfdfde11c, 0x93933dae, 0x26264c6a, 0x36366c5a, 0x3f3f7e41, 0xf7f7f502, 0xcccc834f, 0x3434685c, 0xa5a551f4, 0xe5e5d134, 0xf1f1f908, 0x7171e293, 0xd8d8ab73, 0x31316253, 0x15152a3f, 0x0404080c, 0xc7c79552, 0x23234665, 0xc3c39d5e, 0x18183028, 0x969637a1, 0x05050a0f, 0x9a9a2fb5, 0x07070e09, 0x12122436, 0x80801b9b, 0xe2e2df3d, 0xebebcd26, 0x27274e69, 0xb2b27fcd, 0x7575ea9f, 0x0909121b, 0x83831d9e, 0x2c2c5874, 0x1a1a342e, 0x1b1b362d, 0x6e6edcb2, 0x5a5ab4ee, 0xa0a05bfb, 0x5252a4f6, 0x3b3b764d, 0xd6d6b761, 0xb3b37dce, 0x2929527b, 0xe3e3dd3e, 0x2f2f5e71, 0x84841397, 0x5353a6f5, 0xd1d1b968, 0x00000000, 0xededc12c, 0x20204060, 0xfcfce31f, 0xb1b179c8, 0x5b5bb6ed, 0x6a6ad4be, 0xcbcb8d46, 0xbebe67d9, 0x3939724b, 0x4a4a94de, 0x4c4c98d4, 0x5858b0e8, 0xcfcf854a, 0xd0d0bb6b, 0xefefc52a, 0xaaaa4fe5, 0xfbfbed16, 0x434386c5, 0x4d4d9ad7, 0x33336655, 0x85851194, 0x45458acf, 0xf9f9e910, 0x02020406, 0x7f7ffe81, 0x5050a0f0, 0x3c3c7844, 0x9f9f25ba, 0xa8a84be3, 0x5151a2f3, 0xa3a35dfe, 0x404080c0, 0x8f8f058a, 0x92923fad, 0x9d9d21bc, 0x38387048, 0xf5f5f104, 0xbcbc63df, 0xb6b677c1, 0xdadaaf75, 0x21214263, 0x10102030, 0xffffe51a, 0xf3f3fd0e, 0xd2d2bf6d, 0xcdcd814c, 0x0c0c1814, 0x13132635, 0xececc32f, 0x5f5fbee1, 0x979735a2, 0x444488cc, 0x17172e39, 0xc4c49357, 0xa7a755f2, 0x7e7efc82, 0x3d3d7a47, 0x6464c8ac, 0x5d5dbae7, 0x1919322b, 0x7373e695, 0x6060c0a0, 0x81811998, 0x4f4f9ed1, 0xdcdca37f, 0x22224466, 0x2a2a547e, 0x90903bab, 0x88880b83, 0x46468cca, 0xeeeec729, 0xb8b86bd3, 0x1414283c, 0xdedea779, 0x5e5ebce2, 0x0b0b161d, 0xdbdbad76, 0xe0e0db3b, 0x32326456, 0x3a3a744e, 0x0a0a141e, 0x494992db, 0x06060c0a, 0x2424486c, 0x5c5cb8e4, 0xc2c29f5d, 0xd3d3bd6e, 0xacac43ef, 0x6262c4a6, 0x919139a8, 0x959531a4, 0xe4e4d337, 0x7979f28b, 0xe7e7d532, 0xc8c88b43, 0x37376e59, 0x6d6ddab7, 0x8d8d018c, 0xd5d5b164, 0x4e4e9cd2, 0xa9a949e0, 0x6c6cd8b4, 0x5656acfa, 0xf4f4f307, 0xeaeacf25, 0x6565caaf, 0x7a7af48e, 0xaeae47e9, 0x08081018, 0xbaba6fd5, 0x7878f088, 0x25254a6f, 0x2e2e5c72, 0x1c1c3824, 0xa6a657f1, 0xb4b473c7, 0xc6c69751, 0xe8e8cb23, 0xdddda17c, 0x7474e89c, 0x1f1f3e21, 0x4b4b96dd, 0xbdbd61dc, 0x8b8b0d86, 0x8a8a0f85, 0x7070e090, 0x3e3e7c42, 0xb5b571c4, 0x6666ccaa, 0x484890d8, 0x03030605, 0xf6f6f701, 0x0e0e1c12, 0x6161c2a3, 0x35356a5f, 0x5757aef9, 0xb9b969d0, 0x86861791, 0xc1c19958, 0x1d1d3a27, 0x9e9e27b9, 0xe1e1d938, 0xf8f8eb13, 0x98982bb3, 0x11112233, 0x6969d2bb, 0xd9d9a970, 0x8e8e0789, 0x949433a7, 0x9b9b2db6, 0x1e1e3c22, 0x87871592, 0xe9e9c920, 0xcece8749, 0x5555aaff, 0x28285078, 0xdfdfa57a, 0x8c8c038f, 0xa1a159f8, 0x89890980, 0x0d0d1a17, 0xbfbf65da, 0xe6e6d731, 0x424284c6, 0x6868d0b8, 0x414182c3, 0x999929b0, 0x2d2d5a77, 0x0f0f1e11, 0xb0b07bcb, 0x5454a8fc, 0xbbbb6dd6, 0x16162c3a]);

var T3 = new Uint32Array([0x63c6a563, 0x7cf8847c, 0x77ee9977, 0x7bf68d7b, 0xf2ff0df2, 0x6bd6bd6b, 0x6fdeb16f, 0xc59154c5, 0x30605030, 0x01020301, 0x67cea967, 0x2b567d2b, 0xfee719fe, 0xd7b562d7, 0xab4de6ab, 0x76ec9a76, 0xca8f45ca, 0x821f9d82, 0xc98940c9, 0x7dfa877d, 0xfaef15fa, 0x59b2eb59, 0x478ec947, 0xf0fb0bf0, 0xad41ecad, 0xd4b367d4, 0xa25ffda2, 0xaf45eaaf, 0x9c23bf9c, 0xa453f7a4, 0x72e49672, 0xc09b5bc0, 0xb775c2b7, 0xfde11cfd, 0x933dae93, 0x264c6a26, 0x366c5a36, 0x3f7e413f, 0xf7f502f7, 0xcc834fcc, 0x34685c34, 0xa551f4a5, 0xe5d134e5, 0xf1f908f1, 0x71e29371, 0xd8ab73d8, 0x31625331, 0x152a3f15, 0x04080c04, 0xc79552c7, 0x23466523, 0xc39d5ec3, 0x18302818, 0x9637a196, 0x050a0f05, 0x9a2fb59a, 0x070e0907, 0x12243612, 0x801b9b80, 0xe2df3de2, 0xebcd26eb, 0x274e6927, 0xb27fcdb2, 0x75ea9f75, 0x09121b09, 0x831d9e83, 0x2c58742c, 0x1a342e1a, 0x1b362d1b, 0x6edcb26e, 0x5ab4ee5a, 0xa05bfba0, 0x52a4f652, 0x3b764d3b, 0xd6b761d6, 0xb37dceb3, 0x29527b29, 0xe3dd3ee3, 0x2f5e712f, 0x84139784, 0x53a6f553, 0xd1b968d1, 0x00000000, 0xedc12ced, 0x20406020, 0xfce31ffc, 0xb179c8b1, 0x5bb6ed5b, 0x6ad4be6a, 0xcb8d46cb, 0xbe67d9be, 0x39724b39, 0x4a94de4a, 0x4c98d44c, 0x58b0e858, 0xcf854acf, 0xd0bb6bd0, 0xefc52aef, 0xaa4fe5aa, 0xfbed16fb, 0x4386c543, 0x4d9ad74d, 0x33665533, 0x85119485, 0x458acf45, 0xf9e910f9, 0x02040602, 0x7ffe817f, 0x50a0f050, 0x3c78443c, 0x9f25ba9f, 0xa84be3a8, 0x51a2f351, 0xa35dfea3, 0x4080c040, 0x8f058a8f, 0x923fad92, 0x9d21bc9d, 0x38704838, 0xf5f104f5, 0xbc63dfbc, 0xb677c1b6, 0xdaaf75da, 0x21426321, 0x10203010, 0xffe51aff, 0xf3fd0ef3, 0xd2bf6dd2, 0xcd814ccd, 0x0c18140c, 0x13263513, 0xecc32fec, 0x5fbee15f, 0x9735a297, 0x4488cc44, 0x172e3917, 0xc49357c4, 0xa755f2a7, 0x7efc827e, 0x3d7a473d, 0x64c8ac64, 0x5dbae75d, 0x19322b19, 0x73e69573, 0x60c0a060, 0x81199881, 0x4f9ed14f, 0xdca37fdc, 0x22446622, 0x2a547e2a, 0x903bab90, 0x880b8388, 0x468cca46, 0xeec729ee, 0xb86bd3b8, 0x14283c14, 0xdea779de, 0x5ebce25e, 0x0b161d0b, 0xdbad76db, 0xe0db3be0, 0x32645632, 0x3a744e3a, 0x0a141e0a, 0x4992db49, 0x060c0a06, 0x24486c24, 0x5cb8e45c, 0xc29f5dc2, 0xd3bd6ed3, 0xac43efac, 0x62c4a662, 0x9139a891, 0x9531a495, 0xe4d337e4, 0x79f28b79, 0xe7d532e7, 0xc88b43c8, 0x376e5937, 0x6ddab76d, 0x8d018c8d, 0xd5b164d5, 0x4e9cd24e, 0xa949e0a9, 0x6cd8b46c, 0x56acfa56, 0xf4f307f4, 0xeacf25ea, 0x65caaf65, 0x7af48e7a, 0xae47e9ae, 0x08101808, 0xba6fd5ba, 0x78f08878, 0x254a6f25, 0x2e5c722e, 0x1c38241c, 0xa657f1a6, 0xb473c7b4, 0xc69751c6, 0xe8cb23e8, 0xdda17cdd, 0x74e89c74, 0x1f3e211f, 0x4b96dd4b, 0xbd61dcbd, 0x8b0d868b, 0x8a0f858a, 0x70e09070, 0x3e7c423e, 0xb571c4b5, 0x66ccaa66, 0x4890d848, 0x03060503, 0xf6f701f6, 0x0e1c120e, 0x61c2a361, 0x356a5f35, 0x57aef957, 0xb969d0b9, 0x86179186, 0xc19958c1, 0x1d3a271d, 0x9e27b99e, 0xe1d938e1, 0xf8eb13f8, 0x982bb398, 0x11223311, 0x69d2bb69, 0xd9a970d9, 0x8e07898e, 0x9433a794, 0x9b2db69b, 0x1e3c221e, 0x87159287, 0xe9c920e9, 0xce8749ce, 0x55aaff55, 0x28507828, 0xdfa57adf, 0x8c038f8c, 0xa159f8a1, 0x89098089, 0x0d1a170d, 0xbf65dabf, 0xe6d731e6, 0x4284c642, 0x68d0b868, 0x4182c341, 0x9929b099, 0x2d5a772d, 0x0f1e110f, 0xb07bcbb0, 0x54a8fc54, 0xbb6dd6bb, 0x162c3a16]);

var T4 = new Uint32Array([0xc6a56363, 0xf8847c7c, 0xee997777, 0xf68d7b7b, 0xff0df2f2, 0xd6bd6b6b, 0xdeb16f6f, 0x9154c5c5, 0x60503030, 0x02030101, 0xcea96767, 0x567d2b2b, 0xe719fefe, 0xb562d7d7, 0x4de6abab, 0xec9a7676, 0x8f45caca, 0x1f9d8282, 0x8940c9c9, 0xfa877d7d, 0xef15fafa, 0xb2eb5959, 0x8ec94747, 0xfb0bf0f0, 0x41ecadad, 0xb367d4d4, 0x5ffda2a2, 0x45eaafaf, 0x23bf9c9c, 0x53f7a4a4, 0xe4967272, 0x9b5bc0c0, 0x75c2b7b7, 0xe11cfdfd, 0x3dae9393, 0x4c6a2626, 0x6c5a3636, 0x7e413f3f, 0xf502f7f7, 0x834fcccc, 0x685c3434, 0x51f4a5a5, 0xd134e5e5, 0xf908f1f1, 0xe2937171, 0xab73d8d8, 0x62533131, 0x2a3f1515, 0x080c0404, 0x9552c7c7, 0x46652323, 0x9d5ec3c3, 0x30281818, 0x37a19696, 0x0a0f0505, 0x2fb59a9a, 0x0e090707, 0x24361212, 0x1b9b8080, 0xdf3de2e2, 0xcd26ebeb, 0x4e692727, 0x7fcdb2b2, 0xea9f7575, 0x121b0909, 0x1d9e8383, 0x58742c2c, 0x342e1a1a, 0x362d1b1b, 0xdcb26e6e, 0xb4ee5a5a, 0x5bfba0a0, 0xa4f65252, 0x764d3b3b, 0xb761d6d6, 0x7dceb3b3, 0x527b2929, 0xdd3ee3e3, 0x5e712f2f, 0x13978484, 0xa6f55353, 0xb968d1d1, 0x00000000, 0xc12ceded, 0x40602020, 0xe31ffcfc, 0x79c8b1b1, 0xb6ed5b5b, 0xd4be6a6a, 0x8d46cbcb, 0x67d9bebe, 0x724b3939, 0x94de4a4a, 0x98d44c4c, 0xb0e85858, 0x854acfcf, 0xbb6bd0d0, 0xc52aefef, 0x4fe5aaaa, 0xed16fbfb, 0x86c54343, 0x9ad74d4d, 0x66553333, 0x11948585, 0x8acf4545, 0xe910f9f9, 0x04060202, 0xfe817f7f, 0xa0f05050, 0x78443c3c, 0x25ba9f9f, 0x4be3a8a8, 0xa2f35151, 0x5dfea3a3, 0x80c04040, 0x058a8f8f, 0x3fad9292, 0x21bc9d9d, 0x70483838, 0xf104f5f5, 0x63dfbcbc, 0x77c1b6b6, 0xaf75dada, 0x42632121, 0x20301010, 0xe51affff, 0xfd0ef3f3, 0xbf6dd2d2, 0x814ccdcd, 0x18140c0c, 0x26351313, 0xc32fecec, 0xbee15f5f, 0x35a29797, 0x88cc4444, 0x2e391717, 0x9357c4c4, 0x55f2a7a7, 0xfc827e7e, 0x7a473d3d, 0xc8ac6464, 0xbae75d5d, 0x322b1919, 0xe6957373, 0xc0a06060, 0x19988181, 0x9ed14f4f, 0xa37fdcdc, 0x44662222, 0x547e2a2a, 0x3bab9090, 0x0b838888, 0x8cca4646, 0xc729eeee, 0x6bd3b8b8, 0x283c1414, 0xa779dede, 0xbce25e5e, 0x161d0b0b, 0xad76dbdb, 0xdb3be0e0, 0x64563232, 0x744e3a3a, 0x141e0a0a, 0x92db4949, 0x0c0a0606, 0x486c2424, 0xb8e45c5c, 0x9f5dc2c2, 0xbd6ed3d3, 0x43efacac, 0xc4a66262, 0x39a89191, 0x31a49595, 0xd337e4e4, 0xf28b7979, 0xd532e7e7, 0x8b43c8c8, 0x6e593737, 0xdab76d6d, 0x018c8d8d, 0xb164d5d5, 0x9cd24e4e, 0x49e0a9a9, 0xd8b46c6c, 0xacfa5656, 0xf307f4f4, 0xcf25eaea, 0xcaaf6565, 0xf48e7a7a, 0x47e9aeae, 0x10180808, 0x6fd5baba, 0xf0887878, 0x4a6f2525, 0x5c722e2e, 0x38241c1c, 0x57f1a6a6, 0x73c7b4b4, 0x9751c6c6, 0xcb23e8e8, 0xa17cdddd, 0xe89c7474, 0x3e211f1f, 0x96dd4b4b, 0x61dcbdbd, 0x0d868b8b, 0x0f858a8a, 0xe0907070, 0x7c423e3e, 0x71c4b5b5, 0xccaa6666, 0x90d84848, 0x06050303, 0xf701f6f6, 0x1c120e0e, 0xc2a36161, 0x6a5f3535, 0xaef95757, 0x69d0b9b9, 0x17918686, 0x9958c1c1, 0x3a271d1d, 0x27b99e9e, 0xd938e1e1, 0xeb13f8f8, 0x2bb39898, 0x22331111, 0xd2bb6969, 0xa970d9d9, 0x07898e8e, 0x33a79494, 0x2db69b9b, 0x3c221e1e, 0x15928787, 0xc920e9e9, 0x8749cece, 0xaaff5555, 0x50782828, 0xa57adfdf, 0x038f8c8c, 0x59f8a1a1, 0x09808989, 0x1a170d0d, 0x65dabfbf, 0xd731e6e6, 0x84c64242, 0xd0b86868, 0x82c34141, 0x29b09999, 0x5a772d2d, 0x1e110f0f, 0x7bcbb0b0, 0xa8fc5454, 0x6dd6bbbb, 0x2c3a1616]);

function B0(x) {
  return x & 255;
}

function B1(x) {
  return x >> 8 & 255;
}

function B2(x) {
  return x >> 16 & 255;
}

function B3(x) {
  return x >> 24 & 255;
}

function F1(x0, x1, x2, x3) {
  return B1(T1[x0 & 255]) | B1(T1[x1 >> 8 & 255]) << 8 | B1(T1[x2 >> 16 & 255]) << 16 | B1(T1[x3 >>> 24]) << 24;
}

function packBytes(octets) {
  var i, j;
  var len = octets.length;
  var b = new Array(len / 4);

  if (!octets || len % 4) {
    return;
  }

  for (i = 0, j = 0; j < len; j += 4) {
    b[i++] = octets[j] | octets[j + 1] << 8 | octets[j + 2] << 16 | octets[j + 3] << 24;
  }

  return b;
}

function unpackBytes(packed) {
  var j;
  var i = 0,
      l = packed.length;
  var r = new Array(l * 4);

  for (j = 0; j < l; j++) {
    r[i++] = B0(packed[j]);
    r[i++] = B1(packed[j]);
    r[i++] = B2(packed[j]);
    r[i++] = B3(packed[j]);
  }
  return r;
}

// ------------------------------------------------

var maxkc = 8;
var maxrk = 14;

function keyExpansion(key) {
  var kc, i, j, r, t;
  var rounds;
  var keySched = new Array(maxrk + 1);
  var keylen = key.length;
  var k = new Array(maxkc);
  var tk = new Array(maxkc);
  var rconpointer = 0;

  if (keylen === 16) {
    rounds = 10;
    kc = 4;
  } else if (keylen === 24) {
    rounds = 12;
    kc = 6;
  } else if (keylen === 32) {
    rounds = 14;
    kc = 8;
  } else {
    throw new Error('Invalid key-length for AES key:' + keylen);
  }

  for (i = 0; i < maxrk + 1; i++) {
    keySched[i] = new Uint32Array(4);
  }

  for (i = 0, j = 0; j < keylen; j++, i += 4) {
    k[j] = key[i] | key[i + 1] << 8 | key[i + 2] << 16 | key[i + 3] << 24;
  }

  for (j = kc - 1; j >= 0; j--) {
    tk[j] = k[j];
  }

  r = 0;
  t = 0;
  for (j = 0; j < kc && r < rounds + 1;) {
    for (; j < kc && t < 4; j++, t++) {
      keySched[r][t] = tk[j];
    }
    if (t === 4) {
      r++;
      t = 0;
    }
  }

  while (r < rounds + 1) {
    var temp = tk[kc - 1];

    tk[0] ^= S[B1(temp)] | S[B2(temp)] << 8 | S[B3(temp)] << 16 | S[B0(temp)] << 24;
    tk[0] ^= Rcon[rconpointer++];

    if (kc !== 8) {
      for (j = 1; j < kc; j++) {
        tk[j] ^= tk[j - 1];
      }
    } else {
      for (j = 1; j < kc / 2; j++) {
        tk[j] ^= tk[j - 1];
      }

      temp = tk[kc / 2 - 1];
      tk[kc / 2] ^= S[B0(temp)] | S[B1(temp)] << 8 | S[B2(temp)] << 16 | S[B3(temp)] << 24;

      for (j = kc / 2 + 1; j < kc; j++) {
        tk[j] ^= tk[j - 1];
      }
    }

    for (j = 0; j < kc && r < rounds + 1;) {
      for (; j < kc && t < 4; j++, t++) {
        keySched[r][t] = tk[j];
      }
      if (t === 4) {
        r++;
        t = 0;
      }
    }
  }

  return {
    rounds: rounds,
    rk: keySched
  };
}

function AESencrypt(block, ctx, t) {
  var r, rounds, b;

  b = packBytes(block);
  rounds = ctx.rounds;

  for (r = 0; r < rounds - 1; r++) {
    t[0] = b[0] ^ ctx.rk[r][0];
    t[1] = b[1] ^ ctx.rk[r][1];
    t[2] = b[2] ^ ctx.rk[r][2];
    t[3] = b[3] ^ ctx.rk[r][3];

    b[0] = T1[t[0] & 255] ^ T2[t[1] >> 8 & 255] ^ T3[t[2] >> 16 & 255] ^ T4[t[3] >>> 24];
    b[1] = T1[t[1] & 255] ^ T2[t[2] >> 8 & 255] ^ T3[t[3] >> 16 & 255] ^ T4[t[0] >>> 24];
    b[2] = T1[t[2] & 255] ^ T2[t[3] >> 8 & 255] ^ T3[t[0] >> 16 & 255] ^ T4[t[1] >>> 24];
    b[3] = T1[t[3] & 255] ^ T2[t[0] >> 8 & 255] ^ T3[t[1] >> 16 & 255] ^ T4[t[2] >>> 24];
  }

  // last round is special
  r = rounds - 1;

  t[0] = b[0] ^ ctx.rk[r][0];
  t[1] = b[1] ^ ctx.rk[r][1];
  t[2] = b[2] ^ ctx.rk[r][2];
  t[3] = b[3] ^ ctx.rk[r][3];

  b[0] = F1(t[0], t[1], t[2], t[3]) ^ ctx.rk[rounds][0];
  b[1] = F1(t[1], t[2], t[3], t[0]) ^ ctx.rk[rounds][1];
  b[2] = F1(t[2], t[3], t[0], t[1]) ^ ctx.rk[rounds][2];
  b[3] = F1(t[3], t[0], t[1], t[2]) ^ ctx.rk[rounds][3];

  return unpackBytes(b);
}

function makeClass(length) {

  var c = function c(key) {
    this.key = keyExpansion(key);
    this._temp = new Uint32Array(this.blockSize / 4);

    this.encrypt = function (block) {
      return AESencrypt(block, this.key, this._temp);
    };
  };

  c.blockSize = c.prototype.blockSize = 16;
  c.keySize = c.prototype.keySize = length / 8;

  return c;
}

exports.default = {
  128: makeClass(128),
  192: makeClass(192),
  256: makeClass(256)
};

},{}],13:[function(_dereq_,module,exports){
/* Modified by Recurity Labs GmbH
 *
 * Originally written by nklein software (nklein.com)
 */

/**
 *  @module crypto/cipher/blowfish
 */

'use strict';

/*
 * Javascript implementation based on Bruce Schneier's reference implementation.
 *
 *
 * The constructor doesn't do much of anything.  It's just here
 * so we can start defining properties and methods and such.
 */

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = BF;
function Blowfish() {}

/*
 * Declare the block size so that protocols know what size
 * Initialization Vector (IV) they will need.
 */
Blowfish.prototype.BLOCKSIZE = 8;

/*
 * These are the default SBOXES.
 */
Blowfish.prototype.SBOXES = [[0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96, 0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16, 0x636920d8, 0x71574e69, 0xa458fea3, 0xf4933d7e, 0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013, 0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e, 0x6c9e0e8b, 0xb01e8a3e, 0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60, 0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440, 0x55ca396a, 0x2aab10b6, 0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636fbc2a, 0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c, 0x7a325381, 0x28958677, 0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193, 0x61d809cc, 0xfb21a991, 0x487cac60, 0x5dec8032, 0xef845d5d, 0xe98575b1, 0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5, 0x0f6d6ff3, 0x83f44239, 0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e, 0x21c66842, 0xf6e96c9a, 0x670c9c61, 0xabd388f0, 0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3, 0x6eef0b6c, 0x137a3be4, 0xba3bf050, 0x7efb2a98, 0xa1f1651d, 0x39af0176, 0x66ca593e, 0x82430e88, 0x8cee8619, 0x456f9fb4, 0x7d84a5c3, 0x3b8b5ebe, 0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6, 0x4ed3aa62, 0x363f7706, 0x1bfedf72, 0x429b023d, 0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b, 0x075372c9, 0x80991b7b, 0x25d479d8, 0xf6e8def7, 0xe3fe501a, 0xb6794c3b, 0x976ce0bd, 0x04c006ba, 0xc1a94fb6, 0x409f60c4, 0x5e5c9ec2, 0x196a2463, 0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f, 0x6dfc511f, 0x9b30952c, 0xcc814544, 0xaf5ebd09, 0xbee3d004, 0xde334afd, 0x660f2807, 0x192e4bb3, 0xc0cba857, 0x45c8740f, 0xd20b5f39, 0xb9d3fbdb, 0x5579c0bd, 0x1a60320a, 0xd6a100c6, 0x402c7279, 0x679f25fe, 0xfb1fa3cc, 0x8ea5e9f8, 0xdb3222f8, 0x3c7516df, 0xfd616b15, 0x2f501ec8, 0xad0552ab, 0x323db5fa, 0xfd238760, 0x53317b48, 0x3e00df82, 0x9e5c57bb, 0xca6f8ca0, 0x1a87562e, 0xdf1769db, 0xd542a8f6, 0x287effc3, 0xac6732c6, 0x8c4f5573, 0x695b27b0, 0xbbca58c8, 0xe1ffa35d, 0xb8f011a0, 0x10fa3d98, 0xfd2183b8, 0x4afcb56c, 0x2dd1d35b, 0x9a53e479, 0xb6f84565, 0xd28e49bc, 0x4bfb9790, 0xe1ddf2da, 0xa4cb7e33, 0x62fb1341, 0xcee4c6e8, 0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4, 0x95dbda4d, 0xae909198, 0xeaad8e71, 0x6b93d5a0, 0xd08ed1d0, 0xafc725e0, 0x8e3c5b2f, 0x8e7594b7, 0x8ff6e2fb, 0xf2122b64, 0x8888b812, 0x900df01c, 0x4fad5ea0, 0x688fc31c, 0xd1cff191, 0xb3a8c1ad, 0x2f2f2218, 0xbe0e1777, 0xea752dfe, 0x8b021fa1, 0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6, 0xce89e299, 0xb4a84fe0, 0xfd13e0b7, 0x7cc43b81, 0xd2ada8d9, 0x165fa266, 0x80957705, 0x93cc7314, 0x211a1477, 0xe6ad2065, 0x77b5fa86, 0xc75442f5, 0xfb9d35cf, 0xebcdaf0c, 0x7b3e89a0, 0xd6411bd3, 0xae1e7e49, 0x00250e2d, 0x2071b35e, 0x226800bb, 0x57b8e0af, 0x2464369b, 0xf009b91e, 0x5563911d, 0x59dfa6aa, 0x78c14389, 0xd95a537f, 0x207d5ba2, 0x02e5b9c5, 0x83260376, 0x6295cfa9, 0x11c81968, 0x4e734a41, 0xb3472dca, 0x7b14a94a, 0x1b510052, 0x9a532915, 0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400, 0x08ba6fb5, 0x571be91f, 0xf296ec6b, 0x2a0dd915, 0xb6636521, 0xe7b9f9b6, 0xff34052e, 0xc5855664, 0x53b02d5d, 0xa99f8fa1, 0x08ba4799, 0x6e85076a], [0x4b7a70e9, 0xb5b32944, 0xdb75092e, 0xc4192623, 0xad6ea6b0, 0x49a7df7d, 0x9cee60b8, 0x8fedb266, 0xecaa8c71, 0x699a17ff, 0x5664526c, 0xc2b19ee1, 0x193602a5, 0x75094c29, 0xa0591340, 0xe4183a3e, 0x3f54989a, 0x5b429d65, 0x6b8fe4d6, 0x99f73fd6, 0xa1d29c07, 0xefe830f5, 0x4d2d38e6, 0xf0255dc1, 0x4cdd2086, 0x8470eb26, 0x6382e9c6, 0x021ecc5e, 0x09686b3f, 0x3ebaefc9, 0x3c971814, 0x6b6a70a1, 0x687f3584, 0x52a0e286, 0xb79c5305, 0xaa500737, 0x3e07841c, 0x7fdeae5c, 0x8e7d44ec, 0x5716f2b8, 0xb03ada37, 0xf0500c0d, 0xf01c1f04, 0x0200b3ff, 0xae0cf51a, 0x3cb574b2, 0x25837a58, 0xdc0921bd, 0xd19113f9, 0x7ca92ff6, 0x94324773, 0x22f54701, 0x3ae5e581, 0x37c2dadc, 0xc8b57634, 0x9af3dda7, 0xa9446146, 0x0fd0030e, 0xecc8c73e, 0xa4751e41, 0xe238cd99, 0x3bea0e2f, 0x3280bba1, 0x183eb331, 0x4e548b38, 0x4f6db908, 0x6f420d03, 0xf60a04bf, 0x2cb81290, 0x24977c79, 0x5679b072, 0xbcaf89af, 0xde9a771f, 0xd9930810, 0xb38bae12, 0xdccf3f2e, 0x5512721f, 0x2e6b7124, 0x501adde6, 0x9f84cd87, 0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c, 0xec7aec3a, 0xdb851dfa, 0x63094366, 0xc464c3d2, 0xef1c1847, 0x3215d908, 0xdd433b37, 0x24c2ba16, 0x12a14d43, 0x2a65c451, 0x50940002, 0x133ae4dd, 0x71dff89e, 0x10314e55, 0x81ac77d6, 0x5f11199b, 0x043556f1, 0xd7a3c76b, 0x3c11183b, 0x5924a509, 0xf28fe6ed, 0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e, 0x86e34570, 0xeae96fb1, 0x860e5e0a, 0x5a3e2ab3, 0x771fe71c, 0x4e3d06fa, 0x2965dcb9, 0x99e71d0f, 0x803e89d6, 0x5266c825, 0x2e4cc978, 0x9c10b36a, 0xc6150eba, 0x94e2ea78, 0xa5fc3c53, 0x1e0a2df4, 0xf2f74ea7, 0x361d2b3d, 0x1939260f, 0x19c27960, 0x5223a708, 0xf71312b6, 0xebadfe6e, 0xeac31f66, 0xe3bc4595, 0xa67bc883, 0xb17f37d1, 0x018cff28, 0xc332ddef, 0xbe6c5aa5, 0x65582185, 0x68ab9802, 0xeecea50f, 0xdb2f953b, 0x2aef7dad, 0x5b6e2f84, 0x1521b628, 0x29076170, 0xecdd4775, 0x619f1510, 0x13cca830, 0xeb61bd96, 0x0334fe1e, 0xaa0363cf, 0xb5735c90, 0x4c70a239, 0xd59e9e0b, 0xcbaade14, 0xeecc86bc, 0x60622ca7, 0x9cab5cab, 0xb2f3846e, 0x648b1eaf, 0x19bdf0ca, 0xa02369b9, 0x655abb50, 0x40685a32, 0x3c2ab4b3, 0x319ee9d5, 0xc021b8f7, 0x9b540b19, 0x875fa099, 0x95f7997e, 0x623d7da8, 0xf837889a, 0x97e32d77, 0x11ed935f, 0x16681281, 0x0e358829, 0xc7e61fd6, 0x96dedfa1, 0x7858ba99, 0x57f584a5, 0x1b227263, 0x9b83c3ff, 0x1ac24696, 0xcdb30aeb, 0x532e3054, 0x8fd948e4, 0x6dbc3128, 0x58ebf2ef, 0x34c6ffea, 0xfe28ed61, 0xee7c3c73, 0x5d4a14d9, 0xe864b7e3, 0x42105d14, 0x203e13e0, 0x45eee2b6, 0xa3aaabea, 0xdb6c4f15, 0xfacb4fd0, 0xc742f442, 0xef6abbb5, 0x654f3b1d, 0x41cd2105, 0xd81e799e, 0x86854dc7, 0xe44b476a, 0x3d816250, 0xcf62a1f2, 0x5b8d2646, 0xfc8883a0, 0xc1c7b6a3, 0x7f1524c3, 0x69cb7492, 0x47848a0b, 0x5692b285, 0x095bbf00, 0xad19489d, 0x1462b174, 0x23820e00, 0x58428d2a, 0x0c55f5ea, 0x1dadf43e, 0x233f7061, 0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb, 0x7cde3759, 0xcbee7460, 0x4085f2a7, 0xce77326e, 0xa6078084, 0x19f8509e, 0xe8efd855, 0x61d99735, 0xa969a7aa, 0xc50c06c2, 0x5a04abfc, 0x800bcadc, 0x9e447a2e, 0xc3453484, 0xfdd56705, 0x0e1e9ec9, 0xdb73dbd3, 0x105588cd, 0x675fda79, 0xe3674340, 0xc5c43465, 0x713e38d8, 0x3d28f89e, 0xf16dff20, 0x153e21e7, 0x8fb03d4a, 0xe6e39f2b, 0xdb83adf7], [0xe93d5a68, 0x948140f7, 0xf64c261c, 0x94692934, 0x411520f7, 0x7602d4f7, 0xbcf46b2e, 0xd4a20068, 0xd4082471, 0x3320f46a, 0x43b7d4b7, 0x500061af, 0x1e39f62e, 0x97244546, 0x14214f74, 0xbf8b8840, 0x4d95fc1d, 0x96b591af, 0x70f4ddd3, 0x66a02f45, 0xbfbc09ec, 0x03bd9785, 0x7fac6dd0, 0x31cb8504, 0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a, 0x28507825, 0x530429f4, 0x0a2c86da, 0xe9b66dfb, 0x68dc1462, 0xd7486900, 0x680ec0a4, 0x27a18dee, 0x4f3ffea2, 0xe887ad8c, 0xb58ce006, 0x7af4d6b6, 0xaace1e7c, 0xd3375fec, 0xce78a399, 0x406b2a42, 0x20fe9e35, 0xd9f385b9, 0xee39d7ab, 0x3b124e8b, 0x1dc9faf7, 0x4b6d1856, 0x26a36631, 0xeae397b2, 0x3a6efa74, 0xdd5b4332, 0x6841e7f7, 0xca7820fb, 0xfb0af54e, 0xd8feb397, 0x454056ac, 0xba489527, 0x55533a3a, 0x20838d87, 0xfe6ba9b7, 0xd096954b, 0x55a867bc, 0xa1159a58, 0xcca92963, 0x99e1db33, 0xa62a4a56, 0x3f3125f9, 0x5ef47e1c, 0x9029317c, 0xfdf8e802, 0x04272f70, 0x80bb155c, 0x05282ce3, 0x95c11548, 0xe4c66d22, 0x48c1133f, 0xc70f86dc, 0x07f9c9ee, 0x41041f0f, 0x404779a4, 0x5d886e17, 0x325f51eb, 0xd59bc0d1, 0xf2bcc18f, 0x41113564, 0x257b7834, 0x602a9c60, 0xdff8e8a3, 0x1f636c1b, 0x0e12b4c2, 0x02e1329e, 0xaf664fd1, 0xcad18115, 0x6b2395e0, 0x333e92e1, 0x3b240b62, 0xeebeb922, 0x85b2a20e, 0xe6ba0d99, 0xde720c8c, 0x2da2f728, 0xd0127845, 0x95b794fd, 0x647d0862, 0xe7ccf5f0, 0x5449a36f, 0x877d48fa, 0xc39dfd27, 0xf33e8d1e, 0x0a476341, 0x992eff74, 0x3a6f6eab, 0xf4f8fd37, 0xa812dc60, 0xa1ebddf8, 0x991be14c, 0xdb6e6b0d, 0xc67b5510, 0x6d672c37, 0x2765d43b, 0xdcd0e804, 0xf1290dc7, 0xcc00ffa3, 0xb5390f92, 0x690fed0b, 0x667b9ffb, 0xcedb7d9c, 0xa091cf0b, 0xd9155ea3, 0xbb132f88, 0x515bad24, 0x7b9479bf, 0x763bd6eb, 0x37392eb3, 0xcc115979, 0x8026e297, 0xf42e312d, 0x6842ada7, 0xc66a2b3b, 0x12754ccc, 0x782ef11c, 0x6a124237, 0xb79251e7, 0x06a1bbe6, 0x4bfb6350, 0x1a6b1018, 0x11caedfa, 0x3d25bdd8, 0xe2e1c3c9, 0x44421659, 0x0a121386, 0xd90cec6e, 0xd5abea2a, 0x64af674e, 0xda86a85f, 0xbebfe988, 0x64e4c3fe, 0x9dbc8057, 0xf0f7c086, 0x60787bf8, 0x6003604d, 0xd1fd8346, 0xf6381fb0, 0x7745ae04, 0xd736fccc, 0x83426b33, 0xf01eab71, 0xb0804187, 0x3c005e5f, 0x77a057be, 0xbde8ae24, 0x55464299, 0xbf582e61, 0x4e58f48f, 0xf2ddfda2, 0xf474ef38, 0x8789bdc2, 0x5366f9c3, 0xc8b38e74, 0xb475f255, 0x46fcd9b9, 0x7aeb2661, 0x8b1ddf84, 0x846a0e79, 0x915f95e2, 0x466e598e, 0x20b45770, 0x8cd55591, 0xc902de4c, 0xb90bace1, 0xbb8205d0, 0x11a86248, 0x7574a99e, 0xb77f19b6, 0xe0a9dc09, 0x662d09a1, 0xc4324633, 0xe85a1f02, 0x09f0be8c, 0x4a99a025, 0x1d6efe10, 0x1ab93d1d, 0x0ba5a4df, 0xa186f20f, 0x2868f169, 0xdcb7da83, 0x573906fe, 0xa1e2ce9b, 0x4fcd7f52, 0x50115e01, 0xa70683fa, 0xa002b5c4, 0x0de6d027, 0x9af88c27, 0x773f8641, 0xc3604c06, 0x61a806b5, 0xf0177a28, 0xc0f586e0, 0x006058aa, 0x30dc7d62, 0x11e69ed7, 0x2338ea63, 0x53c2dd94, 0xc2c21634, 0xbbcbee56, 0x90bcb6de, 0xebfc7da1, 0xce591d76, 0x6f05e409, 0x4b7c0188, 0x39720a3d, 0x7c927c24, 0x86e3725f, 0x724d9db9, 0x1ac15bb4, 0xd39eb8fc, 0xed545578, 0x08fca5b5, 0xd83d7cd3, 0x4dad0fc4, 0x1e50ef5e, 0xb161e6f8, 0xa28514d9, 0x6c51133c, 0x6fd5c7e7, 0x56e14ec4, 0x362abfce, 0xddc6c837, 0xd79a3234, 0x92638212, 0x670efa8e, 0x406000e0], [0x3a39ce37, 0xd3faf5cf, 0xabc27737, 0x5ac52d1b, 0x5cb0679e, 0x4fa33742, 0xd3822740, 0x99bc9bbe, 0xd5118e9d, 0xbf0f7315, 0xd62d1c7e, 0xc700c47b, 0xb78c1b6b, 0x21a19045, 0xb26eb1be, 0x6a366eb4, 0x5748ab2f, 0xbc946e79, 0xc6a376d2, 0x6549c2c8, 0x530ff8ee, 0x468dde7d, 0xd5730a1d, 0x4cd04dc6, 0x2939bbdb, 0xa9ba4650, 0xac9526e8, 0xbe5ee304, 0xa1fad5f0, 0x6a2d519a, 0x63ef8ce2, 0x9a86ee22, 0xc089c2b8, 0x43242ef6, 0xa51e03aa, 0x9cf2d0a4, 0x83c061ba, 0x9be96a4d, 0x8fe51550, 0xba645bd6, 0x2826a2f9, 0xa73a3ae1, 0x4ba99586, 0xef5562e9, 0xc72fefd3, 0xf752f7da, 0x3f046f69, 0x77fa0a59, 0x80e4a915, 0x87b08601, 0x9b09e6ad, 0x3b3ee593, 0xe990fd5a, 0x9e34d797, 0x2cf0b7d9, 0x022b8b51, 0x96d5ac3a, 0x017da67d, 0xd1cf3ed6, 0x7c7d2d28, 0x1f9f25cf, 0xadf2b89b, 0x5ad6b472, 0x5a88f54c, 0xe029ac71, 0xe019a5e6, 0x47b0acfd, 0xed93fa9b, 0xe8d3c48d, 0x283b57cc, 0xf8d56629, 0x79132e28, 0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c, 0x15056dd4, 0x88f46dba, 0x03a16125, 0x0564f0bd, 0xc3eb9e15, 0x3c9057a2, 0x97271aec, 0xa93a072a, 0x1b3f6d9b, 0x1e6321f5, 0xf59c66fb, 0x26dcf319, 0x7533d928, 0xb155fdf5, 0x03563482, 0x8aba3cbb, 0x28517711, 0xc20ad9f8, 0xabcc5167, 0xccad925f, 0x4de81751, 0x3830dc8e, 0x379d5862, 0x9320f991, 0xea7a90c2, 0xfb3e7bce, 0x5121ce64, 0x774fbe32, 0xa8b6e37e, 0xc3293d46, 0x48de5369, 0x6413e680, 0xa2ae0810, 0xdd6db224, 0x69852dfd, 0x09072166, 0xb39a460a, 0x6445c0dd, 0x586cdecf, 0x1c20c8ae, 0x5bbef7dd, 0x1b588d40, 0xccd2017f, 0x6bb4e3bb, 0xdda26a7e, 0x3a59ff45, 0x3e350a44, 0xbcb4cdd5, 0x72eacea8, 0xfa6484bb, 0x8d6612ae, 0xbf3c6f47, 0xd29be463, 0x542f5d9e, 0xaec2771b, 0xf64e6370, 0x740e0d8d, 0xe75b1357, 0xf8721671, 0xaf537d5d, 0x4040cb08, 0x4eb4e2cc, 0x34d2466a, 0x0115af84, 0xe1b00428, 0x95983a1d, 0x06b89fb4, 0xce6ea048, 0x6f3f3b82, 0x3520ab82, 0x011a1d4b, 0x277227f8, 0x611560b1, 0xe7933fdc, 0xbb3a792b, 0x344525bd, 0xa08839e1, 0x51ce794b, 0x2f32c9b7, 0xa01fbac9, 0xe01cc87e, 0xbcc7d1f6, 0xcf0111c3, 0xa1e8aac7, 0x1a908749, 0xd44fbd9a, 0xd0dadecb, 0xd50ada38, 0x0339c32a, 0xc6913667, 0x8df9317c, 0xe0b12b4f, 0xf79e59b7, 0x43f5bb3a, 0xf2d519ff, 0x27d9459c, 0xbf97222c, 0x15e6fc2a, 0x0f91fc71, 0x9b941525, 0xfae59361, 0xceb69ceb, 0xc2a86459, 0x12baa8d1, 0xb6c1075e, 0xe3056a0c, 0x10d25065, 0xcb03a442, 0xe0ec6e0e, 0x1698db3b, 0x4c98a0be, 0x3278e964, 0x9f1f9532, 0xe0d392df, 0xd3a0342b, 0x8971f21e, 0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8, 0xdf359f8d, 0x9b992f2e, 0xe60b6f47, 0x0fe3f11d, 0xe54cda54, 0x1edad891, 0xce6279cf, 0xcd3e7e6f, 0x1618b166, 0xfd2c1d05, 0x848fd2c5, 0xf6fb2299, 0xf523f357, 0xa6327623, 0x93a83531, 0x56cccd02, 0xacf08162, 0x5a75ebb5, 0x6e163697, 0x88d273cc, 0xde966292, 0x81b949d0, 0x4c50901b, 0x71c65614, 0xe6c6c7bd, 0x327a140a, 0x45e1d006, 0xc3f27b9a, 0xc9aa53fd, 0x62a80f00, 0xbb25bfe2, 0x35bdd2f6, 0x71126905, 0xb2040222, 0xb6cbcf7c, 0xcd769c2b, 0x53113ec0, 0x1640e3d3, 0x38abbd60, 0x2547adf0, 0xba38209c, 0xf746ce76, 0x77afa1c5, 0x20756060, 0x85cbfe4e, 0x8ae88dd8, 0x7aaaf9b0, 0x4cf9aa7e, 0x1948c25c, 0x02fb8a8c, 0x01c36ae4, 0xd6ebe1f9, 0x90d4f869, 0xa65cdea0, 0x3f09252d, 0xc208e69f, 0xb74e6132, 0xce77e25b, 0x578fdfe3, 0x3ac372e6]];

//*
//* This is the default PARRAY
//*
Blowfish.prototype.PARRAY = [0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b];

//*
//* This is the number of rounds the cipher will go
//*
Blowfish.prototype.NN = 16;

//*
//* This function is needed to get rid of problems
//* with the high-bit getting set.  If we don't do
//* this, then sometimes ( aa & 0x00FFFFFFFF ) is not
//* equal to ( bb & 0x00FFFFFFFF ) even when they
//* agree bit-for-bit for the first 32 bits.
//*
Blowfish.prototype._clean = function (xx) {
  if (xx < 0) {
    var yy = xx & 0x7FFFFFFF;
    xx = yy + 0x80000000;
  }
  return xx;
};

//*
//* This is the mixing function that uses the sboxes
//*
Blowfish.prototype._F = function (xx) {
  var aa;
  var bb;
  var cc;
  var dd;
  var yy;

  dd = xx & 0x00FF;
  xx >>>= 8;
  cc = xx & 0x00FF;
  xx >>>= 8;
  bb = xx & 0x00FF;
  xx >>>= 8;
  aa = xx & 0x00FF;

  yy = this.sboxes[0][aa] + this.sboxes[1][bb];
  yy = yy ^ this.sboxes[2][cc];
  yy = yy + this.sboxes[3][dd];

  return yy;
};

//*
//* This method takes an array with two values, left and right
//* and does NN rounds of Blowfish on them.
//*
Blowfish.prototype._encrypt_block = function (vals) {
  var dataL = vals[0];
  var dataR = vals[1];

  var ii;

  for (ii = 0; ii < this.NN; ++ii) {
    dataL = dataL ^ this.parray[ii];
    dataR = this._F(dataL) ^ dataR;

    var tmp = dataL;
    dataL = dataR;
    dataR = tmp;
  }

  dataL = dataL ^ this.parray[this.NN + 0];
  dataR = dataR ^ this.parray[this.NN + 1];

  vals[0] = this._clean(dataR);
  vals[1] = this._clean(dataL);
};

//*
//* This method takes a vector of numbers and turns them
//* into long words so that they can be processed by the
//* real algorithm.
//*
//* Maybe I should make the real algorithm above take a vector
//* instead.  That will involve more looping, but it won't require
//* the F() method to deconstruct the vector.
//*
Blowfish.prototype.encrypt_block = function (vector) {
  var ii;
  var vals = [0, 0];
  var off = this.BLOCKSIZE / 2;
  for (ii = 0; ii < this.BLOCKSIZE / 2; ++ii) {
    vals[0] = vals[0] << 8 | vector[ii + 0] & 0x00FF;
    vals[1] = vals[1] << 8 | vector[ii + off] & 0x00FF;
  }

  this._encrypt_block(vals);

  var ret = [];
  for (ii = 0; ii < this.BLOCKSIZE / 2; ++ii) {
    ret[ii + 0] = vals[0] >>> 24 - 8 * ii & 0x00FF;
    ret[ii + off] = vals[1] >>> 24 - 8 * ii & 0x00FF;
    // vals[ 0 ] = ( vals[ 0 ] >>> 8 );
    // vals[ 1 ] = ( vals[ 1 ] >>> 8 );
  }

  return ret;
};

//*
//* This method takes an array with two values, left and right
//* and undoes NN rounds of Blowfish on them.
//*
Blowfish.prototype._decrypt_block = function (vals) {
  var dataL = vals[0];
  var dataR = vals[1];

  var ii;

  for (ii = this.NN + 1; ii > 1; --ii) {
    dataL = dataL ^ this.parray[ii];
    dataR = this._F(dataL) ^ dataR;

    var tmp = dataL;
    dataL = dataR;
    dataR = tmp;
  }

  dataL = dataL ^ this.parray[1];
  dataR = dataR ^ this.parray[0];

  vals[0] = this._clean(dataR);
  vals[1] = this._clean(dataL);
};

//*
//* This method takes a key array and initializes the
//* sboxes and parray for this encryption.
//*
Blowfish.prototype.init = function (key) {
  var ii;
  var jj = 0;

  this.parray = [];
  for (ii = 0; ii < this.NN + 2; ++ii) {
    var data = 0x00000000;
    var kk;
    for (kk = 0; kk < 4; ++kk) {
      data = data << 8 | key[jj] & 0x00FF;
      if (++jj >= key.length) {
        jj = 0;
      }
    }
    this.parray[ii] = this.PARRAY[ii] ^ data;
  }

  this.sboxes = [];
  for (ii = 0; ii < 4; ++ii) {
    this.sboxes[ii] = [];
    for (jj = 0; jj < 256; ++jj) {
      this.sboxes[ii][jj] = this.SBOXES[ii][jj];
    }
  }

  var vals = [0x00000000, 0x00000000];

  for (ii = 0; ii < this.NN + 2; ii += 2) {
    this._encrypt_block(vals);
    this.parray[ii + 0] = vals[0];
    this.parray[ii + 1] = vals[1];
  }

  for (ii = 0; ii < 4; ++ii) {
    for (jj = 0; jj < 256; jj += 2) {
      this._encrypt_block(vals);
      this.sboxes[ii][jj + 0] = vals[0];
      this.sboxes[ii][jj + 1] = vals[1];
    }
  }
};

// added by Recurity Labs

function BF(key) {
  this.bf = new Blowfish();
  this.bf.init(key);

  this.encrypt = function (block) {
    return this.bf.encrypt_block(block);
  };
}
BF.keySize = BF.prototype.keySize = 16;
BF.blockSize = BF.prototype.blockSize = 16;

},{}],14:[function(_dereq_,module,exports){
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Copyright 2010 pjacobs@xeekr.com . All rights reserved.

// Modified by Recurity Labs GmbH

// fixed/modified by Herbert Hanewinkel, www.haneWIN.de
// check www.haneWIN.de for the latest version

// cast5.js is a Javascript implementation of CAST-128, as defined in RFC 2144.
// CAST-128 is a common OpenPGP cipher.

// CAST5 constructor

/** @module crypto/cipher/cast5 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = Cast5;
function OpenpgpSymencCast5() {
  this.BlockSize = 8;
  this.KeySize = 16;

  this.setKey = function (key) {
    this.masking = new Array(16);
    this.rotate = new Array(16);

    this.reset();

    if (key.length === this.KeySize) {
      this.keySchedule(key);
    } else {
      throw new Error('CAST-128: keys must be 16 bytes');
    }
    return true;
  };

  this.reset = function () {
    for (var i = 0; i < 16; i++) {
      this.masking[i] = 0;
      this.rotate[i] = 0;
    }
  };

  this.getBlockSize = function () {
    return this.BlockSize;
  };

  this.encrypt = function (src) {
    var dst = new Array(src.length);

    for (var i = 0; i < src.length; i += 8) {
      var l = src[i] << 24 | src[i + 1] << 16 | src[i + 2] << 8 | src[i + 3];
      var r = src[i + 4] << 24 | src[i + 5] << 16 | src[i + 6] << 8 | src[i + 7];
      var t;

      t = r;
      r = l ^ f1(r, this.masking[0], this.rotate[0]);
      l = t;
      t = r;
      r = l ^ f2(r, this.masking[1], this.rotate[1]);
      l = t;
      t = r;
      r = l ^ f3(r, this.masking[2], this.rotate[2]);
      l = t;
      t = r;
      r = l ^ f1(r, this.masking[3], this.rotate[3]);
      l = t;

      t = r;
      r = l ^ f2(r, this.masking[4], this.rotate[4]);
      l = t;
      t = r;
      r = l ^ f3(r, this.masking[5], this.rotate[5]);
      l = t;
      t = r;
      r = l ^ f1(r, this.masking[6], this.rotate[6]);
      l = t;
      t = r;
      r = l ^ f2(r, this.masking[7], this.rotate[7]);
      l = t;

      t = r;
      r = l ^ f3(r, this.masking[8], this.rotate[8]);
      l = t;
      t = r;
      r = l ^ f1(r, this.masking[9], this.rotate[9]);
      l = t;
      t = r;
      r = l ^ f2(r, this.masking[10], this.rotate[10]);
      l = t;
      t = r;
      r = l ^ f3(r, this.masking[11], this.rotate[11]);
      l = t;

      t = r;
      r = l ^ f1(r, this.masking[12], this.rotate[12]);
      l = t;
      t = r;
      r = l ^ f2(r, this.masking[13], this.rotate[13]);
      l = t;
      t = r;
      r = l ^ f3(r, this.masking[14], this.rotate[14]);
      l = t;
      t = r;
      r = l ^ f1(r, this.masking[15], this.rotate[15]);
      l = t;

      dst[i] = r >>> 24 & 255;
      dst[i + 1] = r >>> 16 & 255;
      dst[i + 2] = r >>> 8 & 255;
      dst[i + 3] = r & 255;
      dst[i + 4] = l >>> 24 & 255;
      dst[i + 5] = l >>> 16 & 255;
      dst[i + 6] = l >>> 8 & 255;
      dst[i + 7] = l & 255;
    }

    return dst;
  };

  this.decrypt = function (src) {
    var dst = new Array(src.length);

    for (var i = 0; i < src.length; i += 8) {
      var l = src[i] << 24 | src[i + 1] << 16 | src[i + 2] << 8 | src[i + 3];
      var r = src[i + 4] << 24 | src[i + 5] << 16 | src[i + 6] << 8 | src[i + 7];
      var t;

      t = r;
      r = l ^ f1(r, this.masking[15], this.rotate[15]);
      l = t;
      t = r;
      r = l ^ f3(r, this.masking[14], this.rotate[14]);
      l = t;
      t = r;
      r = l ^ f2(r, this.masking[13], this.rotate[13]);
      l = t;
      t = r;
      r = l ^ f1(r, this.masking[12], this.rotate[12]);
      l = t;

      t = r;
      r = l ^ f3(r, this.masking[11], this.rotate[11]);
      l = t;
      t = r;
      r = l ^ f2(r, this.masking[10], this.rotate[10]);
      l = t;
      t = r;
      r = l ^ f1(r, this.masking[9], this.rotate[9]);
      l = t;
      t = r;
      r = l ^ f3(r, this.masking[8], this.rotate[8]);
      l = t;

      t = r;
      r = l ^ f2(r, this.masking[7], this.rotate[7]);
      l = t;
      t = r;
      r = l ^ f1(r, this.masking[6], this.rotate[6]);
      l = t;
      t = r;
      r = l ^ f3(r, this.masking[5], this.rotate[5]);
      l = t;
      t = r;
      r = l ^ f2(r, this.masking[4], this.rotate[4]);
      l = t;

      t = r;
      r = l ^ f1(r, this.masking[3], this.rotate[3]);
      l = t;
      t = r;
      r = l ^ f3(r, this.masking[2], this.rotate[2]);
      l = t;
      t = r;
      r = l ^ f2(r, this.masking[1], this.rotate[1]);
      l = t;
      t = r;
      r = l ^ f1(r, this.masking[0], this.rotate[0]);
      l = t;

      dst[i] = r >>> 24 & 255;
      dst[i + 1] = r >>> 16 & 255;
      dst[i + 2] = r >>> 8 & 255;
      dst[i + 3] = r & 255;
      dst[i + 4] = l >>> 24 & 255;
      dst[i + 5] = l >> 16 & 255;
      dst[i + 6] = l >> 8 & 255;
      dst[i + 7] = l & 255;
    }

    return dst;
  };
  var scheduleA = new Array(4);

  scheduleA[0] = new Array(4);
  scheduleA[0][0] = new Array(4, 0, 0xd, 0xf, 0xc, 0xe, 0x8);
  scheduleA[0][1] = new Array(5, 2, 16 + 0, 16 + 2, 16 + 1, 16 + 3, 0xa);
  scheduleA[0][2] = new Array(6, 3, 16 + 7, 16 + 6, 16 + 5, 16 + 4, 9);
  scheduleA[0][3] = new Array(7, 1, 16 + 0xa, 16 + 9, 16 + 0xb, 16 + 8, 0xb);

  scheduleA[1] = new Array(4);
  scheduleA[1][0] = new Array(0, 6, 16 + 5, 16 + 7, 16 + 4, 16 + 6, 16 + 0);
  scheduleA[1][1] = new Array(1, 4, 0, 2, 1, 3, 16 + 2);
  scheduleA[1][2] = new Array(2, 5, 7, 6, 5, 4, 16 + 1);
  scheduleA[1][3] = new Array(3, 7, 0xa, 9, 0xb, 8, 16 + 3);

  scheduleA[2] = new Array(4);
  scheduleA[2][0] = new Array(4, 0, 0xd, 0xf, 0xc, 0xe, 8);
  scheduleA[2][1] = new Array(5, 2, 16 + 0, 16 + 2, 16 + 1, 16 + 3, 0xa);
  scheduleA[2][2] = new Array(6, 3, 16 + 7, 16 + 6, 16 + 5, 16 + 4, 9);
  scheduleA[2][3] = new Array(7, 1, 16 + 0xa, 16 + 9, 16 + 0xb, 16 + 8, 0xb);

  scheduleA[3] = new Array(4);
  scheduleA[3][0] = new Array(0, 6, 16 + 5, 16 + 7, 16 + 4, 16 + 6, 16 + 0);
  scheduleA[3][1] = new Array(1, 4, 0, 2, 1, 3, 16 + 2);
  scheduleA[3][2] = new Array(2, 5, 7, 6, 5, 4, 16 + 1);
  scheduleA[3][3] = new Array(3, 7, 0xa, 9, 0xb, 8, 16 + 3);

  var scheduleB = new Array(4);

  scheduleB[0] = new Array(4);
  scheduleB[0][0] = new Array(16 + 8, 16 + 9, 16 + 7, 16 + 6, 16 + 2);
  scheduleB[0][1] = new Array(16 + 0xa, 16 + 0xb, 16 + 5, 16 + 4, 16 + 6);
  scheduleB[0][2] = new Array(16 + 0xc, 16 + 0xd, 16 + 3, 16 + 2, 16 + 9);
  scheduleB[0][3] = new Array(16 + 0xe, 16 + 0xf, 16 + 1, 16 + 0, 16 + 0xc);

  scheduleB[1] = new Array(4);
  scheduleB[1][0] = new Array(3, 2, 0xc, 0xd, 8);
  scheduleB[1][1] = new Array(1, 0, 0xe, 0xf, 0xd);
  scheduleB[1][2] = new Array(7, 6, 8, 9, 3);
  scheduleB[1][3] = new Array(5, 4, 0xa, 0xb, 7);

  scheduleB[2] = new Array(4);
  scheduleB[2][0] = new Array(16 + 3, 16 + 2, 16 + 0xc, 16 + 0xd, 16 + 9);
  scheduleB[2][1] = new Array(16 + 1, 16 + 0, 16 + 0xe, 16 + 0xf, 16 + 0xc);
  scheduleB[2][2] = new Array(16 + 7, 16 + 6, 16 + 8, 16 + 9, 16 + 2);
  scheduleB[2][3] = new Array(16 + 5, 16 + 4, 16 + 0xa, 16 + 0xb, 16 + 6);

  scheduleB[3] = new Array(4);
  scheduleB[3][0] = new Array(8, 9, 7, 6, 3);
  scheduleB[3][1] = new Array(0xa, 0xb, 5, 4, 7);
  scheduleB[3][2] = new Array(0xc, 0xd, 3, 2, 8);
  scheduleB[3][3] = new Array(0xe, 0xf, 1, 0, 0xd);

  // changed 'in' to 'inn' (in javascript 'in' is a reserved word)
  this.keySchedule = function (inn) {
    var t = new Array(8);
    var k = new Array(32);

    var i, j;

    for (i = 0; i < 4; i++) {
      j = i * 4;
      t[i] = inn[j] << 24 | inn[j + 1] << 16 | inn[j + 2] << 8 | inn[j + 3];
    }

    var x = [6, 7, 4, 5];
    var ki = 0;
    var w;

    for (var half = 0; half < 2; half++) {
      for (var round = 0; round < 4; round++) {
        for (j = 0; j < 4; j++) {
          var a = scheduleA[round][j];
          w = t[a[1]];

          w ^= sBox[4][t[a[2] >>> 2] >>> 24 - 8 * (a[2] & 3) & 0xff];
          w ^= sBox[5][t[a[3] >>> 2] >>> 24 - 8 * (a[3] & 3) & 0xff];
          w ^= sBox[6][t[a[4] >>> 2] >>> 24 - 8 * (a[4] & 3) & 0xff];
          w ^= sBox[7][t[a[5] >>> 2] >>> 24 - 8 * (a[5] & 3) & 0xff];
          w ^= sBox[x[j]][t[a[6] >>> 2] >>> 24 - 8 * (a[6] & 3) & 0xff];
          t[a[0]] = w;
        }

        for (j = 0; j < 4; j++) {
          var b = scheduleB[round][j];
          w = sBox[4][t[b[0] >>> 2] >>> 24 - 8 * (b[0] & 3) & 0xff];

          w ^= sBox[5][t[b[1] >>> 2] >>> 24 - 8 * (b[1] & 3) & 0xff];
          w ^= sBox[6][t[b[2] >>> 2] >>> 24 - 8 * (b[2] & 3) & 0xff];
          w ^= sBox[7][t[b[3] >>> 2] >>> 24 - 8 * (b[3] & 3) & 0xff];
          w ^= sBox[4 + j][t[b[4] >>> 2] >>> 24 - 8 * (b[4] & 3) & 0xff];
          k[ki] = w;
          ki++;
        }
      }
    }

    for (i = 0; i < 16; i++) {
      this.masking[i] = k[i];
      this.rotate[i] = k[16 + i] & 0x1f;
    }
  };

  // These are the three 'f' functions. See RFC 2144, section 2.2.

  function f1(d, m, r) {
    var t = m + d;
    var I = t << r | t >>> 32 - r;
    return (sBox[0][I >>> 24] ^ sBox[1][I >>> 16 & 255]) - sBox[2][I >>> 8 & 255] + sBox[3][I & 255];
  }

  function f2(d, m, r) {
    var t = m ^ d;
    var I = t << r | t >>> 32 - r;
    return sBox[0][I >>> 24] - sBox[1][I >>> 16 & 255] + sBox[2][I >>> 8 & 255] ^ sBox[3][I & 255];
  }

  function f3(d, m, r) {
    var t = m - d;
    var I = t << r | t >>> 32 - r;
    return (sBox[0][I >>> 24] + sBox[1][I >>> 16 & 255] ^ sBox[2][I >>> 8 & 255]) - sBox[3][I & 255];
  }

  var sBox = new Array(8);
  sBox[0] = new Array(0x30fb40d4, 0x9fa0ff0b, 0x6beccd2f, 0x3f258c7a, 0x1e213f2f, 0x9c004dd3, 0x6003e540, 0xcf9fc949, 0xbfd4af27, 0x88bbbdb5, 0xe2034090, 0x98d09675, 0x6e63a0e0, 0x15c361d2, 0xc2e7661d, 0x22d4ff8e, 0x28683b6f, 0xc07fd059, 0xff2379c8, 0x775f50e2, 0x43c340d3, 0xdf2f8656, 0x887ca41a, 0xa2d2bd2d, 0xa1c9e0d6, 0x346c4819, 0x61b76d87, 0x22540f2f, 0x2abe32e1, 0xaa54166b, 0x22568e3a, 0xa2d341d0, 0x66db40c8, 0xa784392f, 0x004dff2f, 0x2db9d2de, 0x97943fac, 0x4a97c1d8, 0x527644b7, 0xb5f437a7, 0xb82cbaef, 0xd751d159, 0x6ff7f0ed, 0x5a097a1f, 0x827b68d0, 0x90ecf52e, 0x22b0c054, 0xbc8e5935, 0x4b6d2f7f, 0x50bb64a2, 0xd2664910, 0xbee5812d, 0xb7332290, 0xe93b159f, 0xb48ee411, 0x4bff345d, 0xfd45c240, 0xad31973f, 0xc4f6d02e, 0x55fc8165, 0xd5b1caad, 0xa1ac2dae, 0xa2d4b76d, 0xc19b0c50, 0x882240f2, 0x0c6e4f38, 0xa4e4bfd7, 0x4f5ba272, 0x564c1d2f, 0xc59c5319, 0xb949e354, 0xb04669fe, 0xb1b6ab8a, 0xc71358dd, 0x6385c545, 0x110f935d, 0x57538ad5, 0x6a390493, 0xe63d37e0, 0x2a54f6b3, 0x3a787d5f, 0x6276a0b5, 0x19a6fcdf, 0x7a42206a, 0x29f9d4d5, 0xf61b1891, 0xbb72275e, 0xaa508167, 0x38901091, 0xc6b505eb, 0x84c7cb8c, 0x2ad75a0f, 0x874a1427, 0xa2d1936b, 0x2ad286af, 0xaa56d291, 0xd7894360, 0x425c750d, 0x93b39e26, 0x187184c9, 0x6c00b32d, 0x73e2bb14, 0xa0bebc3c, 0x54623779, 0x64459eab, 0x3f328b82, 0x7718cf82, 0x59a2cea6, 0x04ee002e, 0x89fe78e6, 0x3fab0950, 0x325ff6c2, 0x81383f05, 0x6963c5c8, 0x76cb5ad6, 0xd49974c9, 0xca180dcf, 0x380782d5, 0xc7fa5cf6, 0x8ac31511, 0x35e79e13, 0x47da91d0, 0xf40f9086, 0xa7e2419e, 0x31366241, 0x051ef495, 0xaa573b04, 0x4a805d8d, 0x548300d0, 0x00322a3c, 0xbf64cddf, 0xba57a68e, 0x75c6372b, 0x50afd341, 0xa7c13275, 0x915a0bf5, 0x6b54bfab, 0x2b0b1426, 0xab4cc9d7, 0x449ccd82, 0xf7fbf265, 0xab85c5f3, 0x1b55db94, 0xaad4e324, 0xcfa4bd3f, 0x2deaa3e2, 0x9e204d02, 0xc8bd25ac, 0xeadf55b3, 0xd5bd9e98, 0xe31231b2, 0x2ad5ad6c, 0x954329de, 0xadbe4528, 0xd8710f69, 0xaa51c90f, 0xaa786bf6, 0x22513f1e, 0xaa51a79b, 0x2ad344cc, 0x7b5a41f0, 0xd37cfbad, 0x1b069505, 0x41ece491, 0xb4c332e6, 0x032268d4, 0xc9600acc, 0xce387e6d, 0xbf6bb16c, 0x6a70fb78, 0x0d03d9c9, 0xd4df39de, 0xe01063da, 0x4736f464, 0x5ad328d8, 0xb347cc96, 0x75bb0fc3, 0x98511bfb, 0x4ffbcc35, 0xb58bcf6a, 0xe11f0abc, 0xbfc5fe4a, 0xa70aec10, 0xac39570a, 0x3f04442f, 0x6188b153, 0xe0397a2e, 0x5727cb79, 0x9ceb418f, 0x1cacd68d, 0x2ad37c96, 0x0175cb9d, 0xc69dff09, 0xc75b65f0, 0xd9db40d8, 0xec0e7779, 0x4744ead4, 0xb11c3274, 0xdd24cb9e, 0x7e1c54bd, 0xf01144f9, 0xd2240eb1, 0x9675b3fd, 0xa3ac3755, 0xd47c27af, 0x51c85f4d, 0x56907596, 0xa5bb15e6, 0x580304f0, 0xca042cf1, 0x011a37ea, 0x8dbfaadb, 0x35ba3e4a, 0x3526ffa0, 0xc37b4d09, 0xbc306ed9, 0x98a52666, 0x5648f725, 0xff5e569d, 0x0ced63d0, 0x7c63b2cf, 0x700b45e1, 0xd5ea50f1, 0x85a92872, 0xaf1fbda7, 0xd4234870, 0xa7870bf3, 0x2d3b4d79, 0x42e04198, 0x0cd0ede7, 0x26470db8, 0xf881814c, 0x474d6ad7, 0x7c0c5e5c, 0xd1231959, 0x381b7298, 0xf5d2f4db, 0xab838653, 0x6e2f1e23, 0x83719c9e, 0xbd91e046, 0x9a56456e, 0xdc39200c, 0x20c8c571, 0x962bda1c, 0xe1e696ff, 0xb141ab08, 0x7cca89b9, 0x1a69e783, 0x02cc4843, 0xa2f7c579, 0x429ef47d, 0x427b169c, 0x5ac9f049, 0xdd8f0f00, 0x5c8165bf);

  sBox[1] = new Array(0x1f201094, 0xef0ba75b, 0x69e3cf7e, 0x393f4380, 0xfe61cf7a, 0xeec5207a, 0x55889c94, 0x72fc0651, 0xada7ef79, 0x4e1d7235, 0xd55a63ce, 0xde0436ba, 0x99c430ef, 0x5f0c0794, 0x18dcdb7d, 0xa1d6eff3, 0xa0b52f7b, 0x59e83605, 0xee15b094, 0xe9ffd909, 0xdc440086, 0xef944459, 0xba83ccb3, 0xe0c3cdfb, 0xd1da4181, 0x3b092ab1, 0xf997f1c1, 0xa5e6cf7b, 0x01420ddb, 0xe4e7ef5b, 0x25a1ff41, 0xe180f806, 0x1fc41080, 0x179bee7a, 0xd37ac6a9, 0xfe5830a4, 0x98de8b7f, 0x77e83f4e, 0x79929269, 0x24fa9f7b, 0xe113c85b, 0xacc40083, 0xd7503525, 0xf7ea615f, 0x62143154, 0x0d554b63, 0x5d681121, 0xc866c359, 0x3d63cf73, 0xcee234c0, 0xd4d87e87, 0x5c672b21, 0x071f6181, 0x39f7627f, 0x361e3084, 0xe4eb573b, 0x602f64a4, 0xd63acd9c, 0x1bbc4635, 0x9e81032d, 0x2701f50c, 0x99847ab4, 0xa0e3df79, 0xba6cf38c, 0x10843094, 0x2537a95e, 0xf46f6ffe, 0xa1ff3b1f, 0x208cfb6a, 0x8f458c74, 0xd9e0a227, 0x4ec73a34, 0xfc884f69, 0x3e4de8df, 0xef0e0088, 0x3559648d, 0x8a45388c, 0x1d804366, 0x721d9bfd, 0xa58684bb, 0xe8256333, 0x844e8212, 0x128d8098, 0xfed33fb4, 0xce280ae1, 0x27e19ba5, 0xd5a6c252, 0xe49754bd, 0xc5d655dd, 0xeb667064, 0x77840b4d, 0xa1b6a801, 0x84db26a9, 0xe0b56714, 0x21f043b7, 0xe5d05860, 0x54f03084, 0x066ff472, 0xa31aa153, 0xdadc4755, 0xb5625dbf, 0x68561be6, 0x83ca6b94, 0x2d6ed23b, 0xeccf01db, 0xa6d3d0ba, 0xb6803d5c, 0xaf77a709, 0x33b4a34c, 0x397bc8d6, 0x5ee22b95, 0x5f0e5304, 0x81ed6f61, 0x20e74364, 0xb45e1378, 0xde18639b, 0x881ca122, 0xb96726d1, 0x8049a7e8, 0x22b7da7b, 0x5e552d25, 0x5272d237, 0x79d2951c, 0xc60d894c, 0x488cb402, 0x1ba4fe5b, 0xa4b09f6b, 0x1ca815cf, 0xa20c3005, 0x8871df63, 0xb9de2fcb, 0x0cc6c9e9, 0x0beeff53, 0xe3214517, 0xb4542835, 0x9f63293c, 0xee41e729, 0x6e1d2d7c, 0x50045286, 0x1e6685f3, 0xf33401c6, 0x30a22c95, 0x31a70850, 0x60930f13, 0x73f98417, 0xa1269859, 0xec645c44, 0x52c877a9, 0xcdff33a6, 0xa02b1741, 0x7cbad9a2, 0x2180036f, 0x50d99c08, 0xcb3f4861, 0xc26bd765, 0x64a3f6ab, 0x80342676, 0x25a75e7b, 0xe4e6d1fc, 0x20c710e6, 0xcdf0b680, 0x17844d3b, 0x31eef84d, 0x7e0824e4, 0x2ccb49eb, 0x846a3bae, 0x8ff77888, 0xee5d60f6, 0x7af75673, 0x2fdd5cdb, 0xa11631c1, 0x30f66f43, 0xb3faec54, 0x157fd7fa, 0xef8579cc, 0xd152de58, 0xdb2ffd5e, 0x8f32ce19, 0x306af97a, 0x02f03ef8, 0x99319ad5, 0xc242fa0f, 0xa7e3ebb0, 0xc68e4906, 0xb8da230c, 0x80823028, 0xdcdef3c8, 0xd35fb171, 0x088a1bc8, 0xbec0c560, 0x61a3c9e8, 0xbca8f54d, 0xc72feffa, 0x22822e99, 0x82c570b4, 0xd8d94e89, 0x8b1c34bc, 0x301e16e6, 0x273be979, 0xb0ffeaa6, 0x61d9b8c6, 0x00b24869, 0xb7ffce3f, 0x08dc283b, 0x43daf65a, 0xf7e19798, 0x7619b72f, 0x8f1c9ba4, 0xdc8637a0, 0x16a7d3b1, 0x9fc393b7, 0xa7136eeb, 0xc6bcc63e, 0x1a513742, 0xef6828bc, 0x520365d6, 0x2d6a77ab, 0x3527ed4b, 0x821fd216, 0x095c6e2e, 0xdb92f2fb, 0x5eea29cb, 0x145892f5, 0x91584f7f, 0x5483697b, 0x2667a8cc, 0x85196048, 0x8c4bacea, 0x833860d4, 0x0d23e0f9, 0x6c387e8a, 0x0ae6d249, 0xb284600c, 0xd835731d, 0xdcb1c647, 0xac4c56ea, 0x3ebd81b3, 0x230eabb0, 0x6438bc87, 0xf0b5b1fa, 0x8f5ea2b3, 0xfc184642, 0x0a036b7a, 0x4fb089bd, 0x649da589, 0xa345415e, 0x5c038323, 0x3e5d3bb9, 0x43d79572, 0x7e6dd07c, 0x06dfdf1e, 0x6c6cc4ef, 0x7160a539, 0x73bfbe70, 0x83877605, 0x4523ecf1);

  sBox[2] = new Array(0x8defc240, 0x25fa5d9f, 0xeb903dbf, 0xe810c907, 0x47607fff, 0x369fe44b, 0x8c1fc644, 0xaececa90, 0xbeb1f9bf, 0xeefbcaea, 0xe8cf1950, 0x51df07ae, 0x920e8806, 0xf0ad0548, 0xe13c8d83, 0x927010d5, 0x11107d9f, 0x07647db9, 0xb2e3e4d4, 0x3d4f285e, 0xb9afa820, 0xfade82e0, 0xa067268b, 0x8272792e, 0x553fb2c0, 0x489ae22b, 0xd4ef9794, 0x125e3fbc, 0x21fffcee, 0x825b1bfd, 0x9255c5ed, 0x1257a240, 0x4e1a8302, 0xbae07fff, 0x528246e7, 0x8e57140e, 0x3373f7bf, 0x8c9f8188, 0xa6fc4ee8, 0xc982b5a5, 0xa8c01db7, 0x579fc264, 0x67094f31, 0xf2bd3f5f, 0x40fff7c1, 0x1fb78dfc, 0x8e6bd2c1, 0x437be59b, 0x99b03dbf, 0xb5dbc64b, 0x638dc0e6, 0x55819d99, 0xa197c81c, 0x4a012d6e, 0xc5884a28, 0xccc36f71, 0xb843c213, 0x6c0743f1, 0x8309893c, 0x0feddd5f, 0x2f7fe850, 0xd7c07f7e, 0x02507fbf, 0x5afb9a04, 0xa747d2d0, 0x1651192e, 0xaf70bf3e, 0x58c31380, 0x5f98302e, 0x727cc3c4, 0x0a0fb402, 0x0f7fef82, 0x8c96fdad, 0x5d2c2aae, 0x8ee99a49, 0x50da88b8, 0x8427f4a0, 0x1eac5790, 0x796fb449, 0x8252dc15, 0xefbd7d9b, 0xa672597d, 0xada840d8, 0x45f54504, 0xfa5d7403, 0xe83ec305, 0x4f91751a, 0x925669c2, 0x23efe941, 0xa903f12e, 0x60270df2, 0x0276e4b6, 0x94fd6574, 0x927985b2, 0x8276dbcb, 0x02778176, 0xf8af918d, 0x4e48f79e, 0x8f616ddf, 0xe29d840e, 0x842f7d83, 0x340ce5c8, 0x96bbb682, 0x93b4b148, 0xef303cab, 0x984faf28, 0x779faf9b, 0x92dc560d, 0x224d1e20, 0x8437aa88, 0x7d29dc96, 0x2756d3dc, 0x8b907cee, 0xb51fd240, 0xe7c07ce3, 0xe566b4a1, 0xc3e9615e, 0x3cf8209d, 0x6094d1e3, 0xcd9ca341, 0x5c76460e, 0x00ea983b, 0xd4d67881, 0xfd47572c, 0xf76cedd9, 0xbda8229c, 0x127dadaa, 0x438a074e, 0x1f97c090, 0x081bdb8a, 0x93a07ebe, 0xb938ca15, 0x97b03cff, 0x3dc2c0f8, 0x8d1ab2ec, 0x64380e51, 0x68cc7bfb, 0xd90f2788, 0x12490181, 0x5de5ffd4, 0xdd7ef86a, 0x76a2e214, 0xb9a40368, 0x925d958f, 0x4b39fffa, 0xba39aee9, 0xa4ffd30b, 0xfaf7933b, 0x6d498623, 0x193cbcfa, 0x27627545, 0x825cf47a, 0x61bd8ba0, 0xd11e42d1, 0xcead04f4, 0x127ea392, 0x10428db7, 0x8272a972, 0x9270c4a8, 0x127de50b, 0x285ba1c8, 0x3c62f44f, 0x35c0eaa5, 0xe805d231, 0x428929fb, 0xb4fcdf82, 0x4fb66a53, 0x0e7dc15b, 0x1f081fab, 0x108618ae, 0xfcfd086d, 0xf9ff2889, 0x694bcc11, 0x236a5cae, 0x12deca4d, 0x2c3f8cc5, 0xd2d02dfe, 0xf8ef5896, 0xe4cf52da, 0x95155b67, 0x494a488c, 0xb9b6a80c, 0x5c8f82bc, 0x89d36b45, 0x3a609437, 0xec00c9a9, 0x44715253, 0x0a874b49, 0xd773bc40, 0x7c34671c, 0x02717ef6, 0x4feb5536, 0xa2d02fff, 0xd2bf60c4, 0xd43f03c0, 0x50b4ef6d, 0x07478cd1, 0x006e1888, 0xa2e53f55, 0xb9e6d4bc, 0xa2048016, 0x97573833, 0xd7207d67, 0xde0f8f3d, 0x72f87b33, 0xabcc4f33, 0x7688c55d, 0x7b00a6b0, 0x947b0001, 0x570075d2, 0xf9bb88f8, 0x8942019e, 0x4264a5ff, 0x856302e0, 0x72dbd92b, 0xee971b69, 0x6ea22fde, 0x5f08ae2b, 0xaf7a616d, 0xe5c98767, 0xcf1febd2, 0x61efc8c2, 0xf1ac2571, 0xcc8239c2, 0x67214cb8, 0xb1e583d1, 0xb7dc3e62, 0x7f10bdce, 0xf90a5c38, 0x0ff0443d, 0x606e6dc6, 0x60543a49, 0x5727c148, 0x2be98a1d, 0x8ab41738, 0x20e1be24, 0xaf96da0f, 0x68458425, 0x99833be5, 0x600d457d, 0x282f9350, 0x8334b362, 0xd91d1120, 0x2b6d8da0, 0x642b1e31, 0x9c305a00, 0x52bce688, 0x1b03588a, 0xf7baefd5, 0x4142ed9c, 0xa4315c11, 0x83323ec5, 0xdfef4636, 0xa133c501, 0xe9d3531c, 0xee353783);

  sBox[3] = new Array(0x9db30420, 0x1fb6e9de, 0xa7be7bef, 0xd273a298, 0x4a4f7bdb, 0x64ad8c57, 0x85510443, 0xfa020ed1, 0x7e287aff, 0xe60fb663, 0x095f35a1, 0x79ebf120, 0xfd059d43, 0x6497b7b1, 0xf3641f63, 0x241e4adf, 0x28147f5f, 0x4fa2b8cd, 0xc9430040, 0x0cc32220, 0xfdd30b30, 0xc0a5374f, 0x1d2d00d9, 0x24147b15, 0xee4d111a, 0x0fca5167, 0x71ff904c, 0x2d195ffe, 0x1a05645f, 0x0c13fefe, 0x081b08ca, 0x05170121, 0x80530100, 0xe83e5efe, 0xac9af4f8, 0x7fe72701, 0xd2b8ee5f, 0x06df4261, 0xbb9e9b8a, 0x7293ea25, 0xce84ffdf, 0xf5718801, 0x3dd64b04, 0xa26f263b, 0x7ed48400, 0x547eebe6, 0x446d4ca0, 0x6cf3d6f5, 0x2649abdf, 0xaea0c7f5, 0x36338cc1, 0x503f7e93, 0xd3772061, 0x11b638e1, 0x72500e03, 0xf80eb2bb, 0xabe0502e, 0xec8d77de, 0x57971e81, 0xe14f6746, 0xc9335400, 0x6920318f, 0x081dbb99, 0xffc304a5, 0x4d351805, 0x7f3d5ce3, 0xa6c866c6, 0x5d5bcca9, 0xdaec6fea, 0x9f926f91, 0x9f46222f, 0x3991467d, 0xa5bf6d8e, 0x1143c44f, 0x43958302, 0xd0214eeb, 0x022083b8, 0x3fb6180c, 0x18f8931e, 0x281658e6, 0x26486e3e, 0x8bd78a70, 0x7477e4c1, 0xb506e07c, 0xf32d0a25, 0x79098b02, 0xe4eabb81, 0x28123b23, 0x69dead38, 0x1574ca16, 0xdf871b62, 0x211c40b7, 0xa51a9ef9, 0x0014377b, 0x041e8ac8, 0x09114003, 0xbd59e4d2, 0xe3d156d5, 0x4fe876d5, 0x2f91a340, 0x557be8de, 0x00eae4a7, 0x0ce5c2ec, 0x4db4bba6, 0xe756bdff, 0xdd3369ac, 0xec17b035, 0x06572327, 0x99afc8b0, 0x56c8c391, 0x6b65811c, 0x5e146119, 0x6e85cb75, 0xbe07c002, 0xc2325577, 0x893ff4ec, 0x5bbfc92d, 0xd0ec3b25, 0xb7801ab7, 0x8d6d3b24, 0x20c763ef, 0xc366a5fc, 0x9c382880, 0x0ace3205, 0xaac9548a, 0xeca1d7c7, 0x041afa32, 0x1d16625a, 0x6701902c, 0x9b757a54, 0x31d477f7, 0x9126b031, 0x36cc6fdb, 0xc70b8b46, 0xd9e66a48, 0x56e55a79, 0x026a4ceb, 0x52437eff, 0x2f8f76b4, 0x0df980a5, 0x8674cde3, 0xedda04eb, 0x17a9be04, 0x2c18f4df, 0xb7747f9d, 0xab2af7b4, 0xefc34d20, 0x2e096b7c, 0x1741a254, 0xe5b6a035, 0x213d42f6, 0x2c1c7c26, 0x61c2f50f, 0x6552daf9, 0xd2c231f8, 0x25130f69, 0xd8167fa2, 0x0418f2c8, 0x001a96a6, 0x0d1526ab, 0x63315c21, 0x5e0a72ec, 0x49bafefd, 0x187908d9, 0x8d0dbd86, 0x311170a7, 0x3e9b640c, 0xcc3e10d7, 0xd5cad3b6, 0x0caec388, 0xf73001e1, 0x6c728aff, 0x71eae2a1, 0x1f9af36e, 0xcfcbd12f, 0xc1de8417, 0xac07be6b, 0xcb44a1d8, 0x8b9b0f56, 0x013988c3, 0xb1c52fca, 0xb4be31cd, 0xd8782806, 0x12a3a4e2, 0x6f7de532, 0x58fd7eb6, 0xd01ee900, 0x24adffc2, 0xf4990fc5, 0x9711aac5, 0x001d7b95, 0x82e5e7d2, 0x109873f6, 0x00613096, 0xc32d9521, 0xada121ff, 0x29908415, 0x7fbb977f, 0xaf9eb3db, 0x29c9ed2a, 0x5ce2a465, 0xa730f32c, 0xd0aa3fe8, 0x8a5cc091, 0xd49e2ce7, 0x0ce454a9, 0xd60acd86, 0x015f1919, 0x77079103, 0xdea03af6, 0x78a8565e, 0xdee356df, 0x21f05cbe, 0x8b75e387, 0xb3c50651, 0xb8a5c3ef, 0xd8eeb6d2, 0xe523be77, 0xc2154529, 0x2f69efdf, 0xafe67afb, 0xf470c4b2, 0xf3e0eb5b, 0xd6cc9876, 0x39e4460c, 0x1fda8538, 0x1987832f, 0xca007367, 0xa99144f8, 0x296b299e, 0x492fc295, 0x9266beab, 0xb5676e69, 0x9bd3ddda, 0xdf7e052f, 0xdb25701c, 0x1b5e51ee, 0xf65324e6, 0x6afce36c, 0x0316cc04, 0x8644213e, 0xb7dc59d0, 0x7965291f, 0xccd6fd43, 0x41823979, 0x932bcdf6, 0xb657c34d, 0x4edfd282, 0x7ae5290c, 0x3cb9536b, 0x851e20fe, 0x9833557e, 0x13ecf0b0, 0xd3ffb372, 0x3f85c5c1, 0x0aef7ed2);

  sBox[4] = new Array(0x7ec90c04, 0x2c6e74b9, 0x9b0e66df, 0xa6337911, 0xb86a7fff, 0x1dd358f5, 0x44dd9d44, 0x1731167f, 0x08fbf1fa, 0xe7f511cc, 0xd2051b00, 0x735aba00, 0x2ab722d8, 0x386381cb, 0xacf6243a, 0x69befd7a, 0xe6a2e77f, 0xf0c720cd, 0xc4494816, 0xccf5c180, 0x38851640, 0x15b0a848, 0xe68b18cb, 0x4caadeff, 0x5f480a01, 0x0412b2aa, 0x259814fc, 0x41d0efe2, 0x4e40b48d, 0x248eb6fb, 0x8dba1cfe, 0x41a99b02, 0x1a550a04, 0xba8f65cb, 0x7251f4e7, 0x95a51725, 0xc106ecd7, 0x97a5980a, 0xc539b9aa, 0x4d79fe6a, 0xf2f3f763, 0x68af8040, 0xed0c9e56, 0x11b4958b, 0xe1eb5a88, 0x8709e6b0, 0xd7e07156, 0x4e29fea7, 0x6366e52d, 0x02d1c000, 0xc4ac8e05, 0x9377f571, 0x0c05372a, 0x578535f2, 0x2261be02, 0xd642a0c9, 0xdf13a280, 0x74b55bd2, 0x682199c0, 0xd421e5ec, 0x53fb3ce8, 0xc8adedb3, 0x28a87fc9, 0x3d959981, 0x5c1ff900, 0xfe38d399, 0x0c4eff0b, 0x062407ea, 0xaa2f4fb1, 0x4fb96976, 0x90c79505, 0xb0a8a774, 0xef55a1ff, 0xe59ca2c2, 0xa6b62d27, 0xe66a4263, 0xdf65001f, 0x0ec50966, 0xdfdd55bc, 0x29de0655, 0x911e739a, 0x17af8975, 0x32c7911c, 0x89f89468, 0x0d01e980, 0x524755f4, 0x03b63cc9, 0x0cc844b2, 0xbcf3f0aa, 0x87ac36e9, 0xe53a7426, 0x01b3d82b, 0x1a9e7449, 0x64ee2d7e, 0xcddbb1da, 0x01c94910, 0xb868bf80, 0x0d26f3fd, 0x9342ede7, 0x04a5c284, 0x636737b6, 0x50f5b616, 0xf24766e3, 0x8eca36c1, 0x136e05db, 0xfef18391, 0xfb887a37, 0xd6e7f7d4, 0xc7fb7dc9, 0x3063fcdf, 0xb6f589de, 0xec2941da, 0x26e46695, 0xb7566419, 0xf654efc5, 0xd08d58b7, 0x48925401, 0xc1bacb7f, 0xe5ff550f, 0xb6083049, 0x5bb5d0e8, 0x87d72e5a, 0xab6a6ee1, 0x223a66ce, 0xc62bf3cd, 0x9e0885f9, 0x68cb3e47, 0x086c010f, 0xa21de820, 0xd18b69de, 0xf3f65777, 0xfa02c3f6, 0x407edac3, 0xcbb3d550, 0x1793084d, 0xb0d70eba, 0x0ab378d5, 0xd951fb0c, 0xded7da56, 0x4124bbe4, 0x94ca0b56, 0x0f5755d1, 0xe0e1e56e, 0x6184b5be, 0x580a249f, 0x94f74bc0, 0xe327888e, 0x9f7b5561, 0xc3dc0280, 0x05687715, 0x646c6bd7, 0x44904db3, 0x66b4f0a3, 0xc0f1648a, 0x697ed5af, 0x49e92ff6, 0x309e374f, 0x2cb6356a, 0x85808573, 0x4991f840, 0x76f0ae02, 0x083be84d, 0x28421c9a, 0x44489406, 0x736e4cb8, 0xc1092910, 0x8bc95fc6, 0x7d869cf4, 0x134f616f, 0x2e77118d, 0xb31b2be1, 0xaa90b472, 0x3ca5d717, 0x7d161bba, 0x9cad9010, 0xaf462ba2, 0x9fe459d2, 0x45d34559, 0xd9f2da13, 0xdbc65487, 0xf3e4f94e, 0x176d486f, 0x097c13ea, 0x631da5c7, 0x445f7382, 0x175683f4, 0xcdc66a97, 0x70be0288, 0xb3cdcf72, 0x6e5dd2f3, 0x20936079, 0x459b80a5, 0xbe60e2db, 0xa9c23101, 0xeba5315c, 0x224e42f2, 0x1c5c1572, 0xf6721b2c, 0x1ad2fff3, 0x8c25404e, 0x324ed72f, 0x4067b7fd, 0x0523138e, 0x5ca3bc78, 0xdc0fd66e, 0x75922283, 0x784d6b17, 0x58ebb16e, 0x44094f85, 0x3f481d87, 0xfcfeae7b, 0x77b5ff76, 0x8c2302bf, 0xaaf47556, 0x5f46b02a, 0x2b092801, 0x3d38f5f7, 0x0ca81f36, 0x52af4a8a, 0x66d5e7c0, 0xdf3b0874, 0x95055110, 0x1b5ad7a8, 0xf61ed5ad, 0x6cf6e479, 0x20758184, 0xd0cefa65, 0x88f7be58, 0x4a046826, 0x0ff6f8f3, 0xa09c7f70, 0x5346aba0, 0x5ce96c28, 0xe176eda3, 0x6bac307f, 0x376829d2, 0x85360fa9, 0x17e3fe2a, 0x24b79767, 0xf5a96b20, 0xd6cd2595, 0x68ff1ebf, 0x7555442c, 0xf19f06be, 0xf9e0659a, 0xeeb9491d, 0x34010718, 0xbb30cab8, 0xe822fe15, 0x88570983, 0x750e6249, 0xda627e55, 0x5e76ffa8, 0xb1534546, 0x6d47de08, 0xefe9e7d4);

  sBox[5] = new Array(0xf6fa8f9d, 0x2cac6ce1, 0x4ca34867, 0xe2337f7c, 0x95db08e7, 0x016843b4, 0xeced5cbc, 0x325553ac, 0xbf9f0960, 0xdfa1e2ed, 0x83f0579d, 0x63ed86b9, 0x1ab6a6b8, 0xde5ebe39, 0xf38ff732, 0x8989b138, 0x33f14961, 0xc01937bd, 0xf506c6da, 0xe4625e7e, 0xa308ea99, 0x4e23e33c, 0x79cbd7cc, 0x48a14367, 0xa3149619, 0xfec94bd5, 0xa114174a, 0xeaa01866, 0xa084db2d, 0x09a8486f, 0xa888614a, 0x2900af98, 0x01665991, 0xe1992863, 0xc8f30c60, 0x2e78ef3c, 0xd0d51932, 0xcf0fec14, 0xf7ca07d2, 0xd0a82072, 0xfd41197e, 0x9305a6b0, 0xe86be3da, 0x74bed3cd, 0x372da53c, 0x4c7f4448, 0xdab5d440, 0x6dba0ec3, 0x083919a7, 0x9fbaeed9, 0x49dbcfb0, 0x4e670c53, 0x5c3d9c01, 0x64bdb941, 0x2c0e636a, 0xba7dd9cd, 0xea6f7388, 0xe70bc762, 0x35f29adb, 0x5c4cdd8d, 0xf0d48d8c, 0xb88153e2, 0x08a19866, 0x1ae2eac8, 0x284caf89, 0xaa928223, 0x9334be53, 0x3b3a21bf, 0x16434be3, 0x9aea3906, 0xefe8c36e, 0xf890cdd9, 0x80226dae, 0xc340a4a3, 0xdf7e9c09, 0xa694a807, 0x5b7c5ecc, 0x221db3a6, 0x9a69a02f, 0x68818a54, 0xceb2296f, 0x53c0843a, 0xfe893655, 0x25bfe68a, 0xb4628abc, 0xcf222ebf, 0x25ac6f48, 0xa9a99387, 0x53bddb65, 0xe76ffbe7, 0xe967fd78, 0x0ba93563, 0x8e342bc1, 0xe8a11be9, 0x4980740d, 0xc8087dfc, 0x8de4bf99, 0xa11101a0, 0x7fd37975, 0xda5a26c0, 0xe81f994f, 0x9528cd89, 0xfd339fed, 0xb87834bf, 0x5f04456d, 0x22258698, 0xc9c4c83b, 0x2dc156be, 0x4f628daa, 0x57f55ec5, 0xe2220abe, 0xd2916ebf, 0x4ec75b95, 0x24f2c3c0, 0x42d15d99, 0xcd0d7fa0, 0x7b6e27ff, 0xa8dc8af0, 0x7345c106, 0xf41e232f, 0x35162386, 0xe6ea8926, 0x3333b094, 0x157ec6f2, 0x372b74af, 0x692573e4, 0xe9a9d848, 0xf3160289, 0x3a62ef1d, 0xa787e238, 0xf3a5f676, 0x74364853, 0x20951063, 0x4576698d, 0xb6fad407, 0x592af950, 0x36f73523, 0x4cfb6e87, 0x7da4cec0, 0x6c152daa, 0xcb0396a8, 0xc50dfe5d, 0xfcd707ab, 0x0921c42f, 0x89dff0bb, 0x5fe2be78, 0x448f4f33, 0x754613c9, 0x2b05d08d, 0x48b9d585, 0xdc049441, 0xc8098f9b, 0x7dede786, 0xc39a3373, 0x42410005, 0x6a091751, 0x0ef3c8a6, 0x890072d6, 0x28207682, 0xa9a9f7be, 0xbf32679d, 0xd45b5b75, 0xb353fd00, 0xcbb0e358, 0x830f220a, 0x1f8fb214, 0xd372cf08, 0xcc3c4a13, 0x8cf63166, 0x061c87be, 0x88c98f88, 0x6062e397, 0x47cf8e7a, 0xb6c85283, 0x3cc2acfb, 0x3fc06976, 0x4e8f0252, 0x64d8314d, 0xda3870e3, 0x1e665459, 0xc10908f0, 0x513021a5, 0x6c5b68b7, 0x822f8aa0, 0x3007cd3e, 0x74719eef, 0xdc872681, 0x073340d4, 0x7e432fd9, 0x0c5ec241, 0x8809286c, 0xf592d891, 0x08a930f6, 0x957ef305, 0xb7fbffbd, 0xc266e96f, 0x6fe4ac98, 0xb173ecc0, 0xbc60b42a, 0x953498da, 0xfba1ae12, 0x2d4bd736, 0x0f25faab, 0xa4f3fceb, 0xe2969123, 0x257f0c3d, 0x9348af49, 0x361400bc, 0xe8816f4a, 0x3814f200, 0xa3f94043, 0x9c7a54c2, 0xbc704f57, 0xda41e7f9, 0xc25ad33a, 0x54f4a084, 0xb17f5505, 0x59357cbe, 0xedbd15c8, 0x7f97c5ab, 0xba5ac7b5, 0xb6f6deaf, 0x3a479c3a, 0x5302da25, 0x653d7e6a, 0x54268d49, 0x51a477ea, 0x5017d55b, 0xd7d25d88, 0x44136c76, 0x0404a8c8, 0xb8e5a121, 0xb81a928a, 0x60ed5869, 0x97c55b96, 0xeaec991b, 0x29935913, 0x01fdb7f1, 0x088e8dfa, 0x9ab6f6f5, 0x3b4cbf9f, 0x4a5de3ab, 0xe6051d35, 0xa0e1d855, 0xd36b4cf1, 0xf544edeb, 0xb0e93524, 0xbebb8fbd, 0xa2d762cf, 0x49c92f54, 0x38b5f331, 0x7128a454, 0x48392905, 0xa65b1db8, 0x851c97bd, 0xd675cf2f);

  sBox[6] = new Array(0x85e04019, 0x332bf567, 0x662dbfff, 0xcfc65693, 0x2a8d7f6f, 0xab9bc912, 0xde6008a1, 0x2028da1f, 0x0227bce7, 0x4d642916, 0x18fac300, 0x50f18b82, 0x2cb2cb11, 0xb232e75c, 0x4b3695f2, 0xb28707de, 0xa05fbcf6, 0xcd4181e9, 0xe150210c, 0xe24ef1bd, 0xb168c381, 0xfde4e789, 0x5c79b0d8, 0x1e8bfd43, 0x4d495001, 0x38be4341, 0x913cee1d, 0x92a79c3f, 0x089766be, 0xbaeeadf4, 0x1286becf, 0xb6eacb19, 0x2660c200, 0x7565bde4, 0x64241f7a, 0x8248dca9, 0xc3b3ad66, 0x28136086, 0x0bd8dfa8, 0x356d1cf2, 0x107789be, 0xb3b2e9ce, 0x0502aa8f, 0x0bc0351e, 0x166bf52a, 0xeb12ff82, 0xe3486911, 0xd34d7516, 0x4e7b3aff, 0x5f43671b, 0x9cf6e037, 0x4981ac83, 0x334266ce, 0x8c9341b7, 0xd0d854c0, 0xcb3a6c88, 0x47bc2829, 0x4725ba37, 0xa66ad22b, 0x7ad61f1e, 0x0c5cbafa, 0x4437f107, 0xb6e79962, 0x42d2d816, 0x0a961288, 0xe1a5c06e, 0x13749e67, 0x72fc081a, 0xb1d139f7, 0xf9583745, 0xcf19df58, 0xbec3f756, 0xc06eba30, 0x07211b24, 0x45c28829, 0xc95e317f, 0xbc8ec511, 0x38bc46e9, 0xc6e6fa14, 0xbae8584a, 0xad4ebc46, 0x468f508b, 0x7829435f, 0xf124183b, 0x821dba9f, 0xaff60ff4, 0xea2c4e6d, 0x16e39264, 0x92544a8b, 0x009b4fc3, 0xaba68ced, 0x9ac96f78, 0x06a5b79a, 0xb2856e6e, 0x1aec3ca9, 0xbe838688, 0x0e0804e9, 0x55f1be56, 0xe7e5363b, 0xb3a1f25d, 0xf7debb85, 0x61fe033c, 0x16746233, 0x3c034c28, 0xda6d0c74, 0x79aac56c, 0x3ce4e1ad, 0x51f0c802, 0x98f8f35a, 0x1626a49f, 0xeed82b29, 0x1d382fe3, 0x0c4fb99a, 0xbb325778, 0x3ec6d97b, 0x6e77a6a9, 0xcb658b5c, 0xd45230c7, 0x2bd1408b, 0x60c03eb7, 0xb9068d78, 0xa33754f4, 0xf430c87d, 0xc8a71302, 0xb96d8c32, 0xebd4e7be, 0xbe8b9d2d, 0x7979fb06, 0xe7225308, 0x8b75cf77, 0x11ef8da4, 0xe083c858, 0x8d6b786f, 0x5a6317a6, 0xfa5cf7a0, 0x5dda0033, 0xf28ebfb0, 0xf5b9c310, 0xa0eac280, 0x08b9767a, 0xa3d9d2b0, 0x79d34217, 0x021a718d, 0x9ac6336a, 0x2711fd60, 0x438050e3, 0x069908a8, 0x3d7fedc4, 0x826d2bef, 0x4eeb8476, 0x488dcf25, 0x36c9d566, 0x28e74e41, 0xc2610aca, 0x3d49a9cf, 0xbae3b9df, 0xb65f8de6, 0x92aeaf64, 0x3ac7d5e6, 0x9ea80509, 0xf22b017d, 0xa4173f70, 0xdd1e16c3, 0x15e0d7f9, 0x50b1b887, 0x2b9f4fd5, 0x625aba82, 0x6a017962, 0x2ec01b9c, 0x15488aa9, 0xd716e740, 0x40055a2c, 0x93d29a22, 0xe32dbf9a, 0x058745b9, 0x3453dc1e, 0xd699296e, 0x496cff6f, 0x1c9f4986, 0xdfe2ed07, 0xb87242d1, 0x19de7eae, 0x053e561a, 0x15ad6f8c, 0x66626c1c, 0x7154c24c, 0xea082b2a, 0x93eb2939, 0x17dcb0f0, 0x58d4f2ae, 0x9ea294fb, 0x52cf564c, 0x9883fe66, 0x2ec40581, 0x763953c3, 0x01d6692e, 0xd3a0c108, 0xa1e7160e, 0xe4f2dfa6, 0x693ed285, 0x74904698, 0x4c2b0edd, 0x4f757656, 0x5d393378, 0xa132234f, 0x3d321c5d, 0xc3f5e194, 0x4b269301, 0xc79f022f, 0x3c997e7e, 0x5e4f9504, 0x3ffafbbd, 0x76f7ad0e, 0x296693f4, 0x3d1fce6f, 0xc61e45be, 0xd3b5ab34, 0xf72bf9b7, 0x1b0434c0, 0x4e72b567, 0x5592a33d, 0xb5229301, 0xcfd2a87f, 0x60aeb767, 0x1814386b, 0x30bcc33d, 0x38a0c07d, 0xfd1606f2, 0xc363519b, 0x589dd390, 0x5479f8e6, 0x1cb8d647, 0x97fd61a9, 0xea7759f4, 0x2d57539d, 0x569a58cf, 0xe84e63ad, 0x462e1b78, 0x6580f87e, 0xf3817914, 0x91da55f4, 0x40a230f3, 0xd1988f35, 0xb6e318d2, 0x3ffa50bc, 0x3d40f021, 0xc3c0bdae, 0x4958c24c, 0x518f36b2, 0x84b1d370, 0x0fedce83, 0x878ddada, 0xf2a279c7, 0x94e01be8, 0x90716f4b, 0x954b8aa3);

  sBox[7] = new Array(0xe216300d, 0xbbddfffc, 0xa7ebdabd, 0x35648095, 0x7789f8b7, 0xe6c1121b, 0x0e241600, 0x052ce8b5, 0x11a9cfb0, 0xe5952f11, 0xece7990a, 0x9386d174, 0x2a42931c, 0x76e38111, 0xb12def3a, 0x37ddddfc, 0xde9adeb1, 0x0a0cc32c, 0xbe197029, 0x84a00940, 0xbb243a0f, 0xb4d137cf, 0xb44e79f0, 0x049eedfd, 0x0b15a15d, 0x480d3168, 0x8bbbde5a, 0x669ded42, 0xc7ece831, 0x3f8f95e7, 0x72df191b, 0x7580330d, 0x94074251, 0x5c7dcdfa, 0xabbe6d63, 0xaa402164, 0xb301d40a, 0x02e7d1ca, 0x53571dae, 0x7a3182a2, 0x12a8ddec, 0xfdaa335d, 0x176f43e8, 0x71fb46d4, 0x38129022, 0xce949ad4, 0xb84769ad, 0x965bd862, 0x82f3d055, 0x66fb9767, 0x15b80b4e, 0x1d5b47a0, 0x4cfde06f, 0xc28ec4b8, 0x57e8726e, 0x647a78fc, 0x99865d44, 0x608bd593, 0x6c200e03, 0x39dc5ff6, 0x5d0b00a3, 0xae63aff2, 0x7e8bd632, 0x70108c0c, 0xbbd35049, 0x2998df04, 0x980cf42a, 0x9b6df491, 0x9e7edd53, 0x06918548, 0x58cb7e07, 0x3b74ef2e, 0x522fffb1, 0xd24708cc, 0x1c7e27cd, 0xa4eb215b, 0x3cf1d2e2, 0x19b47a38, 0x424f7618, 0x35856039, 0x9d17dee7, 0x27eb35e6, 0xc9aff67b, 0x36baf5b8, 0x09c467cd, 0xc18910b1, 0xe11dbf7b, 0x06cd1af8, 0x7170c608, 0x2d5e3354, 0xd4de495a, 0x64c6d006, 0xbcc0c62c, 0x3dd00db3, 0x708f8f34, 0x77d51b42, 0x264f620f, 0x24b8d2bf, 0x15c1b79e, 0x46a52564, 0xf8d7e54e, 0x3e378160, 0x7895cda5, 0x859c15a5, 0xe6459788, 0xc37bc75f, 0xdb07ba0c, 0x0676a3ab, 0x7f229b1e, 0x31842e7b, 0x24259fd7, 0xf8bef472, 0x835ffcb8, 0x6df4c1f2, 0x96f5b195, 0xfd0af0fc, 0xb0fe134c, 0xe2506d3d, 0x4f9b12ea, 0xf215f225, 0xa223736f, 0x9fb4c428, 0x25d04979, 0x34c713f8, 0xc4618187, 0xea7a6e98, 0x7cd16efc, 0x1436876c, 0xf1544107, 0xbedeee14, 0x56e9af27, 0xa04aa441, 0x3cf7c899, 0x92ecbae6, 0xdd67016d, 0x151682eb, 0xa842eedf, 0xfdba60b4, 0xf1907b75, 0x20e3030f, 0x24d8c29e, 0xe139673b, 0xefa63fb8, 0x71873054, 0xb6f2cf3b, 0x9f326442, 0xcb15a4cc, 0xb01a4504, 0xf1e47d8d, 0x844a1be5, 0xbae7dfdc, 0x42cbda70, 0xcd7dae0a, 0x57e85b7a, 0xd53f5af6, 0x20cf4d8c, 0xcea4d428, 0x79d130a4, 0x3486ebfb, 0x33d3cddc, 0x77853b53, 0x37effcb5, 0xc5068778, 0xe580b3e6, 0x4e68b8f4, 0xc5c8b37e, 0x0d809ea2, 0x398feb7c, 0x132a4f94, 0x43b7950e, 0x2fee7d1c, 0x223613bd, 0xdd06caa2, 0x37df932b, 0xc4248289, 0xacf3ebc3, 0x5715f6b7, 0xef3478dd, 0xf267616f, 0xc148cbe4, 0x9052815e, 0x5e410fab, 0xb48a2465, 0x2eda7fa4, 0xe87b40e4, 0xe98ea084, 0x5889e9e1, 0xefd390fc, 0xdd07d35b, 0xdb485694, 0x38d7e5b2, 0x57720101, 0x730edebc, 0x5b643113, 0x94917e4f, 0x503c2fba, 0x646f1282, 0x7523d24a, 0xe0779695, 0xf9c17a8f, 0x7a5b2121, 0xd187b896, 0x29263a4d, 0xba510cdf, 0x81f47c9f, 0xad1163ed, 0xea7b5965, 0x1a00726e, 0x11403092, 0x00da6d77, 0x4a0cdd61, 0xad1f4603, 0x605bdfb0, 0x9eedc364, 0x22ebe6a8, 0xcee7d28a, 0xa0e736a0, 0x5564a6b9, 0x10853209, 0xc7eb8f37, 0x2de705ca, 0x8951570f, 0xdf09822b, 0xbd691a6c, 0xaa12e4f2, 0x87451c0f, 0xe0f6a27a, 0x3ada4819, 0x4cf1764f, 0x0d771c2b, 0x67cdb156, 0x350d8384, 0x5938fa0f, 0x42399ef3, 0x36997b07, 0x0e84093d, 0x4aa93e61, 0x8360d87b, 0x1fa98b0c, 0x1149382c, 0xe97625a5, 0x0614d1b7, 0x0e25244b, 0x0c768347, 0x589e8d82, 0x0d2059d1, 0xa466bb1e, 0xf8da0a82, 0x04f19130, 0xba6e4ec0, 0x99265164, 0x1ee7230d, 0x50b2ad80, 0xeaee6801, 0x8db2a283, 0xea8bf59e);
}

function Cast5(key) {
  this.cast5 = new OpenpgpSymencCast5();
  this.cast5.setKey(key);

  this.encrypt = function (block) {
    return this.cast5.encrypt(block);
  };
}

Cast5.blockSize = Cast5.prototype.blockSize = 8;
Cast5.keySize = Cast5.prototype.keySize = 16;

},{}],15:[function(_dereq_,module,exports){
//Paul Tero, July 2001
//http://www.tero.co.uk/des/
//
//Optimised for performance with large blocks by Michael Hayworth, November 2001
//http://www.netdealing.com
//
// Modified by Recurity Labs GmbH

//THIS SOFTWARE IS PROVIDED "AS IS" AND
//ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
//FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
//OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
//LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
//OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
//SUCH DAMAGE.

//des
//this takes the key, the message, and whether to encrypt or decrypt

/**
 * @module crypto/cipher/des
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
function des(keys, message, encrypt, mode, iv, padding) {
  //declaring this locally speeds things up a bit
  var spfunction1 = new Array(0x1010400, 0, 0x10000, 0x1010404, 0x1010004, 0x10404, 0x4, 0x10000, 0x400, 0x1010400, 0x1010404, 0x400, 0x1000404, 0x1010004, 0x1000000, 0x4, 0x404, 0x1000400, 0x1000400, 0x10400, 0x10400, 0x1010000, 0x1010000, 0x1000404, 0x10004, 0x1000004, 0x1000004, 0x10004, 0, 0x404, 0x10404, 0x1000000, 0x10000, 0x1010404, 0x4, 0x1010000, 0x1010400, 0x1000000, 0x1000000, 0x400, 0x1010004, 0x10000, 0x10400, 0x1000004, 0x400, 0x4, 0x1000404, 0x10404, 0x1010404, 0x10004, 0x1010000, 0x1000404, 0x1000004, 0x404, 0x10404, 0x1010400, 0x404, 0x1000400, 0x1000400, 0, 0x10004, 0x10400, 0, 0x1010004);
  var spfunction2 = new Array(-0x7fef7fe0, -0x7fff8000, 0x8000, 0x108020, 0x100000, 0x20, -0x7fefffe0, -0x7fff7fe0, -0x7fffffe0, -0x7fef7fe0, -0x7fef8000, -0x80000000, -0x7fff8000, 0x100000, 0x20, -0x7fefffe0, 0x108000, 0x100020, -0x7fff7fe0, 0, -0x80000000, 0x8000, 0x108020, -0x7ff00000, 0x100020, -0x7fffffe0, 0, 0x108000, 0x8020, -0x7fef8000, -0x7ff00000, 0x8020, 0, 0x108020, -0x7fefffe0, 0x100000, -0x7fff7fe0, -0x7ff00000, -0x7fef8000, 0x8000, -0x7ff00000, -0x7fff8000, 0x20, -0x7fef7fe0, 0x108020, 0x20, 0x8000, -0x80000000, 0x8020, -0x7fef8000, 0x100000, -0x7fffffe0, 0x100020, -0x7fff7fe0, -0x7fffffe0, 0x100020, 0x108000, 0, -0x7fff8000, 0x8020, -0x80000000, -0x7fefffe0, -0x7fef7fe0, 0x108000);
  var spfunction3 = new Array(0x208, 0x8020200, 0, 0x8020008, 0x8000200, 0, 0x20208, 0x8000200, 0x20008, 0x8000008, 0x8000008, 0x20000, 0x8020208, 0x20008, 0x8020000, 0x208, 0x8000000, 0x8, 0x8020200, 0x200, 0x20200, 0x8020000, 0x8020008, 0x20208, 0x8000208, 0x20200, 0x20000, 0x8000208, 0x8, 0x8020208, 0x200, 0x8000000, 0x8020200, 0x8000000, 0x20008, 0x208, 0x20000, 0x8020200, 0x8000200, 0, 0x200, 0x20008, 0x8020208, 0x8000200, 0x8000008, 0x200, 0, 0x8020008, 0x8000208, 0x20000, 0x8000000, 0x8020208, 0x8, 0x20208, 0x20200, 0x8000008, 0x8020000, 0x8000208, 0x208, 0x8020000, 0x20208, 0x8, 0x8020008, 0x20200);
  var spfunction4 = new Array(0x802001, 0x2081, 0x2081, 0x80, 0x802080, 0x800081, 0x800001, 0x2001, 0, 0x802000, 0x802000, 0x802081, 0x81, 0, 0x800080, 0x800001, 0x1, 0x2000, 0x800000, 0x802001, 0x80, 0x800000, 0x2001, 0x2080, 0x800081, 0x1, 0x2080, 0x800080, 0x2000, 0x802080, 0x802081, 0x81, 0x800080, 0x800001, 0x802000, 0x802081, 0x81, 0, 0, 0x802000, 0x2080, 0x800080, 0x800081, 0x1, 0x802001, 0x2081, 0x2081, 0x80, 0x802081, 0x81, 0x1, 0x2000, 0x800001, 0x2001, 0x802080, 0x800081, 0x2001, 0x2080, 0x800000, 0x802001, 0x80, 0x800000, 0x2000, 0x802080);
  var spfunction5 = new Array(0x100, 0x2080100, 0x2080000, 0x42000100, 0x80000, 0x100, 0x40000000, 0x2080000, 0x40080100, 0x80000, 0x2000100, 0x40080100, 0x42000100, 0x42080000, 0x80100, 0x40000000, 0x2000000, 0x40080000, 0x40080000, 0, 0x40000100, 0x42080100, 0x42080100, 0x2000100, 0x42080000, 0x40000100, 0, 0x42000000, 0x2080100, 0x2000000, 0x42000000, 0x80100, 0x80000, 0x42000100, 0x100, 0x2000000, 0x40000000, 0x2080000, 0x42000100, 0x40080100, 0x2000100, 0x40000000, 0x42080000, 0x2080100, 0x40080100, 0x100, 0x2000000, 0x42080000, 0x42080100, 0x80100, 0x42000000, 0x42080100, 0x2080000, 0, 0x40080000, 0x42000000, 0x80100, 0x2000100, 0x40000100, 0x80000, 0, 0x40080000, 0x2080100, 0x40000100);
  var spfunction6 = new Array(0x20000010, 0x20400000, 0x4000, 0x20404010, 0x20400000, 0x10, 0x20404010, 0x400000, 0x20004000, 0x404010, 0x400000, 0x20000010, 0x400010, 0x20004000, 0x20000000, 0x4010, 0, 0x400010, 0x20004010, 0x4000, 0x404000, 0x20004010, 0x10, 0x20400010, 0x20400010, 0, 0x404010, 0x20404000, 0x4010, 0x404000, 0x20404000, 0x20000000, 0x20004000, 0x10, 0x20400010, 0x404000, 0x20404010, 0x400000, 0x4010, 0x20000010, 0x400000, 0x20004000, 0x20000000, 0x4010, 0x20000010, 0x20404010, 0x404000, 0x20400000, 0x404010, 0x20404000, 0, 0x20400010, 0x10, 0x4000, 0x20400000, 0x404010, 0x4000, 0x400010, 0x20004010, 0, 0x20404000, 0x20000000, 0x400010, 0x20004010);
  var spfunction7 = new Array(0x200000, 0x4200002, 0x4000802, 0, 0x800, 0x4000802, 0x200802, 0x4200800, 0x4200802, 0x200000, 0, 0x4000002, 0x2, 0x4000000, 0x4200002, 0x802, 0x4000800, 0x200802, 0x200002, 0x4000800, 0x4000002, 0x4200000, 0x4200800, 0x200002, 0x4200000, 0x800, 0x802, 0x4200802, 0x200800, 0x2, 0x4000000, 0x200800, 0x4000000, 0x200800, 0x200000, 0x4000802, 0x4000802, 0x4200002, 0x4200002, 0x2, 0x200002, 0x4000000, 0x4000800, 0x200000, 0x4200800, 0x802, 0x200802, 0x4200800, 0x802, 0x4000002, 0x4200802, 0x4200000, 0x200800, 0, 0x2, 0x4200802, 0, 0x200802, 0x4200000, 0x800, 0x4000002, 0x4000800, 0x800, 0x200002);
  var spfunction8 = new Array(0x10001040, 0x1000, 0x40000, 0x10041040, 0x10000000, 0x10001040, 0x40, 0x10000000, 0x40040, 0x10040000, 0x10041040, 0x41000, 0x10041000, 0x41040, 0x1000, 0x40, 0x10040000, 0x10000040, 0x10001000, 0x1040, 0x41000, 0x40040, 0x10040040, 0x10041000, 0x1040, 0, 0, 0x10040040, 0x10000040, 0x10001000, 0x41040, 0x40000, 0x41040, 0x40000, 0x10041000, 0x1000, 0x40, 0x10040040, 0x1000, 0x41040, 0x10001000, 0x40, 0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x40000, 0x10001040, 0, 0x10041040, 0x40040, 0x10000040, 0x10040000, 0x10001000, 0x10001040, 0, 0x10041040, 0x41000, 0x41000, 0x1040, 0x1040, 0x40040, 0x10000000, 0x10041000);

  //create the 16 or 48 subkeys we will need
  var m = 0,
      i,
      j,
      temp,
      right1,
      right2,
      left,
      right,
      looping;
  var cbcleft, cbcleft2, cbcright, cbcright2;
  var endloop, loopinc;
  var len = message.length;

  //set up the loops for single and triple des
  var iterations = keys.length === 32 ? 3 : 9; //single or triple des
  if (iterations === 3) {
    looping = encrypt ? new Array(0, 32, 2) : new Array(30, -2, -2);
  } else {
    looping = encrypt ? new Array(0, 32, 2, 62, 30, -2, 64, 96, 2) : new Array(94, 62, -2, 32, 64, 2, 30, -2, -2);
  }

  //pad the message depending on the padding parameter
  //only add padding if encrypting - note that you need to use the same padding option for both encrypt and decrypt
  if (encrypt) {
    message = des_addPadding(message, padding);
    len = message.length;
  }

  //store the result here
  var result = new Uint8Array(len);
  var k = 0;

  if (mode === 1) {
    //CBC mode
    cbcleft = iv[m++] << 24 | iv[m++] << 16 | iv[m++] << 8 | iv[m++];
    cbcright = iv[m++] << 24 | iv[m++] << 16 | iv[m++] << 8 | iv[m++];
    m = 0;
  }

  //loop through each 64 bit chunk of the message
  while (m < len) {
    left = message[m++] << 24 | message[m++] << 16 | message[m++] << 8 | message[m++];
    right = message[m++] << 24 | message[m++] << 16 | message[m++] << 8 | message[m++];

    //for Cipher Block Chaining mode, xor the message with the previous result
    if (mode === 1) {
      if (encrypt) {
        left ^= cbcleft;
        right ^= cbcright;
      } else {
        cbcleft2 = cbcleft;
        cbcright2 = cbcright;
        cbcleft = left;
        cbcright = right;
      }
    }

    //first each 64 but chunk of the message must be permuted according to IP
    temp = (left >>> 4 ^ right) & 0x0f0f0f0f;
    right ^= temp;
    left ^= temp << 4;
    temp = (left >>> 16 ^ right) & 0x0000ffff;
    right ^= temp;
    left ^= temp << 16;
    temp = (right >>> 2 ^ left) & 0x33333333;
    left ^= temp;
    right ^= temp << 2;
    temp = (right >>> 8 ^ left) & 0x00ff00ff;
    left ^= temp;
    right ^= temp << 8;
    temp = (left >>> 1 ^ right) & 0x55555555;
    right ^= temp;
    left ^= temp << 1;

    left = left << 1 | left >>> 31;
    right = right << 1 | right >>> 31;

    //do this either 1 or 3 times for each chunk of the message
    for (j = 0; j < iterations; j += 3) {
      endloop = looping[j + 1];
      loopinc = looping[j + 2];
      //now go through and perform the encryption or decryption
      for (i = looping[j]; i !== endloop; i += loopinc) {
        //for efficiency
        right1 = right ^ keys[i];
        right2 = (right >>> 4 | right << 28) ^ keys[i + 1];
        //the result is attained by passing these bytes through the S selection functions
        temp = left;
        left = right;
        right = temp ^ (spfunction2[right1 >>> 24 & 0x3f] | spfunction4[right1 >>> 16 & 0x3f] | spfunction6[right1 >>> 8 & 0x3f] | spfunction8[right1 & 0x3f] | spfunction1[right2 >>> 24 & 0x3f] | spfunction3[right2 >>> 16 & 0x3f] | spfunction5[right2 >>> 8 & 0x3f] | spfunction7[right2 & 0x3f]);
      }
      temp = left;
      left = right;
      right = temp; //unreverse left and right
    } //for either 1 or 3 iterations

    //move then each one bit to the right
    left = left >>> 1 | left << 31;
    right = right >>> 1 | right << 31;

    //now perform IP-1, which is IP in the opposite direction
    temp = (left >>> 1 ^ right) & 0x55555555;
    right ^= temp;
    left ^= temp << 1;
    temp = (right >>> 8 ^ left) & 0x00ff00ff;
    left ^= temp;
    right ^= temp << 8;
    temp = (right >>> 2 ^ left) & 0x33333333;
    left ^= temp;
    right ^= temp << 2;
    temp = (left >>> 16 ^ right) & 0x0000ffff;
    right ^= temp;
    left ^= temp << 16;
    temp = (left >>> 4 ^ right) & 0x0f0f0f0f;
    right ^= temp;
    left ^= temp << 4;

    //for Cipher Block Chaining mode, xor the message with the previous result
    if (mode === 1) {
      if (encrypt) {
        cbcleft = left;
        cbcright = right;
      } else {
        left ^= cbcleft2;
        right ^= cbcright2;
      }
    }

    result[k++] = left >>> 24;
    result[k++] = left >>> 16 & 0xff;
    result[k++] = left >>> 8 & 0xff;
    result[k++] = left & 0xff;
    result[k++] = right >>> 24;
    result[k++] = right >>> 16 & 0xff;
    result[k++] = right >>> 8 & 0xff;
    result[k++] = right & 0xff;
  } //for every 8 characters, or 64 bits in the message

  //only remove padding if decrypting - note that you need to use the same padding option for both encrypt and decrypt
  if (!encrypt) {
    result = des_removePadding(result, padding);
  }

  return result;
} //end of des

//des_createKeys
//this takes as input a 64 bit key (even though only 56 bits are used)
//as an array of 2 integers, and returns 16 48 bit keys

function des_createKeys(key) {
  //declaring this locally speeds things up a bit
  var pc2bytes0 = new Array(0, 0x4, 0x20000000, 0x20000004, 0x10000, 0x10004, 0x20010000, 0x20010004, 0x200, 0x204, 0x20000200, 0x20000204, 0x10200, 0x10204, 0x20010200, 0x20010204);
  var pc2bytes1 = new Array(0, 0x1, 0x100000, 0x100001, 0x4000000, 0x4000001, 0x4100000, 0x4100001, 0x100, 0x101, 0x100100, 0x100101, 0x4000100, 0x4000101, 0x4100100, 0x4100101);
  var pc2bytes2 = new Array(0, 0x8, 0x800, 0x808, 0x1000000, 0x1000008, 0x1000800, 0x1000808, 0, 0x8, 0x800, 0x808, 0x1000000, 0x1000008, 0x1000800, 0x1000808);
  var pc2bytes3 = new Array(0, 0x200000, 0x8000000, 0x8200000, 0x2000, 0x202000, 0x8002000, 0x8202000, 0x20000, 0x220000, 0x8020000, 0x8220000, 0x22000, 0x222000, 0x8022000, 0x8222000);
  var pc2bytes4 = new Array(0, 0x40000, 0x10, 0x40010, 0, 0x40000, 0x10, 0x40010, 0x1000, 0x41000, 0x1010, 0x41010, 0x1000, 0x41000, 0x1010, 0x41010);
  var pc2bytes5 = new Array(0, 0x400, 0x20, 0x420, 0, 0x400, 0x20, 0x420, 0x2000000, 0x2000400, 0x2000020, 0x2000420, 0x2000000, 0x2000400, 0x2000020, 0x2000420);
  var pc2bytes6 = new Array(0, 0x10000000, 0x80000, 0x10080000, 0x2, 0x10000002, 0x80002, 0x10080002, 0, 0x10000000, 0x80000, 0x10080000, 0x2, 0x10000002, 0x80002, 0x10080002);
  var pc2bytes7 = new Array(0, 0x10000, 0x800, 0x10800, 0x20000000, 0x20010000, 0x20000800, 0x20010800, 0x20000, 0x30000, 0x20800, 0x30800, 0x20020000, 0x20030000, 0x20020800, 0x20030800);
  var pc2bytes8 = new Array(0, 0x40000, 0, 0x40000, 0x2, 0x40002, 0x2, 0x40002, 0x2000000, 0x2040000, 0x2000000, 0x2040000, 0x2000002, 0x2040002, 0x2000002, 0x2040002);
  var pc2bytes9 = new Array(0, 0x10000000, 0x8, 0x10000008, 0, 0x10000000, 0x8, 0x10000008, 0x400, 0x10000400, 0x408, 0x10000408, 0x400, 0x10000400, 0x408, 0x10000408);
  var pc2bytes10 = new Array(0, 0x20, 0, 0x20, 0x100000, 0x100020, 0x100000, 0x100020, 0x2000, 0x2020, 0x2000, 0x2020, 0x102000, 0x102020, 0x102000, 0x102020);
  var pc2bytes11 = new Array(0, 0x1000000, 0x200, 0x1000200, 0x200000, 0x1200000, 0x200200, 0x1200200, 0x4000000, 0x5000000, 0x4000200, 0x5000200, 0x4200000, 0x5200000, 0x4200200, 0x5200200);
  var pc2bytes12 = new Array(0, 0x1000, 0x8000000, 0x8001000, 0x80000, 0x81000, 0x8080000, 0x8081000, 0x10, 0x1010, 0x8000010, 0x8001010, 0x80010, 0x81010, 0x8080010, 0x8081010);
  var pc2bytes13 = new Array(0, 0x4, 0x100, 0x104, 0, 0x4, 0x100, 0x104, 0x1, 0x5, 0x101, 0x105, 0x1, 0x5, 0x101, 0x105);

  //how many iterations (1 for des, 3 for triple des)
  var iterations = key.length > 8 ? 3 : 1; //changed by Paul 16/6/2007 to use Triple DES for 9+ byte keys
  //stores the return keys
  var keys = new Array(32 * iterations);
  //now define the left shifts which need to be done
  var shifts = new Array(0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0);
  //other variables
  var lefttemp,
      righttemp,
      m = 0,
      n = 0,
      temp;

  for (var j = 0; j < iterations; j++) {
    //either 1 or 3 iterations
    var left = key[m++] << 24 | key[m++] << 16 | key[m++] << 8 | key[m++];
    var right = key[m++] << 24 | key[m++] << 16 | key[m++] << 8 | key[m++];

    temp = (left >>> 4 ^ right) & 0x0f0f0f0f;
    right ^= temp;
    left ^= temp << 4;
    temp = (right >>> -16 ^ left) & 0x0000ffff;
    left ^= temp;
    right ^= temp << -16;
    temp = (left >>> 2 ^ right) & 0x33333333;
    right ^= temp;
    left ^= temp << 2;
    temp = (right >>> -16 ^ left) & 0x0000ffff;
    left ^= temp;
    right ^= temp << -16;
    temp = (left >>> 1 ^ right) & 0x55555555;
    right ^= temp;
    left ^= temp << 1;
    temp = (right >>> 8 ^ left) & 0x00ff00ff;
    left ^= temp;
    right ^= temp << 8;
    temp = (left >>> 1 ^ right) & 0x55555555;
    right ^= temp;
    left ^= temp << 1;

    //the right side needs to be shifted and to get the last four bits of the left side
    temp = left << 8 | right >>> 20 & 0x000000f0;
    //left needs to be put upside down
    left = right << 24 | right << 8 & 0xff0000 | right >>> 8 & 0xff00 | right >>> 24 & 0xf0;
    right = temp;

    //now go through and perform these shifts on the left and right keys
    for (var i = 0; i < shifts.length; i++) {
      //shift the keys either one or two bits to the left
      if (shifts[i]) {
        left = left << 2 | left >>> 26;
        right = right << 2 | right >>> 26;
      } else {
        left = left << 1 | left >>> 27;
        right = right << 1 | right >>> 27;
      }
      left &= -0xf;
      right &= -0xf;

      //now apply PC-2, in such a way that E is easier when encrypting or decrypting
      //this conversion will look like PC-2 except only the last 6 bits of each byte are used
      //rather than 48 consecutive bits and the order of lines will be according to
      //how the S selection functions will be applied: S2, S4, S6, S8, S1, S3, S5, S7
      lefttemp = pc2bytes0[left >>> 28] | pc2bytes1[left >>> 24 & 0xf] | pc2bytes2[left >>> 20 & 0xf] | pc2bytes3[left >>> 16 & 0xf] | pc2bytes4[left >>> 12 & 0xf] | pc2bytes5[left >>> 8 & 0xf] | pc2bytes6[left >>> 4 & 0xf];
      righttemp = pc2bytes7[right >>> 28] | pc2bytes8[right >>> 24 & 0xf] | pc2bytes9[right >>> 20 & 0xf] | pc2bytes10[right >>> 16 & 0xf] | pc2bytes11[right >>> 12 & 0xf] | pc2bytes12[right >>> 8 & 0xf] | pc2bytes13[right >>> 4 & 0xf];
      temp = (righttemp >>> 16 ^ lefttemp) & 0x0000ffff;
      keys[n++] = lefttemp ^ temp;
      keys[n++] = righttemp ^ temp << 16;
    }
  } //for each iterations
  //return the keys we've created
  return keys;
} //end of des_createKeys

function des_addPadding(message, padding) {
  var padLength = 8 - message.length % 8;

  var pad;
  if (padding === 2 && padLength < 8) {
    //pad the message with spaces
    pad = " ".charCodeAt(0);
  } else if (padding === 1) {
    //PKCS7 padding
    pad = padLength;
  } else if (!padding && padLength < 8) {
    //pad the message out with null bytes
    pad = 0;
  } else if (padLength === 8) {
    return message;
  } else {
    throw new Error('des: invalid padding');
  }

  var paddedMessage = new Uint8Array(message.length + padLength);
  for (var i = 0; i < message.length; i++) {
    paddedMessage[i] = message[i];
  }
  for (var j = 0; j < padLength; j++) {
    paddedMessage[message.length + j] = pad;
  }

  return paddedMessage;
}

function des_removePadding(message, padding) {
  var padLength = null;
  var pad;
  if (padding === 2) {
    // space padded
    pad = " ".charCodeAt(0);
  } else if (padding === 1) {
    // PKCS7
    padLength = message[message.length - 1];
  } else if (!padding) {
    // null padding
    pad = 0;
  } else {
    throw new Error('des: invalid padding');
  }

  if (!padLength) {
    padLength = 1;
    while (message[message.length - padLength] === pad) {
      padLength++;
    }
    padLength--;
  }

  return message.subarray(0, message.length - padLength);
}

// added by Recurity Labs

function Des(key) {
  this.key = [];

  for (var i = 0; i < 3; i++) {
    this.key.push(new Uint8Array(key.subarray(i * 8, i * 8 + 8)));
  }

  this.encrypt = function (block) {
    return des(des_createKeys(this.key[2]), des(des_createKeys(this.key[1]), des(des_createKeys(this.key[0]), block, true, 0, null, null), false, 0, null, null), true, 0, null, null);
  };
}

Des.keySize = Des.prototype.keySize = 24;
Des.blockSize = Des.prototype.blockSize = 8;

// This is "original" DES - Des is actually Triple DES.
// This is only exported so we can unit test.

function OriginalDes(key) {
  this.key = key;

  this.encrypt = function (block, padding) {
    var keys = des_createKeys(this.key);
    return des(keys, block, true, 0, null, padding);
  };

  this.decrypt = function (block, padding) {
    var keys = des_createKeys(this.key);
    return des(keys, block, false, 0, null, padding);
  };
}

exports.default = {
  /** @static */
  des: Des,
  /** @static */
  originalDes: OriginalDes
};

},{}],16:[function(_dereq_,module,exports){
/**
 * @requires crypto/cipher/aes
 * @requires crypto/cipher/blowfish
 * @requires crypto/cipher/cast5
 * @requires crypto/cipher/twofish
 * @module crypto/cipher
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _aes = _dereq_('./aes.js');

var _aes2 = _interopRequireDefault(_aes);

var _des = _dereq_('./des.js');

var _des2 = _interopRequireDefault(_des);

var _cast = _dereq_('./cast5.js');

var _cast2 = _interopRequireDefault(_cast);

var _twofish = _dereq_('./twofish.js');

var _twofish2 = _interopRequireDefault(_twofish);

var _blowfish = _dereq_('./blowfish.js');

var _blowfish2 = _interopRequireDefault(_blowfish);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = {
  /** @see module:crypto/cipher/aes */
  aes128: _aes2.default[128],
  aes192: _aes2.default[192],
  aes256: _aes2.default[256],
  /** @see module:crypto/cipher/des.originalDes */
  des: _des2.default.originalDes,
  /** @see module:crypto/cipher/des.des */
  tripledes: _des2.default.des,
  /** @see module:crypto/cipher/cast5 */
  cast5: _cast2.default,
  /** @see module:crypto/cipher/twofish */
  twofish: _twofish2.default,
  /** @see module:crypto/cipher/blowfish */
  blowfish: _blowfish2.default,
  /** Not implemented */
  idea: function idea() {
    throw new Error('IDEA symmetric-key algorithm not implemented');
  }
};

},{"./aes.js":12,"./blowfish.js":13,"./cast5.js":14,"./des.js":15,"./twofish.js":17}],17:[function(_dereq_,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = TF;
/* Modified by Recurity Labs GmbH
 *
 * Cipher.js
 * A block-cipher algorithm implementation on JavaScript
 * See Cipher.readme.txt for further information.
 *
 * Copyright(c) 2009 Atsushi Oka [ http://oka.nu/ ]
 * This script file is distributed under the LGPL
 *
 * ACKNOWLEDGMENT
 *
 *     The main subroutines are written by Michiel van Everdingen.
 *
 *     Michiel van Everdingen
 *     http://home.versatel.nl/MAvanEverdingen/index.html
 *
 *     All rights for these routines are reserved to Michiel van Everdingen.
 *
 */

/**
 * @module crypto/cipher/twofish
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//Math
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var MAXINT = 0xFFFFFFFF;

function rotw(w, n) {
  return (w << n | w >>> 32 - n) & MAXINT;
}

function getW(a, i) {
  return a[i] | a[i + 1] << 8 | a[i + 2] << 16 | a[i + 3] << 24;
}

function setW(a, i, w) {
  a.splice(i, 4, w & 0xFF, w >>> 8 & 0xFF, w >>> 16 & 0xFF, w >>> 24 & 0xFF);
}

function getB(x, n) {
  return x >>> n * 8 & 0xFF;
}

// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Twofish
// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

function createTwofish() {
  //
  var keyBytes = null;
  var dataBytes = null;
  var dataOffset = -1;
  // var dataLength = -1;
  var algorithmName = null;
  // var idx2 = -1;
  //

  algorithmName = "twofish";

  var tfsKey = [];
  var tfsM = [[], [], [], []];

  function tfsInit(key) {
    keyBytes = key;
    var i,
        a,
        b,
        c,
        d,
        meKey = [],
        moKey = [],
        inKey = [];
    var kLen;
    var sKey = [];
    var f01, f5b, fef;

    var q0 = [[8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4], [2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5]];
    var q1 = [[14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13], [1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8]];
    var q2 = [[11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1], [4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15]];
    var q3 = [[13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10], [11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10]];
    var ror4 = [0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15];
    var ashx = [0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7];
    var q = [[], []];
    var m = [[], [], [], []];

    function ffm5b(x) {
      return x ^ x >> 2 ^ [0, 90, 180, 238][x & 3];
    }

    function ffmEf(x) {
      return x ^ x >> 1 ^ x >> 2 ^ [0, 238, 180, 90][x & 3];
    }

    function mdsRem(p, q) {
      var i, t, u;
      for (i = 0; i < 8; i++) {
        t = q >>> 24;
        q = q << 8 & MAXINT | p >>> 24;
        p = p << 8 & MAXINT;
        u = t << 1;
        if (t & 128) {
          u ^= 333;
        }
        q ^= t ^ u << 16;
        u ^= t >>> 1;
        if (t & 1) {
          u ^= 166;
        }
        q ^= u << 24 | u << 8;
      }
      return q;
    }

    function qp(n, x) {
      var a, b, c, d;
      a = x >> 4;
      b = x & 15;
      c = q0[n][a ^ b];
      d = q1[n][ror4[b] ^ ashx[a]];
      return q3[n][ror4[d] ^ ashx[c]] << 4 | q2[n][c ^ d];
    }

    function hFun(x, key) {
      var a = getB(x, 0),
          b = getB(x, 1),
          c = getB(x, 2),
          d = getB(x, 3);
      switch (kLen) {
        case 4:
          a = q[1][a] ^ getB(key[3], 0);
          b = q[0][b] ^ getB(key[3], 1);
          c = q[0][c] ^ getB(key[3], 2);
          d = q[1][d] ^ getB(key[3], 3);
        case 3:
          a = q[1][a] ^ getB(key[2], 0);
          b = q[1][b] ^ getB(key[2], 1);
          c = q[0][c] ^ getB(key[2], 2);
          d = q[0][d] ^ getB(key[2], 3);
        case 2:
          a = q[0][q[0][a] ^ getB(key[1], 0)] ^ getB(key[0], 0);
          b = q[0][q[1][b] ^ getB(key[1], 1)] ^ getB(key[0], 1);
          c = q[1][q[0][c] ^ getB(key[1], 2)] ^ getB(key[0], 2);
          d = q[1][q[1][d] ^ getB(key[1], 3)] ^ getB(key[0], 3);
      }
      return m[0][a] ^ m[1][b] ^ m[2][c] ^ m[3][d];
    }

    keyBytes = keyBytes.slice(0, 32);
    i = keyBytes.length;
    while (i !== 16 && i !== 24 && i !== 32) {
      keyBytes[i++] = 0;
    }

    for (i = 0; i < keyBytes.length; i += 4) {
      inKey[i >> 2] = getW(keyBytes, i);
    }
    for (i = 0; i < 256; i++) {
      q[0][i] = qp(0, i);
      q[1][i] = qp(1, i);
    }
    for (i = 0; i < 256; i++) {
      f01 = q[1][i];
      f5b = ffm5b(f01);
      fef = ffmEf(f01);
      m[0][i] = f01 + (f5b << 8) + (fef << 16) + (fef << 24);
      m[2][i] = f5b + (fef << 8) + (f01 << 16) + (fef << 24);
      f01 = q[0][i];
      f5b = ffm5b(f01);
      fef = ffmEf(f01);
      m[1][i] = fef + (fef << 8) + (f5b << 16) + (f01 << 24);
      m[3][i] = f5b + (f01 << 8) + (fef << 16) + (f5b << 24);
    }

    kLen = inKey.length / 2;
    for (i = 0; i < kLen; i++) {
      a = inKey[i + i];
      meKey[i] = a;
      b = inKey[i + i + 1];
      moKey[i] = b;
      sKey[kLen - i - 1] = mdsRem(a, b);
    }
    for (i = 0; i < 40; i += 2) {
      a = 0x1010101 * i;
      b = a + 0x1010101;
      a = hFun(a, meKey);
      b = rotw(hFun(b, moKey), 8);
      tfsKey[i] = a + b & MAXINT;
      tfsKey[i + 1] = rotw(a + 2 * b, 9);
    }
    for (i = 0; i < 256; i++) {
      a = b = c = d = i;
      switch (kLen) {
        case 4:
          a = q[1][a] ^ getB(sKey[3], 0);
          b = q[0][b] ^ getB(sKey[3], 1);
          c = q[0][c] ^ getB(sKey[3], 2);
          d = q[1][d] ^ getB(sKey[3], 3);
        case 3:
          a = q[1][a] ^ getB(sKey[2], 0);
          b = q[1][b] ^ getB(sKey[2], 1);
          c = q[0][c] ^ getB(sKey[2], 2);
          d = q[0][d] ^ getB(sKey[2], 3);
        case 2:
          tfsM[0][i] = m[0][q[0][q[0][a] ^ getB(sKey[1], 0)] ^ getB(sKey[0], 0)];
          tfsM[1][i] = m[1][q[0][q[1][b] ^ getB(sKey[1], 1)] ^ getB(sKey[0], 1)];
          tfsM[2][i] = m[2][q[1][q[0][c] ^ getB(sKey[1], 2)] ^ getB(sKey[0], 2)];
          tfsM[3][i] = m[3][q[1][q[1][d] ^ getB(sKey[1], 3)] ^ getB(sKey[0], 3)];
      }
    }
  }

  function tfsG0(x) {
    return tfsM[0][getB(x, 0)] ^ tfsM[1][getB(x, 1)] ^ tfsM[2][getB(x, 2)] ^ tfsM[3][getB(x, 3)];
  }

  function tfsG1(x) {
    return tfsM[0][getB(x, 3)] ^ tfsM[1][getB(x, 0)] ^ tfsM[2][getB(x, 1)] ^ tfsM[3][getB(x, 2)];
  }

  function tfsFrnd(r, blk) {
    var a = tfsG0(blk[0]);
    var b = tfsG1(blk[1]);
    blk[2] = rotw(blk[2] ^ a + b + tfsKey[4 * r + 8] & MAXINT, 31);
    blk[3] = rotw(blk[3], 1) ^ a + 2 * b + tfsKey[4 * r + 9] & MAXINT;
    a = tfsG0(blk[2]);
    b = tfsG1(blk[3]);
    blk[0] = rotw(blk[0] ^ a + b + tfsKey[4 * r + 10] & MAXINT, 31);
    blk[1] = rotw(blk[1], 1) ^ a + 2 * b + tfsKey[4 * r + 11] & MAXINT;
  }

  function tfsIrnd(i, blk) {
    var a = tfsG0(blk[0]);
    var b = tfsG1(blk[1]);
    blk[2] = rotw(blk[2], 1) ^ a + b + tfsKey[4 * i + 10] & MAXINT;
    blk[3] = rotw(blk[3] ^ a + 2 * b + tfsKey[4 * i + 11] & MAXINT, 31);
    a = tfsG0(blk[2]);
    b = tfsG1(blk[3]);
    blk[0] = rotw(blk[0], 1) ^ a + b + tfsKey[4 * i + 8] & MAXINT;
    blk[1] = rotw(blk[1] ^ a + 2 * b + tfsKey[4 * i + 9] & MAXINT, 31);
  }

  function tfsClose() {
    tfsKey = [];
    tfsM = [[], [], [], []];
  }

  function tfsEncrypt(data, offset) {
    dataBytes = data;
    dataOffset = offset;
    var blk = [getW(dataBytes, dataOffset) ^ tfsKey[0], getW(dataBytes, dataOffset + 4) ^ tfsKey[1], getW(dataBytes, dataOffset + 8) ^ tfsKey[2], getW(dataBytes, dataOffset + 12) ^ tfsKey[3]];
    for (var j = 0; j < 8; j++) {
      tfsFrnd(j, blk);
    }
    setW(dataBytes, dataOffset, blk[2] ^ tfsKey[4]);
    setW(dataBytes, dataOffset + 4, blk[3] ^ tfsKey[5]);
    setW(dataBytes, dataOffset + 8, blk[0] ^ tfsKey[6]);
    setW(dataBytes, dataOffset + 12, blk[1] ^ tfsKey[7]);
    dataOffset += 16;
    return dataBytes;
  }

  function tfsDecrypt(data, offset) {
    dataBytes = data;
    dataOffset = offset;
    var blk = [getW(dataBytes, dataOffset) ^ tfsKey[4], getW(dataBytes, dataOffset + 4) ^ tfsKey[5], getW(dataBytes, dataOffset + 8) ^ tfsKey[6], getW(dataBytes, dataOffset + 12) ^ tfsKey[7]];
    for (var j = 7; j >= 0; j--) {
      tfsIrnd(j, blk);
    }
    setW(dataBytes, dataOffset, blk[2] ^ tfsKey[0]);
    setW(dataBytes, dataOffset + 4, blk[3] ^ tfsKey[1]);
    setW(dataBytes, dataOffset + 8, blk[0] ^ tfsKey[2]);
    setW(dataBytes, dataOffset + 12, blk[1] ^ tfsKey[3]);
    dataOffset += 16;
  }

  // added by Recurity Labs

  function tfsFinal() {
    return dataBytes;
  }

  return {
    name: "twofish",
    blocksize: 128 / 8,
    open: tfsInit,
    close: tfsClose,
    encrypt: tfsEncrypt,
    decrypt: tfsDecrypt,
    // added by Recurity Labs
    finalize: tfsFinal
  };
}

// added by Recurity Labs

function TF(key) {
  this.tf = createTwofish();
  this.tf.open(toArray(key), 0);

  this.encrypt = function (block) {
    return this.tf.encrypt(toArray(block), 0);
  };
}

function toArray(typedArray) {
  // Array.apply([], typedArray) does not work in PhantomJS 1.9
  var result = [];
  for (var i = 0; i < typedArray.length; i++) {
    result[i] = typedArray[i];
  }
  return result;
}

TF.keySize = TF.prototype.keySize = 32;
TF.blockSize = TF.prototype.blockSize = 16;

},{}],18:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

// The GPG4Browsers crypto interface

/**
 * @requires crypto/cipher
 * @requires crypto/public_key
 * @requires crypto/random
 * @requires type/mpi
 * @module crypto/crypto
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _random = _dereq_('./random.js');

var _random2 = _interopRequireDefault(_random);

var _cipher = _dereq_('./cipher');

var _cipher2 = _interopRequireDefault(_cipher);

var _public_key = _dereq_('./public_key');

var _public_key2 = _interopRequireDefault(_public_key);

var _mpi = _dereq_('../type/mpi.js');

var _mpi2 = _interopRequireDefault(_mpi);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = {
  /**
   * Encrypts data using the specified public key multiprecision integers
   * and the specified algorithm.
   * @param {module:enums.publicKey} algo Algorithm to be used (See {@link http://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1})
   * @param {Array<module:type/mpi>} publicMPIs Algorithm dependent multiprecision integers
   * @param {module:type/mpi} data Data to be encrypted as MPI
   * @return {Array<module:type/mpi>} if RSA an module:type/mpi;
   * if elgamal encryption an array of two module:type/mpi is returned; otherwise null
   */
  publicKeyEncrypt: function publicKeyEncrypt(algo, publicMPIs, data) {
    var result = function () {
      var m;
      switch (algo) {
        case 'rsa_encrypt':
        case 'rsa_encrypt_sign':
          var rsa = new _public_key2.default.rsa();
          var n = publicMPIs[0].toBigInteger();
          var e = publicMPIs[1].toBigInteger();
          m = data.toBigInteger();
          return [rsa.encrypt(m, e, n)];

        case 'elgamal':
          var elgamal = new _public_key2.default.elgamal();
          var p = publicMPIs[0].toBigInteger();
          var g = publicMPIs[1].toBigInteger();
          var y = publicMPIs[2].toBigInteger();
          m = data.toBigInteger();
          return elgamal.encrypt(m, g, p, y);

        default:
          return [];
      }
    }();

    return result.map(function (bn) {
      var mpi = new _mpi2.default();
      mpi.fromBigInteger(bn);
      return mpi;
    });
  },

  /**
   * Decrypts data using the specified public key multiprecision integers of the private key,
   * the specified secretMPIs of the private key and the specified algorithm.
   * @param {module:enums.publicKey} algo Algorithm to be used (See {@link http://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1})
   * @param {Array<module:type/mpi>} publicMPIs Algorithm dependent multiprecision integers
   * of the public key part of the private key
   * @param {Array<module:type/mpi>} secretMPIs Algorithm dependent multiprecision integers
   * of the private key used
   * @param {module:type/mpi} data Data to be encrypted as MPI
   * @return {module:type/mpi} returns a big integer containing the decrypted data; otherwise null
   */

  publicKeyDecrypt: function publicKeyDecrypt(algo, keyIntegers, dataIntegers) {
    var p;

    var bn = function () {
      switch (algo) {
        case 'rsa_encrypt_sign':
        case 'rsa_encrypt':
          var rsa = new _public_key2.default.rsa();
          // 0 and 1 are the public key.
          var n = keyIntegers[0].toBigInteger();
          var e = keyIntegers[1].toBigInteger();
          // 2 to 5 are the private key.
          var d = keyIntegers[2].toBigInteger();
          p = keyIntegers[3].toBigInteger();
          var q = keyIntegers[4].toBigInteger();
          var u = keyIntegers[5].toBigInteger();
          var m = dataIntegers[0].toBigInteger();
          return rsa.decrypt(m, n, e, d, p, q, u);
        case 'elgamal':
          var elgamal = new _public_key2.default.elgamal();
          var x = keyIntegers[3].toBigInteger();
          var c1 = dataIntegers[0].toBigInteger();
          var c2 = dataIntegers[1].toBigInteger();
          p = keyIntegers[0].toBigInteger();
          return elgamal.decrypt(c1, c2, p, x);
        default:
          return null;
      }
    }();

    var result = new _mpi2.default();
    result.fromBigInteger(bn);
    return result;
  },

  /** Returns the number of integers comprising the private key of an algorithm
   * @param {String} algo The public key algorithm
   * @return {Integer} The number of integers.
   */
  getPrivateMpiCount: function getPrivateMpiCount(algo) {
    switch (algo) {
      case 'rsa_encrypt':
      case 'rsa_encrypt_sign':
      case 'rsa_sign':
        //   Algorithm-Specific Fields for RSA secret keys:
        //   - multiprecision integer (MPI) of RSA secret exponent d.
        //   - MPI of RSA secret prime value p.
        //   - MPI of RSA secret prime value q (p < q).
        //   - MPI of u, the multiplicative inverse of p, mod q.
        return 4;
      case 'elgamal':
        // Algorithm-Specific Fields for Elgamal secret keys:
        //   - MPI of Elgamal secret exponent x.
        return 1;
      case 'dsa':
        // Algorithm-Specific Fields for DSA secret keys:
        //   - MPI of DSA secret exponent x.
        return 1;
      default:
        throw new Error('Unknown algorithm');
    }
  },

  getPublicMpiCount: function getPublicMpiCount(algo) {
    // - A series of multiprecision integers comprising the key material:
    //   Algorithm-Specific Fields for RSA public keys:
    //       - a multiprecision integer (MPI) of RSA public modulus n;
    //       - an MPI of RSA public encryption exponent e.
    switch (algo) {
      case 'rsa_encrypt':
      case 'rsa_encrypt_sign':
      case 'rsa_sign':
        return 2;

      //   Algorithm-Specific Fields for Elgamal public keys:
      //     - MPI of Elgamal prime p;
      //     - MPI of Elgamal group generator g;
      //     - MPI of Elgamal public key value y (= g**x mod p where x  is secret).
      case 'elgamal':
        return 3;

      //   Algorithm-Specific Fields for DSA public keys:
      //       - MPI of DSA prime p;
      //       - MPI of DSA group order q (q is a prime divisor of p-1);
      //       - MPI of DSA group generator g;
      //       - MPI of DSA public-key value y (= g**x mod p where x  is secret).
      case 'dsa':
        return 4;

      default:
        throw new Error('Unknown algorithm.');
    }
  },

  generateMpi: function generateMpi(algo, bits) {
    switch (algo) {
      case 'rsa_encrypt':
      case 'rsa_encrypt_sign':
      case 'rsa_sign':
        //remember "publicKey" refers to the crypto/public_key dir
        var rsa = new _public_key2.default.rsa();
        return rsa.generate(bits, "10001").then(function (keyObject) {
          var output = [];
          output.push(keyObject.n);
          output.push(keyObject.ee);
          output.push(keyObject.d);
          output.push(keyObject.p);
          output.push(keyObject.q);
          output.push(keyObject.u);
          return mapResult(output);
        });
      default:
        throw new Error('Unsupported algorithm for key generation.');
    }

    function mapResult(result) {
      return result.map(function (bn) {
        var mpi = new _mpi2.default();
        mpi.fromBigInteger(bn);
        return mpi;
      });
    }
  },

  /**
   * generate random byte prefix as string for the specified algorithm
   * @param {module:enums.symmetric} algo Algorithm to use (see {@link http://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2})
   * @return {Uint8Array} Random bytes with length equal to the block
   * size of the cipher
   */
  getPrefixRandom: function getPrefixRandom(algo) {
    return _random2.default.getRandomBytes(_cipher2.default[algo].blockSize);
  },

  /**
   * Generating a session key for the specified symmetric algorithm
   * @param {module:enums.symmetric} algo Algorithm to use (see {@link http://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2})
   * @return {Uint8Array} Random bytes as a string to be used as a key
   */
  generateSessionKey: function generateSessionKey(algo) {
    return _random2.default.getRandomBytes(_cipher2.default[algo].keySize);
  }
};

},{"../type/mpi.js":68,"./cipher":16,"./public_key":28,"./random.js":31}],19:[function(_dereq_,module,exports){
// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2016 Tankred Hase
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @fileoverview This module wraps native AES-GCM en/decryption for both
 * the WebCrypto api as well as node.js' crypto api.
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.ivLength = undefined;
exports.encrypt = encrypt;
exports.decrypt = decrypt;

var _util = _dereq_('../util.js');

var _util2 = _interopRequireDefault(_util);

var _config = _dereq_('../config');

var _config2 = _interopRequireDefault(_config);

var _asmcryptoLite = _dereq_('asmcrypto-lite');

var _asmcryptoLite2 = _interopRequireDefault(_asmcryptoLite);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var webCrypto = _util2.default.getWebCrypto(); // no GCM support in IE11, Safari 9
var nodeCrypto = _util2.default.getNodeCrypto();
var Buffer = _util2.default.getNodeBuffer();

var ivLength = exports.ivLength = 12; // size of the IV in bytes
var TAG_LEN = 16; // size of the tag in bytes
var ALGO = 'AES-GCM';

/**
 * Encrypt plaintext input.
 * @param  {String}     cipher      The symmetric cipher algorithm to use e.g. 'aes128'
 * @param  {Uint8Array} plaintext   The cleartext input to be encrypted
 * @param  {Uint8Array} key         The encryption key
 * @param  {Uint8Array} iv          The initialization vector (12 bytes)
 * @return {Promise<Uint8Array>}    The ciphertext output
 */
function encrypt(cipher, plaintext, key, iv) {
  if (cipher.substr(0, 3) !== 'aes') {
    return Promise.reject(new Error('GCM mode supports only AES cipher'));
  }

  if (webCrypto && _config2.default.use_native && key.length !== 24) {
    // WebCrypto (no 192 bit support) see: https://www.chromium.org/blink/webcrypto#TOC-AES-support
    return webEncrypt(plaintext, key, iv);
  } else if (nodeCrypto && _config2.default.use_native) {
    // Node crypto library
    return nodeEncrypt(plaintext, key, iv);
  } else {
    // asm.js fallback
    return Promise.resolve(_asmcryptoLite2.default.AES_GCM.encrypt(plaintext, key, iv));
  }
}

/**
 * Decrypt ciphertext input.
 * @param  {String}     cipher       The symmetric cipher algorithm to use e.g. 'aes128'
 * @param  {Uint8Array} ciphertext   The ciphertext input to be decrypted
 * @param  {Uint8Array} key          The encryption key
 * @param  {Uint8Array} iv           The initialization vector (12 bytes)
 * @return {Promise<Uint8Array>}     The plaintext output
 */
function decrypt(cipher, ciphertext, key, iv) {
  if (cipher.substr(0, 3) !== 'aes') {
    return Promise.reject(new Error('GCM mode supports only AES cipher'));
  }

  if (webCrypto && _config2.default.use_native && key.length !== 24) {
    // WebCrypto (no 192 bit support) see: https://www.chromium.org/blink/webcrypto#TOC-AES-support
    return webDecrypt(ciphertext, key, iv);
  } else if (nodeCrypto && _config2.default.use_native) {
    // Node crypto library
    return nodeDecrypt(ciphertext, key, iv);
  } else {
    // asm.js fallback
    return Promise.resolve(_asmcryptoLite2.default.AES_GCM.decrypt(ciphertext, key, iv));
  }
}

//////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////

function webEncrypt(pt, key, iv) {
  return webCrypto.importKey('raw', key, { name: ALGO }, false, ['encrypt']).then(function (keyObj) {
    return webCrypto.encrypt({ name: ALGO, iv: iv }, keyObj, pt);
  }).then(function (ct) {
    return new Uint8Array(ct);
  });
}

function webDecrypt(ct, key, iv) {
  return webCrypto.importKey('raw', key, { name: ALGO }, false, ['decrypt']).then(function (keyObj) {
    return webCrypto.decrypt({ name: ALGO, iv: iv }, keyObj, ct);
  }).then(function (pt) {
    return new Uint8Array(pt);
  });
}

function nodeEncrypt(pt, key, iv) {
  pt = new Buffer(pt);
  key = new Buffer(key);
  iv = new Buffer(iv);
  var en = new nodeCrypto.createCipheriv('aes-' + key.length * 8 + '-gcm', key, iv);
  var ct = Buffer.concat([en.update(pt), en.final(), en.getAuthTag()]); // append auth tag to ciphertext
  return Promise.resolve(new Uint8Array(ct));
}

function nodeDecrypt(ct, key, iv) {
  ct = new Buffer(ct);
  key = new Buffer(key);
  iv = new Buffer(iv);
  var de = new nodeCrypto.createDecipheriv('aes-' + key.length * 8 + '-gcm', key, iv);
  de.setAuthTag(ct.slice(ct.length - TAG_LEN, ct.length)); // read auth tag at end of ciphertext
  var pt = Buffer.concat([de.update(ct.slice(0, ct.length - TAG_LEN)), de.final()]);
  return Promise.resolve(new Uint8Array(pt));
}

},{"../config":10,"../util.js":70,"asmcrypto-lite":1}],20:[function(_dereq_,module,exports){
/**
 * @requires crypto/hash/sha
 * @requires crypto/hash/md5
 * @requires crypto/hash/ripe-md
 * @requires util
 * @module crypto/hash
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _sha = _dereq_('./sha.js');

var _sha2 = _interopRequireDefault(_sha);

var _asmcryptoLite = _dereq_('asmcrypto-lite');

var _asmcryptoLite2 = _interopRequireDefault(_asmcryptoLite);

var _rusha = _dereq_('rusha');

var _rusha2 = _interopRequireDefault(_rusha);

var _md = _dereq_('./md5.js');

var _md2 = _interopRequireDefault(_md);

var _ripeMd = _dereq_('./ripe-md.js');

var _ripeMd2 = _interopRequireDefault(_ripeMd);

var _util = _dereq_('../../util.js');

var _util2 = _interopRequireDefault(_util);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var rusha = new _rusha2.default(),
    nodeCrypto = _util2.default.getNodeCrypto(),
    Buffer = _util2.default.getNodeBuffer();

function node_hash(type) {
  return function (data) {
    var shasum = nodeCrypto.createHash(type);
    shasum.update(new Buffer(data));
    return new Uint8Array(shasum.digest());
  };
}

var hash_fns;
if (nodeCrypto) {
  // Use Node native crypto for all hash functions

  hash_fns = {
    md5: node_hash('md5'),
    sha1: node_hash('sha1'),
    sha224: node_hash('sha224'),
    sha256: node_hash('sha256'),
    sha384: node_hash('sha384'),
    sha512: node_hash('sha512'),
    ripemd: node_hash('ripemd160')
  };
} else {
  // Use JS fallbacks

  hash_fns = {
    /** @see module:crypto/hash/md5 */
    md5: _md2.default,
    /** @see module:rusha */
    sha1: function sha1(data) {
      return _util2.default.str2Uint8Array(_util2.default.hex2bin(rusha.digest(data)));
    },
    /** @see module:crypto/hash/sha.sha224 */
    sha224: _sha2.default.sha224,
    /** @see module:asmcrypto */
    sha256: _asmcryptoLite2.default.SHA256.bytes,
    /** @see module:crypto/hash/sha.sha384 */
    sha384: _sha2.default.sha384,
    /** @see module:crypto/hash/sha.sha512 */
    sha512: _sha2.default.sha512,
    /** @see module:crypto/hash/ripe-md */
    ripemd: _ripeMd2.default
  };
}

exports.default = {

  md5: hash_fns.md5,
  sha1: hash_fns.sha1,
  sha224: hash_fns.sha224,
  sha256: hash_fns.sha256,
  sha384: hash_fns.sha384,
  sha512: hash_fns.sha512,
  ripemd: hash_fns.ripemd,

  /**
   * Create a hash on the specified data using the specified algorithm
   * @param {module:enums.hash} algo Hash algorithm type (see {@link http://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4})
   * @param {Uint8Array} data Data to be hashed
   * @return {Uint8Array} hash value
   */
  digest: function digest(algo, data) {
    switch (algo) {
      case 1:
        // - MD5 [HAC]
        return this.md5(data);
      case 2:
        // - SHA-1 [FIPS180]
        return this.sha1(data);
      case 3:
        // - RIPE-MD/160 [HAC]
        return this.ripemd(data);
      case 8:
        // - SHA256 [FIPS180]
        return this.sha256(data);
      case 9:
        // - SHA384 [FIPS180]
        return this.sha384(data);
      case 10:
        // - SHA512 [FIPS180]
        return this.sha512(data);
      case 11:
        // - SHA224 [FIPS180]
        return this.sha224(data);
      default:
        throw new Error('Invalid hash function.');
    }
  },

  /**
   * Returns the hash size in bytes of the specified hash algorithm type
   * @param {module:enums.hash} algo Hash algorithm type (See {@link http://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4})
   * @return {Integer} Size in bytes of the resulting hash
   */
  getHashByteLength: function getHashByteLength(algo) {
    switch (algo) {
      case 1:
        // - MD5 [HAC]
        return 16;
      case 2:
      // - SHA-1 [FIPS180]
      case 3:
        // - RIPE-MD/160 [HAC]
        return 20;
      case 8:
        // - SHA256 [FIPS180]
        return 32;
      case 9:
        // - SHA384 [FIPS180]
        return 48;
      case 10:
        // - SHA512 [FIPS180]
        return 64;
      case 11:
        // - SHA224 [FIPS180]
        return 28;
      default:
        throw new Error('Invalid hash algorithm.');
    }
  }
};

},{"../../util.js":70,"./md5.js":21,"./ripe-md.js":22,"./sha.js":23,"asmcrypto-lite":1,"rusha":4}],21:[function(_dereq_,module,exports){
/**
 * A fast MD5 JavaScript implementation
 * Copyright (c) 2012 Joseph Myers
 * http://www.myersdaily.org/joseph/javascript/md5-text.html
 *
 * Permission to use, copy, modify, and distribute this software
 * and its documentation for any purposes and without
 * fee is hereby granted provided that this copyright notice
 * appears in all copies.
 *
 * Of course, this soft is provided "as is" without express or implied
 * warranty of any kind.
 */

/**
 * @requires util
 * @module crypto/hash/md5
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

exports.default = function (entree) {
  var hex = md5(_util2.default.Uint8Array2str(entree));
  var bin = _util2.default.str2Uint8Array(_util2.default.hex2bin(hex));
  return bin;
};

var _util = _dereq_('../../util.js');

var _util2 = _interopRequireDefault(_util);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function md5cycle(x, k) {
  var a = x[0],
      b = x[1],
      c = x[2],
      d = x[3];

  a = ff(a, b, c, d, k[0], 7, -680876936);
  d = ff(d, a, b, c, k[1], 12, -389564586);
  c = ff(c, d, a, b, k[2], 17, 606105819);
  b = ff(b, c, d, a, k[3], 22, -1044525330);
  a = ff(a, b, c, d, k[4], 7, -176418897);
  d = ff(d, a, b, c, k[5], 12, 1200080426);
  c = ff(c, d, a, b, k[6], 17, -1473231341);
  b = ff(b, c, d, a, k[7], 22, -45705983);
  a = ff(a, b, c, d, k[8], 7, 1770035416);
  d = ff(d, a, b, c, k[9], 12, -1958414417);
  c = ff(c, d, a, b, k[10], 17, -42063);
  b = ff(b, c, d, a, k[11], 22, -1990404162);
  a = ff(a, b, c, d, k[12], 7, 1804603682);
  d = ff(d, a, b, c, k[13], 12, -40341101);
  c = ff(c, d, a, b, k[14], 17, -1502002290);
  b = ff(b, c, d, a, k[15], 22, 1236535329);

  a = gg(a, b, c, d, k[1], 5, -165796510);
  d = gg(d, a, b, c, k[6], 9, -1069501632);
  c = gg(c, d, a, b, k[11], 14, 643717713);
  b = gg(b, c, d, a, k[0], 20, -373897302);
  a = gg(a, b, c, d, k[5], 5, -701558691);
  d = gg(d, a, b, c, k[10], 9, 38016083);
  c = gg(c, d, a, b, k[15], 14, -660478335);
  b = gg(b, c, d, a, k[4], 20, -405537848);
  a = gg(a, b, c, d, k[9], 5, 568446438);
  d = gg(d, a, b, c, k[14], 9, -1019803690);
  c = gg(c, d, a, b, k[3], 14, -187363961);
  b = gg(b, c, d, a, k[8], 20, 1163531501);
  a = gg(a, b, c, d, k[13], 5, -1444681467);
  d = gg(d, a, b, c, k[2], 9, -51403784);
  c = gg(c, d, a, b, k[7], 14, 1735328473);
  b = gg(b, c, d, a, k[12], 20, -1926607734);

  a = hh(a, b, c, d, k[5], 4, -378558);
  d = hh(d, a, b, c, k[8], 11, -2022574463);
  c = hh(c, d, a, b, k[11], 16, 1839030562);
  b = hh(b, c, d, a, k[14], 23, -35309556);
  a = hh(a, b, c, d, k[1], 4, -1530992060);
  d = hh(d, a, b, c, k[4], 11, 1272893353);
  c = hh(c, d, a, b, k[7], 16, -155497632);
  b = hh(b, c, d, a, k[10], 23, -1094730640);
  a = hh(a, b, c, d, k[13], 4, 681279174);
  d = hh(d, a, b, c, k[0], 11, -358537222);
  c = hh(c, d, a, b, k[3], 16, -722521979);
  b = hh(b, c, d, a, k[6], 23, 76029189);
  a = hh(a, b, c, d, k[9], 4, -640364487);
  d = hh(d, a, b, c, k[12], 11, -421815835);
  c = hh(c, d, a, b, k[15], 16, 530742520);
  b = hh(b, c, d, a, k[2], 23, -995338651);

  a = ii(a, b, c, d, k[0], 6, -198630844);
  d = ii(d, a, b, c, k[7], 10, 1126891415);
  c = ii(c, d, a, b, k[14], 15, -1416354905);
  b = ii(b, c, d, a, k[5], 21, -57434055);
  a = ii(a, b, c, d, k[12], 6, 1700485571);
  d = ii(d, a, b, c, k[3], 10, -1894986606);
  c = ii(c, d, a, b, k[10], 15, -1051523);
  b = ii(b, c, d, a, k[1], 21, -2054922799);
  a = ii(a, b, c, d, k[8], 6, 1873313359);
  d = ii(d, a, b, c, k[15], 10, -30611744);
  c = ii(c, d, a, b, k[6], 15, -1560198380);
  b = ii(b, c, d, a, k[13], 21, 1309151649);
  a = ii(a, b, c, d, k[4], 6, -145523070);
  d = ii(d, a, b, c, k[11], 10, -1120210379);
  c = ii(c, d, a, b, k[2], 15, 718787259);
  b = ii(b, c, d, a, k[9], 21, -343485551);

  x[0] = add32(a, x[0]);
  x[1] = add32(b, x[1]);
  x[2] = add32(c, x[2]);
  x[3] = add32(d, x[3]);
}

/**
 * MD5 hash
 * @param {String} entree string to hash
 */


function cmn(q, a, b, x, s, t) {
  a = add32(add32(a, q), add32(x, t));
  return add32(a << s | a >>> 32 - s, b);
}

function ff(a, b, c, d, x, s, t) {
  return cmn(b & c | ~b & d, a, b, x, s, t);
}

function gg(a, b, c, d, x, s, t) {
  return cmn(b & d | c & ~d, a, b, x, s, t);
}

function hh(a, b, c, d, x, s, t) {
  return cmn(b ^ c ^ d, a, b, x, s, t);
}

function ii(a, b, c, d, x, s, t) {
  return cmn(c ^ (b | ~d), a, b, x, s, t);
}

function md51(s) {
  var n = s.length,
      state = [1732584193, -271733879, -1732584194, 271733878],
      i;
  for (i = 64; i <= s.length; i += 64) {
    md5cycle(state, md5blk(s.substring(i - 64, i)));
  }
  s = s.substring(i - 64);
  var tail = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  for (i = 0; i < s.length; i++) {
    tail[i >> 2] |= s.charCodeAt(i) << (i % 4 << 3);
  }
  tail[i >> 2] |= 0x80 << (i % 4 << 3);
  if (i > 55) {
    md5cycle(state, tail);
    for (i = 0; i < 16; i++) {
      tail[i] = 0;
    }
  }
  tail[14] = n * 8;
  md5cycle(state, tail);
  return state;
}

/* there needs to be support for Unicode here,
 * unless we pretend that we can redefine the MD-5
 * algorithm for multi-byte characters (perhaps
 * by adding every four 16-bit characters and
 * shortening the sum to 32 bits). Otherwise
 * I suggest performing MD-5 as if every character
 * was two bytes--e.g., 0040 0025 = @%--but then
 * how will an ordinary MD-5 sum be matched?
 * There is no way to standardize text to something
 * like UTF-8 before transformation; speed cost is
 * utterly prohibitive. The JavaScript standard
 * itself needs to look at this: it should start
 * providing access to strings as preformed UTF-8
 * 8-bit unsigned value arrays.
 */
function md5blk(s) {
  /* I figured global was faster.   */
  var md5blks = [],
      i; /* Andy King said do it this way. */
  for (i = 0; i < 64; i += 4) {
    md5blks[i >> 2] = s.charCodeAt(i) + (s.charCodeAt(i + 1) << 8) + (s.charCodeAt(i + 2) << 16) + (s.charCodeAt(i + 3) << 24);
  }
  return md5blks;
}

var hex_chr = '0123456789abcdef'.split('');

function rhex(n) {
  var s = '',
      j = 0;
  for (; j < 4; j++) {
    s += hex_chr[n >> j * 8 + 4 & 0x0F] + hex_chr[n >> j * 8 & 0x0F];
  }
  return s;
}

function hex(x) {
  for (var i = 0; i < x.length; i++) {
    x[i] = rhex(x[i]);
  }
  return x.join('');
}

function md5(s) {
  return hex(md51(s));
}

/* this function is much faster,
so if possible we use it. Some IEs
are the only ones I know of that
need the idiotic second function,
generated by an if clause.  */

function add32(a, b) {
  return a + b & 0xFFFFFFFF;
}

},{"../../util.js":70}],22:[function(_dereq_,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = RMDstring;

var _util = _dereq_("../../util.js");

var _util2 = _interopRequireDefault(_util);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var RMDsize = 160; /*
                    * CryptoMX Tools
                    * Copyright (C) 2004 - 2006 Derek Buitenhuis
                    *
                    * This program is free software; you can redistribute it and/or
                    * modify it under the terms of the GNU General Public License
                    * as published by the Free Software Foundation; either version 2
                    * of the License, or (at your option) any later version.
                    *
                    * This program is distributed in the hope that it will be useful,
                    * but WITHOUT ANY WARRANTY; without even the implied warranty of
                    * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
                    * GNU General Public License for more details.
                    *
                    * You should have received a copy of the GNU General Public License
                    * along with this program; if not, write to the Free Software
                    * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
                    */

/* Modified by Recurity Labs GmbH
 */

/* Modified by ProtonTech AG
 */

/**
 * @requires util
 * @module crypto/hash/ripe-md
 */

var X = [];

function ROL(x, n) {
  return new Number(x << n | x >>> 32 - n);
}

function F(x, y, z) {
  return new Number(x ^ y ^ z);
}

function G(x, y, z) {
  return new Number(x & y | ~x & z);
}

function H(x, y, z) {
  return new Number((x | ~y) ^ z);
}

function I(x, y, z) {
  return new Number(x & z | y & ~z);
}

function J(x, y, z) {
  return new Number(x ^ (y | ~z));
}

function mixOneRound(a, b, c, d, e, x, s, roundNumber) {
  switch (roundNumber) {
    case 0:
      a += F(b, c, d) + x + 0x00000000;
      break;
    case 1:
      a += G(b, c, d) + x + 0x5a827999;
      break;
    case 2:
      a += H(b, c, d) + x + 0x6ed9eba1;
      break;
    case 3:
      a += I(b, c, d) + x + 0x8f1bbcdc;
      break;
    case 4:
      a += J(b, c, d) + x + 0xa953fd4e;
      break;
    case 5:
      a += J(b, c, d) + x + 0x50a28be6;
      break;
    case 6:
      a += I(b, c, d) + x + 0x5c4dd124;
      break;
    case 7:
      a += H(b, c, d) + x + 0x6d703ef3;
      break;
    case 8:
      a += G(b, c, d) + x + 0x7a6d76e9;
      break;
    case 9:
      a += F(b, c, d) + x + 0x00000000;
      break;

    default:
      throw new Error("Bogus round number");
      break;
  }

  a = ROL(a, s) + e;
  c = ROL(c, 10);

  a &= 0xffffffff;
  b &= 0xffffffff;
  c &= 0xffffffff;
  d &= 0xffffffff;
  e &= 0xffffffff;

  var retBlock = [];
  retBlock[0] = a;
  retBlock[1] = b;
  retBlock[2] = c;
  retBlock[3] = d;
  retBlock[4] = e;
  retBlock[5] = x;
  retBlock[6] = s;

  return retBlock;
}

function MDinit(MDbuf) {
  MDbuf[0] = 0x67452301;
  MDbuf[1] = 0xefcdab89;
  MDbuf[2] = 0x98badcfe;
  MDbuf[3] = 0x10325476;
  MDbuf[4] = 0xc3d2e1f0;
}

var ROLs = [[11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8], [7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12], [11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5], [11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12], [9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6], [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6], [9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11], [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5], [15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8], [8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]];

var indexes = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8], [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12], [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2], [4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13], [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12], [6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2], [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13], [8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14], [12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]];

function compress(MDbuf, X) {
  var blockA = [];
  var blockB = [];

  var retBlock;

  var i, j;

  for (i = 0; i < 5; i++) {
    blockA[i] = new Number(MDbuf[i]);
    blockB[i] = new Number(MDbuf[i]);
  }

  var step = 0;
  for (j = 0; j < 5; j++) {
    for (i = 0; i < 16; i++) {
      retBlock = mixOneRound(blockA[(step + 0) % 5], blockA[(step + 1) % 5], blockA[(step + 2) % 5], blockA[(step + 3) % 5], blockA[(step + 4) % 5], X[indexes[j][i]], ROLs[j][i], j);

      blockA[(step + 0) % 5] = retBlock[0];
      blockA[(step + 1) % 5] = retBlock[1];
      blockA[(step + 2) % 5] = retBlock[2];
      blockA[(step + 3) % 5] = retBlock[3];
      blockA[(step + 4) % 5] = retBlock[4];

      step += 4;
    }
  }

  step = 0;
  for (j = 5; j < 10; j++) {
    for (i = 0; i < 16; i++) {
      retBlock = mixOneRound(blockB[(step + 0) % 5], blockB[(step + 1) % 5], blockB[(step + 2) % 5], blockB[(step + 3) % 5], blockB[(step + 4) % 5], X[indexes[j][i]], ROLs[j][i], j);

      blockB[(step + 0) % 5] = retBlock[0];
      blockB[(step + 1) % 5] = retBlock[1];
      blockB[(step + 2) % 5] = retBlock[2];
      blockB[(step + 3) % 5] = retBlock[3];
      blockB[(step + 4) % 5] = retBlock[4];

      step += 4;
    }
  }

  blockB[3] += blockA[2] + MDbuf[1];
  MDbuf[1] = MDbuf[2] + blockA[3] + blockB[4];
  MDbuf[2] = MDbuf[3] + blockA[4] + blockB[0];
  MDbuf[3] = MDbuf[4] + blockA[0] + blockB[1];
  MDbuf[4] = MDbuf[0] + blockA[1] + blockB[2];
  MDbuf[0] = blockB[3];
}

function zeroX(X) {
  for (var i = 0; i < 16; i++) {
    X[i] = 0;
  }
}

function MDfinish(MDbuf, strptr, lswlen, mswlen) {
  var X = new Array(16);
  zeroX(X);

  var j = 0;
  for (var i = 0; i < (lswlen & 63); i++) {
    X[i >>> 2] ^= (strptr.charCodeAt(j++) & 255) << 8 * (i & 3);
  }

  X[lswlen >>> 2 & 15] ^= 1 << 8 * (lswlen & 3) + 7;

  if ((lswlen & 63) > 55) {
    compress(MDbuf, X);
    X = new Array(16);
    zeroX(X);
  }

  X[14] = lswlen << 3;
  X[15] = lswlen >>> 29 | mswlen << 3;

  compress(MDbuf, X);
}

function BYTES_TO_DWORD(fourChars) {
  var tmp = (fourChars.charCodeAt(3) & 255) << 24;
  tmp |= (fourChars.charCodeAt(2) & 255) << 16;
  tmp |= (fourChars.charCodeAt(1) & 255) << 8;
  tmp |= fourChars.charCodeAt(0) & 255;

  return tmp;
}

function RMD(message) {
  var MDbuf = new Array(RMDsize / 32);
  var hashcode = new Array(RMDsize / 8);
  var length;
  var nbytes;

  MDinit(MDbuf);
  length = message.length;

  var X = new Array(16);
  zeroX(X);

  var i,
      j = 0;
  for (nbytes = length; nbytes > 63; nbytes -= 64) {
    for (i = 0; i < 16; i++) {
      X[i] = BYTES_TO_DWORD(message.substr(j, 4));
      j += 4;
    }
    compress(MDbuf, X);
  }

  MDfinish(MDbuf, message.substr(j), length, 0);

  for (i = 0; i < RMDsize / 8; i += 4) {
    hashcode[i] = MDbuf[i >>> 2] & 255;
    hashcode[i + 1] = MDbuf[i >>> 2] >>> 8 & 255;
    hashcode[i + 2] = MDbuf[i >>> 2] >>> 16 & 255;
    hashcode[i + 3] = MDbuf[i >>> 2] >>> 24 & 255;
  }

  return hashcode;
}

function RMDstring(message) {
  var hashcode = RMD(_util2.default.Uint8Array2str(message));
  var retString = "";

  for (var i = 0; i < RMDsize / 8; i++) {
    retString += String.fromCharCode(hashcode[i]);
  }

  return _util2.default.str2Uint8Array(retString);
}

},{"../../util.js":70}],23:[function(_dereq_,module,exports){
/**
 * @preserve A JavaScript implementation of the SHA family of hashes, as
 * defined in FIPS PUB 180-2 as well as the corresponding HMAC implementation
 * as defined in FIPS PUB 198a
 *
 * Copyright Brian Turek 2008-2015
 * Distributed under the BSD License
 * See http://caligatio.github.com/jsSHA/ for more information
 *
 * Several functions taken from Paul Johnston
 */

/**
 * SUPPORTED_ALGS is the stub for a compile flag that will cause pruning of
 * functions that are not needed when a limited number of SHA families are
 * selected
 *
 * @define {number} ORed value of SHA variants to be supported
 *   1 = SHA-1, 2 = SHA-224/SHA-256, 4 = SHA-384/SHA-512
 */

"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
var SUPPORTED_ALGS = 4 | 2 | 1;

/**
 * Int_64 is a object for 2 32-bit numbers emulating a 64-bit number
 *
 * @private
 * @constructor
 * @this {Int_64}
 * @param {number} msint_32 The most significant 32-bits of a 64-bit number
 * @param {number} lsint_32 The least significant 32-bits of a 64-bit number
 */
function Int_64(msint_32, lsint_32) {
  this.highOrder = msint_32;
  this.lowOrder = lsint_32;
}

/**
 * Convert a string to an array of big-endian words
 *
 * @private
 * @param {string} str String to be converted to binary representation
 * @param {string} utfType The Unicode type, UTF8 or UTF16BE, UTF16LE, to
 *   use to encode the source string
 * @return {{value : Array.<number>, binLen : number}} Hash list where
 *   "value" contains the output number array and "binLen" is the binary
 *   length of "value"
 */
function str2binb(str, utfType) {
  var bin = [],
      codePnt,
      binArr = [],
      byteCnt = 0,
      i,
      j,
      offset;

  if ("UTF8" === utfType) {
    for (i = 0; i < str.length; i += 1) {
      codePnt = str.charCodeAt(i);
      binArr = [];

      if (0x80 > codePnt) {
        binArr.push(codePnt);
      } else if (0x800 > codePnt) {
        binArr.push(0xC0 | codePnt >>> 6);
        binArr.push(0x80 | codePnt & 0x3F);
      } else if (0xd800 > codePnt || 0xe000 <= codePnt) {
        binArr.push(0xe0 | codePnt >>> 12, 0x80 | codePnt >>> 6 & 0x3f, 0x80 | codePnt & 0x3f);
      } else {
        i += 1;
        codePnt = 0x10000 + ((codePnt & 0x3ff) << 10 | str.charCodeAt(i) & 0x3ff);
        binArr.push(0xf0 | codePnt >>> 18, 0x80 | codePnt >>> 12 & 0x3f, 0x80 | codePnt >>> 6 & 0x3f, 0x80 | codePnt & 0x3f);
      }

      for (j = 0; j < binArr.length; j += 1) {
        offset = byteCnt >>> 2;
        while (bin.length <= offset) {
          bin.push(0);
        }
        bin[offset] |= binArr[j] << 24 - 8 * (byteCnt % 4);
        byteCnt += 1;
      }
    }
  } else if ("UTF16BE" === utfType || "UTF16LE" === utfType) {
    for (i = 0; i < str.length; i += 1) {
      codePnt = str.charCodeAt(i);
      /* Internally strings are UTF-16BE so only change if UTF-16LE */
      if ("UTF16LE" === utfType) {
        j = codePnt & 0xFF;
        codePnt = j << 8 | codePnt >> 8;
      }

      offset = byteCnt >>> 2;
      while (bin.length <= offset) {
        bin.push(0);
      }
      bin[offset] |= codePnt << 16 - 8 * (byteCnt % 4);
      byteCnt += 2;
    }
  }
  return { "value": bin, "binLen": byteCnt * 8 };
}

/**
 * Convert a hex string to an array of big-endian words
 *
 * @private
 * @param {string} str String to be converted to binary representation
 * @return {{value : Array.<number>, binLen : number}} Hash list where
 *   "value" contains the output number array and "binLen" is the binary
 *   length of "value"
 */
function hex2binb(str) {
  var bin = [],
      length = str.length,
      i,
      num,
      offset;

  if (0 !== length % 2) {
    throw "String of HEX type must be in byte increments";
  }

  for (i = 0; i < length; i += 2) {
    num = parseInt(str.substr(i, 2), 16);
    if (!isNaN(num)) {
      offset = i >>> 3;
      while (bin.length <= offset) {
        bin.push(0);
      }
      bin[i >>> 3] |= num << 24 - 4 * (i % 8);
    } else {
      throw "String of HEX type contains invalid characters";
    }
  }

  return { "value": bin, "binLen": length * 4 };
}

/**
 * Convert a string of raw bytes to an array of big-endian words
 *
 * @private
 * @param {string} str String of raw bytes to be converted to binary representation
 * @return {{value : Array.<number>, binLen : number}} Hash list where
 *   "value" contains the output number array and "binLen" is the binary
 *   length of "value"
 */
function bytes2binb(str) {
  var bin = [],
      codePnt,
      i,
      offset;

  for (i = 0; i < str.length; i += 1) {
    codePnt = str.charCodeAt(i);

    offset = i >>> 2;
    if (bin.length <= offset) {
      bin.push(0);
    }
    bin[offset] |= codePnt << 24 - 8 * (i % 4);
  }

  return { "value": bin, "binLen": str.length * 8 };
}

/**
 * Convert a Uint8Array of raw bytes to an array of big-endian 32-bit words
 *
 * @private
 * @param {Uint8Array} str String of raw bytes to be converted to binary representation
 * @return {{value : Array.<number>, binLen : number}} Hash list where
 *   "value" contains the output array and "binLen" is the binary
 *   length of "value"
 */
function typed2binb(array) {

  var bin = [],
      octet,
      i,
      offset;

  for (i = 0; i < array.length; i += 1) {
    octet = array[i];

    offset = i >>> 2;
    if (bin.length <= offset) {
      bin.push(0);
    }
    bin[offset] |= octet << 24 - 8 * (i % 4);
  }

  return { "value": bin, "binLen": array.length * 8 };
}

/**
 * Convert a base-64 string to an array of big-endian words
 *
 * @private
 * @param {string} str String to be converted to binary representation
 * @return {{value : Array.<number>, binLen : number}} Hash list where
 *   "value" contains the output number array and "binLen" is the binary
 *   length of "value"
 */
function b642binb(str) {
  var retVal = [],
      byteCnt = 0,
      index,
      i,
      j,
      tmpInt,
      strPart,
      firstEqual,
      offset,
      b64Tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  if (-1 === str.search(/^[a-zA-Z0-9=+\/]+$/)) {
    throw "Invalid character in base-64 string";
  }
  firstEqual = str.indexOf('=');
  str = str.replace(/\=/g, '');
  if (-1 !== firstEqual && firstEqual < str.length) {
    throw "Invalid '=' found in base-64 string";
  }

  for (i = 0; i < str.length; i += 4) {
    strPart = str.substr(i, 4);
    tmpInt = 0;

    for (j = 0; j < strPart.length; j += 1) {
      index = b64Tab.indexOf(strPart[j]);
      tmpInt |= index << 18 - 6 * j;
    }

    for (j = 0; j < strPart.length - 1; j += 1) {
      offset = byteCnt >>> 2;
      while (retVal.length <= offset) {
        retVal.push(0);
      }
      retVal[offset] |= (tmpInt >>> 16 - j * 8 & 0xFF) << 24 - 8 * (byteCnt % 4);
      byteCnt += 1;
    }
  }

  return { "value": retVal, "binLen": byteCnt * 8 };
}

/**
 * Convert an array of big-endian words to a hex string.
 *
 * @private
 * @param {Array.<number>} binarray Array of integers to be converted to
 *   hexidecimal representation
 * @param {{outputUpper : boolean, b64Pad : string}} formatOpts Hash list
 *   containing validated output formatting options
 * @return {string} Hexidecimal representation of the parameter in string
 *   form
 */
function binb2hex(binarray, formatOpts) {
  var hex_tab = "0123456789abcdef",
      str = "",
      length = binarray.length * 4,
      i,
      srcByte;

  for (i = 0; i < length; i += 1) {
    /* The below is more than a byte but it gets taken care of later */
    srcByte = binarray[i >>> 2] >>> (3 - i % 4) * 8;
    str += hex_tab.charAt(srcByte >>> 4 & 0xF) + hex_tab.charAt(srcByte & 0xF);
  }

  return formatOpts["outputUpper"] ? str.toUpperCase() : str;
}

/**
 * Convert an array of big-endian words to a base-64 string
 *
 * @private
 * @param {Array.<number>} binarray Array of integers to be converted to
 *   base-64 representation
 * @param {{outputUpper : boolean, b64Pad : string}} formatOpts Hash list
 *   containing validated output formatting options
 * @return {string} Base-64 encoded representation of the parameter in
 *   string form
 */
function binb2b64(binarray, formatOpts) {
  var str = "",
      length = binarray.length * 4,
      i,
      j,
      triplet,
      offset,
      int1,
      int2,
      b64Tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  for (i = 0; i < length; i += 3) {
    offset = i + 1 >>> 2;
    int1 = binarray.length <= offset ? 0 : binarray[offset];
    offset = i + 2 >>> 2;
    int2 = binarray.length <= offset ? 0 : binarray[offset];
    triplet = (binarray[i >>> 2] >>> 8 * (3 - i % 4) & 0xFF) << 16 | (int1 >>> 8 * (3 - (i + 1) % 4) & 0xFF) << 8 | int2 >>> 8 * (3 - (i + 2) % 4) & 0xFF;
    for (j = 0; j < 4; j += 1) {
      if (i * 8 + j * 6 <= binarray.length * 32) {
        str += b64Tab.charAt(triplet >>> 6 * (3 - j) & 0x3F);
      } else {
        str += formatOpts["b64Pad"];
      }
    }
  }
  return str;
}

/**
 * Convert an array of big-endian words to raw bytes string
 *
 * @private
 * @param {Array.<number>} binarray Array of integers to be converted to
 *   a raw bytes string representation
 * @param {!Object} formatOpts Unused Hash list
 * @return {string} Raw bytes representation of the parameter in string
 *   form
 */
function binb2bytes(binarray, formatOpts) {
  var str = "",
      length = binarray.length * 4,
      i,
      srcByte;

  for (i = 0; i < length; i += 1) {
    srcByte = binarray[i >>> 2] >>> (3 - i % 4) * 8 & 0xFF;
    str += String.fromCharCode(srcByte);
  }

  return str;
}

/**
 * Convert an array of big-endian words to raw bytes Uint8Array
 *
 * @private
 * @param {Array.<number>} binarray Array of integers to be converted to
 *   a raw bytes string representation
 * @param {!Object} formatOpts Unused Hash list
 * @return {Uint8Array} Raw bytes representation of the parameter
 */
function binb2typed(binarray, formatOpts) {
  var length = binarray.length * 4;
  var arr = new Uint8Array(length),
      i;

  for (i = 0; i < length; i += 1) {
    arr[i] = binarray[i >>> 2] >>> (3 - i % 4) * 8 & 0xFF;
  }

  return arr;
}

/**
 * Validate hash list containing output formatting options, ensuring
 * presence of every option or adding the default value
 *
 * @private
 * @param {{outputUpper : boolean, b64Pad : string}|undefined} outputOpts
 *   Hash list of output formatting options
 * @return {{outputUpper : boolean, b64Pad : string}} Validated hash list
 *   containing output formatting options
 */
function getOutputOpts(outputOpts) {
  var retVal = { "outputUpper": false, "b64Pad": "=" };

  try {
    if (outputOpts.hasOwnProperty("outputUpper")) {
      retVal["outputUpper"] = outputOpts["outputUpper"];
    }

    if (outputOpts.hasOwnProperty("b64Pad")) {
      retVal["b64Pad"] = outputOpts["b64Pad"];
    }
  } catch (ignore) {}

  if ("boolean" !== typeof retVal["outputUpper"]) {
    throw "Invalid outputUpper formatting option";
  }

  if ("string" !== typeof retVal["b64Pad"]) {
    throw "Invalid b64Pad formatting option";
  }

  return retVal;
}

/**
 * The 32-bit implementation of circular rotate left
 *
 * @private
 * @param {number} x The 32-bit integer argument
 * @param {number} n The number of bits to shift
 * @return {number} The x shifted circularly by n bits
 */
function rotl_32(x, n) {
  return x << n | x >>> 32 - n;
}

/**
 * The 32-bit implementation of circular rotate right
 *
 * @private
 * @param {number} x The 32-bit integer argument
 * @param {number} n The number of bits to shift
 * @return {number} The x shifted circularly by n bits
 */
function rotr_32(x, n) {
  return x >>> n | x << 32 - n;
}

/**
 * The 64-bit implementation of circular rotate right
 *
 * @private
 * @param {Int_64} x The 64-bit integer argument
 * @param {number} n The number of bits to shift
 * @return {Int_64} The x shifted circularly by n bits
 */
function rotr_64(x, n) {
  var retVal = null,
      tmp = new Int_64(x.highOrder, x.lowOrder);

  if (32 >= n) {
    retVal = new Int_64(tmp.highOrder >>> n | tmp.lowOrder << 32 - n & 0xFFFFFFFF, tmp.lowOrder >>> n | tmp.highOrder << 32 - n & 0xFFFFFFFF);
  } else {
    retVal = new Int_64(tmp.lowOrder >>> n - 32 | tmp.highOrder << 64 - n & 0xFFFFFFFF, tmp.highOrder >>> n - 32 | tmp.lowOrder << 64 - n & 0xFFFFFFFF);
  }

  return retVal;
}

/**
 * The 32-bit implementation of shift right
 *
 * @private
 * @param {number} x The 32-bit integer argument
 * @param {number} n The number of bits to shift
 * @return {number} The x shifted by n bits
 */
function shr_32(x, n) {
  return x >>> n;
}

/**
 * The 64-bit implementation of shift right
 *
 * @private
 * @param {Int_64} x The 64-bit integer argument
 * @param {number} n The number of bits to shift
 * @return {Int_64} The x shifted by n bits
 */
function shr_64(x, n) {
  var retVal = null;

  if (32 >= n) {
    retVal = new Int_64(x.highOrder >>> n, x.lowOrder >>> n | x.highOrder << 32 - n & 0xFFFFFFFF);
  } else {
    retVal = new Int_64(0, x.highOrder >>> n - 32);
  }

  return retVal;
}

/**
 * The 32-bit implementation of the NIST specified Parity function
 *
 * @private
 * @param {number} x The first 32-bit integer argument
 * @param {number} y The second 32-bit integer argument
 * @param {number} z The third 32-bit integer argument
 * @return {number} The NIST specified output of the function
 */
function parity_32(x, y, z) {
  return x ^ y ^ z;
}

/**
 * The 32-bit implementation of the NIST specified Ch function
 *
 * @private
 * @param {number} x The first 32-bit integer argument
 * @param {number} y The second 32-bit integer argument
 * @param {number} z The third 32-bit integer argument
 * @return {number} The NIST specified output of the function
 */
function ch_32(x, y, z) {
  return x & y ^ ~x & z;
}

/**
 * The 64-bit implementation of the NIST specified Ch function
 *
 * @private
 * @param {Int_64} x The first 64-bit integer argument
 * @param {Int_64} y The second 64-bit integer argument
 * @param {Int_64} z The third 64-bit integer argument
 * @return {Int_64} The NIST specified output of the function
 */
function ch_64(x, y, z) {
  return new Int_64(x.highOrder & y.highOrder ^ ~x.highOrder & z.highOrder, x.lowOrder & y.lowOrder ^ ~x.lowOrder & z.lowOrder);
}

/**
 * The 32-bit implementation of the NIST specified Maj function
 *
 * @private
 * @param {number} x The first 32-bit integer argument
 * @param {number} y The second 32-bit integer argument
 * @param {number} z The third 32-bit integer argument
 * @return {number} The NIST specified output of the function
 */
function maj_32(x, y, z) {
  return x & y ^ x & z ^ y & z;
}

/**
 * The 64-bit implementation of the NIST specified Maj function
 *
 * @private
 * @param {Int_64} x The first 64-bit integer argument
 * @param {Int_64} y The second 64-bit integer argument
 * @param {Int_64} z The third 64-bit integer argument
 * @return {Int_64} The NIST specified output of the function
 */
function maj_64(x, y, z) {
  return new Int_64(x.highOrder & y.highOrder ^ x.highOrder & z.highOrder ^ y.highOrder & z.highOrder, x.lowOrder & y.lowOrder ^ x.lowOrder & z.lowOrder ^ y.lowOrder & z.lowOrder);
}

/**
 * The 32-bit implementation of the NIST specified Sigma0 function
 *
 * @private
 * @param {number} x The 32-bit integer argument
 * @return {number} The NIST specified output of the function
 */
function sigma0_32(x) {
  return rotr_32(x, 2) ^ rotr_32(x, 13) ^ rotr_32(x, 22);
}

/**
 * The 64-bit implementation of the NIST specified Sigma0 function
 *
 * @private
 * @param {Int_64} x The 64-bit integer argument
 * @return {Int_64} The NIST specified output of the function
 */
function sigma0_64(x) {
  var rotr28 = rotr_64(x, 28),
      rotr34 = rotr_64(x, 34),
      rotr39 = rotr_64(x, 39);

  return new Int_64(rotr28.highOrder ^ rotr34.highOrder ^ rotr39.highOrder, rotr28.lowOrder ^ rotr34.lowOrder ^ rotr39.lowOrder);
}

/**
 * The 32-bit implementation of the NIST specified Sigma1 function
 *
 * @private
 * @param {number} x The 32-bit integer argument
 * @return {number} The NIST specified output of the function
 */
function sigma1_32(x) {
  return rotr_32(x, 6) ^ rotr_32(x, 11) ^ rotr_32(x, 25);
}

/**
 * The 64-bit implementation of the NIST specified Sigma1 function
 *
 * @private
 * @param {Int_64} x The 64-bit integer argument
 * @return {Int_64} The NIST specified output of the function
 */
function sigma1_64(x) {
  var rotr14 = rotr_64(x, 14),
      rotr18 = rotr_64(x, 18),
      rotr41 = rotr_64(x, 41);

  return new Int_64(rotr14.highOrder ^ rotr18.highOrder ^ rotr41.highOrder, rotr14.lowOrder ^ rotr18.lowOrder ^ rotr41.lowOrder);
}

/**
 * The 32-bit implementation of the NIST specified Gamma0 function
 *
 * @private
 * @param {number} x The 32-bit integer argument
 * @return {number} The NIST specified output of the function
 */
function gamma0_32(x) {
  return rotr_32(x, 7) ^ rotr_32(x, 18) ^ shr_32(x, 3);
}

/**
 * The 64-bit implementation of the NIST specified Gamma0 function
 *
 * @private
 * @param {Int_64} x The 64-bit integer argument
 * @return {Int_64} The NIST specified output of the function
 */
function gamma0_64(x) {
  var rotr1 = rotr_64(x, 1),
      rotr8 = rotr_64(x, 8),
      shr7 = shr_64(x, 7);

  return new Int_64(rotr1.highOrder ^ rotr8.highOrder ^ shr7.highOrder, rotr1.lowOrder ^ rotr8.lowOrder ^ shr7.lowOrder);
}

/**
 * The 32-bit implementation of the NIST specified Gamma1 function
 *
 * @private
 * @param {number} x The 32-bit integer argument
 * @return {number} The NIST specified output of the function
 */
function gamma1_32(x) {
  return rotr_32(x, 17) ^ rotr_32(x, 19) ^ shr_32(x, 10);
}

/**
 * The 64-bit implementation of the NIST specified Gamma1 function
 *
 * @private
 * @param {Int_64} x The 64-bit integer argument
 * @return {Int_64} The NIST specified output of the function
 */
function gamma1_64(x) {
  var rotr19 = rotr_64(x, 19),
      rotr61 = rotr_64(x, 61),
      shr6 = shr_64(x, 6);

  return new Int_64(rotr19.highOrder ^ rotr61.highOrder ^ shr6.highOrder, rotr19.lowOrder ^ rotr61.lowOrder ^ shr6.lowOrder);
}

/**
 * Add two 32-bit integers, wrapping at 2^32. This uses 16-bit operations
 * internally to work around bugs in some JS interpreters.
 *
 * @private
 * @param {number} a The first 32-bit integer argument to be added
 * @param {number} b The second 32-bit integer argument to be added
 * @return {number} The sum of a + b
 */
function safeAdd_32_2(a, b) {
  var lsw = (a & 0xFFFF) + (b & 0xFFFF),
      msw = (a >>> 16) + (b >>> 16) + (lsw >>> 16);

  return (msw & 0xFFFF) << 16 | lsw & 0xFFFF;
}

/**
 * Add four 32-bit integers, wrapping at 2^32. This uses 16-bit operations
 * internally to work around bugs in some JS interpreters.
 *
 * @private
 * @param {number} a The first 32-bit integer argument to be added
 * @param {number} b The second 32-bit integer argument to be added
 * @param {number} c The third 32-bit integer argument to be added
 * @param {number} d The fourth 32-bit integer argument to be added
 * @return {number} The sum of a + b + c + d
 */
function safeAdd_32_4(a, b, c, d) {
  var lsw = (a & 0xFFFF) + (b & 0xFFFF) + (c & 0xFFFF) + (d & 0xFFFF),
      msw = (a >>> 16) + (b >>> 16) + (c >>> 16) + (d >>> 16) + (lsw >>> 16);

  return (msw & 0xFFFF) << 16 | lsw & 0xFFFF;
}

/**
 * Add five 32-bit integers, wrapping at 2^32. This uses 16-bit operations
 * internally to work around bugs in some JS interpreters.
 *
 * @private
 * @param {number} a The first 32-bit integer argument to be added
 * @param {number} b The second 32-bit integer argument to be added
 * @param {number} c The third 32-bit integer argument to be added
 * @param {number} d The fourth 32-bit integer argument to be added
 * @param {number} e The fifth 32-bit integer argument to be added
 * @return {number} The sum of a + b + c + d + e
 */
function safeAdd_32_5(a, b, c, d, e) {
  var lsw = (a & 0xFFFF) + (b & 0xFFFF) + (c & 0xFFFF) + (d & 0xFFFF) + (e & 0xFFFF),
      msw = (a >>> 16) + (b >>> 16) + (c >>> 16) + (d >>> 16) + (e >>> 16) + (lsw >>> 16);

  return (msw & 0xFFFF) << 16 | lsw & 0xFFFF;
}

/**
 * Add two 64-bit integers, wrapping at 2^64. This uses 16-bit operations
 * internally to work around bugs in some JS interpreters.
 *
 * @private
 * @param {Int_64} x The first 64-bit integer argument to be added
 * @param {Int_64} y The second 64-bit integer argument to be added
 * @return {Int_64} The sum of x + y
 */
function safeAdd_64_2(x, y) {
  var lsw, msw, lowOrder, highOrder;

  lsw = (x.lowOrder & 0xFFFF) + (y.lowOrder & 0xFFFF);
  msw = (x.lowOrder >>> 16) + (y.lowOrder >>> 16) + (lsw >>> 16);
  lowOrder = (msw & 0xFFFF) << 16 | lsw & 0xFFFF;

  lsw = (x.highOrder & 0xFFFF) + (y.highOrder & 0xFFFF) + (msw >>> 16);
  msw = (x.highOrder >>> 16) + (y.highOrder >>> 16) + (lsw >>> 16);
  highOrder = (msw & 0xFFFF) << 16 | lsw & 0xFFFF;

  return new Int_64(highOrder, lowOrder);
}

/**
 * Add four 64-bit integers, wrapping at 2^64. This uses 16-bit operations
 * internally to work around bugs in some JS interpreters.
 *
 * @private
 * @param {Int_64} a The first 64-bit integer argument to be added
 * @param {Int_64} b The second 64-bit integer argument to be added
 * @param {Int_64} c The third 64-bit integer argument to be added
 * @param {Int_64} d The fouth 64-bit integer argument to be added
 * @return {Int_64} The sum of a + b + c + d
 */
function safeAdd_64_4(a, b, c, d) {
  var lsw, msw, lowOrder, highOrder;

  lsw = (a.lowOrder & 0xFFFF) + (b.lowOrder & 0xFFFF) + (c.lowOrder & 0xFFFF) + (d.lowOrder & 0xFFFF);
  msw = (a.lowOrder >>> 16) + (b.lowOrder >>> 16) + (c.lowOrder >>> 16) + (d.lowOrder >>> 16) + (lsw >>> 16);
  lowOrder = (msw & 0xFFFF) << 16 | lsw & 0xFFFF;

  lsw = (a.highOrder & 0xFFFF) + (b.highOrder & 0xFFFF) + (c.highOrder & 0xFFFF) + (d.highOrder & 0xFFFF) + (msw >>> 16);
  msw = (a.highOrder >>> 16) + (b.highOrder >>> 16) + (c.highOrder >>> 16) + (d.highOrder >>> 16) + (lsw >>> 16);
  highOrder = (msw & 0xFFFF) << 16 | lsw & 0xFFFF;

  return new Int_64(highOrder, lowOrder);
}

/**
 * Add five 64-bit integers, wrapping at 2^64. This uses 16-bit operations
 * internally to work around bugs in some JS interpreters.
 *
 * @private
 * @param {Int_64} a The first 64-bit integer argument to be added
 * @param {Int_64} b The second 64-bit integer argument to be added
 * @param {Int_64} c The third 64-bit integer argument to be added
 * @param {Int_64} d The fouth 64-bit integer argument to be added
 * @param {Int_64} e The fouth 64-bit integer argument to be added
 * @return {Int_64} The sum of a + b + c + d + e
 */
function safeAdd_64_5(a, b, c, d, e) {
  var lsw, msw, lowOrder, highOrder;

  lsw = (a.lowOrder & 0xFFFF) + (b.lowOrder & 0xFFFF) + (c.lowOrder & 0xFFFF) + (d.lowOrder & 0xFFFF) + (e.lowOrder & 0xFFFF);
  msw = (a.lowOrder >>> 16) + (b.lowOrder >>> 16) + (c.lowOrder >>> 16) + (d.lowOrder >>> 16) + (e.lowOrder >>> 16) + (lsw >>> 16);
  lowOrder = (msw & 0xFFFF) << 16 | lsw & 0xFFFF;

  lsw = (a.highOrder & 0xFFFF) + (b.highOrder & 0xFFFF) + (c.highOrder & 0xFFFF) + (d.highOrder & 0xFFFF) + (e.highOrder & 0xFFFF) + (msw >>> 16);
  msw = (a.highOrder >>> 16) + (b.highOrder >>> 16) + (c.highOrder >>> 16) + (d.highOrder >>> 16) + (e.highOrder >>> 16) + (lsw >>> 16);
  highOrder = (msw & 0xFFFF) << 16 | lsw & 0xFFFF;

  return new Int_64(highOrder, lowOrder);
}

/**
 * Calculates the SHA-1 hash of the string set at instantiation
 *
 * @private
 * @param {Array.<number>} message The binary array representation of the
 *   string to hash
 * @param {number} messageLen The number of bits in the message
 * @return {Array.<number>} The array of integers representing the SHA-1
 *   hash of message
 */
function coreSHA1(message, messageLen) {
  var W = [],
      a,
      b,
      c,
      d,
      e,
      T,
      ch = ch_32,
      parity = parity_32,
      maj = maj_32,
      rotl = rotl_32,
      safeAdd_2 = safeAdd_32_2,
      i,
      t,
      safeAdd_5 = safeAdd_32_5,
      appendedMessageLength,
      offset,
      H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

  offset = (messageLen + 65 >>> 9 << 4) + 15;
  while (message.length <= offset) {
    message.push(0);
  }
  /* Append '1' at the end of the binary string */
  message[messageLen >>> 5] |= 0x80 << 24 - messageLen % 32;
  /* Append length of binary string in the position such that the new
  length is a multiple of 512.  Logic does not work for even multiples
  of 512 but there can never be even multiples of 512 */
  message[offset] = messageLen;

  appendedMessageLength = message.length;

  for (i = 0; i < appendedMessageLength; i += 16) {
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];

    for (t = 0; t < 80; t += 1) {
      if (t < 16) {
        W[t] = message[t + i];
      } else {
        W[t] = rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
      }

      if (t < 20) {
        T = safeAdd_5(rotl(a, 5), ch(b, c, d), e, 0x5a827999, W[t]);
      } else if (t < 40) {
        T = safeAdd_5(rotl(a, 5), parity(b, c, d), e, 0x6ed9eba1, W[t]);
      } else if (t < 60) {
        T = safeAdd_5(rotl(a, 5), maj(b, c, d), e, 0x8f1bbcdc, W[t]);
      } else {
        T = safeAdd_5(rotl(a, 5), parity(b, c, d), e, 0xca62c1d6, W[t]);
      }

      e = d;
      d = c;
      c = rotl(b, 30);
      b = a;
      a = T;
    }

    H[0] = safeAdd_2(a, H[0]);
    H[1] = safeAdd_2(b, H[1]);
    H[2] = safeAdd_2(c, H[2]);
    H[3] = safeAdd_2(d, H[3]);
    H[4] = safeAdd_2(e, H[4]);
  }

  return H;
}

/**
 * Calculates the desired SHA-2 hash of the string set at instantiation
 *
 * @private
 * @param {Array.<number>} message The binary array representation of the
 *   string to hash
 * @param {number} messageLen The number of bits in message
 * @param {string} variant The desired SHA-2 variant
 * @return {Array.<number>} The array of integers representing the SHA-2
 *   hash of message
 */
function coreSHA2(message, messageLen, variant) {
  var a,
      b,
      c,
      d,
      e,
      f,
      g,
      h,
      T1,
      T2,
      H,
      numRounds,
      lengthPosition,
      i,
      t,
      binaryStringInc,
      binaryStringMult,
      safeAdd_2,
      safeAdd_4,
      safeAdd_5,
      gamma0,
      gamma1,
      sigma0,
      sigma1,
      ch,
      maj,
      Int,
      W = [],
      int1,
      int2,
      offset,
      appendedMessageLength,
      retVal,
      K = [0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2],
      H_trunc = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4],
      H_full = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];

  /* Set up the various function handles and variable for the specific
   * variant */
  if ((variant === "SHA-224" || variant === "SHA-256") && 2 & SUPPORTED_ALGS) {
    /* 32-bit variant */
    numRounds = 64;
    lengthPosition = (messageLen + 65 >>> 9 << 4) + 15;
    binaryStringInc = 16;
    binaryStringMult = 1;
    Int = Number;
    safeAdd_2 = safeAdd_32_2;
    safeAdd_4 = safeAdd_32_4;
    safeAdd_5 = safeAdd_32_5;
    gamma0 = gamma0_32;
    gamma1 = gamma1_32;
    sigma0 = sigma0_32;
    sigma1 = sigma1_32;
    maj = maj_32;
    ch = ch_32;

    if ("SHA-224" === variant) {
      H = H_trunc;
    } else /* "SHA-256" === variant */
      {
        H = H_full;
      }
  } else if ((variant === "SHA-384" || variant === "SHA-512") && 4 & SUPPORTED_ALGS) {
    /* 64-bit variant */
    numRounds = 80;
    lengthPosition = (messageLen + 128 >>> 10 << 5) + 31;
    binaryStringInc = 32;
    binaryStringMult = 2;
    Int = Int_64;
    safeAdd_2 = safeAdd_64_2;
    safeAdd_4 = safeAdd_64_4;
    safeAdd_5 = safeAdd_64_5;
    gamma0 = gamma0_64;
    gamma1 = gamma1_64;
    sigma0 = sigma0_64;
    sigma1 = sigma1_64;
    maj = maj_64;
    ch = ch_64;

    K = [new Int(K[0], 0xd728ae22), new Int(K[1], 0x23ef65cd), new Int(K[2], 0xec4d3b2f), new Int(K[3], 0x8189dbbc), new Int(K[4], 0xf348b538), new Int(K[5], 0xb605d019), new Int(K[6], 0xaf194f9b), new Int(K[7], 0xda6d8118), new Int(K[8], 0xa3030242), new Int(K[9], 0x45706fbe), new Int(K[10], 0x4ee4b28c), new Int(K[11], 0xd5ffb4e2), new Int(K[12], 0xf27b896f), new Int(K[13], 0x3b1696b1), new Int(K[14], 0x25c71235), new Int(K[15], 0xcf692694), new Int(K[16], 0x9ef14ad2), new Int(K[17], 0x384f25e3), new Int(K[18], 0x8b8cd5b5), new Int(K[19], 0x77ac9c65), new Int(K[20], 0x592b0275), new Int(K[21], 0x6ea6e483), new Int(K[22], 0xbd41fbd4), new Int(K[23], 0x831153b5), new Int(K[24], 0xee66dfab), new Int(K[25], 0x2db43210), new Int(K[26], 0x98fb213f), new Int(K[27], 0xbeef0ee4), new Int(K[28], 0x3da88fc2), new Int(K[29], 0x930aa725), new Int(K[30], 0xe003826f), new Int(K[31], 0x0a0e6e70), new Int(K[32], 0x46d22ffc), new Int(K[33], 0x5c26c926), new Int(K[34], 0x5ac42aed), new Int(K[35], 0x9d95b3df), new Int(K[36], 0x8baf63de), new Int(K[37], 0x3c77b2a8), new Int(K[38], 0x47edaee6), new Int(K[39], 0x1482353b), new Int(K[40], 0x4cf10364), new Int(K[41], 0xbc423001), new Int(K[42], 0xd0f89791), new Int(K[43], 0x0654be30), new Int(K[44], 0xd6ef5218), new Int(K[45], 0x5565a910), new Int(K[46], 0x5771202a), new Int(K[47], 0x32bbd1b8), new Int(K[48], 0xb8d2d0c8), new Int(K[49], 0x5141ab53), new Int(K[50], 0xdf8eeb99), new Int(K[51], 0xe19b48a8), new Int(K[52], 0xc5c95a63), new Int(K[53], 0xe3418acb), new Int(K[54], 0x7763e373), new Int(K[55], 0xd6b2b8a3), new Int(K[56], 0x5defb2fc), new Int(K[57], 0x43172f60), new Int(K[58], 0xa1f0ab72), new Int(K[59], 0x1a6439ec), new Int(K[60], 0x23631e28), new Int(K[61], 0xde82bde9), new Int(K[62], 0xb2c67915), new Int(K[63], 0xe372532b), new Int(0xca273ece, 0xea26619c), new Int(0xd186b8c7, 0x21c0c207), new Int(0xeada7dd6, 0xcde0eb1e), new Int(0xf57d4f7f, 0xee6ed178), new Int(0x06f067aa, 0x72176fba), new Int(0x0a637dc5, 0xa2c898a6), new Int(0x113f9804, 0xbef90dae), new Int(0x1b710b35, 0x131c471b), new Int(0x28db77f5, 0x23047d84), new Int(0x32caab7b, 0x40c72493), new Int(0x3c9ebe0a, 0x15c9bebc), new Int(0x431d67c4, 0x9c100d4c), new Int(0x4cc5d4be, 0xcb3e42b6), new Int(0x597f299c, 0xfc657e2a), new Int(0x5fcb6fab, 0x3ad6faec), new Int(0x6c44198c, 0x4a475817)];

    if ("SHA-384" === variant) {
      H = [new Int(0xcbbb9d5d, H_trunc[0]), new Int(0x0629a292a, H_trunc[1]), new Int(0x9159015a, H_trunc[2]), new Int(0x0152fecd8, H_trunc[3]), new Int(0x67332667, H_trunc[4]), new Int(0x98eb44a87, H_trunc[5]), new Int(0xdb0c2e0d, H_trunc[6]), new Int(0x047b5481d, H_trunc[7])];
    } else /* "SHA-512" === variant */
      {
        H = [new Int(H_full[0], 0xf3bcc908), new Int(H_full[1], 0x84caa73b), new Int(H_full[2], 0xfe94f82b), new Int(H_full[3], 0x5f1d36f1), new Int(H_full[4], 0xade682d1), new Int(H_full[5], 0x2b3e6c1f), new Int(H_full[6], 0xfb41bd6b), new Int(H_full[7], 0x137e2179)];
      }
  } else {
    throw "Unexpected error in SHA-2 implementation";
  }

  while (message.length <= lengthPosition) {
    message.push(0);
  }
  /* Append '1' at the end of the binary string */
  message[messageLen >>> 5] |= 0x80 << 24 - messageLen % 32;
  /* Append length of binary string in the position such that the new
   * length is correct */
  message[lengthPosition] = messageLen;

  appendedMessageLength = message.length;

  for (i = 0; i < appendedMessageLength; i += binaryStringInc) {
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    f = H[5];
    g = H[6];
    h = H[7];

    for (t = 0; t < numRounds; t += 1) {
      if (t < 16) {
        offset = t * binaryStringMult + i;
        int1 = message.length <= offset ? 0 : message[offset];
        int2 = message.length <= offset + 1 ? 0 : message[offset + 1];
        /* Bit of a hack - for 32-bit, the second term is ignored */
        W[t] = new Int(int1, int2);
      } else {
        W[t] = safeAdd_4(gamma1(W[t - 2]), W[t - 7], gamma0(W[t - 15]), W[t - 16]);
      }

      T1 = safeAdd_5(h, sigma1(e), ch(e, f, g), K[t], W[t]);
      T2 = safeAdd_2(sigma0(a), maj(a, b, c));
      h = g;
      g = f;
      f = e;
      e = safeAdd_2(d, T1);
      d = c;
      c = b;
      b = a;
      a = safeAdd_2(T1, T2);
    }

    H[0] = safeAdd_2(a, H[0]);
    H[1] = safeAdd_2(b, H[1]);
    H[2] = safeAdd_2(c, H[2]);
    H[3] = safeAdd_2(d, H[3]);
    H[4] = safeAdd_2(e, H[4]);
    H[5] = safeAdd_2(f, H[5]);
    H[6] = safeAdd_2(g, H[6]);
    H[7] = safeAdd_2(h, H[7]);
  }

  if ("SHA-224" === variant && 2 & SUPPORTED_ALGS) {
    retVal = [H[0], H[1], H[2], H[3], H[4], H[5], H[6]];
  } else if ("SHA-256" === variant && 2 & SUPPORTED_ALGS) {
    retVal = H;
  } else if ("SHA-384" === variant && 4 & SUPPORTED_ALGS) {
    retVal = [H[0].highOrder, H[0].lowOrder, H[1].highOrder, H[1].lowOrder, H[2].highOrder, H[2].lowOrder, H[3].highOrder, H[3].lowOrder, H[4].highOrder, H[4].lowOrder, H[5].highOrder, H[5].lowOrder];
  } else if ("SHA-512" === variant && 4 & SUPPORTED_ALGS) {
    retVal = [H[0].highOrder, H[0].lowOrder, H[1].highOrder, H[1].lowOrder, H[2].highOrder, H[2].lowOrder, H[3].highOrder, H[3].lowOrder, H[4].highOrder, H[4].lowOrder, H[5].highOrder, H[5].lowOrder, H[6].highOrder, H[6].lowOrder, H[7].highOrder, H[7].lowOrder];
  } else /* This should never be reached */
    {
      throw "Unexpected error in SHA-2 implementation";
    }

  return retVal;
}

/**
 * jsSHA is the workhorse of the library.  Instantiate it with the string to
 * be hashed as the parameter
 *
 * @constructor
 * @this {jsSHA}
 * @param {string} srcString The string to be hashed
 * @param {string} inputFormat The format of srcString, HEX, ASCII, TEXT,
   *   B64, or BYTES
 * @param {string=} encoding The text encoding to use to encode the source
 *   string
 */
var jsSHA = function jsSHA(srcString, inputFormat, encoding) {
  var strBinLen = 0,
      strToHash = [0],
      utfType = '',
      srcConvertRet = null;

  utfType = encoding || "UTF8";

  if (!("UTF8" === utfType || "UTF16BE" === utfType || "UTF16LE" === utfType)) {
    throw "encoding must be UTF8, UTF16BE, or UTF16LE";
  }

  /* Convert the input string into the correct type */
  if ("HEX" === inputFormat) {
    if (0 !== srcString.length % 2) {
      throw "srcString of HEX type must be in byte increments";
    }
    srcConvertRet = hex2binb(srcString);
    strBinLen = srcConvertRet["binLen"];
    strToHash = srcConvertRet["value"];
  } else if ("TEXT" === inputFormat || "ASCII" === inputFormat) {
    srcConvertRet = str2binb(srcString, utfType);
    strBinLen = srcConvertRet["binLen"];
    strToHash = srcConvertRet["value"];
  } else if ("B64" === inputFormat) {
    srcConvertRet = b642binb(srcString);
    strBinLen = srcConvertRet["binLen"];
    strToHash = srcConvertRet["value"];
  } else if ("BYTES" === inputFormat) {
    srcConvertRet = bytes2binb(srcString);
    strBinLen = srcConvertRet["binLen"];
    strToHash = srcConvertRet["value"];
  } else if ("TYPED" === inputFormat) {
    srcConvertRet = typed2binb(srcString);
    strBinLen = srcConvertRet["binLen"];
    strToHash = srcConvertRet["value"];
  } else {
    throw "inputFormat must be HEX, TEXT, ASCII, B64, BYTES, or TYPED";
  }

  /**
   * Returns the desired SHA hash of the string specified at instantiation
   * using the specified parameters
   *
   * @expose
   * @param {string} variant The desired SHA variant (SHA-1, SHA-224,
   *   SHA-256, SHA-384, or SHA-512)
   * @param {string} format The desired output formatting (B64, HEX, or BYTES)
   * @param {number=} numRounds The number of rounds of hashing to be
   *   executed
   * @param {{outputUpper : boolean, b64Pad : string}=} outputFormatOpts
   *   Hash list of output formatting options
   * @return {string} The string representation of the hash in the format
   *   specified
   */
  this.getHash = function (variant, format, numRounds, outputFormatOpts) {
    var formatFunc = null,
        message = strToHash.slice(),
        messageBinLen = strBinLen,
        i;

    /* Need to do argument patching since both numRounds and
       outputFormatOpts are optional */
    if (3 === arguments.length) {
      if ("number" !== typeof numRounds) {
        outputFormatOpts = numRounds;
        numRounds = 1;
      }
    } else if (2 === arguments.length) {
      numRounds = 1;
    }

    /* Validate the numRounds argument */
    if (numRounds !== parseInt(numRounds, 10) || 1 > numRounds) {
      throw "numRounds must a integer >= 1";
    }

    /* Validate the output format selection */
    switch (format) {
      case "HEX":
        formatFunc = binb2hex;
        break;
      case "B64":
        formatFunc = binb2b64;
        break;
      case "BYTES":
        formatFunc = binb2bytes;
        break;
      case "TYPED":
        formatFunc = binb2typed;
        break;
      default:
        throw "format must be HEX, B64, or BYTES";
    }

    if ("SHA-1" === variant && 1 & SUPPORTED_ALGS) {
      for (i = 0; i < numRounds; i += 1) {
        message = coreSHA1(message, messageBinLen);
        messageBinLen = 160;
      }
    } else if ("SHA-224" === variant && 2 & SUPPORTED_ALGS) {
      for (i = 0; i < numRounds; i += 1) {
        message = coreSHA2(message, messageBinLen, variant);
        messageBinLen = 224;
      }
    } else if ("SHA-256" === variant && 2 & SUPPORTED_ALGS) {
      for (i = 0; i < numRounds; i += 1) {
        message = coreSHA2(message, messageBinLen, variant);
        messageBinLen = 256;
      }
    } else if ("SHA-384" === variant && 4 & SUPPORTED_ALGS) {
      for (i = 0; i < numRounds; i += 1) {
        message = coreSHA2(message, messageBinLen, variant);
        messageBinLen = 384;
      }
    } else if ("SHA-512" === variant && 4 & SUPPORTED_ALGS) {
      for (i = 0; i < numRounds; i += 1) {
        message = coreSHA2(message, messageBinLen, variant);
        messageBinLen = 512;
      }
    } else {
      throw "Chosen SHA variant is not supported";
    }

    return formatFunc(message, getOutputOpts(outputFormatOpts));
  };

  /**
   * Returns the desired HMAC of the string specified at instantiation
   * using the key and variant parameter
   *
   * @expose
   * @param {string} key The key used to calculate the HMAC
   * @param {string} inputFormat The format of key, HEX, TEXT, ASCII,
       *   B64, or BYTES
   * @param {string} variant The desired SHA variant (SHA-1, SHA-224,
   *   SHA-256, SHA-384, or SHA-512)
   * @param {string} outputFormat The desired output formatting
   *   (B64, HEX, or BYTES)
   * @param {{outputUpper : boolean, b64Pad : string}=} outputFormatOpts
   *   associative array of output formatting options
   * @return {string} The string representation of the hash in the format
   *   specified
   */
  this.getHMAC = function (key, inputFormat, variant, outputFormat, outputFormatOpts) {
    var formatFunc,
        keyToUse,
        blockByteSize,
        blockBitSize,
        i,
        retVal,
        lastArrayIndex,
        keyBinLen,
        hashBitSize,
        keyWithIPad = [],
        keyWithOPad = [],
        keyConvertRet = null;

    /* Validate the output format selection */
    switch (outputFormat) {
      case "HEX":
        formatFunc = binb2hex;
        break;
      case "B64":
        formatFunc = binb2b64;
        break;
      case "BYTES":
        formatFunc = binb2bytes;
        break;
      default:
        throw "outputFormat must be HEX, B64, or BYTES";
    }

    /* Validate the hash variant selection and set needed variables */
    if ("SHA-1" === variant && 1 & SUPPORTED_ALGS) {
      blockByteSize = 64;
      hashBitSize = 160;
    } else if ("SHA-224" === variant && 2 & SUPPORTED_ALGS) {
      blockByteSize = 64;
      hashBitSize = 224;
    } else if ("SHA-256" === variant && 2 & SUPPORTED_ALGS) {
      blockByteSize = 64;
      hashBitSize = 256;
    } else if ("SHA-384" === variant && 4 & SUPPORTED_ALGS) {
      blockByteSize = 128;
      hashBitSize = 384;
    } else if ("SHA-512" === variant && 4 & SUPPORTED_ALGS) {
      blockByteSize = 128;
      hashBitSize = 512;
    } else {
      throw "Chosen SHA variant is not supported";
    }

    /* Validate input format selection */
    if ("HEX" === inputFormat) {
      keyConvertRet = hex2binb(key);
      keyBinLen = keyConvertRet["binLen"];
      keyToUse = keyConvertRet["value"];
    } else if ("TEXT" === inputFormat || "ASCII" === inputFormat) {
      keyConvertRet = str2binb(key, utfType);
      keyBinLen = keyConvertRet["binLen"];
      keyToUse = keyConvertRet["value"];
    } else if ("B64" === inputFormat) {
      keyConvertRet = b642binb(key);
      keyBinLen = keyConvertRet["binLen"];
      keyToUse = keyConvertRet["value"];
    } else if ("BYTES" === inputFormat) {
      keyConvertRet = bytes2binb(key);
      keyBinLen = keyConvertRet["binLen"];
      keyToUse = keyConvertRet["value"];
    } else {
      throw "inputFormat must be HEX, TEXT, ASCII, B64, or BYTES";
    }

    /* These are used multiple times, calculate and store them */
    blockBitSize = blockByteSize * 8;
    lastArrayIndex = blockByteSize / 4 - 1;

    /* Figure out what to do with the key based on its size relative to
     * the hash's block size */
    if (blockByteSize < keyBinLen / 8) {
      if ("SHA-1" === variant && 1 & SUPPORTED_ALGS) {
        keyToUse = coreSHA1(keyToUse, keyBinLen);
      } else if (6 & SUPPORTED_ALGS) {
        keyToUse = coreSHA2(keyToUse, keyBinLen, variant);
      } else {
        throw "Unexpected error in HMAC implementation";
      }
      /* For all variants, the block size is bigger than the output
       * size so there will never be a useful byte at the end of the
       * string */
      while (keyToUse.length <= lastArrayIndex) {
        keyToUse.push(0);
      }
      keyToUse[lastArrayIndex] &= 0xFFFFFF00;
    } else if (blockByteSize > keyBinLen / 8) {
      /* If the blockByteSize is greater than the key length, there
       * will always be at LEAST one "useless" byte at the end of the
       * string */
      while (keyToUse.length <= lastArrayIndex) {
        keyToUse.push(0);
      }
      keyToUse[lastArrayIndex] &= 0xFFFFFF00;
    }

    /* Create ipad and opad */
    for (i = 0; i <= lastArrayIndex; i += 1) {
      keyWithIPad[i] = keyToUse[i] ^ 0x36363636;
      keyWithOPad[i] = keyToUse[i] ^ 0x5C5C5C5C;
    }

    /* Calculate the HMAC */
    if ("SHA-1" === variant && 1 & SUPPORTED_ALGS) {
      retVal = coreSHA1(keyWithOPad.concat(coreSHA1(keyWithIPad.concat(strToHash), blockBitSize + strBinLen)), blockBitSize + hashBitSize);
    } else if (6 & SUPPORTED_ALGS) {
      retVal = coreSHA2(keyWithOPad.concat(coreSHA2(keyWithIPad.concat(strToHash), blockBitSize + strBinLen, variant)), blockBitSize + hashBitSize, variant);
    } else {
      throw "Unexpected error in HMAC implementation";
    }

    return formatFunc(retVal, getOutputOpts(outputFormatOpts));
  };
};

exports.default = {
  /** SHA1 hash */
  sha1: function sha1(str) {
    var shaObj = new jsSHA(str, "TYPED", "UTF8");
    return shaObj.getHash("SHA-1", "TYPED");
  },
  /** SHA224 hash */
  sha224: function sha224(str) {
    var shaObj = new jsSHA(str, "TYPED", "UTF8");
    return shaObj.getHash("SHA-224", "TYPED");
  },
  /** SHA256 hash */
  sha256: function sha256(str) {
    var shaObj = new jsSHA(str, "TYPED", "UTF8");
    return shaObj.getHash("SHA-256", "TYPED");
  },
  /** SHA384 hash */
  sha384: function sha384(str) {
    var shaObj = new jsSHA(str, "TYPED", "UTF8");
    return shaObj.getHash("SHA-384", "TYPED");
  },
  /** SHA512 hash */
  sha512: function sha512(str) {
    var shaObj = new jsSHA(str, "TYPED", "UTF8");
    return shaObj.getHash("SHA-512", "TYPED");
  }
};

},{}],24:[function(_dereq_,module,exports){
/**
 * @see module:crypto/crypto
 * @module crypto
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _cipher = _dereq_('./cipher');

var _cipher2 = _interopRequireDefault(_cipher);

var _hash = _dereq_('./hash');

var _hash2 = _interopRequireDefault(_hash);

var _cfb = _dereq_('./cfb');

var _cfb2 = _interopRequireDefault(_cfb);

var _gcm = _dereq_('./gcm');

var gcm = _interopRequireWildcard(_gcm);

var _public_key = _dereq_('./public_key');

var _public_key2 = _interopRequireDefault(_public_key);

var _signature = _dereq_('./signature');

var _signature2 = _interopRequireDefault(_signature);

var _random = _dereq_('./random');

var _random2 = _interopRequireDefault(_random);

var _pkcs = _dereq_('./pkcs1');

var _pkcs2 = _interopRequireDefault(_pkcs);

var _crypto = _dereq_('./crypto.js');

var _crypto2 = _interopRequireDefault(_crypto);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var mod = {
  /** @see module:crypto/cipher */
  cipher: _cipher2.default,
  /** @see module:crypto/hash */
  hash: _hash2.default,
  /** @see module:crypto/cfb */
  cfb: _cfb2.default,
  /** @see module:crypto/gcm */
  gcm: gcm,
  /** @see module:crypto/public_key */
  publicKey: _public_key2.default,
  /** @see module:crypto/signature */
  signature: _signature2.default,
  /** @see module:crypto/random */
  random: _random2.default,
  /** @see module:crypto/pkcs1 */
  pkcs1: _pkcs2.default
};

for (var i in _crypto2.default) {
  mod[i] = _crypto2.default[i];
}

exports.default = mod;

},{"./cfb":11,"./cipher":16,"./crypto.js":18,"./gcm":19,"./hash":20,"./pkcs1":25,"./public_key":28,"./random":31,"./signature":32}],25:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * PKCS1 encoding
 * @requires crypto/crypto
 * @requires crypto/hash
 * @requires crypto/public_key/jsbn
 * @requires crypto/random
 * @requires util
 * @module crypto/pkcs1
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _random = _dereq_('./random.js');

var _random2 = _interopRequireDefault(_random);

var _util = _dereq_('../util.js');

var _util2 = _interopRequireDefault(_util);

var _jsbn = _dereq_('./public_key/jsbn.js');

var _jsbn2 = _interopRequireDefault(_jsbn);

var _hash = _dereq_('./hash');

var _hash2 = _interopRequireDefault(_hash);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * ASN1 object identifiers for hashes (See {@link http://tools.ietf.org/html/rfc4880#section-5.2.2})
 */
var hash_headers = [];
hash_headers[1] = [0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10];
hash_headers[2] = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];
hash_headers[3] = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24, 0x03, 0x02, 0x01, 0x05, 0x00, 0x04, 0x14];
hash_headers[8] = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];
hash_headers[9] = [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30];
hash_headers[10] = [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40];
hash_headers[11] = [0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1C];

/**
 * Create padding with secure random data
 * @private
 * @param  {Integer} length Length of the padding in bytes
 * @return {String}        Padding as string
 */
function getPkcs1Padding(length) {
  var result = '';
  var randomByte;
  while (result.length < length) {
    randomByte = _random2.default.getSecureRandomOctet();
    if (randomByte !== 0) {
      result += String.fromCharCode(randomByte);
    }
  }
  return result;
}

exports.default = {
  eme: {
    /**
     * create a EME-PKCS1-v1_5 padding (See {@link http://tools.ietf.org/html/rfc4880#section-13.1.1|RFC 4880 13.1.1})
     * @param {String} M message to be encoded
     * @param {Integer} k the length in octets of the key modulus
     * @return {String} EME-PKCS1 padded message
     */
    encode: function encode(M, k) {
      var mLen = M.length;
      // length checking
      if (mLen > k - 11) {
        throw new Error('Message too long');
      }
      // Generate an octet string PS of length k - mLen - 3 consisting of
      // pseudo-randomly generated nonzero octets
      var PS = getPkcs1Padding(k - mLen - 3);
      // Concatenate PS, the message M, and other padding to form an
      // encoded message EM of length k octets as EM = 0x00 || 0x02 || PS || 0x00 || M.
      var EM = String.fromCharCode(0) + String.fromCharCode(2) + PS + String.fromCharCode(0) + M;
      return EM;
    },
    /**
     * decodes a EME-PKCS1-v1_5 padding (See {@link http://tools.ietf.org/html/rfc4880#section-13.1.2|RFC 4880 13.1.2})
     * @param {String} EM encoded message, an octet string
     * @return {String} message, an octet string
     */
    decode: function decode(EM) {
      // leading zeros truncated by jsbn
      if (EM.charCodeAt(0) !== 0) {
        EM = String.fromCharCode(0) + EM;
      }
      var firstOct = EM.charCodeAt(0);
      var secondOct = EM.charCodeAt(1);
      var i = 2;
      while (EM.charCodeAt(i) !== 0 && i < EM.length) {
        i++;
      }
      var psLen = i - 2;
      var separator = EM.charCodeAt(i++);
      if (firstOct === 0 && secondOct === 2 && psLen >= 8 && separator === 0) {
        return EM.substr(i);
      } else {
        throw new Error('Decryption error');
      }
    }
  },

  emsa: {
    /**
     * create a EMSA-PKCS1-v1_5 padding (See {@link http://tools.ietf.org/html/rfc4880#section-13.1.3|RFC 4880 13.1.3})
     * @param {Integer} algo Hash algorithm type used
     * @param {String} M message to be encoded
     * @param {Integer} emLen intended length in octets of the encoded message
     * @returns {String} encoded message
     */
    encode: function encode(algo, M, emLen) {
      var i;
      // Apply the hash function to the message M to produce a hash value H
      var H = _util2.default.Uint8Array2str(_hash2.default.digest(algo, _util2.default.str2Uint8Array(M)));
      if (H.length !== _hash2.default.getHashByteLength(algo)) {
        throw new Error('Invalid hash length');
      }
      // produce an ASN.1 DER value for the hash function used.
      // Let T be the full hash prefix
      var T = '';
      for (i = 0; i < hash_headers[algo].length; i++) {
        T += String.fromCharCode(hash_headers[algo][i]);
      }
      // add hash value to prefix
      T += H;
      // and let tLen be the length in octets of T
      var tLen = T.length;
      if (emLen < tLen + 11) {
        throw new Error('Intended encoded message length too short');
      }
      // an octet string PS consisting of emLen - tLen - 3 octets with hexadecimal value 0xFF
      // The length of PS will be at least 8 octets
      var PS = '';
      for (i = 0; i < emLen - tLen - 3; i++) {
        PS += String.fromCharCode(0xff);
      }
      // Concatenate PS, the hash prefix T, and other padding to form the
      // encoded message EM as EM = 0x00 || 0x01 || PS || 0x00 || T.
      var EM = String.fromCharCode(0x00) + String.fromCharCode(0x01) + PS + String.fromCharCode(0x00) + T;
      return new _jsbn2.default(_util2.default.hexstrdump(EM), 16);
    }
  }
};

},{"../util.js":70,"./hash":20,"./public_key/jsbn.js":29,"./random.js":31}],26:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
//
// A Digital signature algorithm implementation

/**
 * @requires crypto/hash
 * @requires crypto/public_key/jsbn
 * @requires crypto/random
 * @requires util
 * @module crypto/public_key/dsa
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = DSA;

var _jsbn = _dereq_('./jsbn.js');

var _jsbn2 = _interopRequireDefault(_jsbn);

var _random = _dereq_('../random.js');

var _random2 = _interopRequireDefault(_random);

var _hash = _dereq_('../hash');

var _hash2 = _interopRequireDefault(_hash);

var _util = _dereq_('../../util.js');

var _util2 = _interopRequireDefault(_util);

var _config = _dereq_('../../config');

var _config2 = _interopRequireDefault(_config);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function DSA() {
  // s1 = ((g**s) mod p) mod q
  // s1 = ((s**-1)*(sha-1(m)+(s1*x) mod q)
  function sign(hashalgo, m, g, p, q, x) {
    // If the output size of the chosen hash is larger than the number of
    // bits of q, the hash result is truncated to fit by taking the number
    // of leftmost bits equal to the number of bits of q.  This (possibly
    // truncated) hash function result is treated as a number and used
    // directly in the DSA signature algorithm.
    var hashed_data = _util2.default.getLeftNBits(_util2.default.Uint8Array2str(_hash2.default.digest(hashalgo, _util2.default.str2Uint8Array(m))), q.bitLength());
    var hash = new _jsbn2.default(_util2.default.hexstrdump(hashed_data), 16);
    // FIPS-186-4, section 4.6:
    // The values of r and s shall be checked to determine if r = 0 or s = 0.
    // If either r = 0 or s = 0, a new value of k shall be generated, and the
    // signature shall be recalculated. It is extremely unlikely that r = 0
    // or s = 0 if signatures are generated properly.
    var k, s1, s2;
    while (true) {
      k = _random2.default.getRandomBigIntegerInRange(_jsbn2.default.ONE, q.subtract(_jsbn2.default.ONE));
      s1 = g.modPow(k, p).mod(q);
      s2 = k.modInverse(q).multiply(hash.add(x.multiply(s1))).mod(q);
      if (s1 !== 0 && s2 !== 0) {
        break;
      }
    }
    var result = [];
    result[0] = s1.toMPI();
    result[1] = s2.toMPI();
    return result;
  }

  function select_hash_algorithm(q) {
    var usersetting = _config2.default.prefer_hash_algorithm;
    /*
     * 1024-bit key, 160-bit q, SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512 hash
     * 2048-bit key, 224-bit q, SHA-224, SHA-256, SHA-384, or SHA-512 hash
     * 2048-bit key, 256-bit q, SHA-256, SHA-384, or SHA-512 hash
     * 3072-bit key, 256-bit q, SHA-256, SHA-384, or SHA-512 hash
     */
    switch (Math.round(q.bitLength() / 8)) {
      case 20:
        // 1024 bit
        if (usersetting !== 2 && usersetting > 11 && usersetting !== 10 && usersetting < 8) {
          return 2; // prefer sha1
        }
        return usersetting;
      case 28:
        // 2048 bit
        if (usersetting > 11 && usersetting < 8) {
          return 11;
        }
        return usersetting;
      case 32:
        // 4096 bit // prefer sha224
        if (usersetting > 10 && usersetting < 8) {
          return 8; // prefer sha256
        }
        return usersetting;
      default:
        _util2.default.print_debug("DSA select hash algorithm: returning null for an unknown length of q");
        return null;
    }
  }
  this.select_hash_algorithm = select_hash_algorithm;

  function verify(hashalgo, s1, s2, m, p, q, g, y) {
    var hashed_data = _util2.default.getLeftNBits(_util2.default.Uint8Array2str(_hash2.default.digest(hashalgo, _util2.default.str2Uint8Array(m))), q.bitLength());
    var hash = new _jsbn2.default(_util2.default.hexstrdump(hashed_data), 16);
    if (_jsbn2.default.ZERO.compareTo(s1) >= 0 || s1.compareTo(q) >= 0 || _jsbn2.default.ZERO.compareTo(s2) >= 0 || s2.compareTo(q) >= 0) {
      _util2.default.print_debug("invalid DSA Signature");
      return null;
    }
    var w = s2.modInverse(q);
    if (_jsbn2.default.ZERO.compareTo(w) === 0) {
      _util2.default.print_debug("invalid DSA Signature");
      return null;
    }
    var u1 = hash.multiply(w).mod(q);
    var u2 = s1.multiply(w).mod(q);
    return g.modPow(u1, p).multiply(y.modPow(u2, p)).mod(p).mod(q);
  }

  this.sign = sign;
  this.verify = verify;
}

},{"../../config":10,"../../util.js":70,"../hash":20,"../random.js":31,"./jsbn.js":29}],27:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
//
// ElGamal implementation

/**
 * @requires crypto/public_key/jsbn
 * @requires crypto/random
 * @requires util
 * @module crypto/public_key/elgamal
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = Elgamal;

var _jsbn = _dereq_('./jsbn.js');

var _jsbn2 = _interopRequireDefault(_jsbn);

var _random = _dereq_('../random.js');

var _random2 = _interopRequireDefault(_random);

var _util = _dereq_('../../util.js');

var _util2 = _interopRequireDefault(_util);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function Elgamal() {

  function encrypt(m, g, p, y) {
    //  choose k in {2,...,p-2}
    var pMinus2 = p.subtract(_jsbn2.default.TWO);
    var k = _random2.default.getRandomBigIntegerInRange(_jsbn2.default.ONE, pMinus2);
    k = k.mod(pMinus2).add(_jsbn2.default.ONE);
    var c = [];
    c[0] = g.modPow(k, p);
    c[1] = y.modPow(k, p).multiply(m).mod(p);
    return c;
  }

  function decrypt(c1, c2, p, x) {
    _util2.default.print_debug("Elgamal Decrypt:\nc1:" + _util2.default.hexstrdump(c1.toMPI()) + "\n" + "c2:" + _util2.default.hexstrdump(c2.toMPI()) + "\n" + "p:" + _util2.default.hexstrdump(p.toMPI()) + "\n" + "x:" + _util2.default.hexstrdump(x.toMPI()));
    return c1.modPow(x, p).modInverse(p).multiply(c2).mod(p);
    //var c = c1.pow(x).modInverse(p); // c0^-a mod p
    //return c.multiply(c2).mod(p);
  }

  // signing and signature verification using Elgamal is not required by OpenPGP.
  this.encrypt = encrypt;
  this.decrypt = decrypt;
}

},{"../../util.js":70,"../random.js":31,"./jsbn.js":29}],28:[function(_dereq_,module,exports){
/**
 * @requires crypto/public_key/dsa
 * @requires crypto/public_key/elgamal
 * @requires crypto/public_key/rsa
 * @module crypto/public_key
 */

'use strict';

/** @see module:crypto/public_key/rsa */

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _rsa = _dereq_('./rsa.js');

var _rsa2 = _interopRequireDefault(_rsa);

var _elgamal = _dereq_('./elgamal.js');

var _elgamal2 = _interopRequireDefault(_elgamal);

var _dsa = _dereq_('./dsa.js');

var _dsa2 = _interopRequireDefault(_dsa);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/** @see module:crypto/public_key/elgamal */
exports.default = {
  rsa: _rsa2.default,
  elgamal: _elgamal2.default,
  dsa: _dsa2.default
};
/** @see module:crypto/public_key/dsa */

},{"./dsa.js":26,"./elgamal.js":27,"./rsa.js":30}],29:[function(_dereq_,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = BigInteger;

var _util = _dereq_("../../util.js");

var _util2 = _interopRequireDefault(_util);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// Basic JavaScript BN library - subset useful for RSA encryption.

// Bits per digit
var dbits;

// JavaScript engine analysis
/*
 * Copyright (c) 2003-2005  Tom Wu (tjw@cs.Stanford.EDU)
 * All Rights Reserved.
 *
 * Modified by Recurity Labs GmbH
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * In addition, the following condition applies:
 *
 * All redistributions must retain an intact copy of this copyright notice
 * and disclaimer.
 */

/**
 * @requires util
 * @module crypto/public_key/jsbn
 */

var canary = 0xdeadbeefcafe;
var j_lm = (canary & 0xffffff) == 0xefcafe;

// (public) Constructor

function BigInteger(a, b, c) {
  if (a != null) if ("number" == typeof a) this.fromNumber(a, b, c);else if (b == null && "string" != typeof a) this.fromString(a, 256);else this.fromString(a, b);
}

// return new, unset BigInteger

function nbi() {
  return new BigInteger(null);
}

// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.

// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)

function am1(i, x, w, j, c, n) {
  while (--n >= 0) {
    var v = x * this[i++] + w[j] + c;
    c = Math.floor(v / 0x4000000);
    w[j++] = v & 0x3ffffff;
  }
  return c;
}
// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)

function am2(i, x, w, j, c, n) {
  var xl = x & 0x7fff,
      xh = x >> 15;
  while (--n >= 0) {
    var l = this[i] & 0x7fff;
    var h = this[i++] >> 15;
    var m = xh * l + h * xl;
    l = xl * l + ((m & 0x7fff) << 15) + w[j] + (c & 0x3fffffff);
    c = (l >>> 30) + (m >>> 15) + xh * h + (c >>> 30);
    w[j++] = l & 0x3fffffff;
  }
  return c;
}
// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.

function am3(i, x, w, j, c, n) {
  var xl = x & 0x3fff,
      xh = x >> 14;
  while (--n >= 0) {
    var l = this[i] & 0x3fff;
    var h = this[i++] >> 14;
    var m = xh * l + h * xl;
    l = xl * l + ((m & 0x3fff) << 14) + w[j] + c;
    c = (l >> 28) + (m >> 14) + xh * h;
    w[j++] = l & 0xfffffff;
  }
  return c;
}
/*if(j_lm && (navigator != undefined &&
	navigator.appName == "Microsoft Internet Explorer")) {
  BigInteger.prototype.am = am2;
  dbits = 30;
}
else if(j_lm && (navigator != undefined && navigator.appName != "Netscape")) {*/
BigInteger.prototype.am = am1;
dbits = 26;
/*}
else { // Mozilla/Netscape seems to prefer am3
  BigInteger.prototype.am = am3;
  dbits = 28;
}*/

BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = (1 << dbits) - 1;
BigInteger.prototype.DV = 1 << dbits;

var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2, BI_FP);
BigInteger.prototype.F1 = BI_FP - dbits;
BigInteger.prototype.F2 = 2 * dbits - BI_FP;

// Digit conversions
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr, vv;
rr = "0".charCodeAt(0);
for (vv = 0; vv <= 9; ++vv) {
  BI_RC[rr++] = vv;
}rr = "a".charCodeAt(0);
for (vv = 10; vv < 36; ++vv) {
  BI_RC[rr++] = vv;
}rr = "A".charCodeAt(0);
for (vv = 10; vv < 36; ++vv) {
  BI_RC[rr++] = vv;
}function int2char(n) {
  return BI_RM.charAt(n);
}

function intAt(s, i) {
  var c = BI_RC[s.charCodeAt(i)];
  return c == null ? -1 : c;
}

// (protected) copy this to r

function bnpCopyTo(r) {
  for (var i = this.t - 1; i >= 0; --i) {
    r[i] = this[i];
  }r.t = this.t;
  r.s = this.s;
}

// (protected) set from integer value x, -DV <= x < DV

function bnpFromInt(x) {
  this.t = 1;
  this.s = x < 0 ? -1 : 0;
  if (x > 0) this[0] = x;else if (x < -1) this[0] = x + this.DV;else this.t = 0;
}

// return bigint initialized to value

function nbv(i) {
  var r = nbi();
  r.fromInt(i);
  return r;
}

// (protected) set from string and radix

function bnpFromString(s, b) {
  var k;
  if (b == 16) k = 4;else if (b == 8) k = 3;else if (b == 256) k = 8; // byte array
  else if (b == 2) k = 1;else if (b == 32) k = 5;else if (b == 4) k = 2;else {
      this.fromRadix(s, b);
      return;
    }
  this.t = 0;
  this.s = 0;
  var i = s.length,
      mi = false,
      sh = 0;
  while (--i >= 0) {
    var x = k == 8 ? s[i] & 0xff : intAt(s, i);
    if (x < 0) {
      if (s.charAt(i) == "-") mi = true;
      continue;
    }
    mi = false;
    if (sh == 0) this[this.t++] = x;else if (sh + k > this.DB) {
      this[this.t - 1] |= (x & (1 << this.DB - sh) - 1) << sh;
      this[this.t++] = x >> this.DB - sh;
    } else this[this.t - 1] |= x << sh;
    sh += k;
    if (sh >= this.DB) sh -= this.DB;
  }
  if (k == 8 && (s[0] & 0x80) != 0) {
    this.s = -1;
    if (sh > 0) this[this.t - 1] |= (1 << this.DB - sh) - 1 << sh;
  }
  this.clamp();
  if (mi) BigInteger.ZERO.subTo(this, this);
}

// (protected) clamp off excess high words

function bnpClamp() {
  var c = this.s & this.DM;
  while (this.t > 0 && this[this.t - 1] == c) {
    --this.t;
  }
}

// (public) return string representation in given radix

function bnToString(b) {
  if (this.s < 0) return "-" + this.negate().toString(b);
  var k;
  if (b == 16) k = 4;else if (b == 8) k = 3;else if (b == 2) k = 1;else if (b == 32) k = 5;else if (b == 4) k = 2;else return this.toRadix(b);
  var km = (1 << k) - 1,
      d,
      m = false,
      r = "",
      i = this.t;
  var p = this.DB - i * this.DB % k;
  if (i-- > 0) {
    if (p < this.DB && (d = this[i] >> p) > 0) {
      m = true;
      r = int2char(d);
    }
    while (i >= 0) {
      if (p < k) {
        d = (this[i] & (1 << p) - 1) << k - p;
        d |= this[--i] >> (p += this.DB - k);
      } else {
        d = this[i] >> (p -= k) & km;
        if (p <= 0) {
          p += this.DB;
          --i;
        }
      }
      if (d > 0) m = true;
      if (m) r += int2char(d);
    }
  }
  return m ? r : "0";
}

// (public) -this

function bnNegate() {
  var r = nbi();
  BigInteger.ZERO.subTo(this, r);
  return r;
}

// (public) |this|

function bnAbs() {
  return this.s < 0 ? this.negate() : this;
}

// (public) return + if this > a, - if this < a, 0 if equal

function bnCompareTo(a) {
  var r = this.s - a.s;
  if (r != 0) return r;
  var i = this.t;
  r = i - a.t;
  if (r != 0) return this.s < 0 ? -r : r;
  while (--i >= 0) {
    if ((r = this[i] - a[i]) != 0) return r;
  }return 0;
}

// returns bit length of the integer x

function nbits(x) {
  var r = 1,
      t;
  if ((t = x >>> 16) != 0) {
    x = t;
    r += 16;
  }
  if ((t = x >> 8) != 0) {
    x = t;
    r += 8;
  }
  if ((t = x >> 4) != 0) {
    x = t;
    r += 4;
  }
  if ((t = x >> 2) != 0) {
    x = t;
    r += 2;
  }
  if ((t = x >> 1) != 0) {
    x = t;
    r += 1;
  }
  return r;
}

// (public) return the number of bits in "this"

function bnBitLength() {
  if (this.t <= 0) return 0;
  return this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ this.s & this.DM);
}

// (protected) r = this << n*DB

function bnpDLShiftTo(n, r) {
  var i;
  for (i = this.t - 1; i >= 0; --i) {
    r[i + n] = this[i];
  }for (i = n - 1; i >= 0; --i) {
    r[i] = 0;
  }r.t = this.t + n;
  r.s = this.s;
}

// (protected) r = this >> n*DB

function bnpDRShiftTo(n, r) {
  for (var i = n; i < this.t; ++i) {
    r[i - n] = this[i];
  }r.t = Math.max(this.t - n, 0);
  r.s = this.s;
}

// (protected) r = this << n

function bnpLShiftTo(n, r) {
  var bs = n % this.DB;
  var cbs = this.DB - bs;
  var bm = (1 << cbs) - 1;
  var ds = Math.floor(n / this.DB),
      c = this.s << bs & this.DM,
      i;
  for (i = this.t - 1; i >= 0; --i) {
    r[i + ds + 1] = this[i] >> cbs | c;
    c = (this[i] & bm) << bs;
  }
  for (i = ds - 1; i >= 0; --i) {
    r[i] = 0;
  }r[ds] = c;
  r.t = this.t + ds + 1;
  r.s = this.s;
  r.clamp();
}

// (protected) r = this >> n

function bnpRShiftTo(n, r) {
  r.s = this.s;
  var ds = Math.floor(n / this.DB);
  if (ds >= this.t) {
    r.t = 0;
    return;
  }
  var bs = n % this.DB;
  var cbs = this.DB - bs;
  var bm = (1 << bs) - 1;
  r[0] = this[ds] >> bs;
  for (var i = ds + 1; i < this.t; ++i) {
    r[i - ds - 1] |= (this[i] & bm) << cbs;
    r[i - ds] = this[i] >> bs;
  }
  if (bs > 0) r[this.t - ds - 1] |= (this.s & bm) << cbs;
  r.t = this.t - ds;
  r.clamp();
}

// (protected) r = this - a

function bnpSubTo(a, r) {
  var i = 0,
      c = 0,
      m = Math.min(a.t, this.t);
  while (i < m) {
    c += this[i] - a[i];
    r[i++] = c & this.DM;
    c >>= this.DB;
  }
  if (a.t < this.t) {
    c -= a.s;
    while (i < this.t) {
      c += this[i];
      r[i++] = c & this.DM;
      c >>= this.DB;
    }
    c += this.s;
  } else {
    c += this.s;
    while (i < a.t) {
      c -= a[i];
      r[i++] = c & this.DM;
      c >>= this.DB;
    }
    c -= a.s;
  }
  r.s = c < 0 ? -1 : 0;
  if (c < -1) r[i++] = this.DV + c;else if (c > 0) r[i++] = c;
  r.t = i;
  r.clamp();
}

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.

function bnpMultiplyTo(a, r) {
  var x = this.abs(),
      y = a.abs();
  var i = x.t;
  r.t = i + y.t;
  while (--i >= 0) {
    r[i] = 0;
  }for (i = 0; i < y.t; ++i) {
    r[i + x.t] = x.am(0, y[i], r, i, 0, x.t);
  }r.s = 0;
  r.clamp();
  if (this.s != a.s) BigInteger.ZERO.subTo(r, r);
}

// (protected) r = this^2, r != this (HAC 14.16)

function bnpSquareTo(r) {
  var x = this.abs();
  var i = r.t = 2 * x.t;
  while (--i >= 0) {
    r[i] = 0;
  }for (i = 0; i < x.t - 1; ++i) {
    var c = x.am(i, x[i], r, 2 * i, 0, 1);
    if ((r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >= x.DV) {
      r[i + x.t] -= x.DV;
      r[i + x.t + 1] = 1;
    }
  }
  if (r.t > 0) r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1);
  r.s = 0;
  r.clamp();
}

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.

function bnpDivRemTo(m, q, r) {
  var pm = m.abs();
  if (pm.t <= 0) return;
  var pt = this.abs();
  if (pt.t < pm.t) {
    if (q != null) q.fromInt(0);
    if (r != null) this.copyTo(r);
    return;
  }
  if (r == null) r = nbi();
  var y = nbi(),
      ts = this.s,
      ms = m.s;
  var nsh = this.DB - nbits(pm[pm.t - 1]); // normalize modulus
  if (nsh > 0) {
    pm.lShiftTo(nsh, y);
    pt.lShiftTo(nsh, r);
  } else {
    pm.copyTo(y);
    pt.copyTo(r);
  }
  var ys = y.t;
  var y0 = y[ys - 1];
  if (y0 == 0) return;
  var yt = y0 * (1 << this.F1) + (ys > 1 ? y[ys - 2] >> this.F2 : 0);
  var d1 = this.FV / yt,
      d2 = (1 << this.F1) / yt,
      e = 1 << this.F2;
  var i = r.t,
      j = i - ys,
      t = q == null ? nbi() : q;
  y.dlShiftTo(j, t);
  if (r.compareTo(t) >= 0) {
    r[r.t++] = 1;
    r.subTo(t, r);
  }
  BigInteger.ONE.dlShiftTo(ys, t);
  t.subTo(y, y); // "negative" y so we can replace sub with am later
  while (y.t < ys) {
    y[y.t++] = 0;
  }while (--j >= 0) {
    // Estimate quotient digit
    var qd = r[--i] == y0 ? this.DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2);
    if ((r[i] += y.am(0, qd, r, j, 0, ys)) < qd) {
      // Try it out
      y.dlShiftTo(j, t);
      r.subTo(t, r);
      while (r[i] < --qd) {
        r.subTo(t, r);
      }
    }
  }
  if (q != null) {
    r.drShiftTo(ys, q);
    if (ts != ms) BigInteger.ZERO.subTo(q, q);
  }
  r.t = ys;
  r.clamp();
  if (nsh > 0) r.rShiftTo(nsh, r); // Denormalize remainder
  if (ts < 0) BigInteger.ZERO.subTo(r, r);
}

// (public) this mod a

function bnMod(a) {
  var r = nbi();
  this.abs().divRemTo(a, null, r);
  if (this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r, r);
  return r;
}

// Modular reduction using "classic" algorithm

function Classic(m) {
  this.m = m;
}

function cConvert(x) {
  if (x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);else return x;
}

function cRevert(x) {
  return x;
}

function cReduce(x) {
  x.divRemTo(this.m, null, x);
}

function cMulTo(x, y, r) {
  x.multiplyTo(y, r);
  this.reduce(r);
}

function cSqrTo(x, r) {
  x.squareTo(r);
  this.reduce(r);
}

Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.

function bnpInvDigit() {
  if (this.t < 1) return 0;
  var x = this[0];
  if ((x & 1) == 0) return 0;
  var y = x & 3; // y == 1/x mod 2^2
  y = y * (2 - (x & 0xf) * y) & 0xf; // y == 1/x mod 2^4
  y = y * (2 - (x & 0xff) * y) & 0xff; // y == 1/x mod 2^8
  y = y * (2 - ((x & 0xffff) * y & 0xffff)) & 0xffff; // y == 1/x mod 2^16
  // last step - calculate inverse mod DV directly;
  // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
  y = y * (2 - x * y % this.DV) % this.DV; // y == 1/x mod 2^dbits
  // we really want the negative inverse, and -DV < y < DV
  return y > 0 ? this.DV - y : -y;
}

// Montgomery reduction

function Montgomery(m) {
  this.m = m;
  this.mp = m.invDigit();
  this.mpl = this.mp & 0x7fff;
  this.mph = this.mp >> 15;
  this.um = (1 << m.DB - 15) - 1;
  this.mt2 = 2 * m.t;
}

// xR mod m

function montConvert(x) {
  var r = nbi();
  x.abs().dlShiftTo(this.m.t, r);
  r.divRemTo(this.m, null, r);
  if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r, r);
  return r;
}

// x/R mod m

function montRevert(x) {
  var r = nbi();
  x.copyTo(r);
  this.reduce(r);
  return r;
}

// x = x/R mod m (HAC 14.32)

function montReduce(x) {
  while (x.t <= this.mt2) {
    // pad x so am has enough room later
    x[x.t++] = 0;
  }for (var i = 0; i < this.m.t; ++i) {
    // faster way of calculating u0 = x[i]*mp mod DV
    var j = x[i] & 0x7fff;
    var u0 = j * this.mpl + ((j * this.mph + (x[i] >> 15) * this.mpl & this.um) << 15) & x.DM;
    // use am to combine the multiply-shift-add into one call
    j = i + this.m.t;
    x[j] += this.m.am(0, u0, x, i, 0, this.m.t);
    // propagate carry
    while (x[j] >= x.DV) {
      x[j] -= x.DV;
      x[++j]++;
    }
  }
  x.clamp();
  x.drShiftTo(this.m.t, x);
  if (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
}

// r = "x^2/R mod m"; x != r

function montSqrTo(x, r) {
  x.squareTo(r);
  this.reduce(r);
}

// r = "xy/R mod m"; x,y != r

function montMulTo(x, y, r) {
  x.multiplyTo(y, r);
  this.reduce(r);
}

Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;

// (protected) true iff this is even

function bnpIsEven() {
  return (this.t > 0 ? this[0] & 1 : this.s) == 0;
}

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)

function bnpExp(e, z) {
  if (e > 0xffffffff || e < 1) return BigInteger.ONE;
  var r = nbi(),
      r2 = nbi(),
      g = z.convert(this),
      i = nbits(e) - 1;
  g.copyTo(r);
  while (--i >= 0) {
    z.sqrTo(r, r2);
    if ((e & 1 << i) > 0) z.mulTo(r2, g, r);else {
      var t = r;
      r = r2;
      r2 = t;
    }
  }
  return z.revert(r);
}

// (public) this^e % m, 0 <= e < 2^32

function bnModPowInt(e, m) {
  var z;
  if (e < 256 || m.isEven()) z = new Classic(m);else z = new Montgomery(m);
  return this.exp(e, z);
}

// protected
BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;

// public
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;

// "constants"
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);
BigInteger.TWO = nbv(2);

/*
 * Copyright (c) 2003-2005  Tom Wu (tjw@cs.Stanford.EDU)
 * All Rights Reserved.
 *
 * Modified by Recurity Labs GmbH
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * In addition, the following condition applies:
 *
 * All redistributions must retain an intact copy of this copyright notice
 * and disclaimer.
 */

// Extended JavaScript BN functions, required for RSA private ops.

// Version 1.1: new BigInteger("0", 10) returns "proper" zero
// Version 1.2: square() API, isProbablePrime fix

// (public)
function bnClone() {
  var r = nbi();
  this.copyTo(r);
  return r;
}

// (public) return value as integer

function bnIntValue() {
  if (this.s < 0) {
    if (this.t == 1) return this[0] - this.DV;else if (this.t == 0) return -1;
  } else if (this.t == 1) return this[0];else if (this.t == 0) return 0;
  // assumes 16 < DB < 32
  return (this[1] & (1 << 32 - this.DB) - 1) << this.DB | this[0];
}

// (public) return value as byte

function bnByteValue() {
  return this.t == 0 ? this.s : this[0] << 24 >> 24;
}

// (public) return value as short (assumes DB>=16)

function bnShortValue() {
  return this.t == 0 ? this.s : this[0] << 16 >> 16;
}

// (protected) return x s.t. r^x < DV

function bnpChunkSize(r) {
  return Math.floor(Math.LN2 * this.DB / Math.log(r));
}

// (public) 0 if this == 0, 1 if this > 0

function bnSigNum() {
  if (this.s < 0) return -1;else if (this.t <= 0 || this.t == 1 && this[0] <= 0) return 0;else return 1;
}

// (protected) convert to radix string

function bnpToRadix(b) {
  if (b == null) b = 10;
  if (this.signum() == 0 || b < 2 || b > 36) return "0";
  var cs = this.chunkSize(b);
  var a = Math.pow(b, cs);
  var d = nbv(a),
      y = nbi(),
      z = nbi(),
      r = "";
  this.divRemTo(d, y, z);
  while (y.signum() > 0) {
    r = (a + z.intValue()).toString(b).substr(1) + r;
    y.divRemTo(d, y, z);
  }
  return z.intValue().toString(b) + r;
}

// (protected) convert from radix string

function bnpFromRadix(s, b) {
  this.fromInt(0);
  if (b == null) b = 10;
  var cs = this.chunkSize(b);
  var d = Math.pow(b, cs),
      mi = false,
      j = 0,
      w = 0;
  for (var i = 0; i < s.length; ++i) {
    var x = intAt(s, i);
    if (x < 0) {
      if (s.charAt(i) == "-" && this.signum() == 0) mi = true;
      continue;
    }
    w = b * w + x;
    if (++j >= cs) {
      this.dMultiply(d);
      this.dAddOffset(w, 0);
      j = 0;
      w = 0;
    }
  }
  if (j > 0) {
    this.dMultiply(Math.pow(b, j));
    this.dAddOffset(w, 0);
  }
  if (mi) BigInteger.ZERO.subTo(this, this);
}

// (protected) alternate constructor

function bnpFromNumber(a, b, c) {
  if ("number" == typeof b) {
    // new BigInteger(int,int,RNG)
    if (a < 2) this.fromInt(1);else {
      this.fromNumber(a, c);
      if (!this.testBit(a - 1)) // force MSB set
        this.bitwiseTo(BigInteger.ONE.shiftLeft(a - 1), op_or, this);
      if (this.isEven()) this.dAddOffset(1, 0); // force odd
      while (!this.isProbablePrime(b)) {
        this.dAddOffset(2, 0);
        if (this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a - 1), this);
      }
    }
  } else {
    // new BigInteger(int,RNG)
    var x = new Array(),
        t = a & 7;
    x.length = (a >> 3) + 1;
    b.nextBytes(x);
    if (t > 0) x[0] &= (1 << t) - 1;else x[0] = 0;
    this.fromString(x, 256);
  }
}

// (public) convert to bigendian byte array

function bnToByteArray() {
  var i = this.t,
      r = new Array();
  r[0] = this.s;
  var p = this.DB - i * this.DB % 8,
      d,
      k = 0;
  if (i-- > 0) {
    if (p < this.DB && (d = this[i] >> p) != (this.s & this.DM) >> p) r[k++] = d | this.s << this.DB - p;
    while (i >= 0) {
      if (p < 8) {
        d = (this[i] & (1 << p) - 1) << 8 - p;
        d |= this[--i] >> (p += this.DB - 8);
      } else {
        d = this[i] >> (p -= 8) & 0xff;
        if (p <= 0) {
          p += this.DB;
          --i;
        }
      }
      //if((d&0x80) != 0) d |= -256;
      //if(k == 0 && (this.s&0x80) != (d&0x80)) ++k;
      if (k > 0 || d != this.s) r[k++] = d;
    }
  }
  return r;
}

function bnEquals(a) {
  return this.compareTo(a) == 0;
}

function bnMin(a) {
  return this.compareTo(a) < 0 ? this : a;
}

function bnMax(a) {
  return this.compareTo(a) > 0 ? this : a;
}

// (protected) r = this op a (bitwise)

function bnpBitwiseTo(a, op, r) {
  var i,
      f,
      m = Math.min(a.t, this.t);
  for (i = 0; i < m; ++i) {
    r[i] = op(this[i], a[i]);
  }if (a.t < this.t) {
    f = a.s & this.DM;
    for (i = m; i < this.t; ++i) {
      r[i] = op(this[i], f);
    }r.t = this.t;
  } else {
    f = this.s & this.DM;
    for (i = m; i < a.t; ++i) {
      r[i] = op(f, a[i]);
    }r.t = a.t;
  }
  r.s = op(this.s, a.s);
  r.clamp();
}

// (public) this & a

function op_and(x, y) {
  return x & y;
}

function bnAnd(a) {
  var r = nbi();
  this.bitwiseTo(a, op_and, r);
  return r;
}

// (public) this | a

function op_or(x, y) {
  return x | y;
}

function bnOr(a) {
  var r = nbi();
  this.bitwiseTo(a, op_or, r);
  return r;
}

// (public) this ^ a

function op_xor(x, y) {
  return x ^ y;
}

function bnXor(a) {
  var r = nbi();
  this.bitwiseTo(a, op_xor, r);
  return r;
}

// (public) this & ~a

function op_andnot(x, y) {
  return x & ~y;
}

function bnAndNot(a) {
  var r = nbi();
  this.bitwiseTo(a, op_andnot, r);
  return r;
}

// (public) ~this

function bnNot() {
  var r = nbi();
  for (var i = 0; i < this.t; ++i) {
    r[i] = this.DM & ~this[i];
  }r.t = this.t;
  r.s = ~this.s;
  return r;
}

// (public) this << n

function bnShiftLeft(n) {
  var r = nbi();
  if (n < 0) this.rShiftTo(-n, r);else this.lShiftTo(n, r);
  return r;
}

// (public) this >> n

function bnShiftRight(n) {
  var r = nbi();
  if (n < 0) this.lShiftTo(-n, r);else this.rShiftTo(n, r);
  return r;
}

// return index of lowest 1-bit in x, x < 2^31

function lbit(x) {
  if (x == 0) return -1;
  var r = 0;
  if ((x & 0xffff) == 0) {
    x >>= 16;
    r += 16;
  }
  if ((x & 0xff) == 0) {
    x >>= 8;
    r += 8;
  }
  if ((x & 0xf) == 0) {
    x >>= 4;
    r += 4;
  }
  if ((x & 3) == 0) {
    x >>= 2;
    r += 2;
  }
  if ((x & 1) == 0) ++r;
  return r;
}

// (public) returns index of lowest 1-bit (or -1 if none)

function bnGetLowestSetBit() {
  for (var i = 0; i < this.t; ++i) {
    if (this[i] != 0) return i * this.DB + lbit(this[i]);
  }if (this.s < 0) return this.t * this.DB;
  return -1;
}

// return number of 1 bits in x

function cbit(x) {
  var r = 0;
  while (x != 0) {
    x &= x - 1;
    ++r;
  }
  return r;
}

// (public) return number of set bits

function bnBitCount() {
  var r = 0,
      x = this.s & this.DM;
  for (var i = 0; i < this.t; ++i) {
    r += cbit(this[i] ^ x);
  }return r;
}

// (public) true iff nth bit is set

function bnTestBit(n) {
  var j = Math.floor(n / this.DB);
  if (j >= this.t) return this.s != 0;
  return (this[j] & 1 << n % this.DB) != 0;
}

// (protected) this op (1<<n)

function bnpChangeBit(n, op) {
  var r = BigInteger.ONE.shiftLeft(n);
  this.bitwiseTo(r, op, r);
  return r;
}

// (public) this | (1<<n)

function bnSetBit(n) {
  return this.changeBit(n, op_or);
}

// (public) this & ~(1<<n)

function bnClearBit(n) {
  return this.changeBit(n, op_andnot);
}

// (public) this ^ (1<<n)

function bnFlipBit(n) {
  return this.changeBit(n, op_xor);
}

// (protected) r = this + a

function bnpAddTo(a, r) {
  var i = 0,
      c = 0,
      m = Math.min(a.t, this.t);
  while (i < m) {
    c += this[i] + a[i];
    r[i++] = c & this.DM;
    c >>= this.DB;
  }
  if (a.t < this.t) {
    c += a.s;
    while (i < this.t) {
      c += this[i];
      r[i++] = c & this.DM;
      c >>= this.DB;
    }
    c += this.s;
  } else {
    c += this.s;
    while (i < a.t) {
      c += a[i];
      r[i++] = c & this.DM;
      c >>= this.DB;
    }
    c += a.s;
  }
  r.s = c < 0 ? -1 : 0;
  if (c > 0) r[i++] = c;else if (c < -1) r[i++] = this.DV + c;
  r.t = i;
  r.clamp();
}

// (public) this + a

function bnAdd(a) {
  var r = nbi();
  this.addTo(a, r);
  return r;
}

// (public) this - a

function bnSubtract(a) {
  var r = nbi();
  this.subTo(a, r);
  return r;
}

// (public) this * a

function bnMultiply(a) {
  var r = nbi();
  this.multiplyTo(a, r);
  return r;
}

// (public) this^2

function bnSquare() {
  var r = nbi();
  this.squareTo(r);
  return r;
}

// (public) this / a

function bnDivide(a) {
  var r = nbi();
  this.divRemTo(a, r, null);
  return r;
}

// (public) this % a

function bnRemainder(a) {
  var r = nbi();
  this.divRemTo(a, null, r);
  return r;
}

// (public) [this/a,this%a]

function bnDivideAndRemainder(a) {
  var q = nbi(),
      r = nbi();
  this.divRemTo(a, q, r);
  return new Array(q, r);
}

// (protected) this *= n, this >= 0, 1 < n < DV

function bnpDMultiply(n) {
  this[this.t] = this.am(0, n - 1, this, 0, 0, this.t);
  ++this.t;
  this.clamp();
}

// (protected) this += n << w words, this >= 0

function bnpDAddOffset(n, w) {
  if (n == 0) return;
  while (this.t <= w) {
    this[this.t++] = 0;
  }this[w] += n;
  while (this[w] >= this.DV) {
    this[w] -= this.DV;
    if (++w >= this.t) this[this.t++] = 0;
    ++this[w];
  }
}

// A "null" reducer

function NullExp() {}

function nNop(x) {
  return x;
}

function nMulTo(x, y, r) {
  x.multiplyTo(y, r);
}

function nSqrTo(x, r) {
  x.squareTo(r);
}

NullExp.prototype.convert = nNop;
NullExp.prototype.revert = nNop;
NullExp.prototype.mulTo = nMulTo;
NullExp.prototype.sqrTo = nSqrTo;

// (public) this^e

function bnPow(e) {
  return this.exp(e, new NullExp());
}

// (protected) r = lower n words of "this * a", a.t <= n
// "this" should be the larger one if appropriate.

function bnpMultiplyLowerTo(a, n, r) {
  var i = Math.min(this.t + a.t, n);
  r.s = 0; // assumes a,this >= 0
  r.t = i;
  while (i > 0) {
    r[--i] = 0;
  }var j;
  for (j = r.t - this.t; i < j; ++i) {
    r[i + this.t] = this.am(0, a[i], r, i, 0, this.t);
  }for (j = Math.min(a.t, n); i < j; ++i) {
    this.am(0, a[i], r, i, 0, n - i);
  }r.clamp();
}

// (protected) r = "this * a" without lower n words, n > 0
// "this" should be the larger one if appropriate.

function bnpMultiplyUpperTo(a, n, r) {
  --n;
  var i = r.t = this.t + a.t - n;
  r.s = 0; // assumes a,this >= 0
  while (--i >= 0) {
    r[i] = 0;
  }for (i = Math.max(n - this.t, 0); i < a.t; ++i) {
    r[this.t + i - n] = this.am(n - i, a[i], r, 0, 0, this.t + i - n);
  }r.clamp();
  r.drShiftTo(1, r);
}

// Barrett modular reduction

function Barrett(m) {
  // setup Barrett
  this.r2 = nbi();
  this.q3 = nbi();
  BigInteger.ONE.dlShiftTo(2 * m.t, this.r2);
  this.mu = this.r2.divide(m);
  this.m = m;
}

function barrettConvert(x) {
  if (x.s < 0 || x.t > 2 * this.m.t) return x.mod(this.m);else if (x.compareTo(this.m) < 0) return x;else {
    var r = nbi();
    x.copyTo(r);
    this.reduce(r);
    return r;
  }
}

function barrettRevert(x) {
  return x;
}

// x = x mod m (HAC 14.42)

function barrettReduce(x) {
  x.drShiftTo(this.m.t - 1, this.r2);
  if (x.t > this.m.t + 1) {
    x.t = this.m.t + 1;
    x.clamp();
  }
  this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3);
  this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2);
  while (x.compareTo(this.r2) < 0) {
    x.dAddOffset(1, this.m.t + 1);
  }x.subTo(this.r2, x);
  while (x.compareTo(this.m) >= 0) {
    x.subTo(this.m, x);
  }
}

// r = x^2 mod m; x != r

function barrettSqrTo(x, r) {
  x.squareTo(r);
  this.reduce(r);
}

// r = x*y mod m; x,y != r

function barrettMulTo(x, y, r) {
  x.multiplyTo(y, r);
  this.reduce(r);
}

Barrett.prototype.convert = barrettConvert;
Barrett.prototype.revert = barrettRevert;
Barrett.prototype.reduce = barrettReduce;
Barrett.prototype.mulTo = barrettMulTo;
Barrett.prototype.sqrTo = barrettSqrTo;

// (public) this^e % m (HAC 14.85)

function bnModPow(e, m) {
  var i = e.bitLength(),
      k,
      r = nbv(1),
      z;
  if (i <= 0) return r;else if (i < 18) k = 1;else if (i < 48) k = 3;else if (i < 144) k = 4;else if (i < 768) k = 5;else k = 6;
  if (i < 8) z = new Classic(m);else if (m.isEven()) z = new Barrett(m);else z = new Montgomery(m);

  // precomputation
  var g = new Array(),
      n = 3,
      k1 = k - 1,
      km = (1 << k) - 1;
  g[1] = z.convert(this);
  if (k > 1) {
    var g2 = nbi();
    z.sqrTo(g[1], g2);
    while (n <= km) {
      g[n] = nbi();
      z.mulTo(g2, g[n - 2], g[n]);
      n += 2;
    }
  }

  var j = e.t - 1,
      w,
      is1 = true,
      r2 = nbi(),
      t;
  i = nbits(e[j]) - 1;
  while (j >= 0) {
    if (i >= k1) w = e[j] >> i - k1 & km;else {
      w = (e[j] & (1 << i + 1) - 1) << k1 - i;
      if (j > 0) w |= e[j - 1] >> this.DB + i - k1;
    }

    n = k;
    while ((w & 1) == 0) {
      w >>= 1;
      --n;
    }
    if ((i -= n) < 0) {
      i += this.DB;
      --j;
    }
    if (is1) {
      // ret == 1, don't bother squaring or multiplying it
      g[w].copyTo(r);
      is1 = false;
    } else {
      while (n > 1) {
        z.sqrTo(r, r2);
        z.sqrTo(r2, r);
        n -= 2;
      }
      if (n > 0) z.sqrTo(r, r2);else {
        t = r;
        r = r2;
        r2 = t;
      }
      z.mulTo(r2, g[w], r);
    }

    while (j >= 0 && (e[j] & 1 << i) == 0) {
      z.sqrTo(r, r2);
      t = r;
      r = r2;
      r2 = t;
      if (--i < 0) {
        i = this.DB - 1;
        --j;
      }
    }
  }
  return z.revert(r);
}

// (public) gcd(this,a) (HAC 14.54)

function bnGCD(a) {
  var x = this.s < 0 ? this.negate() : this.clone();
  var y = a.s < 0 ? a.negate() : a.clone();
  if (x.compareTo(y) < 0) {
    var t = x;
    x = y;
    y = t;
  }
  var i = x.getLowestSetBit(),
      g = y.getLowestSetBit();
  if (g < 0) return x;
  if (i < g) g = i;
  if (g > 0) {
    x.rShiftTo(g, x);
    y.rShiftTo(g, y);
  }
  while (x.signum() > 0) {
    if ((i = x.getLowestSetBit()) > 0) x.rShiftTo(i, x);
    if ((i = y.getLowestSetBit()) > 0) y.rShiftTo(i, y);
    if (x.compareTo(y) >= 0) {
      x.subTo(y, x);
      x.rShiftTo(1, x);
    } else {
      y.subTo(x, y);
      y.rShiftTo(1, y);
    }
  }
  if (g > 0) y.lShiftTo(g, y);
  return y;
}

// (protected) this % n, n < 2^26

function bnpModInt(n) {
  if (n <= 0) return 0;
  var d = this.DV % n,
      r = this.s < 0 ? n - 1 : 0;
  if (this.t > 0) if (d == 0) r = this[0] % n;else for (var i = this.t - 1; i >= 0; --i) {
    r = (d * r + this[i]) % n;
  }return r;
}

// (public) 1/this % m (HAC 14.61)

function bnModInverse(m) {
  var ac = m.isEven();
  if (this.isEven() && ac || m.signum() == 0) return BigInteger.ZERO;
  var u = m.clone(),
      v = this.clone();
  var a = nbv(1),
      b = nbv(0),
      c = nbv(0),
      d = nbv(1);
  while (u.signum() != 0) {
    while (u.isEven()) {
      u.rShiftTo(1, u);
      if (ac) {
        if (!a.isEven() || !b.isEven()) {
          a.addTo(this, a);
          b.subTo(m, b);
        }
        a.rShiftTo(1, a);
      } else if (!b.isEven()) b.subTo(m, b);
      b.rShiftTo(1, b);
    }
    while (v.isEven()) {
      v.rShiftTo(1, v);
      if (ac) {
        if (!c.isEven() || !d.isEven()) {
          c.addTo(this, c);
          d.subTo(m, d);
        }
        c.rShiftTo(1, c);
      } else if (!d.isEven()) d.subTo(m, d);
      d.rShiftTo(1, d);
    }
    if (u.compareTo(v) >= 0) {
      u.subTo(v, u);
      if (ac) a.subTo(c, a);
      b.subTo(d, b);
    } else {
      v.subTo(u, v);
      if (ac) c.subTo(a, c);
      d.subTo(b, d);
    }
  }
  if (v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
  if (d.compareTo(m) >= 0) return d.subtract(m);
  if (d.signum() < 0) d.addTo(m, d);else return d;
  if (d.signum() < 0) return d.add(m);else return d;
}

var lowprimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997];
var lplim = (1 << 26) / lowprimes[lowprimes.length - 1];

// (public) test primality with certainty >= 1-.5^t

function bnIsProbablePrime(t) {
  var i,
      x = this.abs();
  if (x.t == 1 && x[0] <= lowprimes[lowprimes.length - 1]) {
    for (i = 0; i < lowprimes.length; ++i) {
      if (x[0] == lowprimes[i]) return true;
    }return false;
  }
  if (x.isEven()) return false;
  i = 1;
  while (i < lowprimes.length) {
    var m = lowprimes[i],
        j = i + 1;
    while (j < lowprimes.length && m < lplim) {
      m *= lowprimes[j++];
    }m = x.modInt(m);
    while (i < j) {
      if (m % lowprimes[i++] == 0) return false;
    }
  }
  return x.millerRabin(t);
}

/* added by Recurity Labs */

function nbits(x) {
  var n = 1,
      t;
  if ((t = x >>> 16) != 0) {
    x = t;
    n += 16;
  }
  if ((t = x >> 8) != 0) {
    x = t;
    n += 8;
  }
  if ((t = x >> 4) != 0) {
    x = t;
    n += 4;
  }
  if ((t = x >> 2) != 0) {
    x = t;
    n += 2;
  }
  if ((t = x >> 1) != 0) {
    x = t;
    n += 1;
  }
  return n;
}

function bnToMPI() {
  var ba = this.toByteArray();
  var size = (ba.length - 1) * 8 + nbits(ba[0]);
  var result = "";
  result += String.fromCharCode((size & 0xFF00) >> 8);
  result += String.fromCharCode(size & 0xFF);
  result += _util2.default.bin2str(ba);
  return result;
}
/* END of addition */

// (protected) true if probably prime (HAC 4.24, Miller-Rabin)
function bnpMillerRabin(t) {
  var n1 = this.subtract(BigInteger.ONE);
  var k = n1.getLowestSetBit();
  if (k <= 0) return false;
  var r = n1.shiftRight(k);
  t = t + 1 >> 1;
  if (t > lowprimes.length) t = lowprimes.length;
  var a = nbi();
  var j,
      bases = [];
  for (var i = 0; i < t; ++i) {
    //Pick bases at random, instead of starting at 2
    for (;;) {
      j = lowprimes[Math.floor(Math.random() * lowprimes.length)];
      if (bases.indexOf(j) == -1) break;
    }
    bases.push(j);
    a.fromInt(j);
    var y = a.modPow(r, this);
    if (y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
      var j = 1;
      while (j++ < k && y.compareTo(n1) != 0) {
        y = y.modPowInt(2, this);
        if (y.compareTo(BigInteger.ONE) == 0) return false;
      }
      if (y.compareTo(n1) != 0) return false;
    }
  }
  return true;
}

// protected
BigInteger.prototype.chunkSize = bnpChunkSize;
BigInteger.prototype.toRadix = bnpToRadix;
BigInteger.prototype.fromRadix = bnpFromRadix;
BigInteger.prototype.fromNumber = bnpFromNumber;
BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
BigInteger.prototype.changeBit = bnpChangeBit;
BigInteger.prototype.addTo = bnpAddTo;
BigInteger.prototype.dMultiply = bnpDMultiply;
BigInteger.prototype.dAddOffset = bnpDAddOffset;
BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
BigInteger.prototype.modInt = bnpModInt;
BigInteger.prototype.millerRabin = bnpMillerRabin;

// public
BigInteger.prototype.clone = bnClone;
BigInteger.prototype.intValue = bnIntValue;
BigInteger.prototype.byteValue = bnByteValue;
BigInteger.prototype.shortValue = bnShortValue;
BigInteger.prototype.signum = bnSigNum;
BigInteger.prototype.toByteArray = bnToByteArray;
BigInteger.prototype.equals = bnEquals;
BigInteger.prototype.min = bnMin;
BigInteger.prototype.max = bnMax;
BigInteger.prototype.and = bnAnd;
BigInteger.prototype.or = bnOr;
BigInteger.prototype.xor = bnXor;
BigInteger.prototype.andNot = bnAndNot;
BigInteger.prototype.not = bnNot;
BigInteger.prototype.shiftLeft = bnShiftLeft;
BigInteger.prototype.shiftRight = bnShiftRight;
BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
BigInteger.prototype.bitCount = bnBitCount;
BigInteger.prototype.testBit = bnTestBit;
BigInteger.prototype.setBit = bnSetBit;
BigInteger.prototype.clearBit = bnClearBit;
BigInteger.prototype.flipBit = bnFlipBit;
BigInteger.prototype.add = bnAdd;
BigInteger.prototype.subtract = bnSubtract;
BigInteger.prototype.multiply = bnMultiply;
BigInteger.prototype.divide = bnDivide;
BigInteger.prototype.remainder = bnRemainder;
BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
BigInteger.prototype.modPow = bnModPow;
BigInteger.prototype.modInverse = bnModInverse;
BigInteger.prototype.pow = bnPow;
BigInteger.prototype.gcd = bnGCD;
BigInteger.prototype.isProbablePrime = bnIsProbablePrime;
BigInteger.prototype.toMPI = bnToMPI;

// JSBN-specific extension
BigInteger.prototype.square = bnSquare;

},{"../../util.js":70}],30:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
//
// RSA implementation

/**
 * @requires crypto/public_key/jsbn
 * @requires crypto/random
 * @requires util
 * @module crypto/public_key/rsa
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = RSA;

var _jsbn = _dereq_('./jsbn.js');

var _jsbn2 = _interopRequireDefault(_jsbn);

var _util = _dereq_('../../util.js');

var _util2 = _interopRequireDefault(_util);

var _random = _dereq_('../random.js');

var _random2 = _interopRequireDefault(_random);

var _config = _dereq_('../../config');

var _config2 = _interopRequireDefault(_config);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function SecureRandom() {
  function nextBytes(byteArray) {
    for (var n = 0; n < byteArray.length; n++) {
      byteArray[n] = _random2.default.getSecureRandomOctet();
    }
  }
  this.nextBytes = nextBytes;
}

var blinder = _jsbn2.default.ZERO;
var unblinder = _jsbn2.default.ZERO;

function blind(m, n, e) {
  if (unblinder.bitLength() === n.bitLength()) {
    unblinder = unblinder.square().mod(n);
  } else {
    unblinder = _random2.default.getRandomBigIntegerInRange(_jsbn2.default.TWO, n);
  }
  blinder = unblinder.modInverse(n).modPow(e, n);
  return m.multiply(blinder).mod(n);
}

function unblind(t, n) {
  return t.multiply(unblinder).mod(n);
}

function RSA() {
  /**
   * This function uses jsbn Big Num library to decrypt RSA
   * @param m
   *            message
   * @param n
   *            RSA public modulus n as BigInteger
   * @param e
   *            RSA public exponent as BigInteger
   * @param d
   *            RSA d as BigInteger
   * @param p
   *            RSA p as BigInteger
   * @param q
   *            RSA q as BigInteger
   * @param u
   *            RSA u as BigInteger
   * @return {BigInteger} The decrypted value of the message
   */
  function decrypt(m, n, e, d, p, q, u) {
    if (_config2.default.rsa_blinding) {
      m = blind(m, n, e);
    }
    var xp = m.mod(p).modPow(d.mod(p.subtract(_jsbn2.default.ONE)), p);
    var xq = m.mod(q).modPow(d.mod(q.subtract(_jsbn2.default.ONE)), q);
    _util2.default.print_debug("rsa.js decrypt\nxpn:" + _util2.default.hexstrdump(xp.toMPI()) + "\nxqn:" + _util2.default.hexstrdump(xq.toMPI()));

    var t = xq.subtract(xp);
    if (t[0] === 0) {
      t = xp.subtract(xq);
      t = t.multiply(u).mod(q);
      t = q.subtract(t);
    } else {
      t = t.multiply(u).mod(q);
    }
    t = t.multiply(p).add(xp);
    if (_config2.default.rsa_blinding) {
      t = unblind(t, n);
    }
    return t;
  }

  /**
   * encrypt message
   * @param m message as BigInteger
   * @param e public MPI part as BigInteger
   * @param n public MPI part as BigInteger
   * @return BigInteger
   */
  function encrypt(m, e, n) {
    return m.modPowInt(e, n);
  }

  /* Sign and Verify */
  function sign(m, d, n) {
    return m.modPow(d, n);
  }

  function verify(x, e, n) {
    return x.modPowInt(e, n);
  }

  // "empty" RSA key constructor

  function KeyObject() {
    this.n = null;
    this.e = 0;
    this.ee = null;
    this.d = null;
    this.p = null;
    this.q = null;
    this.dmp1 = null;
    this.dmq1 = null;
    this.u = null;
  }

  // Generate a new random private key B bits long, using public expt E

  function generate(B, E) {
    var webCrypto = _util2.default.getWebCryptoAll();

    //
    // Native RSA keygen using Web Crypto
    //

    if (webCrypto) {
      var Euint32 = new Uint32Array([parseInt(E, 16)]); // get integer of exponent
      var Euint8 = new Uint8Array(Euint32.buffer); // get bytes of exponent
      var keyGenOpt;

      var keys;
      if (window.crypto && window.crypto.webkitSubtle) {
        // outdated spec implemented by Webkit
        keyGenOpt = {
          name: 'RSA-OAEP',
          modulusLength: B, // the specified keysize in bits
          publicExponent: Euint8.subarray(0, 3), // take three bytes (max 65537)
          hash: {
            name: 'SHA-1' // not required for actual RSA keys, but for crypto api 'sign' and 'verify'
          }
        };
        keys = webCrypto.generateKey(keyGenOpt, true, ['encrypt', 'decrypt']);
      } else {
        // current standard spec
        keyGenOpt = {
          name: 'RSASSA-PKCS1-v1_5',
          modulusLength: B, // the specified keysize in bits
          publicExponent: Euint8.subarray(0, 3), // take three bytes (max 65537)
          hash: {
            name: 'SHA-1' // not required for actual RSA keys, but for crypto api 'sign' and 'verify'
          }
        };

        keys = webCrypto.generateKey(keyGenOpt, true, ['sign', 'verify']);
        if (typeof keys.then !== 'function') {
          // IE11 KeyOperation
          keys = _util2.default.promisifyIE11Op(keys, 'Error generating RSA key pair.');
        }
      }

      return keys.then(exportKey).then(function (key) {
        if (key instanceof ArrayBuffer) {
          // parse raw ArrayBuffer bytes to jwk/json (WebKit/Safari/IE11 quirk)
          return decodeKey(JSON.parse(String.fromCharCode.apply(null, new Uint8Array(key))));
        }
        return decodeKey(key);
      });
    }

    function exportKey(keypair) {
      // export the generated keys as JsonWebKey (JWK)
      // https://tools.ietf.org/html/draft-ietf-jose-json-web-key-33
      var key = webCrypto.exportKey('jwk', keypair.privateKey);
      if (typeof key.then !== 'function') {
        // IE11 KeyOperation
        key = _util2.default.promisifyIE11Op(key, 'Error exporting RSA key pair.');
      }
      return key;
    }

    function decodeKey(jwk) {
      // map JWK parameters to local BigInteger type system
      var key = new KeyObject();
      key.n = toBigInteger(jwk.n);
      key.ee = new _jsbn2.default(E, 16);
      key.d = toBigInteger(jwk.d);
      key.p = toBigInteger(jwk.p);
      key.q = toBigInteger(jwk.q);
      key.u = key.p.modInverse(key.q);

      function toBigInteger(base64url) {
        var base64 = base64url.replace(/\-/g, '+').replace(/_/g, '/');
        var hex = _util2.default.hexstrdump(atob(base64));
        return new _jsbn2.default(hex, 16);
      }

      return key;
    }

    //
    // JS code
    //

    return new Promise(function (resolve) {
      var key = new KeyObject();
      var rng = new SecureRandom();
      var qs = B >> 1;
      key.e = parseInt(E, 16);
      key.ee = new _jsbn2.default(E, 16);

      for (;;) {
        for (;;) {
          key.p = new _jsbn2.default(B - qs, 1, rng);
          if (key.p.subtract(_jsbn2.default.ONE).gcd(key.ee).compareTo(_jsbn2.default.ONE) === 0 && key.p.isProbablePrime(10)) {
            break;
          }
        }
        for (;;) {
          key.q = new _jsbn2.default(qs, 1, rng);
          if (key.q.subtract(_jsbn2.default.ONE).gcd(key.ee).compareTo(_jsbn2.default.ONE) === 0 && key.q.isProbablePrime(10)) {
            break;
          }
        }
        if (key.p.compareTo(key.q) <= 0) {
          var t = key.p;
          key.p = key.q;
          key.q = t;
        }
        var p1 = key.p.subtract(_jsbn2.default.ONE);
        var q1 = key.q.subtract(_jsbn2.default.ONE);
        var phi = p1.multiply(q1);
        if (phi.gcd(key.ee).compareTo(_jsbn2.default.ONE) === 0) {
          key.n = key.p.multiply(key.q);
          key.d = key.ee.modInverse(phi);
          key.dmp1 = key.d.mod(p1);
          key.dmq1 = key.d.mod(q1);
          key.u = key.p.modInverse(key.q);
          break;
        }
      }

      resolve(key);
    });
  }

  this.encrypt = encrypt;
  this.decrypt = decrypt;
  this.verify = verify;
  this.sign = sign;
  this.generate = generate;
  this.keyObject = KeyObject;
}

},{"../../config":10,"../../util.js":70,"../random.js":31,"./jsbn.js":29}],31:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

// The GPG4Browsers crypto interface

/**
 * @requires type/mpi
 * @requires util
 * @module crypto/random
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol ? "symbol" : typeof obj; };

var _mpi = _dereq_('../type/mpi.js');

var _mpi2 = _interopRequireDefault(_mpi);

var _util = _dereq_('../util.js');

var _util2 = _interopRequireDefault(_util);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var nodeCrypto = _util2.default.detectNode() && _dereq_('crypto');

exports.default = {
  /**
   * Retrieve secure random byte array of the specified length
   * @param {Integer} length Length in bytes to generate
   * @return {Uint8Array} Random byte array
   */
  getRandomBytes: function getRandomBytes(length) {
    var result = new Uint8Array(length);
    for (var i = 0; i < length; i++) {
      result[i] = this.getSecureRandomOctet();
    }
    return result;
  },

  /**
   * Return a secure random number in the specified range
   * @param {Integer} from Min of the random number
   * @param {Integer} to Max of the random number (max 32bit)
   * @return {Integer} A secure random number
   */
  getSecureRandom: function getSecureRandom(from, to) {
    var randUint = this.getSecureRandomUint();
    var bits = (to - from).toString(2).length;
    while ((randUint & Math.pow(2, bits) - 1) > to - from) {
      randUint = this.getSecureRandomUint();
    }
    return from + Math.abs(randUint & Math.pow(2, bits) - 1);
  },

  getSecureRandomOctet: function getSecureRandomOctet() {
    var buf = new Uint8Array(1);
    this.getRandomValues(buf);
    return buf[0];
  },

  getSecureRandomUint: function getSecureRandomUint() {
    var buf = new Uint8Array(4);
    var dv = new DataView(buf.buffer);
    this.getRandomValues(buf);
    return dv.getUint32(0);
  },

  /**
   * Helper routine which calls platform specific crypto random generator
   * @param {Uint8Array} buf
   */
  getRandomValues: function getRandomValues(buf) {
    if (!(buf instanceof Uint8Array)) {
      throw new Error('Invalid type: buf not an Uint8Array');
    }
    if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
      window.crypto.getRandomValues(buf);
    } else if (typeof window !== 'undefined' && _typeof(window.msCrypto) === 'object' && typeof window.msCrypto.getRandomValues === 'function') {
      window.msCrypto.getRandomValues(buf);
    } else if (nodeCrypto) {
      var bytes = nodeCrypto.randomBytes(buf.length);
      buf.set(bytes);
    } else if (this.randomBuffer.buffer) {
      this.randomBuffer.get(buf);
    } else {
      throw new Error('No secure random number generator available.');
    }
    return buf;
  },

  /**
   * Create a secure random big integer of bits length
   * @param {Integer} bits Bit length of the MPI to create
   * @return {BigInteger} Resulting big integer
   */
  getRandomBigInteger: function getRandomBigInteger(bits) {
    if (bits < 1) {
      throw new Error('Illegal parameter value: bits < 1');
    }
    var numBytes = Math.floor((bits + 7) / 8);

    var randomBits = _util2.default.Uint8Array2str(this.getRandomBytes(numBytes));
    if (bits % 8 > 0) {

      randomBits = String.fromCharCode(Math.pow(2, bits % 8) - 1 & randomBits.charCodeAt(0)) + randomBits.substring(1);
    }
    var mpi = new _mpi2.default();
    mpi.fromBytes(randomBits);
    return mpi.toBigInteger();
  },

  getRandomBigIntegerInRange: function getRandomBigIntegerInRange(min, max) {
    if (max.compareTo(min) <= 0) {
      throw new Error('Illegal parameter value: max <= min');
    }

    var range = max.subtract(min);
    var r = this.getRandomBigInteger(range.bitLength());
    while (r.compareTo(range) > 0) {
      r = this.getRandomBigInteger(range.bitLength());
    }
    return min.add(r);
  },

  randomBuffer: new RandomBuffer()

};

/**
 * Buffer for secure random numbers
 */

function RandomBuffer() {
  this.buffer = null;
  this.size = null;
}

/**
 * Initialize buffer
 * @param  {Integer} size size of buffer
 */
RandomBuffer.prototype.init = function (size) {
  this.buffer = new Uint8Array(size);
  this.size = 0;
};

/**
 * Concat array of secure random numbers to buffer
 * @param {Uint8Array} buf
 */
RandomBuffer.prototype.set = function (buf) {
  if (!this.buffer) {
    throw new Error('RandomBuffer is not initialized');
  }
  if (!(buf instanceof Uint8Array)) {
    throw new Error('Invalid type: buf not an Uint8Array');
  }
  var freeSpace = this.buffer.length - this.size;
  if (buf.length > freeSpace) {
    buf = buf.subarray(0, freeSpace);
  }
  // set buf with offset old size of buffer
  this.buffer.set(buf, this.size);
  this.size += buf.length;
};

/**
 * Take numbers out of buffer and copy to array
 * @param {Uint8Array} buf the destination array
 */
RandomBuffer.prototype.get = function (buf) {
  if (!this.buffer) {
    throw new Error('RandomBuffer is not initialized');
  }
  if (!(buf instanceof Uint8Array)) {
    throw new Error('Invalid type: buf not an Uint8Array');
  }
  if (this.size < buf.length) {
    throw new Error('Random number buffer depleted');
  }
  for (var i = 0; i < buf.length; i++) {
    buf[i] = this.buffer[--this.size];
    // clear buffer value
    this.buffer[this.size] = 0;
  }
};

},{"../type/mpi.js":68,"../util.js":70,"crypto":"crypto"}],32:[function(_dereq_,module,exports){
/**
 * @requires util
 * @requires crypto/hash
 * @requires crypto/pkcs1
 * @requires crypto/public_key
 * @module crypto/signature */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _util = _dereq_('../util');

var _util2 = _interopRequireDefault(_util);

var _public_key = _dereq_('./public_key');

var _public_key2 = _interopRequireDefault(_public_key);

var _pkcs = _dereq_('./pkcs1.js');

var _pkcs2 = _interopRequireDefault(_pkcs);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = {
  /**
   *
   * @param {module:enums.publicKey} algo public Key algorithm
   * @param {module:enums.hash} hash_algo Hash algorithm
   * @param {Array<module:type/mpi>} msg_MPIs Signature multiprecision integers
   * @param {Array<module:type/mpi>} publickey_MPIs Public key multiprecision integers
   * @param {Uint8Array} data Data on where the signature was computed on.
   * @return {Boolean} true if signature (sig_data was equal to data over hash)
   */
  verify: function verify(algo, hash_algo, msg_MPIs, publickey_MPIs, data) {
    var m;

    data = _util2.default.Uint8Array2str(data);

    switch (algo) {
      case 1:
      // RSA (Encrypt or Sign) [HAC]
      case 2:
      // RSA Encrypt-Only [HAC]
      case 3:
        // RSA Sign-Only [HAC]
        var rsa = new _public_key2.default.rsa();
        var n = publickey_MPIs[0].toBigInteger();
        var k = publickey_MPIs[0].byteLength();
        var e = publickey_MPIs[1].toBigInteger();
        m = msg_MPIs[0].toBigInteger();
        var EM = rsa.verify(m, e, n);
        var EM2 = _pkcs2.default.emsa.encode(hash_algo, data, k);
        return EM.compareTo(EM2) === 0;
      case 16:
        // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
        throw new Error("signing with Elgamal is not defined in the OpenPGP standard.");
      case 17:
        // DSA (Digital Signature Algorithm) [FIPS186] [HAC]
        var dsa = new _public_key2.default.dsa();
        var s1 = msg_MPIs[0].toBigInteger();
        var s2 = msg_MPIs[1].toBigInteger();
        var p = publickey_MPIs[0].toBigInteger();
        var q = publickey_MPIs[1].toBigInteger();
        var g = publickey_MPIs[2].toBigInteger();
        var y = publickey_MPIs[3].toBigInteger();
        m = data;
        var dopublic = dsa.verify(hash_algo, s1, s2, m, p, q, g, y);
        return dopublic.compareTo(s1) === 0;
      default:
        throw new Error('Invalid signature algorithm.');
    }
  },

  /**
   * Create a signature on data using the specified algorithm
   * @param {module:enums.hash} hash_algo hash Algorithm to use (See {@link http://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4})
   * @param {module:enums.publicKey} algo Asymmetric cipher algorithm to use (See {@link http://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1})
   * @param {Array<module:type/mpi>} publicMPIs Public key multiprecision integers
   * of the private key
   * @param {Array<module:type/mpi>} secretMPIs Private key multiprecision
   * integers which is used to sign the data
   * @param {Uint8Array} data Data to be signed
   * @return {Array<module:type/mpi>}
   */
  sign: function sign(hash_algo, algo, keyIntegers, data) {

    data = _util2.default.Uint8Array2str(data);

    var m;

    switch (algo) {
      case 1:
      // RSA (Encrypt or Sign) [HAC]
      case 2:
      // RSA Encrypt-Only [HAC]
      case 3:
        // RSA Sign-Only [HAC]
        var rsa = new _public_key2.default.rsa();
        var d = keyIntegers[2].toBigInteger();
        var n = keyIntegers[0].toBigInteger();
        m = _pkcs2.default.emsa.encode(hash_algo, data, keyIntegers[0].byteLength());
        return _util2.default.str2Uint8Array(rsa.sign(m, d, n).toMPI());

      case 17:
        // DSA (Digital Signature Algorithm) [FIPS186] [HAC]
        var dsa = new _public_key2.default.dsa();

        var p = keyIntegers[0].toBigInteger();
        var q = keyIntegers[1].toBigInteger();
        var g = keyIntegers[2].toBigInteger();
        var x = keyIntegers[4].toBigInteger();
        m = data;
        var result = dsa.sign(hash_algo, m, g, p, q, x);

        return _util2.default.str2Uint8Array(result[0].toString() + result[1].toString());
      case 16:
        // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
        throw new Error('Signing with Elgamal is not defined in the OpenPGP standard.');
      default:
        throw new Error('Invalid signature algorithm.');
    }
  }
};

},{"../util":70,"./pkcs1.js":25,"./public_key":28}],33:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @requires encoding/base64
 * @requires enums
 * @requires config
 * @module encoding/armor
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _base = _dereq_('./base64.js');

var _base2 = _interopRequireDefault(_base);

var _enums = _dereq_('../enums.js');

var _enums2 = _interopRequireDefault(_enums);

var _config = _dereq_('../config');

var _config2 = _interopRequireDefault(_config);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * Finds out which Ascii Armoring type is used. Throws error if unknown type.
 * @private
 * @param {String} text [String] ascii armored text
 * @returns {Integer} 0 = MESSAGE PART n of m
 *         1 = MESSAGE PART n
 *         2 = SIGNED MESSAGE
 *         3 = PGP MESSAGE
 *         4 = PUBLIC KEY BLOCK
 *         5 = PRIVATE KEY BLOCK
 *         6 = SIGNATURE
 */
function getType(text) {
  var reHeader = /^-----BEGIN PGP (MESSAGE, PART \d+\/\d+|MESSAGE, PART \d+|SIGNED MESSAGE|MESSAGE|PUBLIC KEY BLOCK|PRIVATE KEY BLOCK|SIGNATURE)-----$\n/m;

  var header = text.match(reHeader);

  if (!header) {
    throw new Error('Unknown ASCII armor type');
  }

  // BEGIN PGP MESSAGE, PART X/Y
  // Used for multi-part messages, where the armor is split amongst Y
  // parts, and this is the Xth part out of Y.
  if (/MESSAGE, PART \d+\/\d+/.test(header[1])) {
    return _enums2.default.armor.multipart_section;
  } else
    // BEGIN PGP MESSAGE, PART X
    // Used for multi-part messages, where this is the Xth part of an
    // unspecified number of parts. Requires the MESSAGE-ID Armor
    // Header to be used.
    if (/MESSAGE, PART \d+/.test(header[1])) {
      return _enums2.default.armor.multipart_last;
    } else
      // BEGIN PGP SIGNED MESSAGE
      if (/SIGNED MESSAGE/.test(header[1])) {
        return _enums2.default.armor.signed;
      } else
        // BEGIN PGP MESSAGE
        // Used for signed, encrypted, or compressed files.
        if (/MESSAGE/.test(header[1])) {
          return _enums2.default.armor.message;
        } else
          // BEGIN PGP PUBLIC KEY BLOCK
          // Used for armoring public keys.
          if (/PUBLIC KEY BLOCK/.test(header[1])) {
            return _enums2.default.armor.public_key;
          } else
            // BEGIN PGP PRIVATE KEY BLOCK
            // Used for armoring private keys.
            if (/PRIVATE KEY BLOCK/.test(header[1])) {
              return _enums2.default.armor.private_key;
            } else
              // BEGIN PGP SIGNATURE
              // Used for detached signatures, OpenPGP/MIME signatures, and
              // cleartext signatures. Note that PGP 2.x uses BEGIN PGP MESSAGE
              // for detached signatures.
              if (/SIGNATURE/.test(header[1])) {
                return _enums2.default.armor.signature;
              }
}

/**
 * Add additional information to the armor version of an OpenPGP binary
 * packet block.
 * @author  Alex
 * @version 2011-12-16
 * @returns {String} The header information
 */
function addheader() {
  var result = "";
  if (_config2.default.show_version) {
    result += "Version: " + _config2.default.versionstring + '\r\n';
  }
  if (_config2.default.show_comment) {
    result += "Comment: " + _config2.default.commentstring + '\r\n';
  }
  result += '\r\n';
  return result;
}

/**
 * Calculates a checksum over the given data and returns it base64 encoded
 * @param {String} data Data to create a CRC-24 checksum for
 * @return {String} Base64 encoded checksum
 */
function getCheckSum(data) {
  var c = createcrc24(data);
  var bytes = new Uint8Array([c >> 16, c >> 8 & 0xFF, c & 0xFF]);
  return _base2.default.encode(bytes);
}

/**
 * Calculates the checksum over the given data and compares it with the
 * given base64 encoded checksum
 * @param {String} data Data to create a CRC-24 checksum for
 * @param {String} checksum Base64 encoded checksum
 * @return {Boolean} True if the given checksum is correct; otherwise false
 */
function verifyCheckSum(data, checksum) {
  var c = getCheckSum(data);
  var d = checksum;
  return c[0] === d[0] && c[1] === d[1] && c[2] === d[2] && c[3] === d[3];
}
/**
 * Internal function to calculate a CRC-24 checksum over a given string (data)
 * @param {String} data Data to create a CRC-24 checksum for
 * @return {Integer} The CRC-24 checksum as number
 */
var crc_table = [0x00000000, 0x00864cfb, 0x018ad50d, 0x010c99f6, 0x0393e6e1, 0x0315aa1a, 0x021933ec, 0x029f7f17, 0x07a18139, 0x0727cdc2, 0x062b5434, 0x06ad18cf, 0x043267d8, 0x04b42b23, 0x05b8b2d5, 0x053efe2e, 0x0fc54e89, 0x0f430272, 0x0e4f9b84, 0x0ec9d77f, 0x0c56a868, 0x0cd0e493, 0x0ddc7d65, 0x0d5a319e, 0x0864cfb0, 0x08e2834b, 0x09ee1abd, 0x09685646, 0x0bf72951, 0x0b7165aa, 0x0a7dfc5c, 0x0afbb0a7, 0x1f0cd1e9, 0x1f8a9d12, 0x1e8604e4, 0x1e00481f, 0x1c9f3708, 0x1c197bf3, 0x1d15e205, 0x1d93aefe, 0x18ad50d0, 0x182b1c2b, 0x192785dd, 0x19a1c926, 0x1b3eb631, 0x1bb8faca, 0x1ab4633c, 0x1a322fc7, 0x10c99f60, 0x104fd39b, 0x11434a6d, 0x11c50696, 0x135a7981, 0x13dc357a, 0x12d0ac8c, 0x1256e077, 0x17681e59, 0x17ee52a2, 0x16e2cb54, 0x166487af, 0x14fbf8b8, 0x147db443, 0x15712db5, 0x15f7614e, 0x3e19a3d2, 0x3e9fef29, 0x3f9376df, 0x3f153a24, 0x3d8a4533, 0x3d0c09c8, 0x3c00903e, 0x3c86dcc5, 0x39b822eb, 0x393e6e10, 0x3832f7e6, 0x38b4bb1d, 0x3a2bc40a, 0x3aad88f1, 0x3ba11107, 0x3b275dfc, 0x31dced5b, 0x315aa1a0, 0x30563856, 0x30d074ad, 0x324f0bba, 0x32c94741, 0x33c5deb7, 0x3343924c, 0x367d6c62, 0x36fb2099, 0x37f7b96f, 0x3771f594, 0x35ee8a83, 0x3568c678, 0x34645f8e, 0x34e21375, 0x2115723b, 0x21933ec0, 0x209fa736, 0x2019ebcd, 0x228694da, 0x2200d821, 0x230c41d7, 0x238a0d2c, 0x26b4f302, 0x2632bff9, 0x273e260f, 0x27b86af4, 0x252715e3, 0x25a15918, 0x24adc0ee, 0x242b8c15, 0x2ed03cb2, 0x2e567049, 0x2f5ae9bf, 0x2fdca544, 0x2d43da53, 0x2dc596a8, 0x2cc90f5e, 0x2c4f43a5, 0x2971bd8b, 0x29f7f170, 0x28fb6886, 0x287d247d, 0x2ae25b6a, 0x2a641791, 0x2b688e67, 0x2beec29c, 0x7c3347a4, 0x7cb50b5f, 0x7db992a9, 0x7d3fde52, 0x7fa0a145, 0x7f26edbe, 0x7e2a7448, 0x7eac38b3, 0x7b92c69d, 0x7b148a66, 0x7a181390, 0x7a9e5f6b, 0x7801207c, 0x78876c87, 0x798bf571, 0x790db98a, 0x73f6092d, 0x737045d6, 0x727cdc20, 0x72fa90db, 0x7065efcc, 0x70e3a337, 0x71ef3ac1, 0x7169763a, 0x74578814, 0x74d1c4ef, 0x75dd5d19, 0x755b11e2, 0x77c46ef5, 0x7742220e, 0x764ebbf8, 0x76c8f703, 0x633f964d, 0x63b9dab6, 0x62b54340, 0x62330fbb, 0x60ac70ac, 0x602a3c57, 0x6126a5a1, 0x61a0e95a, 0x649e1774, 0x64185b8f, 0x6514c279, 0x65928e82, 0x670df195, 0x678bbd6e, 0x66872498, 0x66016863, 0x6cfad8c4, 0x6c7c943f, 0x6d700dc9, 0x6df64132, 0x6f693e25, 0x6fef72de, 0x6ee3eb28, 0x6e65a7d3, 0x6b5b59fd, 0x6bdd1506, 0x6ad18cf0, 0x6a57c00b, 0x68c8bf1c, 0x684ef3e7, 0x69426a11, 0x69c426ea, 0x422ae476, 0x42aca88d, 0x43a0317b, 0x43267d80, 0x41b90297, 0x413f4e6c, 0x4033d79a, 0x40b59b61, 0x458b654f, 0x450d29b4, 0x4401b042, 0x4487fcb9, 0x461883ae, 0x469ecf55, 0x479256a3, 0x47141a58, 0x4defaaff, 0x4d69e604, 0x4c657ff2, 0x4ce33309, 0x4e7c4c1e, 0x4efa00e5, 0x4ff69913, 0x4f70d5e8, 0x4a4e2bc6, 0x4ac8673d, 0x4bc4fecb, 0x4b42b230, 0x49ddcd27, 0x495b81dc, 0x4857182a, 0x48d154d1, 0x5d26359f, 0x5da07964, 0x5cace092, 0x5c2aac69, 0x5eb5d37e, 0x5e339f85, 0x5f3f0673, 0x5fb94a88, 0x5a87b4a6, 0x5a01f85d, 0x5b0d61ab, 0x5b8b2d50, 0x59145247, 0x59921ebc, 0x589e874a, 0x5818cbb1, 0x52e37b16, 0x526537ed, 0x5369ae1b, 0x53efe2e0, 0x51709df7, 0x51f6d10c, 0x50fa48fa, 0x507c0401, 0x5542fa2f, 0x55c4b6d4, 0x54c82f22, 0x544e63d9, 0x56d11cce, 0x56575035, 0x575bc9c3, 0x57dd8538];

function createcrc24(input) {
  var crc = 0xB704CE;

  for (var index = 0; index < input.length; index++) {
    crc = crc << 8 ^ crc_table[(crc >> 16 ^ input[index]) & 0xff];
  }
  return crc & 0xffffff;
}

/**
 * Splits a message into two parts, the headers and the body. This is an internal function
 * @param {String} text OpenPGP armored message part
 * @returns {Object} An object with attribute "headers" containing the headers
 * and an attribute "body" containing the body.
 */
function splitHeaders(text) {
  // empty line with whitespace characters
  var reEmptyLine = /^[ \f\r\t\u00a0\u2000-\u200a\u202f\u205f\u3000]*\n/m;
  var headers = '';
  var body = text;

  var matchResult = reEmptyLine.exec(text);

  if (matchResult !== null) {
    headers = text.slice(0, matchResult.index);
    body = text.slice(matchResult.index + matchResult[0].length);
  } else {
    throw new Error('Mandatory blank line missing between armor headers and armor data');
  }

  headers = headers.split('\n');
  // remove empty entry
  headers.pop();

  return { headers: headers, body: body };
}

/**
 * Verify armored headers. RFC4880, section 6.3: "OpenPGP should consider improperly formatted
 * Armor Headers to be corruption of the ASCII Armor."
 * @private
 * @param  {Array<String>} headers Armor headers
 */
function verifyHeaders(headers) {
  for (var i = 0; i < headers.length; i++) {
    if (!/^[^:\s]+: .+$/.test(headers[i])) {
      throw new Error('Improperly formatted armor header: ' + headers[i]);
    }
    if (_config2.default.debug && !/^(Version|Comment|MessageID|Hash|Charset): .+$/.test(headers[i])) {
      console.log('Unknown header: ' + headers[i]);
    }
  }
}

/**
 * Splits a message into two parts, the body and the checksum. This is an internal function
 * @param {String} text OpenPGP armored message part
 * @returns {Object} An object with attribute "body" containing the body
 * and an attribute "checksum" containing the checksum.
 */
function splitChecksum(text) {
  text = text.trim();
  var body = text;
  var checksum = "";

  var lastEquals = text.lastIndexOf("=");

  if (lastEquals >= 0 && lastEquals !== text.length - 1) {
    // '=' as the last char means no checksum
    body = text.slice(0, lastEquals);
    checksum = text.slice(lastEquals + 1).substr(0, 4);
  }

  return { body: body, checksum: checksum };
}

/**
 * DeArmor an OpenPGP armored message; verify the checksum and return
 * the encoded bytes
 * @param {String} text OpenPGP armored message
 * @returns {Object} An object with attribute "text" containing the message text,
 * an attribute "data" containing the bytes and "type" for the ASCII armor type
 * @static
 */
function dearmor(text) {
  var reSplit = /^-----[^-]+-----$\n/m;

  // remove trailing whitespace at end of line
  text = text.replace(/[\t\r ]+\n/g, '\n');

  var type = getType(text);

  text = text.trim() + "\n";
  var splittext = text.split(reSplit);

  // IE has a bug in split with a re. If the pattern matches the beginning of the
  // string it doesn't create an empty array element 0. So we need to detect this
  // so we know the index of the data we are interested in.
  var indexBase = 1;

  var result, checksum, msg;

  if (text.search(reSplit) !== splittext[0].length) {
    indexBase = 0;
  }

  if (type !== 2) {
    msg = splitHeaders(splittext[indexBase]);
    var msg_sum = splitChecksum(msg.body);

    result = {
      data: _base2.default.decode(msg_sum.body),
      headers: msg.headers,
      type: type
    };

    checksum = msg_sum.checksum;
  } else {
    // Reverse dash-escaping for msg
    msg = splitHeaders(splittext[indexBase].replace(/^- /mg, ''));
    var sig = splitHeaders(splittext[indexBase + 1].replace(/^- /mg, ''));
    verifyHeaders(sig.headers);
    var sig_sum = splitChecksum(sig.body);

    result = {
      text: msg.body.replace(/\n$/, '').replace(/\n/g, "\r\n"),
      data: _base2.default.decode(sig_sum.body),
      headers: msg.headers,
      type: type
    };

    checksum = sig_sum.checksum;
  }

  if (!verifyCheckSum(result.data, checksum) && (checksum || _config2.default.checksum_required)) {
    // will NOT throw error if checksum is empty AND checksum is not required (GPG compatibility)
    throw new Error("Ascii armor integrity check on message failed: '" + checksum + "' should be '" + getCheckSum(result.data) + "'");
  }

  verifyHeaders(result.headers);

  return result;
}

/**
 * Armor an OpenPGP binary packet block
 * @param {Integer} messagetype type of the message
 * @param body
 * @param {Integer} partindex
 * @param {Integer} parttotal
 * @returns {String} Armored text
 * @static
 */
function armor(messagetype, body, partindex, parttotal) {
  var result = [];
  switch (messagetype) {
    case _enums2.default.armor.multipart_section:
      result.push("-----BEGIN PGP MESSAGE, PART " + partindex + "/" + parttotal + "-----\r\n");
      result.push(addheader());
      result.push(_base2.default.encode(body));
      result.push("\r\n=" + getCheckSum(body) + "\r\n");
      result.push("-----END PGP MESSAGE, PART " + partindex + "/" + parttotal + "-----\r\n");
      break;
    case _enums2.default.armor.multipart_last:
      result.push("-----BEGIN PGP MESSAGE, PART " + partindex + "-----\r\n");
      result.push(addheader());
      result.push(_base2.default.encode(body));
      result.push("\r\n=" + getCheckSum(body) + "\r\n");
      result.push("-----END PGP MESSAGE, PART " + partindex + "-----\r\n");
      break;
    case _enums2.default.armor.signed:
      result.push("\r\n-----BEGIN PGP SIGNED MESSAGE-----\r\n");
      result.push("Hash: " + body.hash + "\r\n\r\n");
      result.push(body.text.replace(/\n-/g, "\n- -"));
      result.push("\r\n-----BEGIN PGP SIGNATURE-----\r\n");
      result.push(addheader());
      result.push(_base2.default.encode(body.data));
      result.push("\r\n=" + getCheckSum(body.data) + "\r\n");
      result.push("-----END PGP SIGNATURE-----\r\n");
      break;
    case _enums2.default.armor.message:
      result.push("-----BEGIN PGP MESSAGE-----\r\n");
      result.push(addheader());
      result.push(_base2.default.encode(body));
      result.push("\r\n=" + getCheckSum(body) + "\r\n");
      result.push("-----END PGP MESSAGE-----\r\n");
      break;
    case _enums2.default.armor.public_key:
      result.push("-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n");
      result.push(addheader());
      result.push(_base2.default.encode(body));
      result.push("\r\n=" + getCheckSum(body) + "\r\n");
      result.push("-----END PGP PUBLIC KEY BLOCK-----\r\n\r\n");
      break;
    case _enums2.default.armor.private_key:
      result.push("-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n");
      result.push(addheader());
      result.push(_base2.default.encode(body));
      result.push("\r\n=" + getCheckSum(body) + "\r\n");
      result.push("-----END PGP PRIVATE KEY BLOCK-----\r\n");
      break;
    case _enums2.default.armor.signature:
      result.push("-----BEGIN PGP SIGNATURE-----\r\n");
      result.push(addheader());
      result.push(_base2.default.encode(body));
      result.push("\r\n=" + getCheckSum(body) + "\r\n");
      result.push("-----END PGP SIGNATURE-----\r\n");
      break;
  }

  return result.join('');
}

exports.default = {
  encode: armor,
  decode: dearmor
};

},{"../config":10,"../enums.js":35,"./base64.js":34}],34:[function(_dereq_,module,exports){
/* OpenPGP radix-64/base64 string encoding/decoding
 * Copyright 2005 Herbert Hanewinkel, www.haneWIN.de
 * version 1.0, check www.haneWIN.de for the latest version
 *
 * This software is provided as-is, without express or implied warranty.
 * Permission to use, copy, modify, distribute or sell this software, with or
 * without fee, for any purpose and by any individual or organization, is hereby
 * granted, provided that the above copyright notice and this paragraph appear
 * in all copies. Distribution as a part of an application or binary must
 * include the above copyright notice in the documentation and/or other materials
 * provided with the application or distribution.
 */

/**
 * @module encoding/base64
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
var b64s = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/**
 * Convert binary array to radix-64
 * @param {Uint8Array} t Uint8Array to convert
 * @returns {string} radix-64 version of input string
 * @static
 */
function s2r(t, o) {
  // TODO check btoa alternative
  var a, c, n;
  var r = o ? o : [],
      l = 0,
      s = 0;
  var tl = t.length;

  for (n = 0; n < tl; n++) {
    c = t[n];
    if (s === 0) {
      r.push(b64s.charAt(c >> 2 & 63));
      a = (c & 3) << 4;
    } else if (s === 1) {
      r.push(b64s.charAt(a | c >> 4 & 15));
      a = (c & 15) << 2;
    } else if (s === 2) {
      r.push(b64s.charAt(a | c >> 6 & 3));
      l += 1;
      if (l % 60 === 0) {
        r.push("\n");
      }
      r.push(b64s.charAt(c & 63));
    }
    l += 1;
    if (l % 60 === 0) {
      r.push("\n");
    }

    s += 1;
    if (s === 3) {
      s = 0;
    }
  }
  if (s > 0) {
    r.push(b64s.charAt(a));
    l += 1;
    if (l % 60 === 0) {
      r.push("\n");
    }
    r.push('=');
    l += 1;
  }
  if (s === 1) {
    if (l % 60 === 0) {
      r.push("\n");
    }
    r.push('=');
  }
  if (o) {
    return;
  }
  return r.join('');
}

/**
 * Convert radix-64 to binary array
 * @param {String} t radix-64 string to convert
 * @returns {Uint8Array} binary array version of input string
 * @static
 */
function r2s(t) {
  // TODO check atob alternative
  var c, n;
  var r = [],
      s = 0,
      a = 0;
  var tl = t.length;

  for (n = 0; n < tl; n++) {
    c = b64s.indexOf(t.charAt(n));
    if (c >= 0) {
      if (s) {
        r.push(a | c >> 6 - s & 255);
      }
      s = s + 2 & 7;
      a = c << s & 255;
    }
  }
  return new Uint8Array(r);
}

exports.default = {
  encode: s2r,
  decode: r2s
};

},{}],35:[function(_dereq_,module,exports){
'use strict';

/**
 * @module enums
 */

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = {

  /** A string to key specifier type
   * @enum {Integer}
   * @readonly
   */
  s2k: {
    simple: 0,
    salted: 1,
    iterated: 3,
    gnu: 101
  },

  /** {@link http://tools.ietf.org/html/rfc4880#section-9.1|RFC4880, section 9.1}
   * @enum {Integer}
   * @readonly
   */
  publicKey: {
    rsa_encrypt_sign: 1,
    rsa_encrypt: 2,
    rsa_sign: 3,
    elgamal: 16,
    dsa: 17
  },

  /** {@link http://tools.ietf.org/html/rfc4880#section-9.2|RFC4880, section 9.2}
   * @enum {Integer}
   * @readonly
   */
  symmetric: {
    plaintext: 0,
    /** Not implemented! */
    idea: 1,
    tripledes: 2,
    cast5: 3,
    blowfish: 4,
    aes128: 7,
    aes192: 8,
    aes256: 9,
    twofish: 10
  },

  /** {@link http://tools.ietf.org/html/rfc4880#section-9.3|RFC4880, section 9.3}
   * @enum {Integer}
   * @readonly
   */
  compression: {
    uncompressed: 0,
    /** RFC1951 */
    zip: 1,
    /** RFC1950 */
    zlib: 2,
    bzip2: 3
  },

  /** {@link http://tools.ietf.org/html/rfc4880#section-9.4|RFC4880, section 9.4}
   * @enum {Integer}
   * @readonly
   */
  hash: {
    md5: 1,
    sha1: 2,
    ripemd: 3,
    sha256: 8,
    sha384: 9,
    sha512: 10,
    sha224: 11
  },

  /** A list of packet types and numeric tags associated with them.
   * @enum {Integer}
   * @readonly
   */
  packet: {
    publicKeyEncryptedSessionKey: 1,
    signature: 2,
    symEncryptedSessionKey: 3,
    onePassSignature: 4,
    secretKey: 5,
    publicKey: 6,
    secretSubkey: 7,
    compressed: 8,
    symmetricallyEncrypted: 9,
    marker: 10,
    literal: 11,
    trust: 12,
    userid: 13,
    publicSubkey: 14,
    userAttribute: 17,
    symEncryptedIntegrityProtected: 18,
    modificationDetectionCode: 19,
    symEncryptedAEADProtected: 20 // see IETF draft: https://tools.ietf.org/html/draft-ford-openpgp-format-00#section-2.1
  },

  /** Data types in the literal packet
   * @enum {Integer}
   * @readonly
   */
  literal: {
    /** Binary data 'b' */
    binary: 'b'.charCodeAt(),
    /** Text data 't' */
    text: 't'.charCodeAt(),
    /** Utf8 data 'u' */
    utf8: 'u'.charCodeAt()
  },

  /** One pass signature packet type
   * @enum {Integer}
   * @readonly
   */
  signature: {
    /** 0x00: Signature of a binary document. */
    binary: 0,
    /** 0x01: Signature of a canonical text document.<br/>
     * Canonicalyzing the document by converting line endings. */
    text: 1,
    /** 0x02: Standalone signature.<br/>
     * This signature is a signature of only its own subpacket contents.
     * It is calculated identically to a signature over a zero-lengh
     * binary document.  Note that it doesn't make sense to have a V3
     * standalone signature. */
    standalone: 2,
    /** 0x10: Generic certification of a User ID and Public-Key packet.<br/>
     * The issuer of this certification does not make any particular
     * assertion as to how well the certifier has checked that the owner
     * of the key is in fact the person described by the User ID. */
    cert_generic: 16,
    /** 0x11: Persona certification of a User ID and Public-Key packet.<br/>
     * The issuer of this certification has not done any verification of
     * the claim that the owner of this key is the User ID specified. */
    cert_persona: 17,
    /** 0x12: Casual certification of a User ID and Public-Key packet.<br/>
     * The issuer of this certification has done some casual
     * verification of the claim of identity. */
    cert_casual: 18,
    /** 0x13: Positive certification of a User ID and Public-Key packet.<br/>
     * The issuer of this certification has done substantial
     * verification of the claim of identity.<br/>
     * <br/>
     * Most OpenPGP implementations make their "key signatures" as 0x10
     * certifications.  Some implementations can issue 0x11-0x13
     * certifications, but few differentiate between the types. */
    cert_positive: 19,
    /** 0x30: Certification revocation signature<br/>
     * This signature revokes an earlier User ID certification signature
     * (signature class 0x10 through 0x13) or direct-key signature
     * (0x1F).  It should be issued by the same key that issued the
     * revoked signature or an authorized revocation key.  The signature
     * is computed over the same data as the certificate that it
     * revokes, and should have a later creation date than that
     * certificate. */
    cert_revocation: 48,
    /** 0x18: Subkey Binding Signature<br/>
     * This signature is a statement by the top-level signing key that
     * indicates that it owns the subkey.  This signature is calculated
     * directly on the primary key and subkey, and not on any User ID or
     * other packets.  A signature that binds a signing subkey MUST have
     * an Embedded Signature subpacket in this binding signature that
     * contains a 0x19 signature made by the signing subkey on the
     * primary key and subkey. */
    subkey_binding: 24,
    /** 0x19: Primary Key Binding Signature<br/>
     * This signature is a statement by a signing subkey, indicating
     * that it is owned by the primary key and subkey.  This signature
     * is calculated the same way as a 0x18 signature: directly on the
     * primary key and subkey, and not on any User ID or other packets.<br/>
     * <br/>
     * When a signature is made over a key, the hash data starts with the
     * octet 0x99, followed by a two-octet length of the key, and then body
     * of the key packet.  (Note that this is an old-style packet header for
     * a key packet with two-octet length.)  A subkey binding signature
     * (type 0x18) or primary key binding signature (type 0x19) then hashes
     * the subkey using the same format as the main key (also using 0x99 as
     * the first octet). */
    key_binding: 25,
    /** 0x1F: Signature directly on a key<br/>
     * This signature is calculated directly on a key.  It binds the
     * information in the Signature subpackets to the key, and is
     * appropriate to be used for subpackets that provide information
     * about the key, such as the Revocation Key subpacket.  It is also
     * appropriate for statements that non-self certifiers want to make
     * about the key itself, rather than the binding between a key and a
     * name. */
    key: 31,
    /** 0x20: Key revocation signature<br/>
     * The signature is calculated directly on the key being revoked.  A
     * revoked key is not to be used.  Only revocation signatures by the
     * key being revoked, or by an authorized revocation key, should be
     * considered valid revocation signatures.a */
    key_revocation: 32,
    /** 0x28: Subkey revocation signature<br/>
     * The signature is calculated directly on the subkey being revoked.
     * A revoked subkey is not to be used.  Only revocation signatures
     * by the top-level signature key that is bound to this subkey, or
     * by an authorized revocation key, should be considered valid
     * revocation signatures.<br/>
     * <br/>
     * Key revocation signatures (types 0x20 and 0x28)
     * hash only the key being revoked. */
    subkey_revocation: 40,
    /** 0x40: Timestamp signature.<br/>
     * This signature is only meaningful for the timestamp contained in
     * it. */
    timestamp: 64,
    /** 0x50: Third-Party Confirmation signature.<br/>
     * This signature is a signature over some other OpenPGP Signature
     * packet(s).  It is analogous to a notary seal on the signed data.
     * A third-party signature SHOULD include Signature Target
     * subpacket(s) to give easy identification.  Note that we really do
     * mean SHOULD.  There are plausible uses for this (such as a blind
     * party that only sees the signature, not the key or source
     * document) that cannot include a target subpacket. */
    third_party: 80
  },

  /** Signature subpacket type
   * @enum {Integer}
   * @readonly
   */
  signatureSubpacket: {
    signature_creation_time: 2,
    signature_expiration_time: 3,
    exportable_certification: 4,
    trust_signature: 5,
    regular_expression: 6,
    revocable: 7,
    key_expiration_time: 9,
    placeholder_backwards_compatibility: 10,
    preferred_symmetric_algorithms: 11,
    revocation_key: 12,
    issuer: 16,
    notation_data: 20,
    preferred_hash_algorithms: 21,
    preferred_compression_algorithms: 22,
    key_server_preferences: 23,
    preferred_key_server: 24,
    primary_user_id: 25,
    policy_uri: 26,
    key_flags: 27,
    signers_user_id: 28,
    reason_for_revocation: 29,
    features: 30,
    signature_target: 31,
    embedded_signature: 32
  },

  /** Key flags
   * @enum {Integer}
   * @readonly
   */
  keyFlags: {
    /** 0x01 - This key may be used to certify other keys. */
    certify_keys: 1,
    /** 0x02 - This key may be used to sign data. */
    sign_data: 2,
    /** 0x04 - This key may be used to encrypt communications. */
    encrypt_communication: 4,
    /** 0x08 - This key may be used to encrypt storage. */
    encrypt_storage: 8,
    /** 0x10 - The private component of this key may have been split
     *        by a secret-sharing mechanism. */
    split_private_key: 16,
    /** 0x20 - This key may be used for authentication. */
    authentication: 32,
    /** 0x80 - The private component of this key may be in the
     *        possession of more than one person. */
    shared_private_key: 128
  },

  /** Key status
   * @enum {Integer}
   * @readonly
   */
  keyStatus: {
    invalid: 0,
    expired: 1,
    revoked: 2,
    valid: 3,
    no_self_cert: 4
  },

  /** Armor type
   * @enum {Integer}
   * @readonly
   */
  armor: {
    multipart_section: 0,
    multipart_last: 1,
    signed: 2,
    message: 3,
    public_key: 4,
    private_key: 5,
    signature: 6
  },

  /** Asserts validity and converts from string/integer to integer. */
  write: function write(type, e) {
    if (typeof e === 'number') {
      e = this.read(type, e);
    }

    if (type[e] !== undefined) {
      return type[e];
    } else {
      throw new Error('Invalid enum value.');
    }
  },

  /** Converts from an integer to string. */
  read: function read(type, e) {
    for (var i in type) {
      if (type[i] === parseInt(e)) {
        return i;
      }
    }

    throw new Error('Invalid enum value.');
  }

};

},{}],36:[function(_dereq_,module,exports){
// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2015 Tankred Hase
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @fileoverview This class implements a client for the OpenPGP HTTP Keyserver Protocol (HKP)
 * in order to lookup and upload keys on standard public key servers.
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = HKP;

var _config = _dereq_('./config');

var _config2 = _interopRequireDefault(_config);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * Initialize the HKP client and configure it with the key server url and fetch function.
 * @constructor
 * @param {String}    keyServerBaseUrl  (optional) The HKP key server base url including
 *   the protocol to use e.g. https://pgp.mit.edu
 */
function HKP(keyServerBaseUrl) {
  this._baseUrl = keyServerBaseUrl ? keyServerBaseUrl : _config2.default.keyserver;
  this._fetch = typeof window !== 'undefined' ? window.fetch : _dereq_('node-fetch');
}

/**
 * Search for a public key on the key server either by key ID or part of the user ID.
 * @param  {String}   options.keyID   The long public key ID.
 * @param  {String}   options.query   This can be any part of the key user ID such as name
 *   or email address.
 * @return {Promise<String>}          The ascii armored public key.
 */
HKP.prototype.lookup = function (options) {
  var uri = this._baseUrl + '/pks/lookup?op=get&options=mr&search=',
      fetch = this._fetch;

  if (options.keyId) {
    uri += '0x' + encodeURIComponent(options.keyId);
  } else if (options.query) {
    uri += encodeURIComponent(options.query);
  } else {
    throw new Error('You must provide a query parameter!');
  }

  return fetch(uri).then(function (response) {
    if (response.status === 200) {
      return response.text();
    }
  }).then(function (publicKeyArmored) {
    if (!publicKeyArmored || publicKeyArmored.indexOf('-----END PGP PUBLIC KEY BLOCK-----') < 0) {
      return;
    }
    return publicKeyArmored.trim();
  });
};

/**
 * Upload a public key to the server.
 * @param  {String}   publicKeyArmored  An ascii armored public key to be uploaded.
 * @return {Promise}
 */
HKP.prototype.upload = function (publicKeyArmored) {
  var uri = this._baseUrl + '/pks/add',
      fetch = this._fetch;

  return fetch(uri, {
    method: 'post',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
    },
    body: 'keytext=' + encodeURIComponent(publicKeyArmored)
  });
};

},{"./config":10,"node-fetch":"node-fetch"}],37:[function(_dereq_,module,exports){
'use strict';

/**
 * Export high level api as default.
 * Usage:
 *
 *   import openpgp from 'openpgp.js'
 *   openpgp.encryptMessage(keys, text)
 */

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.HKP = exports.AsyncProxy = exports.Keyring = exports.crypto = exports.config = exports.enums = exports.armor = exports.Keyid = exports.S2K = exports.MPI = exports.packet = exports.util = exports.cleartext = exports.message = exports.signature = exports.key = undefined;

var _openpgp = _dereq_('./openpgp');

Object.keys(_openpgp).forEach(function (key) {
  if (key === "default") return;
  Object.defineProperty(exports, key, {
    enumerable: true,
    get: function get() {
      return _openpgp[key];
    }
  });
});

var _util = _dereq_('./util');

Object.defineProperty(exports, 'util', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_util).default;
  }
});

var _packet = _dereq_('./packet');

Object.defineProperty(exports, 'packet', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_packet).default;
  }
});

var _mpi = _dereq_('./type/mpi');

Object.defineProperty(exports, 'MPI', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_mpi).default;
  }
});

var _s2k = _dereq_('./type/s2k');

Object.defineProperty(exports, 'S2K', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_s2k).default;
  }
});

var _keyid = _dereq_('./type/keyid');

Object.defineProperty(exports, 'Keyid', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_keyid).default;
  }
});

var _armor = _dereq_('./encoding/armor');

Object.defineProperty(exports, 'armor', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_armor).default;
  }
});

var _enums = _dereq_('./enums');

Object.defineProperty(exports, 'enums', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_enums).default;
  }
});

var _config = _dereq_('./config/config');

Object.defineProperty(exports, 'config', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_config).default;
  }
});

var _crypto = _dereq_('./crypto');

Object.defineProperty(exports, 'crypto', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_crypto).default;
  }
});

var _keyring = _dereq_('./keyring');

Object.defineProperty(exports, 'Keyring', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_keyring).default;
  }
});

var _async_proxy = _dereq_('./worker/async_proxy');

Object.defineProperty(exports, 'AsyncProxy', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_async_proxy).default;
  }
});

var _hkp = _dereq_('./hkp');

Object.defineProperty(exports, 'HKP', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_hkp).default;
  }
});

var openpgp = _interopRequireWildcard(_openpgp);

var _key = _dereq_('./key');

var keyMod = _interopRequireWildcard(_key);

var _signature = _dereq_('./signature');

var signatureMod = _interopRequireWildcard(_signature);

var _message = _dereq_('./message');

var messageMod = _interopRequireWildcard(_message);

var _cleartext = _dereq_('./cleartext');

var cleartextMod = _interopRequireWildcard(_cleartext);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = openpgp;

/**
 * Export each high level api function seperately.
 * Usage:
 *
 *   import { encryptMessage } from 'openpgp.js'
 *   encryptMessage(keys, text)
 */


/**
 * @see module:key
 * @name module:openpgp.key
 */

var key = exports.key = keyMod;

/**
 * @see module:signature
 * @name module:openpgp.signature
 */
var signature = exports.signature = signatureMod;

/**
 * @see module:message
 * @name module:openpgp.message
 */
var message = exports.message = messageMod;

/**
 * @see module:cleartext
 * @name module:openpgp.cleartext
 */
var cleartext = exports.cleartext = cleartextMod;

/**
 * @see module:util
 * @name module:openpgp.util
 */

},{"./cleartext":5,"./config/config":9,"./crypto":24,"./encoding/armor":33,"./enums":35,"./hkp":36,"./key":38,"./keyring":39,"./message":42,"./openpgp":43,"./packet":47,"./signature":66,"./type/keyid":67,"./type/mpi":68,"./type/s2k":69,"./util":70,"./worker/async_proxy":71}],38:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @requires config
 * @requires encoding/armor
 * @requires enums
 * @requires packet
 * @module key
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.Key = Key;
exports.read = read;
exports.readArmored = readArmored;
exports.generate = generate;
exports.reformat = reformat;
exports.getPreferredSymAlgo = getPreferredSymAlgo;

var _packet = _dereq_('./packet');

var _packet2 = _interopRequireDefault(_packet);

var _enums = _dereq_('./enums.js');

var _enums2 = _interopRequireDefault(_enums);

var _armor = _dereq_('./encoding/armor.js');

var _armor2 = _interopRequireDefault(_armor);

var _config = _dereq_('./config');

var _config2 = _interopRequireDefault(_config);

var _util = _dereq_('./util');

var _util2 = _interopRequireDefault(_util);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @class
 * @classdesc Class that represents an OpenPGP key. Must contain a primary key.
 * Can contain additional subkeys, signatures, user ids, user attributes.
 * @param  {module:packet/packetlist} packetlist The packets that form this key
 */

function Key(packetlist) {
  if (!(this instanceof Key)) {
    return new Key(packetlist);
  }
  // same data as in packetlist but in structured form
  this.primaryKey = null;
  this.revocationSignature = null;
  this.directSignatures = null;
  this.users = null;
  this.subKeys = null;
  this.packetlist2structure(packetlist);
  if (!this.primaryKey || !this.users) {
    throw new Error('Invalid key: need at least key and user ID packet');
  }
}

/**
 * Transforms packetlist to structured key data
 * @param  {module:packet/packetlist} packetlist The packets that form a key
 */
Key.prototype.packetlist2structure = function (packetlist) {
  var user, primaryKeyId, subKey;
  for (var i = 0; i < packetlist.length; i++) {
    switch (packetlist[i].tag) {
      case _enums2.default.packet.publicKey:
      case _enums2.default.packet.secretKey:
        this.primaryKey = packetlist[i];
        primaryKeyId = this.primaryKey.getKeyId();
        break;
      case _enums2.default.packet.userid:
      case _enums2.default.packet.userAttribute:
        user = new User(packetlist[i]);
        if (!this.users) {
          this.users = [];
        }
        this.users.push(user);
        break;
      case _enums2.default.packet.publicSubkey:
      case _enums2.default.packet.secretSubkey:
        user = null;
        if (!this.subKeys) {
          this.subKeys = [];
        }
        subKey = new SubKey(packetlist[i]);
        this.subKeys.push(subKey);
        break;
      case _enums2.default.packet.signature:
        switch (packetlist[i].signatureType) {
          case _enums2.default.signature.cert_generic:
          case _enums2.default.signature.cert_persona:
          case _enums2.default.signature.cert_casual:
          case _enums2.default.signature.cert_positive:
            if (!user) {
              _util2.default.print_debug('Dropping certification signatures without preceding user packet');
              continue;
            }
            if (packetlist[i].issuerKeyId.equals(primaryKeyId)) {
              if (!user.selfCertifications) {
                user.selfCertifications = [];
              }
              user.selfCertifications.push(packetlist[i]);
            } else {
              if (!user.otherCertifications) {
                user.otherCertifications = [];
              }
              user.otherCertifications.push(packetlist[i]);
            }
            break;
          case _enums2.default.signature.cert_revocation:
            if (user) {
              if (!user.revocationCertifications) {
                user.revocationCertifications = [];
              }
              user.revocationCertifications.push(packetlist[i]);
            } else {
              if (!this.directSignatures) {
                this.directSignatures = [];
              }
              this.directSignatures.push(packetlist[i]);
            }
            break;
          case _enums2.default.signature.key:
            if (!this.directSignatures) {
              this.directSignatures = [];
            }
            this.directSignatures.push(packetlist[i]);
            break;
          case _enums2.default.signature.subkey_binding:
            if (!subKey) {
              _util2.default.print_debug('Dropping subkey binding signature without preceding subkey packet');
              continue;
            }
            subKey.bindingSignatures.push(packetlist[i]);
            break;
          case _enums2.default.signature.key_revocation:
            this.revocationSignature = packetlist[i];
            break;
          case _enums2.default.signature.subkey_revocation:
            if (!subKey) {
              _util2.default.print_debug('Dropping subkey revocation signature without preceding subkey packet');
              continue;
            }
            subKey.revocationSignature = packetlist[i];
            break;
        }
        break;
    }
  }
};

/**
 * Transforms structured key data to packetlist
 * @return {module:packet/packetlist} The packets that form a key
 */
Key.prototype.toPacketlist = function () {
  var packetlist = new _packet2.default.List();
  packetlist.push(this.primaryKey);
  packetlist.push(this.revocationSignature);
  packetlist.concat(this.directSignatures);
  var i;
  for (i = 0; i < this.users.length; i++) {
    packetlist.concat(this.users[i].toPacketlist());
  }
  if (this.subKeys) {
    for (i = 0; i < this.subKeys.length; i++) {
      packetlist.concat(this.subKeys[i].toPacketlist());
    }
  }
  return packetlist;
};

/**
 * Returns all the private and public subkey packets
 * @returns {Array<(module:packet/public_subkey|module:packet/secret_subkey)>}
 */
Key.prototype.getSubkeyPackets = function () {
  var subKeys = [];
  if (this.subKeys) {
    for (var i = 0; i < this.subKeys.length; i++) {
      subKeys.push(this.subKeys[i].subKey);
    }
  }
  return subKeys;
};

/**
 * Returns all the private and public key and subkey packets
 * @returns {Array<(module:packet/public_subkey|module:packet/secret_subkey|module:packet/secret_key|module:packet/public_key)>}
 */
Key.prototype.getAllKeyPackets = function () {
  return [this.primaryKey].concat(this.getSubkeyPackets());
};

/**
 * Returns key IDs of all key packets
 * @returns {Array<module:type/keyid>}
 */
Key.prototype.getKeyIds = function () {
  var keyIds = [];
  var keys = this.getAllKeyPackets();
  for (var i = 0; i < keys.length; i++) {
    keyIds.push(keys[i].getKeyId());
  }
  return keyIds;
};

/**
 * Returns first key packet for given array of key IDs
 * @param  {Array<module:type/keyid>} keyIds
 * @return {(module:packet/public_subkey|module:packet/public_key|
 *           module:packet/secret_subkey|module:packet/secret_key|null)}
 */
Key.prototype.getKeyPacket = function (keyIds) {
  var keys = this.getAllKeyPackets();
  for (var i = 0; i < keys.length; i++) {
    var keyId = keys[i].getKeyId();
    for (var j = 0; j < keyIds.length; j++) {
      if (keyId.equals(keyIds[j])) {
        return keys[i];
      }
    }
  }
  return null;
};

/**
 * Returns userids
 * @return {Array<string>} array of userids
 */
Key.prototype.getUserIds = function () {
  var userids = [];
  for (var i = 0; i < this.users.length; i++) {
    if (this.users[i].userId) {
      userids.push(_util2.default.Uint8Array2str(this.users[i].userId.write()));
    }
  }
  return userids;
};

/**
 * Returns true if this is a public key
 * @return {Boolean}
 */
Key.prototype.isPublic = function () {
  return this.primaryKey.tag === _enums2.default.packet.publicKey;
};

/**
 * Returns true if this is a private key
 * @return {Boolean}
 */
Key.prototype.isPrivate = function () {
  return this.primaryKey.tag === _enums2.default.packet.secretKey;
};

/**
 * Returns key as public key (shallow copy)
 * @return {module:key~Key} new public Key
 */
Key.prototype.toPublic = function () {
  var packetlist = new _packet2.default.List();
  var keyPackets = this.toPacketlist();
  var bytes;
  for (var i = 0; i < keyPackets.length; i++) {
    switch (keyPackets[i].tag) {
      case _enums2.default.packet.secretKey:
        bytes = keyPackets[i].writePublicKey();
        var pubKeyPacket = new _packet2.default.PublicKey();
        pubKeyPacket.read(bytes);
        packetlist.push(pubKeyPacket);
        break;
      case _enums2.default.packet.secretSubkey:
        bytes = keyPackets[i].writePublicKey();
        var pubSubkeyPacket = new _packet2.default.PublicSubkey();
        pubSubkeyPacket.read(bytes);
        packetlist.push(pubSubkeyPacket);
        break;
      default:
        packetlist.push(keyPackets[i]);
    }
  }
  return new Key(packetlist);
};

/**
 * Returns ASCII armored text of key
 * @return {String} ASCII armor
 */
Key.prototype.armor = function () {
  var type = this.isPublic() ? _enums2.default.armor.public_key : _enums2.default.armor.private_key;
  return _armor2.default.encode(type, this.toPacketlist().write());
};

/**
 * Returns first key packet or key packet by given keyId that is available for signing or signature verification
 * @param  {module:type/keyid} keyId, optional
 * @return {(module:packet/secret_subkey|module:packet/secret_key|null)} key packet or null if no signing key has been found
 */
Key.prototype.getSigningKeyPacket = function (keyId) {
  var primaryUser = this.getPrimaryUser();
  if (primaryUser && isValidSigningKeyPacket(this.primaryKey, primaryUser.selfCertificate) && (!keyId || this.primaryKey.getKeyId().equals(keyId))) {
    return this.primaryKey;
  }
  if (this.subKeys) {
    for (var i = 0; i < this.subKeys.length; i++) {
      if (this.subKeys[i].isValidSigningKey(this.primaryKey) && (!keyId || this.subKeys[i].subKey.getKeyId().equals(keyId))) {
        return this.subKeys[i].subKey;
      }
    }
  }
  return null;
};

/**
 * Returns preferred signature hash algorithm of this key
 * @return {String}
 */
Key.prototype.getPreferredHashAlgorithm = function () {
  var primaryUser = this.getPrimaryUser();
  if (primaryUser && primaryUser.selfCertificate.preferredHashAlgorithms) {
    return primaryUser.selfCertificate.preferredHashAlgorithms[0];
  }
  return _config2.default.prefer_hash_algorithm;
};

function isValidEncryptionKeyPacket(keyPacket, signature) {
  return keyPacket.algorithm !== _enums2.default.read(_enums2.default.publicKey, _enums2.default.publicKey.dsa) && keyPacket.algorithm !== _enums2.default.read(_enums2.default.publicKey, _enums2.default.publicKey.rsa_sign) && (!signature.keyFlags || (signature.keyFlags[0] & _enums2.default.keyFlags.encrypt_communication) !== 0 || (signature.keyFlags[0] & _enums2.default.keyFlags.encrypt_storage) !== 0);
}

function isValidSigningKeyPacket(keyPacket, signature) {
  return (keyPacket.algorithm === _enums2.default.read(_enums2.default.publicKey, _enums2.default.publicKey.dsa) || keyPacket.algorithm === _enums2.default.read(_enums2.default.publicKey, _enums2.default.publicKey.rsa_sign) || keyPacket.algorithm === _enums2.default.read(_enums2.default.publicKey, _enums2.default.publicKey.rsa_encrypt_sign)) && (!signature.keyFlags || (signature.keyFlags[0] & _enums2.default.keyFlags.sign_data) !== 0);
}

/**
 * Returns the first valid encryption key packet for this key
 * @returns {(module:packet/public_subkey|module:packet/secret_subkey|module:packet/secret_key|module:packet/public_key|null)} key packet or null if no encryption key has been found
 */
Key.prototype.getEncryptionKeyPacket = function () {
  // V4: by convention subkeys are prefered for encryption service
  // V3: keys MUST NOT have subkeys
  if (this.subKeys) {
    for (var i = 0; i < this.subKeys.length; i++) {
      if (this.subKeys[i].isValidEncryptionKey(this.primaryKey)) {
        return this.subKeys[i].subKey;
      }
    }
  }
  // if no valid subkey for encryption, evaluate primary key
  var primaryUser = this.getPrimaryUser();
  if (primaryUser && primaryUser.selfCertificate && !primaryUser.selfCertificate.isExpired() && isValidEncryptionKeyPacket(this.primaryKey, primaryUser.selfCertificate)) {
    return this.primaryKey;
  }
  return null;
};

/**
 * Encrypts all secret key and subkey packets
 * @param  {String} passphrase
 */
Key.prototype.encrypt = function (passphrase) {
  if (!this.isPrivate()) {
    throw new Error("Nothing to encrypt in a public key");
  }

  var keys = this.getAllKeyPackets();
  for (var i = 0; i < keys.length; i++) {
    keys[i].encrypt(passphrase);
    keys[i].clearPrivateMPIs();
  }
};

/**
 * Decrypts all secret key and subkey packets
 * @param  {String} passphrase
 * @return {Boolean} true if all key and subkey packets decrypted successfully
 */
Key.prototype.decrypt = function (passphrase) {
  if (this.isPrivate()) {
    var keys = this.getAllKeyPackets();
    for (var i = 0; i < keys.length; i++) {
      var success = keys[i].decrypt(passphrase);
      if (!success) {
        return false;
      }
    }
  } else {
    throw new Error("Nothing to decrypt in a public key");
  }
  return true;
};

/**
 * Decrypts specific key packets by key ID
 * @param  {Array<module:type/keyid>} keyIds
 * @param  {String} passphrase
 * @return {Boolean} true if all key packets decrypted successfully
 */
Key.prototype.decryptKeyPacket = function (keyIds, passphrase) {
  if (this.isPrivate()) {
    var keys = this.getAllKeyPackets();
    for (var i = 0; i < keys.length; i++) {
      var keyId = keys[i].getKeyId();
      for (var j = 0; j < keyIds.length; j++) {
        if (keyId.equals(keyIds[j])) {
          var success = keys[i].decrypt(passphrase);
          if (!success) {
            return false;
          }
        }
      }
    }
  } else {
    throw new Error("Nothing to decrypt in a public key");
  }
  return true;
};

/**
 * Verify primary key. Checks for revocation signatures, expiration time
 * and valid self signature
 * @return {module:enums.keyStatus} The status of the primary key
 */
Key.prototype.verifyPrimaryKey = function () {
  // check revocation signature
  if (this.revocationSignature && !this.revocationSignature.isExpired() && (this.revocationSignature.verified || this.revocationSignature.verify(this.primaryKey, { key: this.primaryKey }))) {
    return _enums2.default.keyStatus.revoked;
  }
  // check V3 expiration time
  if (this.primaryKey.version === 3 && this.primaryKey.expirationTimeV3 !== 0 && Date.now() > this.primaryKey.created.getTime() + this.primaryKey.expirationTimeV3 * 24 * 3600 * 1000) {
    return _enums2.default.keyStatus.expired;
  }
  // check for at least one self signature. Self signature of user ID not mandatory
  // See {@link http://tools.ietf.org/html/rfc4880#section-11.1}
  var selfSigned = false;
  for (var i = 0; i < this.users.length; i++) {
    if (this.users[i].userId && this.users[i].selfCertifications) {
      selfSigned = true;
    }
  }
  if (!selfSigned) {
    return _enums2.default.keyStatus.no_self_cert;
  }
  // check for valid self signature
  var primaryUser = this.getPrimaryUser();
  if (!primaryUser) {
    return _enums2.default.keyStatus.invalid;
  }
  // check V4 expiration time
  if (this.primaryKey.version === 4 && primaryUser.selfCertificate.keyNeverExpires === false && Date.now() > this.primaryKey.created.getTime() + primaryUser.selfCertificate.keyExpirationTime * 1000) {
    return _enums2.default.keyStatus.expired;
  }
  return _enums2.default.keyStatus.valid;
};

/**
 * Returns the expiration time of the primary key or null if key does not expire
 * @return {Date|null}
 */
Key.prototype.getExpirationTime = function () {
  if (this.primaryKey.version === 3) {
    return getExpirationTime(this.primaryKey);
  }
  if (this.primaryKey.version === 4) {
    var primaryUser = this.getPrimaryUser();
    if (!primaryUser) {
      return null;
    }
    return getExpirationTime(this.primaryKey, primaryUser.selfCertificate);
  }
};

function getExpirationTime(keyPacket, selfCertificate) {
  // check V3 expiration time
  if (keyPacket.version === 3 && keyPacket.expirationTimeV3 !== 0) {
    return new Date(keyPacket.created.getTime() + keyPacket.expirationTimeV3 * 24 * 3600 * 1000);
  }
  // check V4 expiration time
  if (keyPacket.version === 4 && selfCertificate.keyNeverExpires === false) {
    return new Date(keyPacket.created.getTime() + selfCertificate.keyExpirationTime * 1000);
  }
  return null;
}

/**
 * Returns primary user and most significant (latest valid) self signature
 * - if multiple users are marked as primary users returns the one with the latest self signature
 * - if no primary user is found returns the user with the latest self signature
 * @return {{user: Array<module:packet/User>, selfCertificate: Array<module:packet/signature>}|null} The primary user and the self signature
 */
Key.prototype.getPrimaryUser = function () {
  var primUser = [];
  for (var i = 0; i < this.users.length; i++) {
    if (!this.users[i].userId || !this.users[i].selfCertifications) {
      continue;
    }
    for (var j = 0; j < this.users[i].selfCertifications.length; j++) {
      primUser.push({ index: i, user: this.users[i], selfCertificate: this.users[i].selfCertifications[j] });
    }
  }
  // sort by primary user flag and signature creation time
  primUser = primUser.sort(function (a, b) {
    if (a.selfCertificate.isPrimaryUserID > b.selfCertificate.isPrimaryUserID) {
      return -1;
    } else if (a.selfCertificate.isPrimaryUserID < b.selfCertificate.isPrimaryUserID) {
      return 1;
    } else if (a.selfCertificate.created > b.selfCertificate.created) {
      return -1;
    } else if (a.selfCertificate.created < b.selfCertificate.created) {
      return 1;
    } else {
      return 0;
    }
  });
  // return first valid
  for (var k = 0; k < primUser.length; k++) {
    if (primUser[k].user.isValidSelfCertificate(this.primaryKey, primUser[k].selfCertificate)) {
      return primUser[k];
    }
  }
  return null;
};

/**
 * Update key with new components from specified key with same key ID:
 * users, subkeys, certificates are merged into the destination key,
 * duplicates are ignored.
 * If the specified key is a private key and the destination key is public,
 * the destination key is tranformed to a private key.
 * @param  {module:key~Key} key source key to merge
 */
Key.prototype.update = function (key) {
  var that = this;
  if (key.verifyPrimaryKey() === _enums2.default.keyStatus.invalid) {
    return;
  }
  if (this.primaryKey.getFingerprint() !== key.primaryKey.getFingerprint()) {
    throw new Error('Key update method: fingerprints of keys not equal');
  }
  if (this.isPublic() && key.isPrivate()) {
    // check for equal subkey packets
    var equal = (this.subKeys && this.subKeys.length) === (key.subKeys && key.subKeys.length) && (!this.subKeys || this.subKeys.every(function (destSubKey) {
      return key.subKeys.some(function (srcSubKey) {
        return destSubKey.subKey.getFingerprint() === srcSubKey.subKey.getFingerprint();
      });
    }));
    if (!equal) {
      throw new Error('Cannot update public key with private key if subkey mismatch');
    }
    this.primaryKey = key.primaryKey;
  }
  // revocation signature
  if (!this.revocationSignature && key.revocationSignature && !key.revocationSignature.isExpired() && (key.revocationSignature.verified || key.revocationSignature.verify(key.primaryKey, { key: key.primaryKey }))) {
    this.revocationSignature = key.revocationSignature;
  }
  // direct signatures
  mergeSignatures(key, this, 'directSignatures');
  // users
  key.users.forEach(function (srcUser) {
    var found = false;
    for (var i = 0; i < that.users.length; i++) {
      if (srcUser.userId && srcUser.userId.userid === that.users[i].userId.userid || srcUser.userAttribute && srcUser.userAttribute.equals(that.users[i].userAttribute)) {
        that.users[i].update(srcUser, that.primaryKey);
        found = true;
        break;
      }
    }
    if (!found) {
      that.users.push(srcUser);
    }
  });
  // subkeys
  if (key.subKeys) {
    key.subKeys.forEach(function (srcSubKey) {
      var found = false;
      for (var i = 0; i < that.subKeys.length; i++) {
        if (srcSubKey.subKey.getFingerprint() === that.subKeys[i].subKey.getFingerprint()) {
          that.subKeys[i].update(srcSubKey, that.primaryKey);
          found = true;
          break;
        }
      }
      if (!found) {
        that.subKeys.push(srcSubKey);
      }
    });
  }
};

/**
 * Merges signatures from source[attr] to dest[attr]
 * @private
 * @param  {Object} source
 * @param  {Object} dest
 * @param  {String} attr
 * @param  {Function} checkFn optional, signature only merged if true
 */
function mergeSignatures(source, dest, attr, checkFn) {
  source = source[attr];
  if (source) {
    if (!dest[attr]) {
      dest[attr] = source;
    } else {
      source.forEach(function (sourceSig) {
        if (!sourceSig.isExpired() && (!checkFn || checkFn(sourceSig)) && !dest[attr].some(function (destSig) {
          return _util2.default.equalsUint8Array(destSig.signature, sourceSig.signature);
        })) {
          dest[attr].push(sourceSig);
        }
      });
    }
  }
}

// TODO
Key.prototype.revoke = function () {};

/**
 * Signs primary user of key
 * @param  {Array<module:key~Key>} privateKey decrypted private keys for signing
 * @return {module:key~Key} new public key with new certificate signature
 */
Key.prototype.signPrimaryUser = function (privateKeys) {
  var _ref = this.getPrimaryUser() || {};

  var index = _ref.index;
  var user = _ref.user;

  if (!user) {
    throw new Error('Could not find primary user');
  }
  user = user.sign(this.primaryKey, privateKeys);
  var key = new Key(this.toPacketlist());
  key.users[index] = user;
  return key;
};

/**
 * Signs all users of key
 * @param  {Array<module:key~Key>} privateKeys decrypted private keys for signing
 * @return {module:key~Key} new public key with new certificate signature
 */
Key.prototype.signAllUsers = function (privateKeys) {
  var _this = this;

  var users = this.users.map(function (user) {
    return user.sign(_this.primaryKey, privateKeys);
  });
  var key = new Key(this.toPacketlist());
  key.users = users;
  return key;
};

/**
 * Verifies primary user of key
 * @param  {Array<module:key~Key>} keys array of keys to verify certificate signatures
 * @return {Array<({keyid: module:type/keyid, valid: Boolean})>} list of signer's keyid and validity of signature
 */
Key.prototype.verifyPrimaryUser = function (keys) {
  var _ref2 = this.getPrimaryUser() || {};

  var user = _ref2.user;

  if (!user) {
    throw new Error('Could not find primary user');
  }
  return user.verifyAllSignatures(this.primaryKey, keys);
};

/**
 * Verifies all users of key
 * @param  {Array<module:key~Key>} keys array of keys to verify certificate signatures
 * @return {Array<({userid: String, keyid: module:type/keyid, valid: Boolean})>} list of userid, signer's keyid and validity of signature
 */
Key.prototype.verifyAllUsers = function (keys) {
  var _this2 = this;

  return this.users.reduce(function (signatures, user) {
    return signatures.concat(user.verifyAllSignatures(_this2.primaryKey, keys).map(function (signature) {
      return {
        userid: user.userId.userid,
        keyid: signature.keyid,
        valid: signature.valid
      };
    }));
  }, []);
};

/**
 * @class
 * @classdesc Class that represents an user ID or attribute packet and the relevant signatures.
 */
function User(userPacket) {
  if (!(this instanceof User)) {
    return new User(userPacket);
  }
  this.userId = userPacket.tag === _enums2.default.packet.userid ? userPacket : null;
  this.userAttribute = userPacket.tag === _enums2.default.packet.userAttribute ? userPacket : null;
  this.selfCertifications = null;
  this.otherCertifications = null;
  this.revocationCertifications = null;
}

/**
 * Transforms structured user data to packetlist
 * @return {module:packet/packetlist}
 */
User.prototype.toPacketlist = function () {
  var packetlist = new _packet2.default.List();
  packetlist.push(this.userId || this.userAttribute);
  packetlist.concat(this.revocationCertifications);
  packetlist.concat(this.selfCertifications);
  packetlist.concat(this.otherCertifications);
  return packetlist;
};

/**
 * Checks if a self signature of the user is revoked
 * @param  {module:packet/signature}                    certificate
 * @param  {module:packet/secret_key|module:packet/public_key} primaryKey  The primary key packet
 * @return {Boolean}                                         True if the certificate is revoked
 */
User.prototype.isRevoked = function (certificate, primaryKey) {
  if (this.revocationCertifications) {
    var that = this;
    return this.revocationCertifications.some(function (revCert) {
      return revCert.issuerKeyId.equals(certificate.issuerKeyId) && !revCert.isExpired() && (revCert.verified || revCert.verify(primaryKey, { userid: that.userId || that.userAttribute, key: primaryKey }));
    });
  } else {
    return false;
  }
};

/**
 * Returns the most significant (latest valid) self signature of the user
 * @param  {module:packet/secret_key|module:packet/public_key} primaryKey The primary key packet
 * @return {module:packet/signature}                               The self signature
 */
User.prototype.getValidSelfCertificate = function (primaryKey) {
  if (!this.selfCertifications) {
    return null;
  }
  // most recent first
  var validCert = this.selfCertifications.sort(function (a, b) {
    a = a.created;
    b = b.created;
    return a > b ? -1 : a < b ? 1 : 0;
  });
  for (var i = 0; i < validCert.length; i++) {
    if (this.isValidSelfCertificate(primaryKey, validCert[i])) {
      return validCert[i];
    }
  }
  return null;
};

/**
 * Returns true if the self certificate is valid
 * @param  {module:packet/secret_key|module:packet/public_key}  primaryKey      The primary key packet
 * @param  {module:packet/signature}  selfCertificate A self certificate of this user
 * @return {Boolean}
 */
User.prototype.isValidSelfCertificate = function (primaryKey, selfCertificate) {
  if (this.isRevoked(selfCertificate, primaryKey)) {
    return false;
  }
  if (!selfCertificate.isExpired() && (selfCertificate.verified || selfCertificate.verify(primaryKey, { userid: this.userId || this.userAttribute, key: primaryKey }))) {
    return true;
  }
  return false;
};

/**
 * Signs user
 * @param  {module:packet/secret_key|module:packet/public_key} primaryKey The primary key packet
 * @param  {Array<module:key~Key>} privateKeys decrypted private keys for signing
 * @return {module:key~Key} new user with new certificate signatures
 */
User.prototype.sign = function (primaryKey, privateKeys) {
  var user, dataToSign, signingKeyPacket, signaturePacket;
  dataToSign = {};
  dataToSign.key = primaryKey;
  dataToSign.userid = this.userId || this.userAttribute;
  user = new User(this.userId || this.userAttribute);
  user.otherCertifications = [];
  privateKeys.forEach(function (privateKey) {
    if (privateKey.isPublic()) {
      throw new Error('Need private key for signing');
    }
    if (privateKey.primaryKey.getFingerprint() === primaryKey.getFingerprint()) {
      throw new Error('Not implemented for self signing');
    }
    signingKeyPacket = privateKey.getSigningKeyPacket();
    if (!signingKeyPacket) {
      throw new Error('Could not find valid signing key packet');
    }
    if (!signingKeyPacket.isDecrypted) {
      throw new Error('Private key is not decrypted.');
    }
    signaturePacket = new _packet2.default.Signature();
    // Most OpenPGP implementations use generic certification (0x10)
    signaturePacket.signatureType = _enums2.default.write(_enums2.default.signature, _enums2.default.signature.cert_generic);
    signaturePacket.keyFlags = [_enums2.default.keyFlags.certify_keys | _enums2.default.keyFlags.sign_data];
    signaturePacket.hashAlgorithm = privateKey.getPreferredHashAlgorithm();
    signaturePacket.publicKeyAlgorithm = signingKeyPacket.algorithm;
    signaturePacket.signingKeyId = signingKeyPacket.getKeyId();
    signaturePacket.sign(signingKeyPacket, dataToSign);
    user.otherCertifications.push(signaturePacket);
  });
  user.update(this, primaryKey);
  return user;
};

/**
 * Verifies all user signatures
 * @param  {module:packet/secret_key|module:packet/public_key} primaryKey The primary key packet
 * @param  {Array<module:key~Key>} keys array of keys to verify certificate signatures
 * @return {Array<({keyid: module:type/keyid, valid: Boolean})>} list of signer's keyid and validity of signature
 */
User.prototype.verifyAllSignatures = function (primaryKey, keys) {
  var dataToVerify = { userid: this.userId || this.userAttribute, key: primaryKey };
  var certificates = this.selfCertifications.concat(this.otherCertifications || []);
  return certificates.map(function (signaturePacket) {
    var keyPackets = keys.filter(function (key) {
      return key.getSigningKeyPacket(signaturePacket.issuerKeyId);
    });
    var valid = null;
    if (keyPackets.length > 0) {
      valid = keyPackets.some(function (keyPacket) {
        return signaturePacket.verify(keyPacket.primaryKey, dataToVerify);
      });
    }
    return { keyid: signaturePacket.issuerKeyId, valid: valid };
  });
};

/**
 * Verify User. Checks for existence of self signatures, revocation signatures
 * and validity of self signature
 * @param  {module:packet/secret_key|module:packet/public_key} primaryKey The primary key packet
 * @return {module:enums.keyStatus} status of user
 */
User.prototype.verify = function (primaryKey) {
  if (!this.selfCertifications) {
    return _enums2.default.keyStatus.no_self_cert;
  }
  var status;
  for (var i = 0; i < this.selfCertifications.length; i++) {
    if (this.isRevoked(this.selfCertifications[i], primaryKey)) {
      status = _enums2.default.keyStatus.revoked;
      continue;
    }
    if (!(this.selfCertifications[i].verified || this.selfCertifications[i].verify(primaryKey, { userid: this.userId || this.userAttribute, key: primaryKey }))) {
      status = _enums2.default.keyStatus.invalid;
      continue;
    }
    if (this.selfCertifications[i].isExpired()) {
      status = _enums2.default.keyStatus.expired;
      continue;
    }
    status = _enums2.default.keyStatus.valid;
    break;
  }
  return status;
};

/**
 * Update user with new components from specified user
 * @param  {module:key~User} user source user to merge
 * @param  {module:packet/signature} primaryKey primary key used for validation
 */
User.prototype.update = function (user, primaryKey) {
  var that = this;
  // self signatures
  mergeSignatures(user, this, 'selfCertifications', function (srcSelfSig) {
    return srcSelfSig.verified || srcSelfSig.verify(primaryKey, { userid: that.userId || that.userAttribute, key: primaryKey });
  });
  // other signatures
  mergeSignatures(user, this, 'otherCertifications');
  // revocation signatures
  mergeSignatures(user, this, 'revocationCertifications');
};

/**
 * @class
 * @classdesc Class that represents a subkey packet and the relevant signatures.
 */
function SubKey(subKeyPacket) {
  if (!(this instanceof SubKey)) {
    return new SubKey(subKeyPacket);
  }
  this.subKey = subKeyPacket;
  this.bindingSignatures = [];
  this.revocationSignature = null;
}

/**
 * Transforms structured subkey data to packetlist
 * @return {module:packet/packetlist}
 */
SubKey.prototype.toPacketlist = function () {
  var packetlist = new _packet2.default.List();
  packetlist.push(this.subKey);
  packetlist.push(this.revocationSignature);
  for (var i = 0; i < this.bindingSignatures.length; i++) {
    packetlist.push(this.bindingSignatures[i]);
  }
  return packetlist;
};

/**
 * Returns true if the subkey can be used for encryption
 * @param  {module:packet/secret_key|module:packet/public_key}  primaryKey The primary key packet
 * @return {Boolean}
 */
SubKey.prototype.isValidEncryptionKey = function (primaryKey) {
  if (this.verify(primaryKey) !== _enums2.default.keyStatus.valid) {
    return false;
  }
  for (var i = 0; i < this.bindingSignatures.length; i++) {
    if (isValidEncryptionKeyPacket(this.subKey, this.bindingSignatures[i])) {
      return true;
    }
  }
  return false;
};

/**
 * Returns true if the subkey can be used for signing of data
 * @param  {module:packet/secret_key|module:packet/public_key}  primaryKey The primary key packet
 * @return {Boolean}
 */
SubKey.prototype.isValidSigningKey = function (primaryKey) {
  if (this.verify(primaryKey) !== _enums2.default.keyStatus.valid) {
    return false;
  }
  for (var i = 0; i < this.bindingSignatures.length; i++) {
    if (isValidSigningKeyPacket(this.subKey, this.bindingSignatures[i])) {
      return true;
    }
  }
  return false;
};

/**
 * Verify subkey. Checks for revocation signatures, expiration time
 * and valid binding signature
 * @return {module:enums.keyStatus} The status of the subkey
 */
SubKey.prototype.verify = function (primaryKey) {
  // check subkey revocation signature
  if (this.revocationSignature && !this.revocationSignature.isExpired() && (this.revocationSignature.verified || this.revocationSignature.verify(primaryKey, { key: primaryKey, bind: this.subKey }))) {
    return _enums2.default.keyStatus.revoked;
  }
  // check V3 expiration time
  if (this.subKey.version === 3 && this.subKey.expirationTimeV3 !== 0 && Date.now() > this.subKey.created.getTime() + this.subKey.expirationTimeV3 * 24 * 3600 * 1000) {
    return _enums2.default.keyStatus.expired;
  }
  // check subkey binding signatures (at least one valid binding sig needed)
  for (var i = 0; i < this.bindingSignatures.length; i++) {
    var isLast = i === this.bindingSignatures.length - 1;
    var sig = this.bindingSignatures[i];
    // check binding signature is not expired
    if (sig.isExpired()) {
      if (isLast) {
        return _enums2.default.keyStatus.expired; // last expired binding signature
      } else {
        continue;
      }
    }
    // check binding signature can verify
    if (!(sig.verified || sig.verify(primaryKey, { key: primaryKey, bind: this.subKey }))) {
      if (isLast) {
        return _enums2.default.keyStatus.invalid; // last invalid binding signature
      } else {
        continue;
      }
    }
    // check V4 expiration time
    if (this.subKey.version === 4) {
      if (sig.keyNeverExpires === false && Date.now() > this.subKey.created.getTime() + sig.keyExpirationTime * 1000) {
        if (isLast) {
          return _enums2.default.keyStatus.expired; // last V4 expired binding signature
        } else {
          continue;
        }
      }
    }
    return _enums2.default.keyStatus.valid; // found a binding signature that passed all checks
  }
  return _enums2.default.keyStatus.invalid; // no binding signatures to check
};

/**
 * Returns the expiration time of the subkey or null if key does not expire
 * @return {Date|null}
 */
SubKey.prototype.getExpirationTime = function () {
  var highest;
  for (var i = 0; i < this.bindingSignatures.length; i++) {
    var current = getExpirationTime(this.subKey, this.bindingSignatures[i]);
    if (current === null) {
      return null;
    }
    if (!highest || current > highest) {
      highest = current;
    }
  }
  return highest;
};

/**
 * Update subkey with new components from specified subkey
 * @param  {module:key~SubKey} subKey source subkey to merge
 * @param  {module:packet/signature} primaryKey primary key used for validation
 */
SubKey.prototype.update = function (subKey, primaryKey) {
  if (subKey.verify(primaryKey) === _enums2.default.keyStatus.invalid) {
    return;
  }
  if (this.subKey.getFingerprint() !== subKey.subKey.getFingerprint()) {
    throw new Error('SubKey update method: fingerprints of subkeys not equal');
  }
  // key packet
  if (this.subKey.tag === _enums2.default.packet.publicSubkey && subKey.subKey.tag === _enums2.default.packet.secretSubkey) {
    this.subKey = subKey.subKey;
  }
  // update missing binding signatures
  if (this.bindingSignatures.length < subKey.bindingSignatures.length) {
    for (var i = this.bindingSignatures.length; i < subKey.bindingSignatures.length; i++) {
      var newSig = subKey.bindingSignatures[i];
      if (newSig.verified || newSig.verify(primaryKey, { key: primaryKey, bind: this.subKey })) {
        this.bindingSignatures.push(newSig);
      }
    }
  }
  // revocation signature
  if (!this.revocationSignature && subKey.revocationSignature && !subKey.revocationSignature.isExpired() && (subKey.revocationSignature.verified || subKey.revocationSignature.verify(primaryKey, { key: primaryKey, bind: this.subKey }))) {
    this.revocationSignature = subKey.revocationSignature;
  }
};

/**
 * Reads an unarmored OpenPGP key list and returns one or multiple key objects
 * @param {Uint8Array} data to be parsed
 * @return {{keys: Array<module:key~Key>, err: (Array<Error>|null)}} result object with key and error arrays
 * @static
 */
function read(data) {
  var result = {};
  result.keys = [];
  try {
    var packetlist = new _packet2.default.List();
    packetlist.read(data);
    var keyIndex = packetlist.indexOfTag(_enums2.default.packet.publicKey, _enums2.default.packet.secretKey);
    if (keyIndex.length === 0) {
      throw new Error('No key packet found');
    }
    for (var i = 0; i < keyIndex.length; i++) {
      var oneKeyList = packetlist.slice(keyIndex[i], keyIndex[i + 1]);
      try {
        var newKey = new Key(oneKeyList);
        result.keys.push(newKey);
      } catch (e) {
        result.err = result.err || [];
        result.err.push(e);
      }
    }
  } catch (e) {
    result.err = result.err || [];
    result.err.push(e);
  }
  return result;
}

/**
 * Reads an OpenPGP armored text and returns one or multiple key objects
 * @param {String} armoredText text to be parsed
 * @return {{keys: Array<module:key~Key>, err: (Array<Error>|null)}} result object with key and error arrays
 * @static
 */
function readArmored(armoredText) {
  try {
    var input = _armor2.default.decode(armoredText);
    if (!(input.type === _enums2.default.armor.public_key || input.type === _enums2.default.armor.private_key)) {
      throw new Error('Armored text not of type key');
    }
    return read(input.data);
  } catch (e) {
    var result = { keys: [], err: [] };
    result.err.push(e);
    return result;
  }
}

/**
 * Generates a new OpenPGP key. Currently only supports RSA keys.
 * Primary and subkey will be of same type.
 * @param {module:enums.publicKey} [options.keyType=module:enums.publicKey.rsa_encrypt_sign]    to indicate what type of key to make.
 *                             RSA is 1. See {@link http://tools.ietf.org/html/rfc4880#section-9.1}
 * @param {Integer} options.numBits    number of bits for the key creation.
 * @param {String|Array<String>}  options.userIds    assumes already in form of "User Name <username@email.com>"
                                                     If array is used, the first userId is set as primary user Id
 * @param {String}  options.passphrase The passphrase used to encrypt the resulting private key
 * @param {Boolean} [options.unlocked=false]    The secret part of the generated key is unlocked
 * @param {Number} [options.keyExpirationTime=0] The number of seconds after the key creation time that the key expires
 * @return {module:key~Key}
 * @static
 */
function generate(options) {
  var secretKeyPacket, secretSubkeyPacket;
  return Promise.resolve().then(function () {
    options.keyType = options.keyType || _enums2.default.publicKey.rsa_encrypt_sign;
    if (options.keyType !== _enums2.default.publicKey.rsa_encrypt_sign) {
      // RSA Encrypt-Only and RSA Sign-Only are deprecated and SHOULD NOT be generated
      throw new Error('Only RSA Encrypt or Sign supported');
    }

    if (!options.passphrase) {
      // Key without passphrase is unlocked by definition
      options.unlocked = true;
    }
    if (String.prototype.isPrototypeOf(options.userIds) || typeof options.userIds === 'string') {
      options.userIds = [options.userIds];
    }

    return Promise.all([generateSecretKey(), generateSecretSubkey()]).then(function () {
      return wrapKeyObject(secretKeyPacket, secretSubkeyPacket, options);
    });
  });

  function generateSecretKey() {
    secretKeyPacket = new _packet2.default.SecretKey();
    secretKeyPacket.algorithm = _enums2.default.read(_enums2.default.publicKey, options.keyType);
    return secretKeyPacket.generate(options.numBits);
  }

  function generateSecretSubkey() {
    secretSubkeyPacket = new _packet2.default.SecretSubkey();
    secretSubkeyPacket.algorithm = _enums2.default.read(_enums2.default.publicKey, options.keyType);
    return secretSubkeyPacket.generate(options.numBits);
  }
}

/**
 * Reformats and signs an OpenPGP with a given User ID. Currently only supports RSA keys.
 * @param {module:key~Key} options.privateKey   The private key to reformat
 * @param {module:enums.publicKey} [options.keyType=module:enums.publicKey.rsa_encrypt_sign]
 * @param {String|Array<String>}  options.userIds    assumes already in form of "User Name <username@email.com>"
                                                     If array is used, the first userId is set as primary user Id
 * @param {String}  options.passphrase The passphrase used to encrypt the resulting private key
 * @param {Boolean} [options.unlocked=false]    The secret part of the generated key is unlocked
 * @param {Number} [options.keyExpirationTime=0] The number of seconds after the key creation time that the key expires
 * @return {module:key~Key}
 * @static
 */
function reformat(options) {
  var secretKeyPacket, secretSubkeyPacket;
  return Promise.resolve().then(function () {

    options.keyType = options.keyType || _enums2.default.publicKey.rsa_encrypt_sign;
    if (options.keyType !== _enums2.default.publicKey.rsa_encrypt_sign) {
      // RSA Encrypt-Only and RSA Sign-Only are deprecated and SHOULD NOT be generated
      throw new Error('Only RSA Encrypt or Sign supported');
    }

    if (!options.passphrase) {
      // Key without passphrase is unlocked by definition
      options.unlocked = true;
    }
    if (String.prototype.isPrototypeOf(options.userIds) || typeof options.userIds === 'string') {
      options.userIds = [options.userIds];
    }
    var packetlist = options.privateKey.toPacketlist();
    for (var i = 0; i < packetlist.length; i++) {
      if (packetlist[i].tag === _enums2.default.packet.secretKey) {
        secretKeyPacket = packetlist[i];
      } else if (packetlist[i].tag === _enums2.default.packet.secretSubkey) {
        secretSubkeyPacket = packetlist[i];
      }
    }
    return wrapKeyObject(secretKeyPacket, secretSubkeyPacket, options);
  });
}

function wrapKeyObject(secretKeyPacket, secretSubkeyPacket, options) {
  // set passphrase protection
  if (options.passphrase) {
    secretKeyPacket.encrypt(options.passphrase);
    secretSubkeyPacket.encrypt(options.passphrase);
  }

  var packetlist = new _packet2.default.List();

  packetlist.push(secretKeyPacket);

  options.userIds.forEach(function (userId, index) {

    var userIdPacket = new _packet2.default.Userid();
    userIdPacket.read(_util2.default.str2Uint8Array(userId));

    var dataToSign = {};
    dataToSign.userid = userIdPacket;
    dataToSign.key = secretKeyPacket;
    var signaturePacket = new _packet2.default.Signature();
    signaturePacket.signatureType = _enums2.default.signature.cert_generic;
    signaturePacket.publicKeyAlgorithm = options.keyType;
    signaturePacket.hashAlgorithm = _config2.default.prefer_hash_algorithm;
    signaturePacket.keyFlags = [_enums2.default.keyFlags.certify_keys | _enums2.default.keyFlags.sign_data];
    signaturePacket.preferredSymmetricAlgorithms = [];
    // prefer aes256, aes128, then aes192 (no WebCrypto support: https://www.chromium.org/blink/webcrypto#TOC-AES-support)
    signaturePacket.preferredSymmetricAlgorithms.push(_enums2.default.symmetric.aes256);
    signaturePacket.preferredSymmetricAlgorithms.push(_enums2.default.symmetric.aes128);
    signaturePacket.preferredSymmetricAlgorithms.push(_enums2.default.symmetric.aes192);
    signaturePacket.preferredSymmetricAlgorithms.push(_enums2.default.symmetric.cast5);
    signaturePacket.preferredSymmetricAlgorithms.push(_enums2.default.symmetric.tripledes);
    signaturePacket.preferredHashAlgorithms = [];
    // prefer fast asm.js implementations (SHA-256). SHA-1 will not be secure much longer...move to bottom of list
    signaturePacket.preferredHashAlgorithms.push(_enums2.default.hash.sha256);
    signaturePacket.preferredHashAlgorithms.push(_enums2.default.hash.sha512);
    signaturePacket.preferredHashAlgorithms.push(_enums2.default.hash.sha1);
    signaturePacket.preferredCompressionAlgorithms = [];
    signaturePacket.preferredCompressionAlgorithms.push(_enums2.default.compression.zlib);
    signaturePacket.preferredCompressionAlgorithms.push(_enums2.default.compression.zip);
    if (index === 0) {
      signaturePacket.isPrimaryUserID = true;
    }
    if (_config2.default.integrity_protect) {
      signaturePacket.features = [];
      signaturePacket.features.push(1); // Modification Detection
    }
    if (options.keyExpirationTime > 0) {
      signaturePacket.keyExpirationTime = options.keyExpirationTime;
      signaturePacket.keyNeverExpires = false;
    }
    signaturePacket.sign(secretKeyPacket, dataToSign);

    packetlist.push(userIdPacket);
    packetlist.push(signaturePacket);
  });

  var dataToSign = {};
  dataToSign.key = secretKeyPacket;
  dataToSign.bind = secretSubkeyPacket;
  var subkeySignaturePacket = new _packet2.default.Signature();
  subkeySignaturePacket.signatureType = _enums2.default.signature.subkey_binding;
  subkeySignaturePacket.publicKeyAlgorithm = options.keyType;
  subkeySignaturePacket.hashAlgorithm = _config2.default.prefer_hash_algorithm;
  subkeySignaturePacket.keyFlags = [_enums2.default.keyFlags.encrypt_communication | _enums2.default.keyFlags.encrypt_storage];
  if (options.keyExpirationTime > 0) {
    subkeySignaturePacket.keyExpirationTime = options.keyExpirationTime;
    subkeySignaturePacket.keyNeverExpires = false;
  }
  subkeySignaturePacket.sign(secretKeyPacket, dataToSign);

  packetlist.push(secretSubkeyPacket);
  packetlist.push(subkeySignaturePacket);

  if (!options.unlocked) {
    secretKeyPacket.clearPrivateMPIs();
    secretSubkeyPacket.clearPrivateMPIs();
  }

  return new Key(packetlist);
}

/**
 * Returns the preferred symmetric algorithm for a set of keys
 * @param  {Array<module:key~Key>} keys Set of keys
 * @return {enums.symmetric}   Preferred symmetric algorithm
 */
function getPreferredSymAlgo(keys) {
  var prioMap = {};
  keys.forEach(function (key) {
    var primaryUser = key.getPrimaryUser();
    if (!primaryUser || !primaryUser.selfCertificate.preferredSymmetricAlgorithms) {
      return _config2.default.encryption_cipher;
    }
    primaryUser.selfCertificate.preferredSymmetricAlgorithms.forEach(function (algo, index) {
      var entry = prioMap[algo] || (prioMap[algo] = { prio: 0, count: 0, algo: algo });
      entry.prio += 64 >> index;
      entry.count++;
    });
  });
  var prefAlgo = { prio: 0, algo: _config2.default.encryption_cipher };
  for (var algo in prioMap) {
    try {
      if (algo !== _enums2.default.symmetric.plaintext && algo !== _enums2.default.symmetric.idea && // not implemented
      _enums2.default.read(_enums2.default.symmetric, algo) && // known algorithm
      prioMap[algo].count === keys.length && // available for all keys
      prioMap[algo].prio > prefAlgo.prio) {
        prefAlgo = prioMap[algo];
      }
    } catch (e) {}
  }
  return prefAlgo.algo;
}

},{"./config":10,"./encoding/armor.js":33,"./enums.js":35,"./packet":47,"./util":70}],39:[function(_dereq_,module,exports){
'use strict';

/**
 * @see module:keyring/keyring
 * @module keyring
 */

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _keyring = _dereq_('./keyring.js');

var _keyring2 = _interopRequireDefault(_keyring);

var _localstore = _dereq_('./localstore.js');

var _localstore2 = _interopRequireDefault(_localstore);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

_keyring2.default.localstore = _localstore2.default;

exports.default = _keyring2.default;

},{"./keyring.js":40,"./localstore.js":41}],40:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * The class that deals with storage of the keyring. Currently the only option is to use HTML5 local storage.
 * @requires enums
 * @requires key
 * @requires util
 * @module keyring/keyring
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = Keyring;

var _key = _dereq_('../key.js');

var keyModule = _interopRequireWildcard(_key);

var _localstore = _dereq_('./localstore.js');

var _localstore2 = _interopRequireDefault(_localstore);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

/**
 * Initialization routine for the keyring. This method reads the
 * keyring from HTML5 local storage and initializes this instance.
 * @constructor
 * @param {class} [storeHandler] class implementing loadPublic(), loadPrivate(), storePublic(), and storePrivate() methods
 */
function Keyring(storeHandler) {
  this.storeHandler = storeHandler || new _localstore2.default();
  this.publicKeys = new KeyArray(this.storeHandler.loadPublic());
  this.privateKeys = new KeyArray(this.storeHandler.loadPrivate());
}

/**
 * Calls the storeHandler to save the keys
 */
Keyring.prototype.store = function () {
  this.storeHandler.storePublic(this.publicKeys.keys);
  this.storeHandler.storePrivate(this.privateKeys.keys);
};

/**
 * Clear the keyring - erase all the keys
 */
Keyring.prototype.clear = function () {
  this.publicKeys.keys = [];
  this.privateKeys.keys = [];
};

/**
 * Searches the keyring for keys having the specified key id
 * @param {String} keyId provided as string of lowercase hex number
 * withouth 0x prefix (can be 16-character key ID or fingerprint)
 * @param  {Boolean} deep if true search also in subkeys
 * @return {Array<module:key~Key>|null} keys found or null
 */
Keyring.prototype.getKeysForId = function (keyId, deep) {
  var result = [];
  result = result.concat(this.publicKeys.getForId(keyId, deep) || []);
  result = result.concat(this.privateKeys.getForId(keyId, deep) || []);
  return result.length ? result : null;
};

/**
 * Removes keys having the specified key id from the keyring
 * @param {String} keyId provided as string of lowercase hex number
 * withouth 0x prefix (can be 16-character key ID or fingerprint)
 * @return {Array<module:key~Key>|null} keys found or null
 */
Keyring.prototype.removeKeysForId = function (keyId) {
  var result = [];
  result = result.concat(this.publicKeys.removeForId(keyId) || []);
  result = result.concat(this.privateKeys.removeForId(keyId) || []);
  return result.length ? result : null;
};

/**
 * Get all public and private keys
 * @return {Array<module:key~Key>} all keys
 */
Keyring.prototype.getAllKeys = function () {
  return this.publicKeys.keys.concat(this.privateKeys.keys);
};

/**
 * Array of keys
 * @param {Array<module:key~Key>} keys The keys to store in this array
 */
function KeyArray(keys) {
  this.keys = keys;
}

/**
 * Searches all keys in the KeyArray matching the address or address part of the user ids
 * @param {String} email email address to search for
 * @return {Array<module:key~Key>} The public keys associated with provided email address.
 */
KeyArray.prototype.getForAddress = function (email) {
  var results = [];
  for (var i = 0; i < this.keys.length; i++) {
    if (emailCheck(email, this.keys[i])) {
      results.push(this.keys[i]);
    }
  }
  return results;
};

/**
 * Checks a key to see if it matches the specified email address
 * @private
 * @param {String} email email address to search for
 * @param {module:key~Key} key The key to be checked.
 * @return {Boolean} True if the email address is defined in the specified key
 */
function emailCheck(email, key) {
  email = email.toLowerCase();
  // escape email before using in regular expression
  var emailEsc = email.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  var emailRegex = new RegExp('<' + emailEsc + '>');
  var userIds = key.getUserIds();
  for (var i = 0; i < userIds.length; i++) {
    var userId = userIds[i].toLowerCase();
    if (email === userId || emailRegex.test(userId)) {
      return true;
    }
  }
  return false;
}

/**
 * Checks a key to see if it matches the specified keyid
 * @private
 * @param {String} keyId provided as string of lowercase hex number
 * withouth 0x prefix (can be 16-character key ID or fingerprint)
 * @param {module:packet/secret_key|public_key|public_subkey|secret_subkey} keypacket The keypacket to be checked
 * @return {Boolean} True if keypacket has the specified keyid
 */
function keyIdCheck(keyId, keypacket) {
  if (keyId.length === 16) {
    return keyId === keypacket.getKeyId().toHex();
  } else {
    return keyId === keypacket.getFingerprint();
  }
}

/**
 * Searches the KeyArray for a key having the specified key id
 * @param {String} keyId provided as string of lowercase hex number
 * withouth 0x prefix (can be 16-character key ID or fingerprint)
 * @param  {Boolean} deep if true search also in subkeys
 * @return {module:key~Key|null} key found or null
 */
KeyArray.prototype.getForId = function (keyId, deep) {
  for (var i = 0; i < this.keys.length; i++) {
    if (keyIdCheck(keyId, this.keys[i].primaryKey)) {
      return this.keys[i];
    }
    if (deep && this.keys[i].subKeys) {
      for (var j = 0; j < this.keys[i].subKeys.length; j++) {
        if (keyIdCheck(keyId, this.keys[i].subKeys[j].subKey)) {
          return this.keys[i];
        }
      }
    }
  }
  return null;
};

/**
 * Imports a key from an ascii armored message
 * @param {String} armored message to read the keys/key from
 * @return {Array<Error>|null} array of error objects or null
 */
KeyArray.prototype.importKey = function (armored) {
  var imported = keyModule.readArmored(armored);
  var that = this;
  imported.keys.forEach(function (key) {
    // check if key already in key array
    var keyidHex = key.primaryKey.getKeyId().toHex();
    var keyFound = that.getForId(keyidHex);
    if (keyFound) {
      keyFound.update(key);
    } else {
      that.push(key);
    }
  });
  return imported.err ? imported.err : null;
};

/**
 * Add key to KeyArray
 * @param {module:key~Key} key The key that will be added to the keyring
 * @return {Number} The new length of the KeyArray
 */
KeyArray.prototype.push = function (key) {
  return this.keys.push(key);
};

/**
 * Removes a key with the specified keyid from the keyring
 * @param {String} keyId provided as string of lowercase hex number
 * withouth 0x prefix (can be 16-character key ID or fingerprint)
 * @return {module:key~Key|null} The key object which has been removed or null
 */
KeyArray.prototype.removeForId = function (keyId) {
  for (var i = 0; i < this.keys.length; i++) {
    if (keyIdCheck(keyId, this.keys[i].primaryKey)) {
      return this.keys.splice(i, 1)[0];
    }
  }
  return null;
};

},{"../key.js":38,"./localstore.js":41}],41:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * The class that deals with storage of the keyring. Currently the only option is to use HTML5 local storage.
 * @requires config
 * @module keyring/localstore
 * @param {String} prefix prefix for itemnames in localstore
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = LocalStore;

var _config = _dereq_('../config');

var _config2 = _interopRequireDefault(_config);

var _key = _dereq_('../key.js');

var keyModule = _interopRequireWildcard(_key);

var _util = _dereq_('../util.js');

var _util2 = _interopRequireDefault(_util);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function LocalStore(prefix) {
  prefix = prefix || 'openpgp-';
  this.publicKeysItem = prefix + this.publicKeysItem;
  this.privateKeysItem = prefix + this.privateKeysItem;
  if (typeof window !== 'undefined' && window.localStorage) {
    this.storage = window.localStorage;
  } else {
    this.storage = new (_dereq_('node-localstorage').LocalStorage)(_config2.default.node_store);
  }
}

/*
 * Declare the localstore itemnames
 */
LocalStore.prototype.publicKeysItem = 'public-keys';
LocalStore.prototype.privateKeysItem = 'private-keys';

/**
 * Load the public keys from HTML5 local storage.
 * @return {Array<module:key~Key>} array of keys retrieved from localstore
 */
LocalStore.prototype.loadPublic = function () {
  return loadKeys(this.storage, this.publicKeysItem);
};

/**
 * Load the private keys from HTML5 local storage.
 * @return {Array<module:key~Key>} array of keys retrieved from localstore
 */
LocalStore.prototype.loadPrivate = function () {
  return loadKeys(this.storage, this.privateKeysItem);
};

function loadKeys(storage, itemname) {
  var armoredKeys = JSON.parse(storage.getItem(itemname));
  var keys = [];
  if (armoredKeys !== null && armoredKeys.length !== 0) {
    var key;
    for (var i = 0; i < armoredKeys.length; i++) {
      key = keyModule.readArmored(armoredKeys[i]);
      if (!key.err) {
        keys.push(key.keys[0]);
      } else {
        _util2.default.print_debug("Error reading armored key from keyring index: " + i);
      }
    }
  }
  return keys;
}

/**
 * Saves the current state of the public keys to HTML5 local storage.
 * The key array gets stringified using JSON
 * @param {Array<module:key~Key>} keys array of keys to save in localstore
 */
LocalStore.prototype.storePublic = function (keys) {
  storeKeys(this.storage, this.publicKeysItem, keys);
};

/**
 * Saves the current state of the private keys to HTML5 local storage.
 * The key array gets stringified using JSON
 * @param {Array<module:key~Key>} keys array of keys to save in localstore
 */
LocalStore.prototype.storePrivate = function (keys) {
  storeKeys(this.storage, this.privateKeysItem, keys);
};

function storeKeys(storage, itemname, keys) {
  var armoredKeys = [];
  if (keys.length) {
    for (var i = 0; i < keys.length; i++) {
      armoredKeys.push(keys[i].armor());
    }
    storage.setItem(itemname, JSON.stringify(armoredKeys));
  } else {
    storage.removeItem(itemname);
  }
}

},{"../config":10,"../key.js":38,"../util.js":70,"node-localstorage":"node-localstorage"}],42:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @requires config
 * @requires crypto
 * @requires encoding/armor
 * @requires enums
 * @requires packet
 * @module message
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.Message = Message;
exports.encryptSessionKey = encryptSessionKey;
exports.readArmored = readArmored;
exports.read = read;
exports.readSignedContent = readSignedContent;
exports.fromText = fromText;
exports.fromBinary = fromBinary;

var _util = _dereq_('./util.js');

var _util2 = _interopRequireDefault(_util);

var _packet = _dereq_('./packet');

var _packet2 = _interopRequireDefault(_packet);

var _enums = _dereq_('./enums.js');

var _enums2 = _interopRequireDefault(_enums);

var _armor = _dereq_('./encoding/armor.js');

var _armor2 = _interopRequireDefault(_armor);

var _config = _dereq_('./config');

var _config2 = _interopRequireDefault(_config);

var _crypto = _dereq_('./crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _signature = _dereq_('./signature.js');

var sigModule = _interopRequireWildcard(_signature);

var _key = _dereq_('./key.js');

var keyModule = _interopRequireWildcard(_key);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @class
 * @classdesc Class that represents an OpenPGP message.
 * Can be an encrypted message, signed message, compressed message or literal message
 * @param  {module:packet/packetlist} packetlist The packets that form this message
 * See {@link http://tools.ietf.org/html/rfc4880#section-11.3}
 */

function Message(packetlist) {
  if (!(this instanceof Message)) {
    return new Message(packetlist);
  }
  this.packets = packetlist || new _packet2.default.List();
}

/**
 * Returns the key IDs of the keys to which the session key is encrypted
 * @return {Array<module:type/keyid>} array of keyid objects
 */
Message.prototype.getEncryptionKeyIds = function () {
  var keyIds = [];
  var pkESKeyPacketlist = this.packets.filterByTag(_enums2.default.packet.publicKeyEncryptedSessionKey);
  pkESKeyPacketlist.forEach(function (packet) {
    keyIds.push(packet.publicKeyId);
  });
  return keyIds;
};

/**
 * Returns the key IDs of the keys that signed the message
 * @return {Array<module:type/keyid>} array of keyid objects
 */
Message.prototype.getSigningKeyIds = function () {
  var keyIds = [];
  var msg = this.unwrapCompressed();
  // search for one pass signatures
  var onePassSigList = msg.packets.filterByTag(_enums2.default.packet.onePassSignature);
  onePassSigList.forEach(function (packet) {
    keyIds.push(packet.signingKeyId);
  });
  // if nothing found look for signature packets
  if (!keyIds.length) {
    var signatureList = msg.packets.filterByTag(_enums2.default.packet.signature);
    signatureList.forEach(function (packet) {
      keyIds.push(packet.issuerKeyId);
    });
  }
  return keyIds;
};

/**
 * Decrypt the message. Either a private key, a session key, or a password must be specified.
 * @param  {Key} privateKey      (optional) private key with decrypted secret data
 * @param  {Object} sessionKey   (optional) session key in the form: { data:Uint8Array, algorithm:String }
 * @param  {String} password     (optional) password used to decrypt
 * @return {Message}             new message with decrypted content
 */
Message.prototype.decrypt = function (privateKey, sessionKey, password) {
  var _this = this;

  return Promise.resolve().then(function () {
    var keyObj = sessionKey || _this.decryptSessionKey(privateKey, password);
    if (!keyObj || !_util2.default.isUint8Array(keyObj.data) || !_util2.default.isString(keyObj.algorithm)) {
      throw new Error('Invalid session key for decryption.');
    }

    var symEncryptedPacketlist = _this.packets.filterByTag(_enums2.default.packet.symmetricallyEncrypted, _enums2.default.packet.symEncryptedIntegrityProtected, _enums2.default.packet.symEncryptedAEADProtected);

    if (symEncryptedPacketlist.length === 0) {
      return;
    }

    var symEncryptedPacket = symEncryptedPacketlist[0];
    return symEncryptedPacket.decrypt(keyObj.algorithm, keyObj.data).then(function () {
      var resultMsg = new Message(symEncryptedPacket.packets);
      symEncryptedPacket.packets = new _packet2.default.List(); // remove packets after decryption
      return resultMsg;
    });
  });
};

/**
 * Decrypt an encrypted session key either with a private key or a password.
 * @param  {Key} privateKey    (optional) private key with decrypted secret data
 * @param  {String} password   (optional) password used to decrypt
 * @return {Object}            object with sessionKey, algorithm in the form:
 *                               { data:Uint8Array, algorithm:String }
 */
Message.prototype.decryptSessionKey = function (privateKey, password) {
  var keyPacket;

  if (password) {
    var symEncryptedSessionKeyPacketlist = this.packets.filterByTag(_enums2.default.packet.symEncryptedSessionKey);
    var symLength = symEncryptedSessionKeyPacketlist.length;
    for (var i = 0; i < symLength; i++) {
      keyPacket = symEncryptedSessionKeyPacketlist[i];
      try {
        keyPacket.decrypt(password);
        break;
      } catch (err) {
        if (i === symLength - 1) {
          throw err;
        }
      }
    }
    if (!keyPacket) {
      throw new Error('No symmetrically encrypted session key packet found.');
    }
  } else if (privateKey) {
    var encryptionKeyIds = this.getEncryptionKeyIds();
    if (!encryptionKeyIds.length) {
      // nothing to decrypt
      return;
    }
    var privateKeyPacket = privateKey.getKeyPacket(encryptionKeyIds);
    if (!privateKeyPacket.isDecrypted) {
      throw new Error('Private key is not decrypted.');
    }
    var pkESKeyPacketlist = this.packets.filterByTag(_enums2.default.packet.publicKeyEncryptedSessionKey);
    for (var j = 0; j < pkESKeyPacketlist.length; j++) {
      if (pkESKeyPacketlist[j].publicKeyId.equals(privateKeyPacket.getKeyId())) {
        keyPacket = pkESKeyPacketlist[j];
        keyPacket.decrypt(privateKeyPacket);
        break;
      }
    }
  } else {
    throw new Error('No key or password specified.');
  }

  if (keyPacket) {
    return {
      data: keyPacket.sessionKey,
      algorithm: keyPacket.sessionKeyAlgorithm
    };
  }
};

/**
 * Get literal data that is the body of the message
 * @return {(Uint8Array|null)} literal body of the message as Uint8Array
 */
Message.prototype.getLiteralData = function () {
  var literal = this.packets.findPacket(_enums2.default.packet.literal);
  return literal && literal.data || null;
};

/**
 * Get filename from literal data packet
 * @return {(String|null)} filename of literal data packet as string
 */
Message.prototype.getFilename = function () {
  var literal = this.packets.findPacket(_enums2.default.packet.literal);
  return literal && literal.getFilename() || null;
};

/**
 * Get literal data as text
 * @return {(String|null)} literal body of the message interpreted as text
 */
Message.prototype.getText = function () {
  var literal = this.packets.findPacket(_enums2.default.packet.literal);
  if (literal) {
    return literal.getText();
  } else {
    return null;
  }
};

/**
 * Encrypt the message either with public keys, passwords, or both at once.
 * @param  {Array<Key>} keys           (optional) public key(s) for message encryption
 * @param  {Array<String>} passwords   (optional) password(s) for message encryption
 * @return {Message}                   new message with encrypted content
 */
Message.prototype.encrypt = function (keys, passwords) {
  var _this2 = this;

  var symAlgo = void 0,
      msg = void 0,
      symEncryptedPacket = void 0;
  return Promise.resolve().then(function () {
    if (keys) {
      symAlgo = keyModule.getPreferredSymAlgo(keys);
    } else if (passwords) {
      symAlgo = _config2.default.encryption_cipher;
    } else {
      throw new Error('No keys or passwords');
    }

    var sessionKey = _crypto2.default.generateSessionKey(_enums2.default.read(_enums2.default.symmetric, symAlgo));
    msg = encryptSessionKey(sessionKey, _enums2.default.read(_enums2.default.symmetric, symAlgo), keys, passwords);

    if (_config2.default.aead_protect) {
      symEncryptedPacket = new _packet2.default.SymEncryptedAEADProtected();
    } else if (_config2.default.integrity_protect) {
      symEncryptedPacket = new _packet2.default.SymEncryptedIntegrityProtected();
    } else {
      symEncryptedPacket = new _packet2.default.SymmetricallyEncrypted();
    }
    symEncryptedPacket.packets = _this2.packets;

    return symEncryptedPacket.encrypt(_enums2.default.read(_enums2.default.symmetric, symAlgo), sessionKey);
  }).then(function () {
    msg.packets.push(symEncryptedPacket);
    symEncryptedPacket.packets = new _packet2.default.List(); // remove packets after encryption
    return msg;
  });
};

/**
 * Encrypt a session key either with public keys, passwords, or both at once.
 * @param  {Uint8Array} sessionKey     session key for encryption
 * @param  {String} symAlgo            session key algorithm
 * @param  {Array<Key>} publicKeys     (optional) public key(s) for message encryption
 * @param  {Array<String>} passwords   (optional) for message encryption
 * @return {Message}                   new message with encrypted content
 */
function encryptSessionKey(sessionKey, symAlgo, publicKeys, passwords) {
  var packetlist = new _packet2.default.List();

  if (publicKeys) {
    publicKeys.forEach(function (key) {
      var encryptionKeyPacket = key.getEncryptionKeyPacket();
      if (encryptionKeyPacket) {
        var pkESKeyPacket = new _packet2.default.PublicKeyEncryptedSessionKey();
        pkESKeyPacket.publicKeyId = encryptionKeyPacket.getKeyId();
        pkESKeyPacket.publicKeyAlgorithm = encryptionKeyPacket.algorithm;
        pkESKeyPacket.sessionKey = sessionKey;
        pkESKeyPacket.sessionKeyAlgorithm = symAlgo;
        pkESKeyPacket.encrypt(encryptionKeyPacket);
        delete pkESKeyPacket.sessionKey; // delete plaintext session key after encryption
        packetlist.push(pkESKeyPacket);
      } else {
        throw new Error('Could not find valid key packet for encryption in key ' + key.primaryKey.getKeyId().toHex());
      }
    });
  }

  if (passwords) {
    passwords.forEach(function (password) {
      var symEncryptedSessionKeyPacket = new _packet2.default.SymEncryptedSessionKey();
      symEncryptedSessionKeyPacket.sessionKey = sessionKey;
      symEncryptedSessionKeyPacket.sessionKeyAlgorithm = symAlgo;
      symEncryptedSessionKeyPacket.encrypt(password);
      delete symEncryptedSessionKeyPacket.sessionKey; // delete plaintext session key after encryption
      packetlist.push(symEncryptedSessionKeyPacket);
    });
  }

  return new Message(packetlist);
}

/**
 * Sign the message (the literal data packet of the message)
 * @param  {Array<module:key~Key>}        privateKey private keys with decrypted secret key data for signing
 * @param  {Signature} signature          (optional) any existing detached signature to add to the message
 * @return {module:message~Message}       new message with signed content
 */
Message.prototype.sign = function () {
  var privateKeys = arguments.length <= 0 || arguments[0] === undefined ? [] : arguments[0];
  var signature = arguments.length <= 1 || arguments[1] === undefined ? null : arguments[1];


  var packetlist = new _packet2.default.List();

  var literalDataPacket = this.packets.findPacket(_enums2.default.packet.literal);
  if (!literalDataPacket) {
    throw new Error('No literal data packet to sign.');
  }

  var literalFormat = _enums2.default.write(_enums2.default.literal, literalDataPacket.format);
  var signatureType = literalFormat === _enums2.default.literal.binary ? _enums2.default.signature.binary : _enums2.default.signature.text;
  var i, signingKeyPacket, existingSigPacketlist, onePassSig;

  if (signature) {
    existingSigPacketlist = signature.packets.filterByTag(_enums2.default.packet.signature);
    if (existingSigPacketlist.length) {
      for (i = existingSigPacketlist.length - 1; i >= 0; i--) {
        var sigPacket = existingSigPacketlist[i];
        onePassSig = new _packet2.default.OnePassSignature();
        onePassSig.type = signatureType;
        onePassSig.hashAlgorithm = _config2.default.prefer_hash_algorithm;
        onePassSig.publicKeyAlgorithm = sigPacket.publicKeyAlgorithm;
        onePassSig.signingKeyId = sigPacket.issuerKeyId;
        if (!privateKeys.length && i === 0) {
          onePassSig.flags = 1;
        }
        packetlist.push(onePassSig);
      }
    }
  }
  for (i = 0; i < privateKeys.length; i++) {
    if (privateKeys[i].isPublic()) {
      throw new Error('Need private key for signing');
    }
    onePassSig = new _packet2.default.OnePassSignature();
    onePassSig.type = signatureType;
    //TODO get preferred hashg algo from key signature
    onePassSig.hashAlgorithm = _config2.default.prefer_hash_algorithm;
    signingKeyPacket = privateKeys[i].getSigningKeyPacket();
    if (!signingKeyPacket) {
      throw new Error('Could not find valid key packet for signing in key ' + privateKeys[i].primaryKey.getKeyId().toHex());
    }
    onePassSig.publicKeyAlgorithm = signingKeyPacket.algorithm;
    onePassSig.signingKeyId = signingKeyPacket.getKeyId();
    if (i === privateKeys.length - 1) {
      onePassSig.flags = 1;
    }
    packetlist.push(onePassSig);
  }

  packetlist.push(literalDataPacket);

  for (i = privateKeys.length - 1; i >= 0; i--) {
    var signaturePacket = new _packet2.default.Signature();
    signaturePacket.signatureType = signatureType;
    signaturePacket.hashAlgorithm = _config2.default.prefer_hash_algorithm;
    signaturePacket.publicKeyAlgorithm = signingKeyPacket.algorithm;
    if (!signingKeyPacket.isDecrypted) {
      throw new Error('Private key is not decrypted.');
    }
    signaturePacket.sign(signingKeyPacket, literalDataPacket);
    packetlist.push(signaturePacket);
  }

  if (signature) {
    packetlist.concat(existingSigPacketlist);
  }

  return new Message(packetlist);
};

/**
 * Create a detached signature for the message (the literal data packet of the message)
 * @param  {Array<module:key~Key>}           privateKey private keys with decrypted secret key data for signing
 * @param  {Signature} signature             (optional) any existing detached signature
 * @return {module:signature~Signature}      new detached signature of message content
 */
Message.prototype.signDetached = function () {
  var privateKeys = arguments.length <= 0 || arguments[0] === undefined ? [] : arguments[0];
  var signature = arguments.length <= 1 || arguments[1] === undefined ? null : arguments[1];


  var packetlist = new _packet2.default.List();

  var literalDataPacket = this.packets.findPacket(_enums2.default.packet.literal);
  if (!literalDataPacket) {
    throw new Error('No literal data packet to sign.');
  }

  var literalFormat = _enums2.default.write(_enums2.default.literal, literalDataPacket.format);
  var signatureType = literalFormat === _enums2.default.literal.binary ? _enums2.default.signature.binary : _enums2.default.signature.text;

  for (var i = 0; i < privateKeys.length; i++) {
    var signingKeyPacket = privateKeys[i].getSigningKeyPacket();
    var signaturePacket = new _packet2.default.Signature();
    signaturePacket.signatureType = signatureType;
    signaturePacket.hashAlgorithm = _config2.default.prefer_hash_algorithm;
    signaturePacket.publicKeyAlgorithm = signingKeyPacket.algorithm;
    if (!signingKeyPacket.isDecrypted) {
      throw new Error('Private key is not decrypted.');
    }
    signaturePacket.sign(signingKeyPacket, literalDataPacket);
    packetlist.push(signaturePacket);
  }
  if (signature) {
    var existingSigPacketlist = signature.packets.filterByTag(_enums2.default.packet.signature);
    packetlist.concat(existingSigPacketlist);
  }

  return new sigModule.Signature(packetlist);
};

/**
 * Verify message signatures
 * @param {Array<module:key~Key>} keys array of keys to verify signatures
 * @return {Array<({keyid: module:type/keyid, valid: Boolean})>} list of signer's keyid and validity of signature
 */
Message.prototype.verify = function (keys) {
  var msg = this.unwrapCompressed();
  var literalDataList = msg.packets.filterByTag(_enums2.default.packet.literal);
  if (literalDataList.length !== 1) {
    throw new Error('Can only verify message with one literal data packet.');
  }
  var signatureList = msg.packets.filterByTag(_enums2.default.packet.signature);
  return createVerificationObjects(signatureList, literalDataList, keys);
};

/**
 * Verify detached message signature
 * @param {Array<module:key~Key>} keys array of keys to verify signatures
 * @param {Signature}
 * @return {Array<({keyid: module:type/keyid, valid: Boolean})>} list of signer's keyid and validity of signature
 */
Message.prototype.verifyDetached = function (signature, keys) {
  var msg = this.unwrapCompressed();
  var literalDataList = msg.packets.filterByTag(_enums2.default.packet.literal);
  if (literalDataList.length !== 1) {
    throw new Error('Can only verify message with one literal data packet.');
  }
  var signatureList = signature.packets;
  return createVerificationObjects(signatureList, literalDataList, keys);
};

/**
 * Create list of objects containing signer's keyid and validity of signature
 * @param {Array<module:packet/signature>} signatureList array of signature packets
 * @param {Array<module:packet/literal>} literalDataList array of literal data packets
 * @param {Array<module:key~Key>} keys array of keys to verify signatures
 * @return {Array<({keyid: module:type/keyid, valid: Boolean})>} list of signer's keyid and validity of signature
 */
function createVerificationObjects(signatureList, literalDataList, keys) {
  var result = [];
  for (var i = 0; i < signatureList.length; i++) {
    var keyPacket = null;
    for (var j = 0; j < keys.length; j++) {
      keyPacket = keys[j].getSigningKeyPacket(signatureList[i].issuerKeyId);
      if (keyPacket) {
        break;
      }
    }

    var verifiedSig = {};
    if (keyPacket) {
      //found a key packet that matches keyId of signature
      verifiedSig.keyid = signatureList[i].issuerKeyId;
      verifiedSig.valid = signatureList[i].verify(keyPacket, literalDataList[0]);
    } else {
      verifiedSig.keyid = signatureList[i].issuerKeyId;
      verifiedSig.valid = null;
    }

    var packetlist = new _packet2.default.List();
    packetlist.push(signatureList[i]);
    verifiedSig.signature = new sigModule.Signature(packetlist);

    result.push(verifiedSig);
  }
  return result;
}

/**
 * Unwrap compressed message
 * @return {module:message~Message} message Content of compressed message
 */
Message.prototype.unwrapCompressed = function () {
  var compressed = this.packets.filterByTag(_enums2.default.packet.compressed);
  if (compressed.length) {
    return new Message(compressed[0].packets);
  } else {
    return this;
  }
};

/**
 * Returns ASCII armored text of message
 * @return {String} ASCII armor
 */
Message.prototype.armor = function () {
  return _armor2.default.encode(_enums2.default.armor.message, this.packets.write());
};

/**
 * reads an OpenPGP armored message and returns a message object
 * @param {String} armoredText text to be parsed
 * @return {module:message~Message} new message object
 * @static
 */
function readArmored(armoredText) {
  //TODO how do we want to handle bad text? Exception throwing
  //TODO don't accept non-message armored texts
  var input = _armor2.default.decode(armoredText).data;
  return read(input);
}

/**
 * reads an OpenPGP message as byte array and returns a message object
 * @param {Uint8Array} input   binary message
 * @return {Message}           new message object
 * @static
 */
function read(input) {
  var packetlist = new _packet2.default.List();
  packetlist.read(input);
  return new Message(packetlist);
}

/**
 * Create a message object from signed content and a detached armored signature.
 * @param {String} content An 8 bit ascii string containing e.g. a MIME subtree with text nodes or attachments
 * @param {String} detachedSignature The detached ascii armored PGP signature
 */
function readSignedContent(content, detachedSignature) {
  var literalDataPacket = new _packet2.default.Literal();
  literalDataPacket.setBytes(_util2.default.str2Uint8Array(content), _enums2.default.read(_enums2.default.literal, _enums2.default.literal.binary));
  var packetlist = new _packet2.default.List();
  packetlist.push(literalDataPacket);
  var input = _armor2.default.decode(detachedSignature).data;
  packetlist.read(input);
  return new Message(packetlist);
}

/**
 * creates new message object from text
 * @param {String} text
 * @param {String} filename (optional)
 * @return {module:message~Message} new message object
 * @static
 */
function fromText(text, filename) {
  var literalDataPacket = new _packet2.default.Literal();
  // text will be converted to UTF8
  literalDataPacket.setText(text);
  if (filename !== undefined) {
    literalDataPacket.setFilename(filename);
  }
  var literalDataPacketlist = new _packet2.default.List();
  literalDataPacketlist.push(literalDataPacket);
  return new Message(literalDataPacketlist);
}

/**
 * creates new message object from binary data
 * @param {Uint8Array} bytes
 * @param {String} filename (optional)
 * @return {module:message~Message} new message object
 * @static
 */
function fromBinary(bytes, filename) {
  if (!_util2.default.isUint8Array(bytes)) {
    throw new Error('Data must be in the form of a Uint8Array');
  }

  var literalDataPacket = new _packet2.default.Literal();
  if (filename) {
    literalDataPacket.setFilename(filename);
  }
  literalDataPacket.setBytes(bytes, _enums2.default.read(_enums2.default.literal, _enums2.default.literal.binary));
  if (filename !== undefined) {
    literalDataPacket.setFilename(filename);
  }
  var literalDataPacketlist = new _packet2.default.List();
  literalDataPacketlist.push(literalDataPacket);
  return new Message(literalDataPacketlist);
}

},{"./config":10,"./crypto":24,"./encoding/armor.js":33,"./enums.js":35,"./key.js":38,"./packet":47,"./signature.js":66,"./util.js":70}],43:[function(_dereq_,module,exports){
// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2016 Tankred Hase
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @requires message
 * @requires cleartext
 * @requires key
 * @requires config
 * @requires util
 * @module openpgp
 */

/**
 * @fileoverview The openpgp base module should provide all of the functionality
 * to consume the openpgp.js library. All additional classes are documented
 * for extending and developing on top of the base library.
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.initWorker = initWorker;
exports.getWorker = getWorker;
exports.destroyWorker = destroyWorker;
exports.generateKey = generateKey;
exports.reformatKey = reformatKey;
exports.decryptKey = decryptKey;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
exports.sign = sign;
exports.verify = verify;
exports.encryptSessionKey = encryptSessionKey;
exports.decryptSessionKey = decryptSessionKey;

var _message = _dereq_('./message.js');

var messageLib = _interopRequireWildcard(_message);

var _cleartext = _dereq_('./cleartext.js');

var cleartext = _interopRequireWildcard(_cleartext);

var _key = _dereq_('./key.js');

var key = _interopRequireWildcard(_key);

var _config = _dereq_('./config/config.js');

var _config2 = _interopRequireDefault(_config);

var _util = _dereq_('./util');

var _util2 = _interopRequireDefault(_util);

var _async_proxy = _dereq_('./worker/async_proxy.js');

var _async_proxy2 = _interopRequireDefault(_async_proxy);

var _es6Promise = _dereq_('es6-promise');

var _es6Promise2 = _interopRequireDefault(_es6Promise);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

_es6Promise2.default.polyfill(); // load ES6 Promises polyfill

//////////////////////////
//                      //
//   Web Worker setup   //
//                      //
//////////////////////////

var asyncProxy = void 0; // instance of the asyncproxy

/**
 * Set the path for the web worker script and create an instance of the async proxy
 * @param {String} path     relative path to the worker scripts, default: 'openpgp.worker.js'
 * @param {Object} worker   alternative to path parameter: web worker initialized with 'openpgp.worker.js'
 */
function initWorker() {
  var _ref = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

  var _ref$path = _ref.path;
  var path = _ref$path === undefined ? 'openpgp.worker.js' : _ref$path;
  var worker = _ref.worker;

  if (worker || typeof window !== 'undefined' && window.Worker) {
    asyncProxy = new _async_proxy2.default({ path: path, worker: worker, config: _config2.default });
    return true;
  }
}

/**
 * Returns a reference to the async proxy if the worker was initialized with openpgp.initWorker()
 * @return {module:worker/async_proxy~AsyncProxy|null} the async proxy or null if not initialized
 */
function getWorker() {
  return asyncProxy;
}

/**
 * Cleanup the current instance of the web worker.
 */
function destroyWorker() {
  asyncProxy = undefined;
}

//////////////////////
//                  //
//   Key handling   //
//                  //
//////////////////////

/**
 * Generates a new OpenPGP key pair. Currently only supports RSA keys. Primary and subkey will be of same type.
 * @param  {Array<Object>} userIds   array of user IDs e.g. [{ name:'Phil Zimmermann', email:'phil@openpgp.org' }]
 * @param  {String} passphrase       (optional) The passphrase used to encrypt the resulting private key
 * @param  {Number} numBits          (optional) number of bits for the key creation. (should be 2048 or 4096)
 * @param  {Boolean} unlocked        (optional) If the returned secret part of the generated key is unlocked
 * @param  {Number} keyExpirationTime (optional) The number of seconds after the key creation time that the key expires
 * @return {Promise<Object>}         The generated key object in the form:
 *                                     { key:Key, privateKeyArmored:String, publicKeyArmored:String }
 * @static
 */
function generateKey() {
  var _ref2 = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

  var _ref2$userIds = _ref2.userIds;
  var userIds = _ref2$userIds === undefined ? [] : _ref2$userIds;
  var passphrase = _ref2.passphrase;
  var _ref2$numBits = _ref2.numBits;
  var numBits = _ref2$numBits === undefined ? 2048 : _ref2$numBits;
  var _ref2$unlocked = _ref2.unlocked;
  var unlocked = _ref2$unlocked === undefined ? false : _ref2$unlocked;
  var _ref2$keyExpirationTi = _ref2.keyExpirationTime;
  var keyExpirationTime = _ref2$keyExpirationTi === undefined ? 0 : _ref2$keyExpirationTi;

  var options = formatUserIds({ userIds: userIds, passphrase: passphrase, numBits: numBits, unlocked: unlocked, keyExpirationTime: keyExpirationTime });

  if (!_util2.default.getWebCryptoAll() && asyncProxy) {
    // use web worker if web crypto apis are not supported
    return asyncProxy.delegate('generateKey', options);
  }

  return key.generate(options).then(function (newKey) {
    return {

      key: newKey,
      privateKeyArmored: newKey.armor(),
      publicKeyArmored: newKey.toPublic().armor()

    };
  }).catch(onError.bind(null, 'Error generating keypair'));
}

/**
 * Reformats signature packets for a key and rewraps key object.
 * @param  {Array<Object>} userIds   array of user IDs e.g. [{ name:'Phil Zimmermann', email:'phil@openpgp.org' }]
 * @param  {String} passphrase       (optional) The passphrase used to encrypt the resulting private key
 * @param  {Boolean} unlocked        (optional) If the returned secret part of the generated key is unlocked
 * @param  {Number} keyExpirationTime (optional) The number of seconds after the key creation time that the key expires
 * @return {Promise<Object>}         The generated key object in the form:
 *                                     { key:Key, privateKeyArmored:String, publicKeyArmored:String }
 * @static
 */
function reformatKey() {
  var _ref3 = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

  var privateKey = _ref3.privateKey;
  var _ref3$userIds = _ref3.userIds;
  var userIds = _ref3$userIds === undefined ? [] : _ref3$userIds;
  var _ref3$passphrase = _ref3.passphrase;
  var passphrase = _ref3$passphrase === undefined ? "" : _ref3$passphrase;
  var _ref3$unlocked = _ref3.unlocked;
  var unlocked = _ref3$unlocked === undefined ? false : _ref3$unlocked;
  var _ref3$keyExpirationTi = _ref3.keyExpirationTime;
  var keyExpirationTime = _ref3$keyExpirationTi === undefined ? 0 : _ref3$keyExpirationTi;

  var options = formatUserIds({ privateKey: privateKey, userIds: userIds, passphrase: passphrase, unlocked: unlocked, keyExpirationTime: keyExpirationTime });

  if (asyncProxy) {
    return asyncProxy.delegate('reformatKey', options);
  }

  return key.reformat(options).then(function (newKey) {
    return {

      key: newKey,
      privateKeyArmored: newKey.armor(),
      publicKeyArmored: newKey.toPublic().armor()

    };
  }).catch(onError.bind(null, 'Error reformatting keypair'));
}

/**
 * Unlock a private key with your passphrase.
 * @param  {Key} privateKey      the private key that is to be decrypted
 * @param  {String} passphrase   the user's passphrase chosen during key generation
 * @return {Key}                 the unlocked private key
 */
function decryptKey(_ref4) {
  var privateKey = _ref4.privateKey;
  var passphrase = _ref4.passphrase;

  if (asyncProxy) {
    // use web worker if available
    return asyncProxy.delegate('decryptKey', { privateKey: privateKey, passphrase: passphrase });
  }

  return execute(function () {

    if (!privateKey.decrypt(passphrase)) {
      throw new Error('Invalid passphrase');
    }
    return {
      key: privateKey
    };
  }, 'Error decrypting private key');
}

///////////////////////////////////////////
//                                       //
//   Message encryption and decryption   //
//                                       //
///////////////////////////////////////////

/**
 * Encrypts message text/data with public keys, passwords or both at once. At least either public keys or passwords
 *   must be specified. If private keys are specified, those will be used to sign the message.
 * @param  {String|Uint8Array} data           text/data to be encrypted as JavaScript binary string or Uint8Array
 * @param  {Key|Array<Key>} publicKeys        (optional) array of keys or single key, used to encrypt the message
 * @param  {Key|Array<Key>} privateKeys       (optional) private keys for signing. If omitted message will not be signed
 * @param  {String|Array<String>} passwords   (optional) array of passwords or a single password to encrypt the message
 * @param  {String} filename                  (optional) a filename for the literal data packet
 * @param  {Boolean} armor                    (optional) if the return values should be ascii armored or the message/signature objects
 * @param  {Boolean} detached                 (optional) if the signature should be detached (if true, signature will be added to returned object)
 * @param  {Signature} signature              (optional) a detached signature to add to the encrypted message
 * @return {Promise<Object>}                  encrypted (and optionally signed message) in the form:
 *                                              {data: ASCII armored message if 'armor' is true,
 *                                                message: full Message object if 'armor' is false, signature: detached signature if 'detached' is true}
 * @static
 */
function encrypt(_ref5) {
  var data = _ref5.data;
  var publicKeys = _ref5.publicKeys;
  var privateKeys = _ref5.privateKeys;
  var passwords = _ref5.passwords;
  var filename = _ref5.filename;
  var _ref5$armor = _ref5.armor;
  var armor = _ref5$armor === undefined ? true : _ref5$armor;
  var _ref5$detached = _ref5.detached;
  var detached = _ref5$detached === undefined ? false : _ref5$detached;
  var _ref5$signature = _ref5.signature;
  var signature = _ref5$signature === undefined ? null : _ref5$signature;

  checkData(data);publicKeys = toArray(publicKeys);privateKeys = toArray(privateKeys);passwords = toArray(passwords);

  if (!nativeAEAD() && asyncProxy) {
    // use web worker if web crypto apis are not supported
    return asyncProxy.delegate('encrypt', { data: data, publicKeys: publicKeys, privateKeys: privateKeys, passwords: passwords, filename: filename, armor: armor, detached: detached, signature: signature });
  }
  var result = {};
  return Promise.resolve().then(function () {

    var message = createMessage(data, filename);
    if (!privateKeys) {
      privateKeys = [];
    }
    if (privateKeys.length || signature) {
      // sign the message only if private keys or signature is specified
      if (detached) {
        var detachedSignature = message.signDetached(privateKeys, signature);
        if (armor) {
          result.signature = detachedSignature.armor();
        } else {
          result.signature = detachedSignature;
        }
      } else {
        message = message.sign(privateKeys, signature);
      }
    }
    return message.encrypt(publicKeys, passwords);
  }).then(function (message) {
    if (armor) {
      result.data = message.armor();
    } else {
      result.message = message;
    }
    return result;
  }).catch(onError.bind(null, 'Error encrypting message'));
}

/**
 * Decrypts a message with the user's private key, a session key or a password. Either a private key,
 *   a session key or a password must be specified.
 * @param  {Message} message             the message object with the encrypted data
 * @param  {Key} privateKey              (optional) private key with decrypted secret key data or session key
 * @param  {Key|Array<Key>} publicKeys   (optional) array of public keys or single key, to verify signatures
 * @param  {Object} sessionKey           (optional) session key in the form: { data:Uint8Array, algorithm:String }
 * @param  {String} password             (optional) single password to decrypt the message
 * @param  {String} format               (optional) return data format either as 'utf8' or 'binary'
 * @param  {Signature} signature         (optional) detached signature for verification
 * @return {Promise<Object>}             decrypted and verified message in the form:
 *                                         { data:Uint8Array|String, filename:String, signatures:[{ keyid:String, valid:Boolean }] }
 * @static
 */
function decrypt(_ref6) {
  var message = _ref6.message;
  var privateKey = _ref6.privateKey;
  var publicKeys = _ref6.publicKeys;
  var sessionKey = _ref6.sessionKey;
  var password = _ref6.password;
  var _ref6$format = _ref6.format;
  var format = _ref6$format === undefined ? 'utf8' : _ref6$format;
  var _ref6$signature = _ref6.signature;
  var signature = _ref6$signature === undefined ? null : _ref6$signature;

  checkMessage(message);publicKeys = toArray(publicKeys);

  if (!nativeAEAD() && asyncProxy) {
    // use web worker if web crypto apis are not supported
    return asyncProxy.delegate('decrypt', { message: message, privateKey: privateKey, publicKeys: publicKeys, sessionKey: sessionKey, password: password, format: format, signature: signature });
  }

  return message.decrypt(privateKey, sessionKey, password).then(function (message) {

    var result = parseMessage(message, format);
    if (result.data) {
      // verify
      if (!publicKeys) {
        publicKeys = [];
      }
      if (signature) {
        //detached signature
        result.signatures = message.verifyDetached(signature, publicKeys);
      } else {
        result.signatures = message.verify(publicKeys);
      }
    }
    return result;
  }).catch(onError.bind(null, 'Error decrypting message'));
}

//////////////////////////////////////////
//                                      //
//   Message signing and verification   //
//                                      //
//////////////////////////////////////////

/**
 * Signs a cleartext message.
 * @param  {String | Uint8Array} data           cleartext input to be signed
 * @param  {Key|Array<Key>} privateKeys         array of keys or single key with decrypted secret key data to sign cleartext
 * @param  {Boolean} armor                      (optional) if the return value should be ascii armored or the message object
 * @param  {Boolean} detached                   (optional) if the return value should contain a detached signature
 * @return {Promise<Object>}                    signed cleartext in the form:
 *                                                {data: ASCII armored message if 'armor' is true,
 *                                                message: full Message object if 'armor' is false, signature: detached signature if 'detached' is true}
 * @static
 */
function sign(_ref7) {
  var data = _ref7.data;
  var privateKeys = _ref7.privateKeys;
  var _ref7$armor = _ref7.armor;
  var armor = _ref7$armor === undefined ? true : _ref7$armor;
  var _ref7$detached = _ref7.detached;
  var detached = _ref7$detached === undefined ? false : _ref7$detached;

  checkData(data);
  privateKeys = toArray(privateKeys);

  if (asyncProxy) {
    // use web worker if available
    return asyncProxy.delegate('sign', { data: data, privateKeys: privateKeys, armor: armor, detached: detached });
  }

  var result = {};
  return execute(function () {
    var message;

    if (_util2.default.isString(data)) {
      message = new cleartext.CleartextMessage(data);
    } else {
      message = messageLib.fromBinary(data);
    }

    if (detached) {
      var signature = message.signDetached(privateKeys);
      if (armor) {
        result.signature = signature.armor();
      } else {
        result.signature = signature;
      }
    } else {
      message = message.sign(privateKeys);
    }

    if (armor) {
      result.data = message.armor();
    } else {
      result.message = message;
    }
    return result;
  }, 'Error signing cleartext message');
}

/**
 * Verifies signatures of cleartext signed message
 * @param  {Key|Array<Key>} publicKeys   array of publicKeys or single key, to verify signatures
 * @param  {CleartextMessage} message    cleartext message object with signatures
 * @param  {Signature} signature         (optional) detached signature for verification
 * @return {Promise<Object>}             cleartext with status of verified signatures in the form of:
 *                                         { data:String, signatures: [{ keyid:String, valid:Boolean }] }
 * @static
 */
function verify(_ref8) {
  var message = _ref8.message;
  var publicKeys = _ref8.publicKeys;
  var _ref8$signature = _ref8.signature;
  var signature = _ref8$signature === undefined ? null : _ref8$signature;

  checkCleartextOrMessage(message);
  publicKeys = toArray(publicKeys);

  if (asyncProxy) {
    // use web worker if available
    return asyncProxy.delegate('verify', { message: message, publicKeys: publicKeys, signature: signature });
  }

  var result = {};
  return execute(function () {
    if (cleartext.CleartextMessage.prototype.isPrototypeOf(message)) {
      result.data = message.getText();
    } else {
      result.data = message.getLiteralData();
    }
    if (signature) {
      //detached signature
      result.signatures = message.verifyDetached(signature, publicKeys);
    } else {
      result.signatures = message.verify(publicKeys);
    }
    return result;
  }, 'Error verifying cleartext signed message');
}

///////////////////////////////////////////////
//                                           //
//   Session key encryption and decryption   //
//                                           //
///////////////////////////////////////////////

/**
 * Encrypt a symmetric session key with public keys, passwords, or both at once. At least either public keys
 *   or passwords must be specified.
 * @param  {Uint8Array} data                  the session key to be encrypted e.g. 16 random bytes (for aes128)
 * @param  {String} algorithm                 algorithm of the symmetric session key e.g. 'aes128' or 'aes256'
 * @param  {Key|Array<Key>} publicKeys        (optional) array of public keys or single key, used to encrypt the key
 * @param  {String|Array<String>} passwords   (optional) passwords for the message
 * @return {Promise<Message>}                 the encrypted session key packets contained in a message object
 * @static
 */
function encryptSessionKey(_ref9) {
  var data = _ref9.data;
  var algorithm = _ref9.algorithm;
  var publicKeys = _ref9.publicKeys;
  var passwords = _ref9.passwords;

  checkBinary(data);checkString(algorithm, 'algorithm');publicKeys = toArray(publicKeys);passwords = toArray(passwords);

  if (asyncProxy) {
    // use web worker if available
    return asyncProxy.delegate('encryptSessionKey', { data: data, algorithm: algorithm, publicKeys: publicKeys, passwords: passwords });
  }

  return execute(function () {
    return {

      message: messageLib.encryptSessionKey(data, algorithm, publicKeys, passwords)

    };
  }, 'Error encrypting session key');
}

/**
 * Decrypt a symmetric session key with a private key or password. Either a private key or
 *   a password must be specified.
 * @param  {Message} message              a message object containing the encrypted session key packets
 * @param  {Key} privateKey               (optional) private key with decrypted secret key data
 * @param  {String} password              (optional) a single password to decrypt the session key
 * @return {Promise<Object|undefined>}    decrypted session key and algorithm in object form:
 *                                          { data:Uint8Array, algorithm:String }
 *                                          or 'undefined' if no key packets found
 * @static
 */
function decryptSessionKey(_ref10) {
  var message = _ref10.message;
  var privateKey = _ref10.privateKey;
  var password = _ref10.password;

  checkMessage(message);

  if (asyncProxy) {
    // use web worker if available
    return asyncProxy.delegate('decryptSessionKey', { message: message, privateKey: privateKey, password: password });
  }

  return execute(function () {
    return message.decryptSessionKey(privateKey, password);
  }, 'Error decrypting session key');
}

//////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////

/**
 * Input validation
 */
function checkString(data, name) {
  if (!_util2.default.isString(data)) {
    throw new Error('Parameter [' + (name || 'data') + '] must be of type String');
  }
}
function checkBinary(data, name) {
  if (!_util2.default.isUint8Array(data)) {
    throw new Error('Parameter [' + (name || 'data') + '] must be of type Uint8Array');
  }
}
function checkData(data, name) {
  if (!_util2.default.isUint8Array(data) && !_util2.default.isString(data)) {
    throw new Error('Parameter [' + (name || 'data') + '] must be of type String or Uint8Array');
  }
}
function checkMessage(message) {
  if (!messageLib.Message.prototype.isPrototypeOf(message)) {
    throw new Error('Parameter [message] needs to be of type Message');
  }
}
function checkCleartextOrMessage(message) {
  if (!cleartext.CleartextMessage.prototype.isPrototypeOf(message) && !messageLib.Message.prototype.isPrototypeOf(message)) {
    throw new Error('Parameter [message] needs to be of type Message or CleartextMessage');
  }
}

/**
 * Format user ids for internal use.
 */
function formatUserIds(options) {
  if (!options.userIds) {
    return options;
  }
  options.userIds = toArray(options.userIds); // normalize to array
  options.userIds = options.userIds.map(function (id) {
    if (_util2.default.isString(id) && !_util2.default.isUserId(id)) {
      throw new Error('Invalid user id format');
    }
    if (_util2.default.isUserId(id)) {
      return id; // user id is already in correct format... no conversion necessary
    }
    // name and email address can be empty but must be of the correct type
    id.name = id.name || '';
    id.email = id.email || '';
    if (!_util2.default.isString(id.name) || id.email && !_util2.default.isEmailAddress(id.email)) {
      throw new Error('Invalid user id format');
    }
    id.name = id.name.trim();
    if (id.name.length > 0) {
      id.name += ' ';
    }
    return id.name + '<' + id.email + '>';
  });
  return options;
}

/**
 * Normalize parameter to an array if it is not undefined.
 * @param  {Object} param              the parameter to be normalized
 * @return {Array<Object>|undefined}   the resulting array or undefined
 */
function toArray(param) {
  if (param && !_util2.default.isArray(param)) {
    param = [param];
  }
  return param;
}

/**
 * Creates a message obejct either from a Uint8Array or a string.
 * @param  {String|Uint8Array} data   the payload for the message
 * @param  {String} filename          the literal data packet's filename
 * @return {Message}                  a message object
 */
function createMessage(data, filename) {
  var msg = void 0;
  if (_util2.default.isUint8Array(data)) {
    msg = messageLib.fromBinary(data, filename);
  } else if (_util2.default.isString(data)) {
    msg = messageLib.fromText(data, filename);
  } else {
    throw new Error('Data must be of type String or Uint8Array');
  }
  return msg;
}

/**
 * Parse the message given a certain format.
 * @param  {Message} message   the message object to be parse
 * @param  {String} format     the output format e.g. 'utf8' or 'binary'
 * @return {Object}            the parse data in the respective format
 */
function parseMessage(message, format) {
  if (format === 'binary') {
    return {
      data: message.getLiteralData(),
      filename: message.getFilename()
    };
  } else if (format === 'utf8') {
    return {
      data: message.getText(),
      filename: message.getFilename()
    };
  } else {
    throw new Error('Invalid format');
  }
}

/**
 * Command pattern that wraps synchronous code into a promise.
 * @param  {function} cmd     The synchronous function with a return value
 *                              to be wrapped in a promise
 * @param  {String} message   A human readable error Message
 * @return {Promise}          The promise wrapped around cmd
 */
function execute(cmd, message) {
  // wrap the sync cmd in a promise
  var promise = new Promise(function (resolve) {
    return resolve(cmd());
  });
  // handler error globally
  return promise.catch(onError.bind(null, message));
}

/**
 * Global error handler that logs the stack trace and rethrows a high lvl error message.
 * @param {String} message   A human readable high level error Message
 * @param {Error} error      The internal error that caused the failure
 */
function onError(message, error) {
  // log the stack trace
  if (_config2.default.debug) {
    console.error(error.stack);
  }
  // rethrow new high level error for api users
  throw new Error(message + ': ' + error.message);
}

/**
 * Check for AES-GCM support and configuration by the user. Only browsers that
 * implement the current WebCrypto specification support native AES-GCM.
 * @return {Boolean}   If authenticated encryption should be used
 */
function nativeAEAD() {
  return _util2.default.getWebCrypto() && _config2.default.aead_protect;
}

},{"./cleartext.js":5,"./config/config.js":9,"./key.js":38,"./message.js":42,"./util":70,"./worker/async_proxy.js":71,"es6-promise":2}],44:[function(_dereq_,module,exports){
/**
 * @requires enums
 * @module packet
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.Trust = exports.Signature = exports.SecretSubkey = exports.Userid = exports.SecretKey = exports.OnePassSignature = exports.UserAttribute = exports.PublicSubkey = exports.Marker = exports.SymmetricallyEncrypted = exports.PublicKey = exports.Literal = exports.SymEncryptedSessionKey = exports.PublicKeyEncryptedSessionKey = exports.SymEncryptedAEADProtected = exports.SymEncryptedIntegrityProtected = exports.Compressed = undefined;

var _compressed = _dereq_('./compressed.js');

Object.defineProperty(exports, 'Compressed', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_compressed).default;
  }
});

var _sym_encrypted_integrity_protected = _dereq_('./sym_encrypted_integrity_protected.js');

Object.defineProperty(exports, 'SymEncryptedIntegrityProtected', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_sym_encrypted_integrity_protected).default;
  }
});

var _sym_encrypted_aead_protected = _dereq_('./sym_encrypted_aead_protected.js');

Object.defineProperty(exports, 'SymEncryptedAEADProtected', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_sym_encrypted_aead_protected).default;
  }
});

var _public_key_encrypted_session_key = _dereq_('./public_key_encrypted_session_key.js');

Object.defineProperty(exports, 'PublicKeyEncryptedSessionKey', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_public_key_encrypted_session_key).default;
  }
});

var _sym_encrypted_session_key = _dereq_('./sym_encrypted_session_key.js');

Object.defineProperty(exports, 'SymEncryptedSessionKey', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_sym_encrypted_session_key).default;
  }
});

var _literal = _dereq_('./literal.js');

Object.defineProperty(exports, 'Literal', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_literal).default;
  }
});

var _public_key = _dereq_('./public_key.js');

Object.defineProperty(exports, 'PublicKey', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_public_key).default;
  }
});

var _symmetrically_encrypted = _dereq_('./symmetrically_encrypted.js');

Object.defineProperty(exports, 'SymmetricallyEncrypted', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_symmetrically_encrypted).default;
  }
});

var _marker = _dereq_('./marker.js');

Object.defineProperty(exports, 'Marker', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_marker).default;
  }
});

var _public_subkey = _dereq_('./public_subkey.js');

Object.defineProperty(exports, 'PublicSubkey', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_public_subkey).default;
  }
});

var _user_attribute = _dereq_('./user_attribute.js');

Object.defineProperty(exports, 'UserAttribute', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_user_attribute).default;
  }
});

var _one_pass_signature = _dereq_('./one_pass_signature.js');

Object.defineProperty(exports, 'OnePassSignature', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_one_pass_signature).default;
  }
});

var _secret_key = _dereq_('./secret_key.js');

Object.defineProperty(exports, 'SecretKey', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_secret_key).default;
  }
});

var _userid = _dereq_('./userid.js');

Object.defineProperty(exports, 'Userid', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_userid).default;
  }
});

var _secret_subkey = _dereq_('./secret_subkey.js');

Object.defineProperty(exports, 'SecretSubkey', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_secret_subkey).default;
  }
});

var _signature = _dereq_('./signature.js');

Object.defineProperty(exports, 'Signature', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_signature).default;
  }
});

var _trust = _dereq_('./trust.js');

Object.defineProperty(exports, 'Trust', {
  enumerable: true,
  get: function get() {
    return _interopRequireDefault(_trust).default;
  }
});
exports.newPacketFromTag = newPacketFromTag;
exports.fromStructuredClone = fromStructuredClone;

var _enums = _dereq_('../enums.js');

var _enums2 = _interopRequireDefault(_enums);

var _all_packets = _dereq_('./all_packets.js');

var packets = _interopRequireWildcard(_all_packets);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * Allocate a new packet
 * @param {String} tag property name from {@link module:enums.packet}
 * @returns {Object} new packet object with type based on tag
 */
function newPacketFromTag(tag) {
  return new packets[packetClassFromTagName(tag)]();
}

/**
 * Allocate a new packet from structured packet clone
 * See {@link http://www.w3.org/html/wg/drafts/html/master/infrastructure.html#safe-passing-of-structured-data}
 * @param {Object} packetClone packet clone
 * @returns {Object} new packet object with data from packet clone
 */
function fromStructuredClone(packetClone) {
  var tagName = _enums2.default.read(_enums2.default.packet, packetClone.tag);
  var packet = newPacketFromTag(tagName);
  for (var attr in packetClone) {
    if (packetClone.hasOwnProperty(attr)) {
      packet[attr] = packetClone[attr];
    }
  }
  if (packet.postCloneTypeFix) {
    packet.postCloneTypeFix();
  }
  return packet;
}

/**
 * Convert tag name to class name
 * @param {String} tag property name from {@link module:enums.packet}
 * @returns {String}
 */
function packetClassFromTagName(tag) {
  return tag.substr(0, 1).toUpperCase() + tag.substr(1);
}

},{"../enums.js":35,"./all_packets.js":44,"./compressed.js":46,"./literal.js":48,"./marker.js":49,"./one_pass_signature.js":50,"./public_key.js":53,"./public_key_encrypted_session_key.js":54,"./public_subkey.js":55,"./secret_key.js":56,"./secret_subkey.js":57,"./signature.js":58,"./sym_encrypted_aead_protected.js":59,"./sym_encrypted_integrity_protected.js":60,"./sym_encrypted_session_key.js":61,"./symmetrically_encrypted.js":62,"./trust.js":63,"./user_attribute.js":64,"./userid.js":65}],45:[function(_dereq_,module,exports){
// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2015 Tankred Hase
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @fileoverview This module implements packet list cloning required to
 * pass certain object types beteen the web worker and main thread using
 * the structured cloning algorithm.
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.clonePackets = clonePackets;
exports.parseClonedPackets = parseClonedPackets;

var _key = _dereq_('../key.js');

var key = _interopRequireWildcard(_key);

var _message = _dereq_('../message.js');

var message = _interopRequireWildcard(_message);

var _cleartext = _dereq_('../cleartext.js');

var cleartext = _interopRequireWildcard(_cleartext);

var _signature = _dereq_('../signature.js');

var signature = _interopRequireWildcard(_signature);

var _packetlist = _dereq_('./packetlist.js');

var _packetlist2 = _interopRequireDefault(_packetlist);

var _keyid = _dereq_('../type/keyid.js');

var _keyid2 = _interopRequireDefault(_keyid);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

//////////////////////////////
//                          //
//   Packetlist --> Clone   //
//                          //
//////////////////////////////

/**
 * Create a packetlist from the correspoding object types.
 * @param  {Object} options   the object passed to and from the web worker
 * @return {Object}           a mutated version of the options optject
 */
function clonePackets(options) {
  if (options.publicKeys) {
    options.publicKeys = options.publicKeys.map(function (key) {
      return key.toPacketlist();
    });
  }
  if (options.privateKeys) {
    options.privateKeys = options.privateKeys.map(function (key) {
      return key.toPacketlist();
    });
  }
  if (options.privateKey) {
    options.privateKey = options.privateKey.toPacketlist();
  }
  if (options.key) {
    options.key = options.key.toPacketlist();
  }
  if (options.message) {
    //could be either a Message or CleartextMessage object
    if (options.message instanceof message.Message) {
      options.message = options.message.packets;
    } else if (options.message instanceof cleartext.CleartextMessage) {
      options.message.signature = options.message.signature.packets;
    }
  }
  if (options.signature && options.signature instanceof signature.Signature) {
    options.signature = options.signature.packets;
  }
  if (options.signatures) {
    options.signatures = options.signatures.map(function (sig) {
      return verificationObjectToClone(sig);
    });
  }
  return options;
}

function verificationObjectToClone(verObject) {
  verObject.signature = verObject.signature.packets;
  return verObject;
}

//////////////////////////////
//                          //
//   Clone --> Packetlist   //
//                          //
//////////////////////////////

/**
 * Creates an object with the correct prototype from a corresponding packetlist.
 * @param  {Object} options   the object passed to and from the web worker
 * @param  {String} method    the public api function name to be delegated to the worker
 * @return {Object}           a mutated version of the options optject
 */
function parseClonedPackets(options, method) {
  if (options.publicKeys) {
    options.publicKeys = options.publicKeys.map(packetlistCloneToKey);
  }
  if (options.privateKeys) {
    options.privateKeys = options.privateKeys.map(packetlistCloneToKey);
  }
  if (options.privateKey) {
    options.privateKey = packetlistCloneToKey(options.privateKey);
  }
  if (options.key) {
    options.key = packetlistCloneToKey(options.key);
  }
  if (options.message && options.message.signature) {
    options.message = packetlistCloneToCleartextMessage(options.message);
  } else if (options.message) {
    options.message = packetlistCloneToMessage(options.message);
  }
  if (options.signatures) {
    options.signatures = options.signatures.map(packetlistCloneToSignatures);
  }
  if (options.signature) {
    options.signature = packetlistCloneToSignature(options.signature);
  }
  return options;
}

function packetlistCloneToKey(clone) {
  var packetlist = _packetlist2.default.fromStructuredClone(clone);
  return new key.Key(packetlist);
}

function packetlistCloneToMessage(clone) {
  var packetlist = _packetlist2.default.fromStructuredClone(clone);
  return new message.Message(packetlist);
}

function packetlistCloneToCleartextMessage(clone) {
  var packetlist = _packetlist2.default.fromStructuredClone(clone.signature);
  return new cleartext.CleartextMessage(clone.text, new signature.Signature(packetlist));
}

//verification objects
function packetlistCloneToSignatures(clone) {
  clone.keyid = _keyid2.default.fromClone(clone.keyid);
  clone.signature = new signature.Signature(clone.signature);
  return clone;
}

function packetlistCloneToSignature(clone) {
  if (typeof clone === "string") {
    //signature is armored
    return clone;
  }
  var packetlist = _packetlist2.default.fromStructuredClone(clone);
  return new signature.Signature(packetlist);
}

},{"../cleartext.js":5,"../key.js":38,"../message.js":42,"../signature.js":66,"../type/keyid.js":67,"./packetlist.js":52}],46:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the Compressed Data Packet (Tag 8)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.6|RFC4880 5.6}: The Compressed Data packet contains compressed data.  Typically,
 * this packet is found as the contents of an encrypted packet, or following
 * a Signature or One-Pass Signature packet, and contains a literal data packet.
 * @requires compression/zlib
 * @requires compression/rawinflate
 * @requires compression/rawdeflate
 * @requires enums
 * @requires util
 * @module packet/compressed
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = Compressed;

var _enums = _dereq_('../enums.js');

var _enums2 = _interopRequireDefault(_enums);

var _util = _dereq_('../util.js');

var _util2 = _interopRequireDefault(_util);

var _zlibMin = _dereq_('../compression/zlib.min.js');

var _zlibMin2 = _interopRequireDefault(_zlibMin);

var _rawinflateMin = _dereq_('../compression/rawinflate.min.js');

var _rawinflateMin2 = _interopRequireDefault(_rawinflateMin);

var _rawdeflateMin = _dereq_('../compression/rawdeflate.min.js');

var _rawdeflateMin2 = _interopRequireDefault(_rawdeflateMin);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @constructor
 */
function Compressed() {
  /**
   * Packet type
   * @type {module:enums.packet}
   */
  this.tag = _enums2.default.packet.compressed;
  /**
   * List of packets
   * @type {module:packet/packetlist}
   */
  this.packets = null;
  /**
   * Compression algorithm
   * @type {compression}
   */
  this.algorithm = 'zip';

  /**
   * Compressed packet data
   * @type {String}
   */
  this.compressed = null;
}

/**
 * Parsing function for the packet.
 * @param {String} bytes Payload of a tag 8 packet
 */
Compressed.prototype.read = function (bytes) {
  // One octet that gives the algorithm used to compress the packet.
  this.algorithm = _enums2.default.read(_enums2.default.compression, bytes[0]);

  // Compressed data, which makes up the remainder of the packet.
  this.compressed = bytes.subarray(1, bytes.length);

  this.decompress();
};

/**
 * Return the compressed packet.
 * @return {String} binary compressed packet
 */
Compressed.prototype.write = function () {
  if (this.compressed === null) {
    this.compress();
  }

  return _util2.default.concatUint8Array(new Uint8Array([_enums2.default.write(_enums2.default.compression, this.algorithm)]), this.compressed);
};

/**
 * Decompression method for decompressing the compressed data
 * read by read_packet
 */
Compressed.prototype.decompress = function () {
  var decompressed, inflate;

  switch (this.algorithm) {
    case 'uncompressed':
      decompressed = this.compressed;
      break;

    case 'zip':
      inflate = new _rawinflateMin2.default.Zlib.RawInflate(this.compressed);
      decompressed = inflate.decompress();
      break;

    case 'zlib':
      inflate = new _zlibMin2.default.Zlib.Inflate(this.compressed);
      decompressed = inflate.decompress();
      break;

    case 'bzip2':
      // TODO: need to implement this
      throw new Error('Compression algorithm BZip2 [BZ2] is not implemented.');

    default:
      throw new Error("Compression algorithm unknown :" + this.algorithm);
  }

  this.packets.read(decompressed);
};

/**
 * Compress the packet data (member decompressedData)
 */
Compressed.prototype.compress = function () {
  var uncompressed, deflate;
  uncompressed = this.packets.write();

  switch (this.algorithm) {

    case 'uncompressed':
      // - Uncompressed
      this.compressed = uncompressed;
      break;

    case 'zip':
      // - ZIP [RFC1951]
      deflate = new _rawdeflateMin2.default.Zlib.RawDeflate(uncompressed);
      this.compressed = deflate.compress();
      break;

    case 'zlib':
      // - ZLIB [RFC1950]
      deflate = new _zlibMin2.default.Zlib.Deflate(uncompressed);
      this.compressed = deflate.compress();
      break;

    case 'bzip2':
      //  - BZip2 [BZ2]
      // TODO: need to implement this
      throw new Error("Compression algorithm BZip2 [BZ2] is not implemented.");

    default:
      throw new Error("Compression algorithm unknown :" + this.type);
  }
};

},{"../compression/rawdeflate.min.js":6,"../compression/rawinflate.min.js":7,"../compression/zlib.min.js":8,"../enums.js":35,"../util.js":70}],47:[function(_dereq_,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _all_packets = _dereq_('./all_packets.js');

var packets = _interopRequireWildcard(_all_packets);

var _clone = _dereq_('./clone.js');

var clone = _interopRequireWildcard(_clone);

var _packetlist = _dereq_('./packetlist.js');

var _packetlist2 = _interopRequireDefault(_packetlist);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

var mod = {
  /** @see module:packet/packetlist */
  List: _packetlist2.default,
  /** @see module:packet/clone */
  clone: clone
};

for (var i in packets) {
  mod[i] = packets[i];
}

exports.default = mod;

},{"./all_packets.js":44,"./clone.js":45,"./packetlist.js":52}],48:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the Literal Data Packet (Tag 11)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.9|RFC4880 5.9}: A Literal Data packet contains the body of a message; data that
 * is not to be further interpreted.
 * @requires enums
 * @requires util
 * @module packet/literal
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = Literal;

var _util = _dereq_('../util.js');

var _util2 = _interopRequireDefault(_util);

var _enums = _dereq_('../enums.js');

var _enums2 = _interopRequireDefault(_enums);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @constructor
 */
function Literal() {
  this.tag = _enums2.default.packet.literal;
  this.format = 'utf8'; // default format for literal data packets
  this.date = new Date();
  this.data = new Uint8Array(0); // literal data representation
  this.filename = 'msg.txt';
}

/**
 * Set the packet data to a javascript native string, end of line
 * will be normalized to \r\n and by default text is converted to UTF8
 * @param {String} text Any native javascript string
 */
Literal.prototype.setText = function (text) {
  // normalize EOL to \r\n
  text = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/\n/g, '\r\n');
  // encode UTF8
  this.data = this.format === 'utf8' ? _util2.default.str2Uint8Array(_util2.default.encode_utf8(text)) : _util2.default.str2Uint8Array(text);
};

/**
 * Returns literal data packets as native JavaScript string
 * with normalized end of line to \n
 * @return {String} literal data as text
 */
Literal.prototype.getText = function () {
  // decode UTF8
  var text = _util2.default.decode_utf8(_util2.default.Uint8Array2str(this.data));
  // normalize EOL to \n
  return text.replace(/\r\n/g, '\n');
};

/**
 * Set the packet data to value represented by the provided string of bytes.
 * @param {Uint8Array} bytes The string of bytes
 * @param {utf8|binary|text} format The format of the string of bytes
 */
Literal.prototype.setBytes = function (bytes, format) {
  this.format = format;
  this.data = bytes;
};

/**
 * Get the byte sequence representing the literal packet data
 * @returns {Uint8Array} A sequence of bytes
 */
Literal.prototype.getBytes = function () {
  return this.data;
};

/**
 * Sets the filename of the literal packet data
 * @param {String} filename Any native javascript string
 */
Literal.prototype.setFilename = function (filename) {
  this.filename = filename;
};

/**
 * Get the filename of the literal packet data
 * @returns {String} filename
 */
Literal.prototype.getFilename = function () {
  return this.filename;
};

/**
 * Parsing function for a literal data packet (tag 11).
 *
 * @param {Uint8Array} input Payload of a tag 11 packet
 * @return {module:packet/literal} object representation
 */
Literal.prototype.read = function (bytes) {
  // - A one-octet field that describes how the data is formatted.
  var format = _enums2.default.read(_enums2.default.literal, bytes[0]);

  var filename_len = bytes[1];
  this.filename = _util2.default.decode_utf8(_util2.default.Uint8Array2str(bytes.subarray(2, 2 + filename_len)));

  this.date = _util2.default.readDate(bytes.subarray(2 + filename_len, 2 + filename_len + 4));

  var data = bytes.subarray(6 + filename_len, bytes.length);

  this.setBytes(data, format);
};

/**
 * Creates a string representation of the packet
 *
 * @return {Uint8Array} Uint8Array representation of the packet
 */
Literal.prototype.write = function () {
  var filename = _util2.default.str2Uint8Array(_util2.default.encode_utf8(this.filename));
  var filename_length = new Uint8Array([filename.length]);

  var format = new Uint8Array([_enums2.default.write(_enums2.default.literal, this.format)]);
  var date = _util2.default.writeDate(this.date);
  var data = this.getBytes();

  return _util2.default.concatUint8Array([format, filename_length, filename, date, data]);
};

},{"../enums.js":35,"../util.js":70}],49:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the strange "Marker packet" (Tag 10)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.8|RFC4880 5.8}: An experimental version of PGP used this packet as the Literal
 * packet, but no released version of PGP generated Literal packets with this
 * tag. With PGP 5.x, this packet has been reassigned and is reserved for use as
 * the Marker packet.<br/>
 * <br/>
 * Such a packet MUST be ignored when received.
 * @requires enums
 * @module packet/marker
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = Marker;

var _enums = _dereq_('../enums.js');

var _enums2 = _interopRequireDefault(_enums);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @constructor
 */
function Marker() {
  this.tag = _enums2.default.packet.marker;
}

/**
 * Parsing function for a literal data packet (tag 10).
 *
 * @param {String} input Payload of a tag 10 packet
 * @param {Integer} position
 *            Position to start reading from the input string
 * @param {Integer} len
 *            Length of the packet or the remaining length of
 *            input at position
 * @return {module:packet/marker} Object representation
 */
Marker.prototype.read = function (bytes) {
  if (bytes[0] === 0x50 && // P
  bytes[1] === 0x47 && // G
  bytes[2] === 0x50) {
    // P
    return true;
  }
  // marker packet does not contain "PGP"
  return false;
};

},{"../enums.js":35}],50:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the One-Pass Signature Packets (Tag 4)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.4|RFC4880 5.4}: The One-Pass Signature packet precedes the signed data and contains
 * enough information to allow the receiver to begin calculating any
 * hashes needed to verify the signature.  It allows the Signature
 * packet to be placed at the end of the message, so that the signer
 * can compute the entire signed message in one pass.
* @requires util
 * @requires enums
 * @requires type/keyid
 * @module packet/one_pass_signature
*/

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = OnePassSignature;

var _util = _dereq_('../util.js');

var _util2 = _interopRequireDefault(_util);

var _enums = _dereq_('../enums.js');

var _enums2 = _interopRequireDefault(_enums);

var _keyid = _dereq_('../type/keyid.js');

var _keyid2 = _interopRequireDefault(_keyid);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @constructor
 */
function OnePassSignature() {
  this.tag = _enums2.default.packet.onePassSignature; // The packet type
  this.version = null; // A one-octet version number.  The current version is 3.
  this.type = null; // A one-octet signature type.  Signature types are described in {@link http://tools.ietf.org/html/rfc4880#section-5.2.1|RFC4880 Section 5.2.1}.
  this.hashAlgorithm = null; // A one-octet number describing the hash algorithm used. (See {@link http://tools.ietf.org/html/rfc4880#section-9.4|RFC4880 9.4})
  this.publicKeyAlgorithm = null; // A one-octet number describing the public-key algorithm used. (See {@link http://tools.ietf.org/html/rfc4880#section-9.1|RFC4880 9.1})
  this.signingKeyId = null; // An eight-octet number holding the Key ID of the signing key.
  this.flags = null; //  A one-octet number holding a flag showing whether the signature is nested.  A zero value indicates that the next packet is another One-Pass Signature packet that describes another signature to be applied to the same message data.
}

/**
 * parsing function for a one-pass signature packet (tag 4).
 * @param {Uint8Array} bytes payload of a tag 4 packet
 * @return {module:packet/one_pass_signature} object representation
 */
OnePassSignature.prototype.read = function (bytes) {
  var mypos = 0;
  // A one-octet version number.  The current version is 3.
  this.version = bytes[mypos++];

  // A one-octet signature type.  Signature types are described in
  //   Section 5.2.1.
  this.type = _enums2.default.read(_enums2.default.signature, bytes[mypos++]);

  // A one-octet number describing the hash algorithm used.
  this.hashAlgorithm = _enums2.default.read(_enums2.default.hash, bytes[mypos++]);

  // A one-octet number describing the public-key algorithm used.
  this.publicKeyAlgorithm = _enums2.default.read(_enums2.default.publicKey, bytes[mypos++]);

  // An eight-octet number holding the Key ID of the signing key.
  this.signingKeyId = new _keyid2.default();
  this.signingKeyId.read(bytes.subarray(mypos, mypos + 8));
  mypos += 8;

  // A one-octet number holding a flag showing whether the signature
  //   is nested.  A zero value indicates that the next packet is
  //   another One-Pass Signature packet that describes another
  //   signature to be applied to the same message data.
  this.flags = bytes[mypos++];
  return this;
};

/**
 * creates a string representation of a one-pass signature packet
 * @return {Uint8Array} a Uint8Array representation of a one-pass signature packet
 */
OnePassSignature.prototype.write = function () {

  var start = new Uint8Array([3, _enums2.default.write(_enums2.default.signature, this.type), _enums2.default.write(_enums2.default.hash, this.hashAlgorithm), _enums2.default.write(_enums2.default.publicKey, this.publicKeyAlgorithm)]);

  var end = new Uint8Array([this.flags]);

  return _util2.default.concatUint8Array([start, this.signingKeyId.write(), end]);
};

/**
 * Fix custom types after cloning
 */
OnePassSignature.prototype.postCloneTypeFix = function () {
  this.signingKeyId = _keyid2.default.fromClone(this.signingKeyId);
};

},{"../enums.js":35,"../type/keyid.js":67,"../util.js":70}],51:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @requires enums
 * @requires util
 * @module packet/packet
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _util = _dereq_('../util.js');

var _util2 = _interopRequireDefault(_util);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = {
  readSimpleLength: function readSimpleLength(bytes) {
    var len = 0,
        offset,
        type = bytes[0];

    if (type < 192) {
      len = bytes[0];
      offset = 1;
    } else if (type < 255) {
      len = (bytes[0] - 192 << 8) + bytes[1] + 192;
      offset = 2;
    } else if (type === 255) {
      len = _util2.default.readNumber(bytes.subarray(1, 1 + 4));
      offset = 5;
    }

    return {
      len: len,
      offset: offset
    };
  },

  /**
   * Encodes a given integer of length to the openpgp length specifier to a
   * string
   *
   * @param {Integer} length The length to encode
   * @return {Uint8Array} String with openpgp length representation
   */
  writeSimpleLength: function writeSimpleLength(length) {

    if (length < 192) {
      return new Uint8Array([length]);
    } else if (length > 191 && length < 8384) {
      /*
       * let a = (total data packet length) - 192 let bc = two octet
       * representation of a let d = b + 192
       */
      return new Uint8Array([(length - 192 >> 8) + 192, length - 192 & 0xFF]);
    } else {
      return _util2.default.concatUint8Array([new Uint8Array([255]), _util2.default.writeNumber(length, 4)]);
    }
  },

  /**
   * Writes a packet header version 4 with the given tag_type and length to a
   * string
   *
   * @param {Integer} tag_type Tag type
   * @param {Integer} length Length of the payload
   * @return {String} String of the header
   */
  writeHeader: function writeHeader(tag_type, length) {
    /* we're only generating v4 packet headers here */
    return _util2.default.concatUint8Array([new Uint8Array([0xC0 | tag_type]), this.writeSimpleLength(length)]);
  },

  /**
   * Writes a packet header Version 3 with the given tag_type and length to a
   * string
   *
   * @param {Integer} tag_type Tag type
   * @param {Integer} length Length of the payload
   * @return {String} String of the header
   */
  writeOldHeader: function writeOldHeader(tag_type, length) {

    if (length < 256) {
      return new Uint8Array([0x80 | tag_type << 2, length]);
    } else if (length < 65536) {
      return _util2.default.concatUint8Array([new Uint8Array([0x80 | tag_type << 2 | 1]), _util2.default.writeNumber(length, 2)]);
    } else {
      return _util2.default.concatUint8Array([new Uint8Array([0x80 | tag_type << 2 | 2]), _util2.default.writeNumber(length, 4)]);
    }
  },

  /**
   * Generic static Packet Parser function
   *
   * @param {String} input Input stream as string
   * @param {integer} position Position to start parsing
   * @param {integer} len Length of the input from position on
   * @return {Object} Returns a parsed module:packet/packet
   */
  read: function read(input, position, len) {
    // some sanity checks
    if (input === null || input.length <= position || input.subarray(position, input.length).length < 2 || (input[position] & 0x80) === 0) {
      throw new Error("Error during parsing. This message / key probably does not conform to a valid OpenPGP format.");
    }
    var mypos = position;
    var tag = -1;
    var format = -1;
    var packet_length;

    format = 0; // 0 = old format; 1 = new format
    if ((input[mypos] & 0x40) !== 0) {
      format = 1;
    }

    var packet_length_type;
    if (format) {
      // new format header
      tag = input[mypos] & 0x3F; // bit 5-0
    } else {
      // old format header
      tag = (input[mypos] & 0x3F) >> 2; // bit 5-2
      packet_length_type = input[mypos] & 0x03; // bit 1-0
    }

    // header octet parsing done
    mypos++;

    // parsed length from length field
    var bodydata = null;

    // used for partial body lengths
    var real_packet_length = -1;
    if (!format) {
      // 4.2.1. Old Format Packet Lengths
      switch (packet_length_type) {
        case 0:
          // The packet has a one-octet length. The header is 2 octets
          // long.
          packet_length = input[mypos++];
          break;
        case 1:
          // The packet has a two-octet length. The header is 3 octets
          // long.
          packet_length = input[mypos++] << 8 | input[mypos++];
          break;
        case 2:
          // The packet has a four-octet length. The header is 5
          // octets long.
          packet_length = input[mypos++] << 24 | input[mypos++] << 16 | input[mypos++] << 8 | input[mypos++];
          break;
        default:
          // 3 - The packet is of indeterminate length. The header is 1
          // octet long, and the implementation must determine how long
          // the packet is. If the packet is in a file, this means that
          // the packet extends until the end of the file. In general,
          // an implementation SHOULD NOT use indeterminate-length
          // packets except where the end of the data will be clear
          // from the context, and even then it is better to use a
          // definite length, or a new format header. The new format
          // headers described below have a mechanism for precisely
          // encoding data of indeterminate length.
          packet_length = len;
          break;
      }
    } else // 4.2.2. New Format Packet Lengths
      {

        // 4.2.2.1. One-Octet Lengths
        if (input[mypos] < 192) {
          packet_length = input[mypos++];
          _util2.default.print_debug("1 byte length:" + packet_length);
          // 4.2.2.2. Two-Octet Lengths
        } else if (input[mypos] >= 192 && input[mypos] < 224) {
          packet_length = (input[mypos++] - 192 << 8) + input[mypos++] + 192;
          _util2.default.print_debug("2 byte length:" + packet_length);
          // 4.2.2.4. Partial Body Lengths
        } else if (input[mypos] > 223 && input[mypos] < 255) {
          packet_length = 1 << (input[mypos++] & 0x1F);
          _util2.default.print_debug("4 byte length:" + packet_length);
          // EEEK, we're reading the full data here...
          var mypos2 = mypos + packet_length;
          bodydata = [input.subarray(mypos, mypos + packet_length)];
          var tmplen;
          while (true) {
            if (input[mypos2] < 192) {
              tmplen = input[mypos2++];
              packet_length += tmplen;
              bodydata.push(input.subarray(mypos2, mypos2 + tmplen));
              mypos2 += tmplen;
              break;
            } else if (input[mypos2] >= 192 && input[mypos2] < 224) {
              tmplen = (input[mypos2++] - 192 << 8) + input[mypos2++] + 192;
              packet_length += tmplen;
              bodydata.push(input.subarray(mypos2, mypos2 + tmplen));
              mypos2 += tmplen;
              break;
            } else if (input[mypos2] > 223 && input[mypos2] < 255) {
              tmplen = 1 << (input[mypos2++] & 0x1F);
              packet_length += tmplen;
              bodydata.push(input.subarray(mypos2, mypos2 + tmplen));
              mypos2 += tmplen;
            } else {
              mypos2++;
              tmplen = input[mypos2++] << 24 | input[mypos2++] << 16 | input[mypos2++] << 8 | input[mypos2++];
              bodydata.push(input.subarray(mypos2, mypos2 + tmplen));
              packet_length += tmplen;
              mypos2 += tmplen;
              break;
            }
          }
          real_packet_length = mypos2 - mypos;
          // 4.2.2.3. Five-Octet Lengths
        } else {
          mypos++;
          packet_length = input[mypos++] << 24 | input[mypos++] << 16 | input[mypos++] << 8 | input[mypos++];
        }
      }

    // if there was'nt a partial body length: use the specified
    // packet_length
    if (real_packet_length === -1) {
      real_packet_length = packet_length;
    }

    if (bodydata === null) {
      bodydata = input.subarray(mypos, mypos + real_packet_length);
    } else if (bodydata instanceof Array) {
      bodydata = _util2.default.concatUint8Array(bodydata);
    }

    return {
      tag: tag,
      packet: bodydata,
      offset: mypos + real_packet_length
    };
  }
};

},{"../util.js":70}],52:[function(_dereq_,module,exports){
/**
 * This class represents a list of openpgp packets.
 * Take care when iterating over it - the packets themselves
 * are stored as numerical indices.
 * @requires util
 * @requires enums
 * @requires packet
 * @requires packet/packet
 * @module packet/packetlist
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = Packetlist;

var _util = _dereq_('../util');

var _util2 = _interopRequireDefault(_util);

var _packet = _dereq_('./packet.js');

var _packet2 = _interopRequireDefault(_packet);

var _all_packets = _dereq_('./all_packets.js');

var packets = _interopRequireWildcard(_all_packets);

var _enums = _dereq_('../enums.js');

var _enums2 = _interopRequireDefault(_enums);

var _config = _dereq_('../config');

var _config2 = _interopRequireDefault(_config);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @constructor
 */
function Packetlist() {
  /** The number of packets contained within the list.
   * @readonly
   * @type {Integer} */
  this.length = 0;
}
/**
 * Reads a stream of binary data and interprents it as a list of packets.
 * @param {Uint8Array} A Uint8Array of bytes.
 */
Packetlist.prototype.read = function (bytes) {
  var i = 0;

  while (i < bytes.length) {
    var parsed = _packet2.default.read(bytes, i, bytes.length - i);
    i = parsed.offset;

    var pushed = false;
    try {
      var tag = _enums2.default.read(_enums2.default.packet, parsed.tag);
      var packet = packets.newPacketFromTag(tag);
      this.push(packet);
      pushed = true;
      packet.read(parsed.packet);
    } catch (e) {
      if (!_config2.default.tolerant || parsed.tag == _enums2.default.packet.symmetricallyEncrypted || parsed.tag == _enums2.default.packet.literal || parsed.tag == _enums2.default.packet.compressed) {
        throw e;
      }
      if (pushed) {
        this.pop(); // drop unsupported packet
      }
    }
  }
};

/**
 * Creates a binary representation of openpgp objects contained within the
 * class instance.
 * @returns {Uint8Array} A Uint8Array containing valid openpgp packets.
 */
Packetlist.prototype.write = function () {
  var arr = [];

  for (var i = 0; i < this.length; i++) {
    var packetbytes = this[i].write();
    arr.push(_packet2.default.writeHeader(this[i].tag, packetbytes.length));
    arr.push(packetbytes);
  }

  return _util2.default.concatUint8Array(arr);
};

/**
 * Adds a packet to the list. This is the only supported method of doing so;
 * writing to packetlist[i] directly will result in an error.
 */
Packetlist.prototype.push = function (packet) {
  if (!packet) {
    return;
  }

  packet.packets = packet.packets || new Packetlist();

  this[this.length] = packet;
  this.length++;
};

/**
 * Remove a packet from the list and return it.
 * @return {Object}   The packet that was removed
 */
Packetlist.prototype.pop = function () {
  if (this.length === 0) {
    return;
  }

  var packet = this[this.length - 1];
  delete this[this.length - 1];
  this.length--;

  return packet;
};

/**
* Creates a new PacketList with all packets that pass the test implemented by the provided function.
*/
Packetlist.prototype.filter = function (callback) {

  var filtered = new Packetlist();

  for (var i = 0; i < this.length; i++) {
    if (callback(this[i], i, this)) {
      filtered.push(this[i]);
    }
  }

  return filtered;
};

/**
* Creates a new PacketList with all packets from the given types
*/
Packetlist.prototype.filterByTag = function () {
  var args = Array.prototype.slice.call(arguments);
  var filtered = new Packetlist();
  var that = this;

  function handle(packetType) {
    return that[i].tag === packetType;
  }
  for (var i = 0; i < this.length; i++) {
    if (args.some(handle)) {
      filtered.push(this[i]);
    }
  }

  return filtered;
};

/**
* Executes the provided callback once for each element
*/
Packetlist.prototype.forEach = function (callback) {
  for (var i = 0; i < this.length; i++) {
    callback(this[i]);
  }
};

/**
 * Traverses packet tree and returns first matching packet
 * @param  {module:enums.packet} type The packet type
 * @return {module:packet/packet|null}
 */
Packetlist.prototype.findPacket = function (type) {
  var packetlist = this.filterByTag(type);
  if (packetlist.length) {
    return packetlist[0];
  } else {
    var found = null;
    for (var i = 0; i < this.length; i++) {
      if (this[i].packets.length) {
        found = this[i].packets.findPacket(type);
        if (found) {
          return found;
        }
      }
    }
  }
  return null;
};

/**
 * Returns array of found indices by tag
 */
Packetlist.prototype.indexOfTag = function () {
  var args = Array.prototype.slice.call(arguments);
  var tagIndex = [];
  var that = this;

  function handle(packetType) {
    return that[i].tag === packetType;
  }
  for (var i = 0; i < this.length; i++) {
    if (args.some(handle)) {
      tagIndex.push(i);
    }
  }
  return tagIndex;
};

/**
 * Returns slice of packetlist
 */
Packetlist.prototype.slice = function (begin, end) {
  if (!end) {
    end = this.length;
  }
  var part = new Packetlist();
  for (var i = begin; i < end; i++) {
    part.push(this[i]);
  }
  return part;
};

/**
 * Concatenates packetlist or array of packets
 */
Packetlist.prototype.concat = function (packetlist) {
  if (packetlist) {
    for (var i = 0; i < packetlist.length; i++) {
      this.push(packetlist[i]);
    }
  }
};

/**
 * Allocate a new packetlist from structured packetlist clone
 * See {@link http://www.w3.org/html/wg/drafts/html/master/infrastructure.html#safe-passing-of-structured-data}
 * @param {Object} packetClone packetlist clone
 * @returns {Object} new packetlist object with data from packetlist clone
 */
Packetlist.fromStructuredClone = function (packetlistClone) {
  var packetlist = new Packetlist();
  for (var i = 0; i < packetlistClone.length; i++) {
    packetlist.push(packets.fromStructuredClone(packetlistClone[i]));
    if (packetlist[i].packets.length !== 0) {
      packetlist[i].packets = this.fromStructuredClone(packetlist[i].packets);
    } else {
      packetlist[i].packets = new Packetlist();
    }
  }
  return packetlist;
};

},{"../config":10,"../enums.js":35,"../util":70,"./all_packets.js":44,"./packet.js":51}],53:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the Key Material Packet (Tag 5,6,7,14)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.5|RFC4480 5.5}:
 * A key material packet contains all the information about a public or
 * private key.  There are four variants of this packet type, and two
 * major versions.  Consequently, this section is complex.
 * @requires crypto
 * @requires enums
 * @requires type/keyid
 * @requires type/mpi
 * @requires util
 * @module packet/public_key
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = PublicKey;

var _util = _dereq_('../util.js');

var _util2 = _interopRequireDefault(_util);

var _mpi = _dereq_('../type/mpi.js');

var _mpi2 = _interopRequireDefault(_mpi);

var _keyid = _dereq_('../type/keyid.js');

var _keyid2 = _interopRequireDefault(_keyid);

var _enums = _dereq_('../enums.js');

var _enums2 = _interopRequireDefault(_enums);

var _crypto = _dereq_('../crypto');

var _crypto2 = _interopRequireDefault(_crypto);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @constructor
 */
function PublicKey() {
  this.tag = _enums2.default.packet.publicKey;
  this.version = 4;
  /** Key creation date.
   * @type {Date} */
  this.created = new Date();
  /** A list of multiprecision integers
   * @type {module:type/mpi} */
  this.mpi = [];
  /** Public key algorithm
   * @type {module:enums.publicKey} */
  this.algorithm = 'rsa_sign';
  // time in days (V3 only)
  this.expirationTimeV3 = 0;
  /**
   * Fingerprint in lowercase hex
   * @type {String}
   */
  this.fingerprint = null;
  /**
   * Keyid
   * @type {module:type/keyid}
   */
  this.keyid = null;
}

/**
 * Internal Parser for public keys as specified in {@link http://tools.ietf.org/html/rfc4880#section-5.5.2|RFC 4880 section 5.5.2 Public-Key Packet Formats}
 * called by read_tag&lt;num&gt;
 * @param {Uint8Array} bytes Input array to read the packet from
 * @return {Object} This object with attributes set by the parser
 */
PublicKey.prototype.read = function (bytes) {
  var pos = 0;
  // A one-octet version number (3 or 4).
  this.version = bytes[pos++];

  if (this.version === 3 || this.version === 4) {
    // - A four-octet number denoting the time that the key was created.
    this.created = _util2.default.readDate(bytes.subarray(pos, pos + 4));
    pos += 4;

    if (this.version === 3) {
      // - A two-octet number denoting the time in days that this key is
      //   valid.  If this number is zero, then it does not expire.
      this.expirationTimeV3 = _util2.default.readNumber(bytes.subarray(pos, pos + 2));
      pos += 2;
    }

    // - A one-octet number denoting the public-key algorithm of this key.
    this.algorithm = _enums2.default.read(_enums2.default.publicKey, bytes[pos++]);

    var mpicount = _crypto2.default.getPublicMpiCount(this.algorithm);
    this.mpi = [];

    var bmpi = bytes.subarray(pos, bytes.length);
    var p = 0;

    for (var i = 0; i < mpicount && p < bmpi.length; i++) {

      this.mpi[i] = new _mpi2.default();

      p += this.mpi[i].read(bmpi.subarray(p, bmpi.length));

      if (p > bmpi.length) {
        throw new Error('Error reading MPI @:' + p);
      }
    }

    return p + 6;
  } else {
    throw new Error('Version ' + this.version + ' of the key packet is unsupported.');
  }
};

/**
 * Alias of read()
 * @see module:packet/public_key~PublicKey#read
 */
PublicKey.prototype.readPublicKey = PublicKey.prototype.read;

/**
 * Same as write_private_key, but has less information because of
 * public key.
 * @return {Uint8Array} OpenPGP packet body contents,
 */
PublicKey.prototype.write = function () {

  var arr = [];
  // Version
  arr.push(new Uint8Array([this.version]));
  arr.push(_util2.default.writeDate(this.created));
  if (this.version === 3) {
    arr.push(_util2.default.writeNumber(this.expirationTimeV3, 2));
  }
  arr.push(new Uint8Array([_enums2.default.write(_enums2.default.publicKey, this.algorithm)]));

  var mpicount = _crypto2.default.getPublicMpiCount(this.algorithm);

  for (var i = 0; i < mpicount; i++) {
    arr.push(this.mpi[i].write());
  }

  return _util2.default.concatUint8Array(arr);
};

/**
 * Alias of write()
 * @see module:packet/public_key~PublicKey#write
 */
PublicKey.prototype.writePublicKey = PublicKey.prototype.write;

/**
 * Write an old version packet - it's used by some of the internal routines.
 */
PublicKey.prototype.writeOld = function () {
  var bytes = this.writePublicKey();

  return _util2.default.concatUint8Array([new Uint8Array([0x99]), _util2.default.writeNumber(bytes.length, 2), bytes]);
};

/**
 * Calculates the key id of the key
 * @return {String} A 8 byte key id
 */
PublicKey.prototype.getKeyId = function () {
  if (this.keyid) {
    return this.keyid;
  }
  this.keyid = new _keyid2.default();
  if (this.version === 4) {
    this.keyid.read(_util2.default.str2Uint8Array(_util2.default.hex2bin(this.getFingerprint()).substr(12, 8)));
  } else if (this.version === 3) {
    var arr = this.mpi[0].write();
    this.keyid.read(arr.subarray(arr.length - 8, arr.length));
  }
  return this.keyid;
};

/**
 * Calculates the fingerprint of the key
 * @return {String} A string containing the fingerprint in lowercase hex
 */
PublicKey.prototype.getFingerprint = function () {
  if (this.fingerprint) {
    return this.fingerprint;
  }
  var toHash = '';
  if (this.version === 4) {
    toHash = this.writeOld();
    this.fingerprint = _util2.default.Uint8Array2str(_crypto2.default.hash.sha1(toHash));
  } else if (this.version === 3) {
    var mpicount = _crypto2.default.getPublicMpiCount(this.algorithm);
    for (var i = 0; i < mpicount; i++) {
      toHash += this.mpi[i].toBytes();
    }
    this.fingerprint = _util2.default.Uint8Array2str(_crypto2.default.hash.md5(_util2.default.str2Uint8Array(toHash)));
  }
  this.fingerprint = _util2.default.hexstrdump(this.fingerprint);
  return this.fingerprint;
};

/**
 * Returns bit size of key
 * @return {int} Number of bits
 */
PublicKey.prototype.getBitSize = function () {
  return this.mpi[0].byteLength() * 8;
};

/**
 * Fix custom types after cloning
 */
PublicKey.prototype.postCloneTypeFix = function () {
  for (var i = 0; i < this.mpi.length; i++) {
    this.mpi[i] = _mpi2.default.fromClone(this.mpi[i]);
  }
  if (this.keyid) {
    this.keyid = _keyid2.default.fromClone(this.keyid);
  }
};

},{"../crypto":24,"../enums.js":35,"../type/keyid.js":67,"../type/mpi.js":68,"../util.js":70}],54:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Public-Key Encrypted Session Key Packets (Tag 1)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.1|RFC4880 5.1}: A Public-Key Encrypted Session Key packet holds the session key
 * used to encrypt a message. Zero or more Public-Key Encrypted Session Key
 * packets and/or Symmetric-Key Encrypted Session Key packets may precede a
 * Symmetrically Encrypted Data Packet, which holds an encrypted message. The
 * message is encrypted with the session key, and the session key is itself
 * encrypted and stored in the Encrypted Session Key packet(s). The
 * Symmetrically Encrypted Data Packet is preceded by one Public-Key Encrypted
 * Session Key packet for each OpenPGP key to which the message is encrypted.
 * The recipient of the message finds a session key that is encrypted to their
 * public key, decrypts the session key, and then uses the session key to
 * decrypt the message.
 * @requires crypto
 * @requires enums
 * @requires type/keyid
 * @requires type/mpi
 * @requires util
 * @module packet/public_key_encrypted_session_key
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = PublicKeyEncryptedSessionKey;

var _keyid = _dereq_('../type/keyid.js');

var _keyid2 = _interopRequireDefault(_keyid);

var _util = _dereq_('../util.js');

var _util2 = _interopRequireDefault(_util);

var _mpi = _dereq_('../type/mpi.js');

var _mpi2 = _interopRequireDefault(_mpi);

var _enums = _dereq_('../enums.js');

var _enums2 = _interopRequireDefault(_enums);

var _crypto = _dereq_('../crypto');

var _crypto2 = _interopRequireDefault(_crypto);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @constructor
 */
function PublicKeyEncryptedSessionKey() {
  this.tag = _enums2.default.packet.publicKeyEncryptedSessionKey;
  this.version = 3;

  this.publicKeyId = new _keyid2.default();
  this.publicKeyAlgorithm = 'rsa_encrypt';

  this.sessionKey = null;
  this.sessionKeyAlgorithm = 'aes256';

  /** @type {Array<module:type/mpi>} */
  this.encrypted = [];
}

/**
 * Parsing function for a publickey encrypted session key packet (tag 1).
 *
 * @param {Uint8Array} input Payload of a tag 1 packet
 * @param {Integer} position Position to start reading from the input string
 * @param {Integer} len Length of the packet or the remaining length of
 *            input at position
 * @return {module:packet/public_key_encrypted_session_key} Object representation
 */
PublicKeyEncryptedSessionKey.prototype.read = function (bytes) {

  this.version = bytes[0];
  this.publicKeyId.read(bytes.subarray(1, bytes.length));
  this.publicKeyAlgorithm = _enums2.default.read(_enums2.default.publicKey, bytes[9]);

  var i = 10;

  var integerCount = function (algo) {
    switch (algo) {
      case 'rsa_encrypt':
      case 'rsa_encrypt_sign':
        return 1;

      case 'elgamal':
        return 2;

      default:
        throw new Error("Invalid algorithm.");
    }
  }(this.publicKeyAlgorithm);

  this.encrypted = [];

  for (var j = 0; j < integerCount; j++) {
    var mpi = new _mpi2.default();
    i += mpi.read(bytes.subarray(i, bytes.length));
    this.encrypted.push(mpi);
  }
};

/**
 * Create a string representation of a tag 1 packet
 *
 * @return {Uint8Array} The Uint8Array representation
 */
PublicKeyEncryptedSessionKey.prototype.write = function () {

  var arr = [new Uint8Array([this.version]), this.publicKeyId.write(), new Uint8Array([_enums2.default.write(_enums2.default.publicKey, this.publicKeyAlgorithm)])];

  for (var i = 0; i < this.encrypted.length; i++) {
    arr.push(this.encrypted[i].write());
  }

  return _util2.default.concatUint8Array(arr);
};

PublicKeyEncryptedSessionKey.prototype.encrypt = function (key) {
  var data = String.fromCharCode(_enums2.default.write(_enums2.default.symmetric, this.sessionKeyAlgorithm));

  data += _util2.default.Uint8Array2str(this.sessionKey);
  var checksum = _util2.default.calc_checksum(this.sessionKey);
  data += _util2.default.Uint8Array2str(_util2.default.writeNumber(checksum, 2));

  var mpi = new _mpi2.default();
  mpi.fromBytes(_crypto2.default.pkcs1.eme.encode(data, key.mpi[0].byteLength()));

  this.encrypted = _crypto2.default.publicKeyEncrypt(this.publicKeyAlgorithm, key.mpi, mpi);
};

/**
 * Decrypts the session key (only for public key encrypted session key
 * packets (tag 1)
 *
 * @param {module:packet/secret_key} key
 *            Private key with secMPIs unlocked
 * @return {String} The unencrypted session key
 */
PublicKeyEncryptedSessionKey.prototype.decrypt = function (key) {
  var result = _crypto2.default.publicKeyDecrypt(this.publicKeyAlgorithm, key.mpi, this.encrypted).toBytes();

  var checksum = _util2.default.readNumber(_util2.default.str2Uint8Array(result.substr(result.length - 2)));

  var decoded = _crypto2.default.pkcs1.eme.decode(result);

  key = _util2.default.str2Uint8Array(decoded.substring(1, decoded.length - 2));

  if (checksum !== _util2.default.calc_checksum(key)) {
    throw new Error('Checksum mismatch');
  } else {
    this.sessionKey = key;
    this.sessionKeyAlgorithm = _enums2.default.read(_enums2.default.symmetric, decoded.charCodeAt(0));
  }
};

/**
 * Fix custom types after cloning
 */
PublicKeyEncryptedSessionKey.prototype.postCloneTypeFix = function () {
  this.publicKeyId = _keyid2.default.fromClone(this.publicKeyId);
  for (var i = 0; i < this.encrypted.length; i++) {
    this.encrypted[i] = _mpi2.default.fromClone(this.encrypted[i]);
  }
};

},{"../crypto":24,"../enums.js":35,"../type/keyid.js":67,"../type/mpi.js":68,"../util.js":70}],55:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @requires packet/public_key
 * @requires enums
 * @module packet/public_subkey
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = PublicSubkey;

var _public_key = _dereq_('./public_key.js');

var _public_key2 = _interopRequireDefault(_public_key);

var _enums = _dereq_('../enums.js');

var _enums2 = _interopRequireDefault(_enums);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @constructor
 * @extends module:packet/public_key
 */
function PublicSubkey() {
  _public_key2.default.call(this);
  this.tag = _enums2.default.packet.publicSubkey;
}

PublicSubkey.prototype = new _public_key2.default();
PublicSubkey.prototype.constructor = PublicSubkey;

},{"../enums.js":35,"./public_key.js":53}],56:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the Key Material Packet (Tag 5,6,7,14)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.5|RFC4480 5.5}:
 * A key material packet contains all the information about a public or
 * private key.  There are four variants of this packet type, and two
 * major versions.  Consequently, this section is complex.
 * @requires crypto
 * @requires enums
 * @requires packet/public_key
 * @requires type/mpi
 * @requires type/s2k
 * @requires util
 * @module packet/secret_key
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = SecretKey;

var _public_key = _dereq_('./public_key.js');

var _public_key2 = _interopRequireDefault(_public_key);

var _enums = _dereq_('../enums.js');

var _enums2 = _interopRequireDefault(_enums);

var _util = _dereq_('../util.js');

var _util2 = _interopRequireDefault(_util);

var _crypto = _dereq_('../crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _mpi = _dereq_('../type/mpi.js');

var _mpi2 = _interopRequireDefault(_mpi);

var _s2k = _dereq_('../type/s2k.js');

var _s2k2 = _interopRequireDefault(_s2k);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @constructor
 * @extends module:packet/public_key
 */
function SecretKey() {
  _public_key2.default.call(this);
  this.tag = _enums2.default.packet.secretKey;
  // encrypted secret-key data
  this.encrypted = null;
  // indicator if secret-key data is available in decrypted form
  this.isDecrypted = false;
}

SecretKey.prototype = new _public_key2.default();
SecretKey.prototype.constructor = SecretKey;

function get_hash_len(hash) {
  if (hash === 'sha1') {
    return 20;
  } else {
    return 2;
  }
}

function get_hash_fn(hash) {
  if (hash === 'sha1') {
    return _crypto2.default.hash.sha1;
  } else {
    return function (c) {
      return _util2.default.writeNumber(_util2.default.calc_checksum(c), 2);
    };
  }
}

// Helper function

function parse_cleartext_mpi(hash_algorithm, cleartext, algorithm) {
  var hashlen = get_hash_len(hash_algorithm),
      hashfn = get_hash_fn(hash_algorithm);

  var hashtext = _util2.default.Uint8Array2str(cleartext.subarray(cleartext.length - hashlen, cleartext.length));
  cleartext = cleartext.subarray(0, cleartext.length - hashlen);

  var hash = _util2.default.Uint8Array2str(hashfn(cleartext));

  if (hash !== hashtext) {
    return new Error("Hash mismatch.");
  }

  var mpis = _crypto2.default.getPrivateMpiCount(algorithm);

  var j = 0;
  var mpi = [];

  for (var i = 0; i < mpis && j < cleartext.length; i++) {
    mpi[i] = new _mpi2.default();
    j += mpi[i].read(cleartext.subarray(j, cleartext.length));
  }

  return mpi;
}

function write_cleartext_mpi(hash_algorithm, algorithm, mpi) {
  var arr = [];
  var discard = _crypto2.default.getPublicMpiCount(algorithm);

  for (var i = discard; i < mpi.length; i++) {
    arr.push(mpi[i].write());
  }

  var bytes = _util2.default.concatUint8Array(arr);

  var hash = get_hash_fn(hash_algorithm)(bytes);

  return _util2.default.concatUint8Array([bytes, hash]);
}

// 5.5.3.  Secret-Key Packet Formats

/**
 * Internal parser for private keys as specified in {@link http://tools.ietf.org/html/rfc4880#section-5.5.3|RFC 4880 section 5.5.3}
 * @param {String} bytes Input string to read the packet from
 */
SecretKey.prototype.read = function (bytes) {
  // - A Public-Key or Public-Subkey packet, as described above.
  var len = this.readPublicKey(bytes);

  bytes = bytes.subarray(len, bytes.length);

  // - One octet indicating string-to-key usage conventions.  Zero
  //   indicates that the secret-key data is not encrypted.  255 or 254
  //   indicates that a string-to-key specifier is being given.  Any
  //   other value is a symmetric-key encryption algorithm identifier.
  var isEncrypted = bytes[0];

  if (isEncrypted) {
    this.encrypted = bytes;
  } else {
    // - Plain or encrypted multiprecision integers comprising the secret
    //   key data.  These algorithm-specific fields are as described
    //   below.
    var parsedMPI = parse_cleartext_mpi('mod', bytes.subarray(1, bytes.length), this.algorithm);
    if (parsedMPI instanceof Error) {
      throw parsedMPI;
    }
    this.mpi = this.mpi.concat(parsedMPI);
    this.isDecrypted = true;
  }
};

/** Creates an OpenPGP key packet for the given key.
  * @return {String} A string of bytes containing the secret key OpenPGP packet
  */
SecretKey.prototype.write = function () {
  var arr = [this.writePublicKey()];

  if (!this.encrypted) {
    arr.push(new Uint8Array([0]));
    arr.push(write_cleartext_mpi('mod', this.algorithm, this.mpi));
  } else {
    arr.push(this.encrypted);
  }

  return _util2.default.concatUint8Array(arr);
};

/** Encrypt the payload. By default, we use aes256 and iterated, salted string
 * to key specifier. If the key is in a decrypted state (isDecrypted === true)
 * and the passphrase is empty or undefined, the key will be set as not encrypted.
 * This can be used to remove passphrase protection after calling decrypt().
 * @param {String} passphrase
 */
SecretKey.prototype.encrypt = function (passphrase) {
  if (this.isDecrypted && !passphrase) {
    this.encrypted = null;
    return;
  } else if (!passphrase) {
    throw new Error('The key must be decrypted before removing passphrase protection.');
  }

  var s2k = new _s2k2.default(),
      symmetric = 'aes256',
      cleartext = write_cleartext_mpi('sha1', this.algorithm, this.mpi),
      key = produceEncryptionKey(s2k, passphrase, symmetric),
      blockLen = _crypto2.default.cipher[symmetric].blockSize,
      iv = _crypto2.default.random.getRandomBytes(blockLen);

  var arr = [new Uint8Array([254, _enums2.default.write(_enums2.default.symmetric, symmetric)])];
  arr.push(s2k.write());
  arr.push(iv);
  arr.push(_crypto2.default.cfb.normalEncrypt(symmetric, key, cleartext, iv));

  this.encrypted = _util2.default.concatUint8Array(arr);
};

function produceEncryptionKey(s2k, passphrase, algorithm) {
  return s2k.produce_key(passphrase, _crypto2.default.cipher[algorithm].keySize);
}

/**
 * Decrypts the private key MPIs which are needed to use the key.
 * @link module:packet/secret_key.isDecrypted should be
 * false otherwise a call to this function is not needed
 *
 * @param {String} str_passphrase The passphrase for this private key
 * as string
 * @return {Boolean} True if the passphrase was correct or MPI already
 *                   decrypted; false if not
 */
SecretKey.prototype.decrypt = function (passphrase) {
  if (this.isDecrypted) {
    return true;
  }

  var i = 0,
      symmetric,
      key;

  var s2k_usage = this.encrypted[i++];

  // - [Optional] If string-to-key usage octet was 255 or 254, a one-
  //   octet symmetric encryption algorithm.
  if (s2k_usage === 255 || s2k_usage === 254) {
    symmetric = this.encrypted[i++];
    symmetric = _enums2.default.read(_enums2.default.symmetric, symmetric);

    // - [Optional] If string-to-key usage octet was 255 or 254, a
    //   string-to-key specifier.  The length of the string-to-key
    //   specifier is implied by its type, as described above.
    var s2k = new _s2k2.default();
    i += s2k.read(this.encrypted.subarray(i, this.encrypted.length));

    key = produceEncryptionKey(s2k, passphrase, symmetric);
  } else {
    symmetric = s2k_usage;
    symmetric = _enums2.default.read(_enums2.default.symmetric, symmetric);
    key = _crypto2.default.hash.md5(passphrase);
  }

  // - [Optional] If secret data is encrypted (string-to-key usage octet
  //   not zero), an Initial Vector (IV) of the same length as the
  //   cipher's block size.
  var iv = this.encrypted.subarray(i, i + _crypto2.default.cipher[symmetric].blockSize);

  i += iv.length;

  var cleartext,
      ciphertext = this.encrypted.subarray(i, this.encrypted.length);

  cleartext = _crypto2.default.cfb.normalDecrypt(symmetric, key, ciphertext, iv);

  var hash = s2k_usage === 254 ? 'sha1' : 'mod';

  var parsedMPI = parse_cleartext_mpi(hash, cleartext, this.algorithm);
  if (parsedMPI instanceof Error) {
    return false;
  }
  this.mpi = this.mpi.concat(parsedMPI);
  this.isDecrypted = true;
  this.encrypted = null;
  return true;
};

SecretKey.prototype.generate = function (bits) {
  var self = this;

  return _crypto2.default.generateMpi(self.algorithm, bits).then(function (mpi) {
    self.mpi = mpi;
    self.isDecrypted = true;
  });
};

/**
 * Clear private MPIs, return to initial state
 */
SecretKey.prototype.clearPrivateMPIs = function () {
  if (!this.encrypted) {
    throw new Error('If secret key is not encrypted, clearing private MPIs is irreversible.');
  }
  this.mpi = this.mpi.slice(0, _crypto2.default.getPublicMpiCount(this.algorithm));
  this.isDecrypted = false;
};

},{"../crypto":24,"../enums.js":35,"../type/mpi.js":68,"../type/s2k.js":69,"../util.js":70,"./public_key.js":53}],57:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @requires packet/secret_key
 * @requires enums
 * @module packet/secret_subkey
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = SecretSubkey;

var _secret_key = _dereq_('./secret_key.js');

var _secret_key2 = _interopRequireDefault(_secret_key);

var _enums = _dereq_('../enums.js');

var _enums2 = _interopRequireDefault(_enums);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @constructor
 * @extends module:packet/secret_key
 */
function SecretSubkey() {
  _secret_key2.default.call(this);
  this.tag = _enums2.default.packet.secretSubkey;
}

SecretSubkey.prototype = new _secret_key2.default();
SecretSubkey.prototype.constructor = SecretSubkey;

},{"../enums.js":35,"./secret_key.js":56}],58:[function(_dereq_,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = Signature;

var _util = _dereq_('../util.js');

var _util2 = _interopRequireDefault(_util);

var _packet = _dereq_('./packet.js');

var _packet2 = _interopRequireDefault(_packet);

var _enums = _dereq_('../enums.js');

var _enums2 = _interopRequireDefault(_enums);

var _crypto = _dereq_('../crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _mpi = _dereq_('../type/mpi.js');

var _mpi2 = _interopRequireDefault(_mpi);

var _keyid = _dereq_('../type/keyid.js');

var _keyid2 = _interopRequireDefault(_keyid);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @constructor
 */
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the Signature Packet (Tag 2)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.2|RFC4480 5.2}:
 * A Signature packet describes a binding between some public key and
 * some data.  The most common signatures are a signature of a file or a
 * block of text, and a signature that is a certification of a User ID.
 * @requires crypto
 * @requires enums
 * @requires packet/packet
 * @requires type/keyid
 * @requires type/mpi
 * @requires util
 * @module packet/signature
 */

function Signature() {
  this.tag = _enums2.default.packet.signature;
  this.version = 4;
  this.signatureType = null;
  this.hashAlgorithm = null;
  this.publicKeyAlgorithm = null;

  this.signatureData = null;
  this.unhashedSubpackets = null;
  this.signedHashValue = null;

  this.created = new Date();
  this.signatureExpirationTime = null;
  this.signatureNeverExpires = true;
  this.exportable = null;
  this.trustLevel = null;
  this.trustAmount = null;
  this.regularExpression = null;
  this.revocable = null;
  this.keyExpirationTime = null;
  this.keyNeverExpires = null;
  this.preferredSymmetricAlgorithms = null;
  this.revocationKeyClass = null;
  this.revocationKeyAlgorithm = null;
  this.revocationKeyFingerprint = null;
  this.issuerKeyId = new _keyid2.default();
  this.notation = null;
  this.preferredHashAlgorithms = null;
  this.preferredCompressionAlgorithms = null;
  this.keyServerPreferences = null;
  this.preferredKeyServer = null;
  this.isPrimaryUserID = null;
  this.policyURI = null;
  this.keyFlags = null;
  this.signersUserId = null;
  this.reasonForRevocationFlag = null;
  this.reasonForRevocationString = null;
  this.features = null;
  this.signatureTargetPublicKeyAlgorithm = null;
  this.signatureTargetHashAlgorithm = null;
  this.signatureTargetHash = null;
  this.embeddedSignature = null;

  this.verified = false;
}

/**
 * parsing function for a signature packet (tag 2).
 * @param {String} bytes payload of a tag 2 packet
 * @param {Integer} position position to start reading from the bytes string
 * @param {Integer} len length of the packet or the remaining length of bytes at position
 * @return {module:packet/signature} object representation
 */
Signature.prototype.read = function (bytes) {
  var _this = this;

  var i = 0;
  this.version = bytes[i++];
  // switch on version (3 and 4)
  var sigpos;
  var sigDataLength;

  (function () {
    switch (_this.version) {
      case 3:
        // One-octet length of following hashed material. MUST be 5.
        if (bytes[i++] !== 5) {
          _util2.default.print_debug("packet/signature.js\n" + 'invalid One-octet length of following hashed material.' + 'MUST be 5. @:' + (i - 1));
        }

        sigpos = i;
        // One-octet signature type.

        _this.signatureType = bytes[i++];

        // Four-octet creation time.
        _this.created = _util2.default.readDate(bytes.subarray(i, i + 4));
        i += 4;

        // storing data appended to data which gets verified
        _this.signatureData = bytes.subarray(sigpos, i);

        // Eight-octet Key ID of signer.
        _this.issuerKeyId.read(bytes.subarray(i, i + 8));
        i += 8;

        // One-octet public-key algorithm.
        _this.publicKeyAlgorithm = bytes[i++];

        // One-octet hash algorithm.
        _this.hashAlgorithm = bytes[i++];
        break;
      case 4:
        _this.signatureType = bytes[i++];
        _this.publicKeyAlgorithm = bytes[i++];
        _this.hashAlgorithm = bytes[i++];

        var subpackets = function subpackets(bytes) {
          // Two-octet scalar octet count for following subpacket data.
          var subpacket_length = _util2.default.readNumber(bytes.subarray(0, 2));

          var i = 2;

          // subpacket data set (zero or more subpackets)
          while (i < 2 + subpacket_length) {

            var len = _packet2.default.readSimpleLength(bytes.subarray(i, bytes.length));
            i += len.offset;

            this.read_sub_packet(bytes.subarray(i, i + len.len));

            i += len.len;
          }

          return i;
        };

        // hashed subpackets


        i += subpackets.call(_this, bytes.subarray(i, bytes.length), true);

        // A V4 signature hashes the packet body
        // starting from its first field, the version number, through the end
        // of the hashed subpacket data.  Thus, the fields hashed are the
        // signature version, the signature type, the public-key algorithm, the
        // hash algorithm, the hashed subpacket length, and the hashed
        // subpacket body.
        _this.signatureData = bytes.subarray(0, i);
        sigDataLength = i;

        // unhashed subpackets

        i += subpackets.call(_this, bytes.subarray(i, bytes.length), false);
        _this.unhashedSubpackets = bytes.subarray(sigDataLength, i);

        break;
      default:
        throw new Error('Version ' + _this.version + ' of the signature is unsupported.');
    }

    // Two-octet field holding left 16 bits of signed hash value.
  })();

  this.signedHashValue = bytes.subarray(i, i + 2);
  i += 2;

  this.signature = bytes.subarray(i, bytes.length);
};

Signature.prototype.write = function () {
  var arr = [];
  switch (this.version) {
    case 3:
      arr.push(new Uint8Array([3, 5])); // version, One-octet length of following hashed material.  MUST be 5
      arr.push(new Uint8Array([this.signatureType]));
      arr.push(_util2.default.writeDate(this.created));
      arr.push(this.issuerKeyId.write());
      arr.push(new Uint8Array([_enums2.default.write(_enums2.default.publicKey, this.publicKeyAlgorithm), _enums2.default.write(_enums2.default.hash, this.hashAlgorithm)]));
      break;
    case 4:
      arr.push(this.signatureData);
      arr.push(this.unhashedSubpackets ? this.unhashedSubpackets : _util2.default.writeNumber(0, 2));
      break;
  }
  arr.push(this.signedHashValue);
  arr.push(this.signature);
  return _util2.default.concatUint8Array(arr);
};

/**
 * Signs provided data. This needs to be done prior to serialization.
 * @param {module:packet/secret_key} key private key used to sign the message.
 * @param {Object} data Contains packets to be signed.
 */
Signature.prototype.sign = function (key, data) {
  var signatureType = _enums2.default.write(_enums2.default.signature, this.signatureType),
      publicKeyAlgorithm = _enums2.default.write(_enums2.default.publicKey, this.publicKeyAlgorithm),
      hashAlgorithm = _enums2.default.write(_enums2.default.hash, this.hashAlgorithm);

  var arr = [new Uint8Array([4, signatureType, publicKeyAlgorithm, hashAlgorithm])];

  this.issuerKeyId = key.getKeyId();

  // Add hashed subpackets
  arr.push(this.write_all_sub_packets());

  this.signatureData = _util2.default.concatUint8Array(arr);

  var trailer = this.calculateTrailer();

  var toHash = null;

  switch (this.version) {
    case 3:
      toHash = _util2.default.concatUint8Array([this.toSign(signatureType, data), new Uint8Array([signatureType]), _util2.default.writeDate(this.created)]);
      break;
    case 4:
      toHash = _util2.default.concatUint8Array([this.toSign(signatureType, data), this.signatureData, trailer]);
      break;
    default:
      throw new Error('Version ' + this.version + ' of the signature is unsupported.');
  }

  var hash = _crypto2.default.hash.digest(hashAlgorithm, toHash);

  this.signedHashValue = hash.subarray(0, 2);

  this.signature = _crypto2.default.signature.sign(hashAlgorithm, publicKeyAlgorithm, key.mpi, toHash);
};

/**
 * Creates string of bytes with all subpacket data
 * @return {String} a string-representation of a all subpacket data
 */
Signature.prototype.write_all_sub_packets = function () {
  var sub = _enums2.default.signatureSubpacket;
  var arr = [];
  var bytes;
  if (this.created !== null) {
    arr.push(write_sub_packet(sub.signature_creation_time, _util2.default.writeDate(this.created)));
  }
  if (this.signatureExpirationTime !== null) {
    arr.push(write_sub_packet(sub.signature_expiration_time, _util2.default.writeNumber(this.signatureExpirationTime, 4)));
  }
  if (this.exportable !== null) {
    arr.push(write_sub_packet(sub.exportable_certification, new Uint8Array([this.exportable ? 1 : 0])));
  }
  if (this.trustLevel !== null) {
    bytes = new Uint8Array([this.trustLevel, this.trustAmount]);
    arr.push(write_sub_packet(sub.trust_signature, bytes));
  }
  if (this.regularExpression !== null) {
    arr.push(write_sub_packet(sub.regular_expression, this.regularExpression));
  }
  if (this.revocable !== null) {
    arr.push(write_sub_packet(sub.revocable, new Uint8Array([this.revocable ? 1 : 0])));
  }
  if (this.keyExpirationTime !== null) {
    arr.push(write_sub_packet(sub.key_expiration_time, _util2.default.writeNumber(this.keyExpirationTime, 4)));
  }
  if (this.preferredSymmetricAlgorithms !== null) {
    bytes = _util2.default.str2Uint8Array(_util2.default.bin2str(this.preferredSymmetricAlgorithms));
    arr.push(write_sub_packet(sub.preferred_symmetric_algorithms, bytes));
  }
  if (this.revocationKeyClass !== null) {

    bytes = new Uint8Array([this.revocationKeyClass, this.revocationKeyAlgorithm]);
    bytes = _util2.default.concatUint8Array([bytes, this.revocationKeyFingerprint]);
    arr.push(write_sub_packet(sub.revocation_key, bytes));
  }
  if (!this.issuerKeyId.isNull()) {
    arr.push(write_sub_packet(sub.issuer, this.issuerKeyId.write()));
  }
  if (this.notation !== null) {
    for (var name in this.notation) {
      if (this.notation.hasOwnProperty(name)) {
        var value = this.notation[name];
        bytes = [new Uint8Array([0x80, 0, 0, 0])];
        // 2 octets of name length
        bytes.push(_util2.default.writeNumber(name.length, 2));
        // 2 octets of value length
        bytes.push(_util2.default.writeNumber(value.length, 2));
        bytes.push(_util2.default.str2Uint8Array(name + value));
        bytes = _util2.default.concatUint8Array(bytes);
        arr.push(write_sub_packet(sub.notation_data, bytes));
      }
    }
  }
  if (this.preferredHashAlgorithms !== null) {
    bytes = _util2.default.str2Uint8Array(_util2.default.bin2str(this.preferredHashAlgorithms));
    arr.push(write_sub_packet(sub.preferred_hash_algorithms, bytes));
  }
  if (this.preferredCompressionAlgorithms !== null) {
    bytes = _util2.default.str2Uint8Array(_util2.default.bin2str(this.preferredCompressionAlgorithms));
    arr.push(write_sub_packet(sub.preferred_compression_algorithms, bytes));
  }
  if (this.keyServerPreferences !== null) {
    bytes = _util2.default.str2Uint8Array(_util2.default.bin2str(this.keyServerPreferences));
    arr.push(write_sub_packet(sub.key_server_preferences, bytes));
  }
  if (this.preferredKeyServer !== null) {
    arr.push(write_sub_packet(sub.preferred_key_server, _util2.default.str2Uint8Array(this.preferredKeyServer)));
  }
  if (this.isPrimaryUserID !== null) {
    arr.push(write_sub_packet(sub.primary_user_id, new Uint8Array([this.isPrimaryUserID ? 1 : 0])));
  }
  if (this.policyURI !== null) {
    arr.push(write_sub_packet(sub.policy_uri, _util2.default.str2Uint8Array(this.policyURI)));
  }
  if (this.keyFlags !== null) {
    bytes = _util2.default.str2Uint8Array(_util2.default.bin2str(this.keyFlags));
    arr.push(write_sub_packet(sub.key_flags, bytes));
  }
  if (this.signersUserId !== null) {
    arr.push(write_sub_packet(sub.signers_user_id, _util2.default.str2Uint8Array(this.signersUserId)));
  }
  if (this.reasonForRevocationFlag !== null) {
    bytes = _util2.default.str2Uint8Array(String.fromCharCode(this.reasonForRevocationFlag) + this.reasonForRevocationString);
    arr.push(write_sub_packet(sub.reason_for_revocation, bytes));
  }
  if (this.features !== null) {
    bytes = _util2.default.str2Uint8Array(_util2.default.bin2str(this.features));
    arr.push(write_sub_packet(sub.features, bytes));
  }
  if (this.signatureTargetPublicKeyAlgorithm !== null) {
    bytes = [new Uint8Array([this.signatureTargetPublicKeyAlgorithm, this.signatureTargetHashAlgorithm])];
    bytes.push(_util2.default.str2Uint8Array(this.signatureTargetHash));
    bytes = _util2.default.concatUint8Array(bytes);
    arr.push(write_sub_packet(sub.signature_target, bytes));
  }
  if (this.embeddedSignature !== null) {
    arr.push(write_sub_packet(sub.embedded_signature, this.embeddedSignature.write()));
  }

  var result = _util2.default.concatUint8Array(arr);
  var length = _util2.default.writeNumber(result.length, 2);

  return _util2.default.concatUint8Array([length, result]);
};

/**
 * creates a string representation of a sub signature packet (See {@link http://tools.ietf.org/html/rfc4880#section-5.2.3.1|RFC 4880 5.2.3.1})
 * @param {Integer} type subpacket signature type. Signature types as described
 * in {@link http://tools.ietf.org/html/rfc4880#section-5.2.3.2|RFC4880 Section 5.2.3.2}
 * @param {String} data data to be included
 * @return {String} a string-representation of a sub signature packet (See {@link http://tools.ietf.org/html/rfc4880#section-5.2.3.1|RFC 4880 5.2.3.1})
 */
function write_sub_packet(type, data) {
  var arr = [];
  arr.push(_packet2.default.writeSimpleLength(data.length + 1));
  arr.push(new Uint8Array([type]));
  arr.push(data);
  return _util2.default.concatUint8Array(arr);
}

// V4 signature sub packets

Signature.prototype.read_sub_packet = function (bytes) {
  var mypos = 0;

  function read_array(prop, bytes) {
    this[prop] = [];

    for (var i = 0; i < bytes.length; i++) {
      this[prop].push(bytes[i]);
    }
  }

  // The leftwost bit denotes a "critical" packet, but we ignore it.
  var type = bytes[mypos++] & 0x7F;
  var seconds;

  // subpacket type
  switch (type) {
    case 2:
      // Signature Creation Time
      this.created = _util2.default.readDate(bytes.subarray(mypos, bytes.length));
      break;
    case 3:
      // Signature Expiration Time in seconds
      seconds = _util2.default.readNumber(bytes.subarray(mypos, bytes.length));

      this.signatureNeverExpires = seconds === 0;
      this.signatureExpirationTime = seconds;

      break;
    case 4:
      // Exportable Certification
      this.exportable = bytes[mypos++] === 1;
      break;
    case 5:
      // Trust Signature
      this.trustLevel = bytes[mypos++];
      this.trustAmount = bytes[mypos++];
      break;
    case 6:
      // Regular Expression
      this.regularExpression = bytes[mypos];
      break;
    case 7:
      // Revocable
      this.revocable = bytes[mypos++] === 1;
      break;
    case 9:
      // Key Expiration Time in seconds
      seconds = _util2.default.readNumber(bytes.subarray(mypos, bytes.length));

      this.keyExpirationTime = seconds;
      this.keyNeverExpires = seconds === 0;

      break;
    case 11:
      // Preferred Symmetric Algorithms
      read_array.call(this, 'preferredSymmetricAlgorithms', bytes.subarray(mypos, bytes.length));
      break;
    case 12:
      // Revocation Key
      // (1 octet of class, 1 octet of public-key algorithm ID, 20
      // octets of
      // fingerprint)
      this.revocationKeyClass = bytes[mypos++];
      this.revocationKeyAlgorithm = bytes[mypos++];
      this.revocationKeyFingerprint = bytes.subarray(mypos, 20);
      break;

    case 16:
      // Issuer
      this.issuerKeyId.read(bytes.subarray(mypos, bytes.length));
      break;

    case 20:
      // Notation Data
      // We don't know how to handle anything but a text flagged data.
      if (bytes[mypos] === 0x80) {

        // We extract key/value tuple from the byte stream.
        mypos += 4;
        var m = _util2.default.readNumber(bytes.subarray(mypos, mypos + 2));
        mypos += 2;
        var n = _util2.default.readNumber(bytes.subarray(mypos, mypos + 2));
        mypos += 2;

        var name = _util2.default.Uint8Array2str(bytes.subarray(mypos, mypos + m)),
            value = _util2.default.Uint8Array2str(bytes.subarray(mypos + m, mypos + m + n));

        this.notation = this.notation || {};
        this.notation[name] = value;
      } else {
        _util2.default.print_debug("Unsupported notation flag " + bytes[mypos]);
      }
      break;
    case 21:
      // Preferred Hash Algorithms
      read_array.call(this, 'preferredHashAlgorithms', bytes.subarray(mypos, bytes.length));
      break;
    case 22:
      // Preferred Compression Algorithms
      read_array.call(this, 'preferredCompressionAlgorithms', bytes.subarray(mypos, bytes.length));
      break;
    case 23:
      // Key Server Preferences
      read_array.call(this, 'keyServerPreferencess', bytes.subarray(mypos, bytes.length));
      break;
    case 24:
      // Preferred Key Server
      this.preferredKeyServer = _util2.default.Uint8Array2str(bytes.subarray(mypos, bytes.length));
      break;
    case 25:
      // Primary User ID
      this.isPrimaryUserID = bytes[mypos++] !== 0;
      break;
    case 26:
      // Policy URI
      this.policyURI = _util2.default.Uint8Array2str(bytes.subarray(mypos, bytes.length));
      break;
    case 27:
      // Key Flags
      read_array.call(this, 'keyFlags', bytes.subarray(mypos, bytes.length));
      break;
    case 28:
      // Signer's User ID
      this.signersUserId += _util2.default.Uint8Array2str(bytes.subarray(mypos, bytes.length));
      break;
    case 29:
      // Reason for Revocation
      this.reasonForRevocationFlag = bytes[mypos++];
      this.reasonForRevocationString = _util2.default.Uint8Array2str(bytes.subarray(mypos, bytes.length));
      break;
    case 30:
      // Features
      read_array.call(this, 'features', bytes.subarray(mypos, bytes.length));
      break;
    case 31:
      // Signature Target
      // (1 octet public-key algorithm, 1 octet hash algorithm, N octets hash)
      this.signatureTargetPublicKeyAlgorithm = bytes[mypos++];
      this.signatureTargetHashAlgorithm = bytes[mypos++];

      var len = _crypto2.default.getHashByteLength(this.signatureTargetHashAlgorithm);

      this.signatureTargetHash = _util2.default.Uint8Array2str(bytes.subarray(mypos, mypos + len));
      break;
    case 32:
      // Embedded Signature
      this.embeddedSignature = new Signature();
      this.embeddedSignature.read(bytes.subarray(mypos, bytes.length));
      break;
    default:
      _util2.default.print_debug("Unknown signature subpacket type " + type + " @:" + mypos);
  }
};

// Produces data to produce signature on
Signature.prototype.toSign = function (type, data) {
  var t = _enums2.default.signature;

  switch (type) {
    case t.binary:
    case t.text:
      return data.getBytes();

    case t.standalone:
      return new Uint8Array(0);

    case t.cert_generic:
    case t.cert_persona:
    case t.cert_casual:
    case t.cert_positive:
    case t.cert_revocation:
      var packet, tag;

      if (data.userid !== undefined) {
        tag = 0xB4;
        packet = data.userid;
      } else if (data.userattribute !== undefined) {
        tag = 0xD1;
        packet = data.userattribute;
      } else {
        throw new Error('Either a userid or userattribute packet needs to be ' + 'supplied for certification.');
      }

      var bytes = packet.write();

      if (this.version === 4) {
        return _util2.default.concatUint8Array([this.toSign(t.key, data), new Uint8Array([tag]), _util2.default.writeNumber(bytes.length, 4), bytes]);
      } else if (this.version === 3) {
        return _util2.default.concatUint8Array([this.toSign(t.key, data), bytes]);
      }
      break;

    case t.subkey_binding:
    case t.subkey_revocation:
    case t.key_binding:
      return _util2.default.concatUint8Array([this.toSign(t.key, data), this.toSign(t.key, {
        key: data.bind
      })]);

    case t.key:
      if (data.key === undefined) {
        throw new Error('Key packet is required for this signature.');
      }
      return data.key.writeOld();

    case t.key_revocation:
      return this.toSign(t.key, data);
    case t.timestamp:
      return new Uint8Array(0);
    case t.third_party:
      throw new Error('Not implemented');
    default:
      throw new Error('Unknown signature type.');
  }
};

Signature.prototype.calculateTrailer = function () {
  // calculating the trailer
  // V3 signatures don't have a trailer
  if (this.version === 3) {
    return new Uint8Array(0);
  }
  var first = new Uint8Array([4, 0xFF]); //Version, ?
  return _util2.default.concatUint8Array([first, _util2.default.writeNumber(this.signatureData.length, 4)]);
};

/**
 * verifys the signature packet. Note: not signature types are implemented
 * @param {String|Object} data data which on the signature applies
 * @param {module:packet/public_subkey|module:packet/public_key|
 *         module:packet/secret_subkey|module:packet/secret_key} key the public key to verify the signature
 * @return {boolean} True if message is verified, else false.
 */
Signature.prototype.verify = function (key, data) {
  var signatureType = _enums2.default.write(_enums2.default.signature, this.signatureType),
      publicKeyAlgorithm = _enums2.default.write(_enums2.default.publicKey, this.publicKeyAlgorithm),
      hashAlgorithm = _enums2.default.write(_enums2.default.hash, this.hashAlgorithm);

  var bytes = this.toSign(signatureType, data),
      trailer = this.calculateTrailer();

  var mpicount = 0;
  // Algorithm-Specific Fields for RSA signatures:
  //      - multiprecision number (MPI) of RSA signature value m**d mod n.
  if (publicKeyAlgorithm > 0 && publicKeyAlgorithm < 4) {
    mpicount = 1;
  }
  //    Algorithm-Specific Fields for DSA signatures:
  //      - MPI of DSA value r.
  //      - MPI of DSA value s.
  else if (publicKeyAlgorithm === 17) {
      mpicount = 2;
    }

  var mpi = [],
      i = 0;
  for (var j = 0; j < mpicount; j++) {
    mpi[j] = new _mpi2.default();
    i += mpi[j].read(this.signature.subarray(i, this.signature.length));
  }

  this.verified = _crypto2.default.signature.verify(publicKeyAlgorithm, hashAlgorithm, mpi, key.mpi, _util2.default.concatUint8Array([bytes, this.signatureData, trailer]));

  return this.verified;
};

/**
 * Verifies signature expiration date
 * @return {Boolean} true if expired
 */
Signature.prototype.isExpired = function () {
  if (!this.signatureNeverExpires) {
    return Date.now() > this.created.getTime() + this.signatureExpirationTime * 1000;
  }
  return false;
};

/**
 * Fix custom types after cloning
 */
Signature.prototype.postCloneTypeFix = function () {
  this.issuerKeyId = _keyid2.default.fromClone(this.issuerKeyId);
};

},{"../crypto":24,"../enums.js":35,"../type/keyid.js":67,"../type/mpi.js":68,"../util.js":70,"./packet.js":51}],59:[function(_dereq_,module,exports){
// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2016 Tankred Hase
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the Symmetrically Encrypted Authenticated Encryption with Additional Data (AEAD) Protected Data Packet
 * {@link https://tools.ietf.org/html/draft-ford-openpgp-format-00#section-2.1}: AEAD Protected Data Packet
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = SymEncryptedAEADProtected;

var _util = _dereq_('../util.js');

var _util2 = _interopRequireDefault(_util);

var _crypto = _dereq_('../crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _enums = _dereq_('../enums.js');

var _enums2 = _interopRequireDefault(_enums);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var VERSION = 1; // A one-octet version number of the data packet.
var IV_LEN = _crypto2.default.gcm.ivLength; // currently only AES-GCM is supported

/**
 * @constructor
 */
function SymEncryptedAEADProtected() {
  this.tag = _enums2.default.packet.symEncryptedAEADProtected;
  this.version = VERSION;
  this.iv = null;
  this.encrypted = null;
  this.packets = null;
}

/**
 * Parse an encrypted payload of bytes in the order: version, IV, ciphertext (see specification)
 */
SymEncryptedAEADProtected.prototype.read = function (bytes) {
  var offset = 0;
  if (bytes[offset] !== VERSION) {
    // The only currently defined value is 1.
    throw new Error('Invalid packet version.');
  }
  offset++;
  this.iv = bytes.subarray(offset, IV_LEN + offset);
  offset += IV_LEN;
  this.encrypted = bytes.subarray(offset, bytes.length);
};

/**
 * Write the encrypted payload of bytes in the order: version, IV, ciphertext (see specification)
 * @return {Uint8Array} The encrypted payload
 */
SymEncryptedAEADProtected.prototype.write = function () {
  return _util2.default.concatUint8Array([new Uint8Array([this.version]), this.iv, this.encrypted]);
};

/**
 * Decrypt the encrypted payload.
 * @param  {String} sessionKeyAlgorithm   The session key's cipher algorithm e.g. 'aes128'
 * @param  {Uint8Array} key               The session key used to encrypt the payload
 * @return {Promise<undefined>}           Nothing is returned
 */
SymEncryptedAEADProtected.prototype.decrypt = function (sessionKeyAlgorithm, key) {
  var _this = this;

  return _crypto2.default.gcm.decrypt(sessionKeyAlgorithm, this.encrypted, key, this.iv).then(function (decrypted) {
    _this.packets.read(decrypted);
  });
};

/**
 * Encrypt the packet list payload.
 * @param  {String} sessionKeyAlgorithm   The session key's cipher algorithm e.g. 'aes128'
 * @param  {Uint8Array} key               The session key used to encrypt the payload
 * @return {Promise<undefined>}           Nothing is returned
 */
SymEncryptedAEADProtected.prototype.encrypt = function (sessionKeyAlgorithm, key) {
  var _this2 = this;

  this.iv = _crypto2.default.random.getRandomValues(new Uint8Array(IV_LEN)); // generate new random IV
  return _crypto2.default.gcm.encrypt(sessionKeyAlgorithm, this.packets.write(), key, this.iv).then(function (encrypted) {
    _this2.encrypted = encrypted;
  });
};

},{"../crypto":24,"../enums.js":35,"../util.js":70}],60:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the Sym. Encrypted Integrity Protected Data
 * Packet (Tag 18)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.13|RFC4880 5.13}:
 * The Symmetrically Encrypted Integrity Protected Data packet is
 * a variant of the Symmetrically Encrypted Data packet. It is a new feature
 * created for OpenPGP that addresses the problem of detecting a modification to
 * encrypted data. It is used in combination with a Modification Detection Code
 * packet.
 * @requires crypto
 * @requires util
 * @requires enums
 * @requires config
 * @module packet/sym_encrypted_integrity_protected
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = SymEncryptedIntegrityProtected;

var _util = _dereq_('../util.js');

var _util2 = _interopRequireDefault(_util);

var _crypto = _dereq_('../crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _enums = _dereq_('../enums.js');

var _enums2 = _interopRequireDefault(_enums);

var _asmcryptoLite = _dereq_('asmcrypto-lite');

var _asmcryptoLite2 = _interopRequireDefault(_asmcryptoLite);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var nodeCrypto = _util2.default.getNodeCrypto();
var Buffer = _util2.default.getNodeBuffer();

var VERSION = 1; // A one-octet version number of the data packet.

/**
 * @constructor
 */
function SymEncryptedIntegrityProtected() {
  this.tag = _enums2.default.packet.symEncryptedIntegrityProtected;
  this.version = VERSION;
  /** The encrypted payload. */
  this.encrypted = null; // string
  /**
   * If after decrypting the packet this is set to true,
   * a modification has been detected and thus the contents
   * should be discarded.
   * @type {Boolean}
   */
  this.modification = false;
  this.packets = null;
}

SymEncryptedIntegrityProtected.prototype.read = function (bytes) {
  // - A one-octet version number. The only currently defined value is 1.
  if (bytes[0] !== VERSION) {
    throw new Error('Invalid packet version.');
  }

  // - Encrypted data, the output of the selected symmetric-key cipher
  //   operating in Cipher Feedback mode with shift amount equal to the
  //   block size of the cipher (CFB-n where n is the block size).
  this.encrypted = bytes.subarray(1, bytes.length);
};

SymEncryptedIntegrityProtected.prototype.write = function () {
  return _util2.default.concatUint8Array([new Uint8Array([VERSION]), this.encrypted]);
};

/**
 * Encrypt the payload in the packet.
 * @param  {String} sessionKeyAlgorithm   The selected symmetric encryption algorithm to be used e.g. 'aes128'
 * @param  {Uint8Array} key               The key of cipher blocksize length to be used
 * @return {Promise}
 */
SymEncryptedIntegrityProtected.prototype.encrypt = function (sessionKeyAlgorithm, key) {
  var bytes = this.packets.write();
  var prefixrandom = _crypto2.default.getPrefixRandom(sessionKeyAlgorithm);
  var repeat = new Uint8Array([prefixrandom[prefixrandom.length - 2], prefixrandom[prefixrandom.length - 1]]);
  var prefix = _util2.default.concatUint8Array([prefixrandom, repeat]);
  var mdc = new Uint8Array([0xD3, 0x14]); // modification detection code packet

  var tohash = _util2.default.concatUint8Array([bytes, mdc]);
  var hash = _crypto2.default.hash.sha1(_util2.default.concatUint8Array([prefix, tohash]));
  tohash = _util2.default.concatUint8Array([tohash, hash]);

  if (sessionKeyAlgorithm.substr(0, 3) === 'aes') {
    // AES optimizations. Native code for node, asmCrypto for browser.
    this.encrypted = aesEncrypt(sessionKeyAlgorithm, prefix, tohash, key);
  } else {
    this.encrypted = _crypto2.default.cfb.encrypt(prefixrandom, sessionKeyAlgorithm, tohash, key, false);
    this.encrypted = this.encrypted.subarray(0, prefix.length + tohash.length);
  }

  return Promise.resolve();
};

/**
 * Decrypts the encrypted data contained in the packet.
 * @param  {String} sessionKeyAlgorithm   The selected symmetric encryption algorithm to be used e.g. 'aes128'
 * @param  {Uint8Array} key               The key of cipher blocksize length to be used
 * @return {Promise}
 */
SymEncryptedIntegrityProtected.prototype.decrypt = function (sessionKeyAlgorithm, key) {
  var decrypted = void 0;
  if (sessionKeyAlgorithm.substr(0, 3) === 'aes') {
    // AES optimizations. Native code for node, asmCrypto for browser.
    decrypted = aesDecrypt(sessionKeyAlgorithm, this.encrypted, key);
  } else {
    decrypted = _crypto2.default.cfb.decrypt(sessionKeyAlgorithm, key, this.encrypted, false);
  }

  // there must be a modification detection code packet as the
  // last packet and everything gets hashed except the hash itself
  var prefix = _crypto2.default.cfb.mdc(sessionKeyAlgorithm, key, this.encrypted);
  var bytes = decrypted.subarray(0, decrypted.length - 20);
  var tohash = _util2.default.concatUint8Array([prefix, bytes]);
  this.hash = _util2.default.Uint8Array2str(_crypto2.default.hash.sha1(tohash));
  var mdc = _util2.default.Uint8Array2str(decrypted.subarray(decrypted.length - 20, decrypted.length));

  if (this.hash !== mdc) {
    throw new Error('Modification detected.');
  } else {
    this.packets.read(decrypted.subarray(0, decrypted.length - 22));
  }

  return Promise.resolve();
};

//////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////

function aesEncrypt(algo, prefix, pt, key) {
  if (nodeCrypto) {
    // Node crypto library.
    return nodeEncrypt(algo, prefix, pt, key);
  } else {
    // asm.js fallback
    return _asmcryptoLite2.default.AES_CFB.encrypt(_util2.default.concatUint8Array([prefix, pt]), key);
  }
}

function aesDecrypt(algo, ct, key) {
  var pt = void 0;
  if (nodeCrypto) {
    // Node crypto library.
    pt = nodeDecrypt(algo, ct, key);
  } else {
    // asm.js fallback
    pt = _asmcryptoLite2.default.AES_CFB.decrypt(ct, key);
  }
  return pt.subarray(_crypto2.default.cipher[algo].blockSize + 2, pt.length); // Remove random prefix
}

function nodeEncrypt(algo, prefix, pt, key) {
  key = new Buffer(key);
  var iv = new Buffer(new Uint8Array(_crypto2.default.cipher[algo].blockSize));
  var cipherObj = new nodeCrypto.createCipheriv('aes-' + algo.substr(3, 3) + '-cfb', key, iv);
  var ct = cipherObj.update(new Buffer(_util2.default.concatUint8Array([prefix, pt])));
  return new Uint8Array(ct);
}

function nodeDecrypt(algo, ct, key) {
  ct = new Buffer(ct);
  key = new Buffer(key);
  var iv = new Buffer(new Uint8Array(_crypto2.default.cipher[algo].blockSize));
  var decipherObj = new nodeCrypto.createDecipheriv('aes-' + algo.substr(3, 3) + '-cfb', key, iv);
  var pt = decipherObj.update(ct);
  return new Uint8Array(pt);
}

},{"../crypto":24,"../enums.js":35,"../util.js":70,"asmcrypto-lite":1}],61:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Public-Key Encrypted Session Key Packets (Tag 1)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.1|RFC4880 5.1}: A Public-Key Encrypted Session Key packet holds the session key
 * used to encrypt a message. Zero or more Public-Key Encrypted Session Key
 * packets and/or Symmetric-Key Encrypted Session Key packets may precede a
 * Symmetrically Encrypted Data Packet, which holds an encrypted message. The
 * message is encrypted with the session key, and the session key is itself
 * encrypted and stored in the Encrypted Session Key packet(s). The
 * Symmetrically Encrypted Data Packet is preceded by one Public-Key Encrypted
 * Session Key packet for each OpenPGP key to which the message is encrypted.
 * The recipient of the message finds a session key that is encrypted to their
 * public key, decrypts the session key, and then uses the session key to
 * decrypt the message.
 * @requires util
 * @requires crypto
 * @requires enums
 * @requires type/s2k
 * @module packet/sym_encrypted_session_key
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = SymEncryptedSessionKey;

var _util = _dereq_('../util.js');

var _util2 = _interopRequireDefault(_util);

var _s2k = _dereq_('../type/s2k.js');

var _s2k2 = _interopRequireDefault(_s2k);

var _enums = _dereq_('../enums.js');

var _enums2 = _interopRequireDefault(_enums);

var _crypto = _dereq_('../crypto');

var _crypto2 = _interopRequireDefault(_crypto);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @constructor
 */
function SymEncryptedSessionKey() {
  this.tag = _enums2.default.packet.symEncryptedSessionKey;
  this.version = 4;
  this.sessionKey = null;
  this.sessionKeyEncryptionAlgorithm = null;
  this.sessionKeyAlgorithm = 'aes256';
  this.encrypted = null;
  this.s2k = new _s2k2.default();
}

/**
 * Parsing function for a symmetric encrypted session key packet (tag 3).
 *
 * @param {Uint8Array} input Payload of a tag 1 packet
 * @param {Integer} position Position to start reading from the input string
 * @param {Integer} len
 *            Length of the packet or the remaining length of
 *            input at position
 * @return {module:packet/sym_encrypted_session_key} Object representation
 */
SymEncryptedSessionKey.prototype.read = function (bytes) {
  // A one-octet version number. The only currently defined version is 4.
  this.version = bytes[0];

  // A one-octet number describing the symmetric algorithm used.
  var algo = _enums2.default.read(_enums2.default.symmetric, bytes[1]);

  // A string-to-key (S2K) specifier, length as defined above.
  var s2klength = this.s2k.read(bytes.subarray(2, bytes.length));

  // Optionally, the encrypted session key itself, which is decrypted
  // with the string-to-key object.
  var done = s2klength + 2;

  if (done < bytes.length) {
    this.encrypted = bytes.subarray(done, bytes.length);
    this.sessionKeyEncryptionAlgorithm = algo;
  } else {
    this.sessionKeyAlgorithm = algo;
  }
};

SymEncryptedSessionKey.prototype.write = function () {
  var algo = this.encrypted === null ? this.sessionKeyAlgorithm : this.sessionKeyEncryptionAlgorithm;

  var bytes = _util2.default.concatUint8Array([new Uint8Array([this.version, _enums2.default.write(_enums2.default.symmetric, algo)]), this.s2k.write()]);

  if (this.encrypted !== null) {
    bytes = _util2.default.concatUint8Array([bytes, this.encrypted]);
  }
  return bytes;
};

/**
 * Decrypts the session key (only for public key encrypted session key
 * packets (tag 1)
 *
 * @return {Uint8Array} The unencrypted session key
 */
SymEncryptedSessionKey.prototype.decrypt = function (passphrase) {
  var algo = this.sessionKeyEncryptionAlgorithm !== null ? this.sessionKeyEncryptionAlgorithm : this.sessionKeyAlgorithm;

  var length = _crypto2.default.cipher[algo].keySize;
  var key = this.s2k.produce_key(passphrase, length);

  if (this.encrypted === null) {
    this.sessionKey = key;
  } else {
    var decrypted = _crypto2.default.cfb.normalDecrypt(algo, key, this.encrypted, null);

    this.sessionKeyAlgorithm = _enums2.default.read(_enums2.default.symmetric, decrypted[0]);

    this.sessionKey = decrypted.subarray(1, decrypted.length);
  }
};

SymEncryptedSessionKey.prototype.encrypt = function (passphrase) {
  var algo = this.sessionKeyEncryptionAlgorithm !== null ? this.sessionKeyEncryptionAlgorithm : this.sessionKeyAlgorithm;

  this.sessionKeyEncryptionAlgorithm = algo;

  var length = _crypto2.default.cipher[algo].keySize;
  var key = this.s2k.produce_key(passphrase, length);

  var algo_enum = new Uint8Array([_enums2.default.write(_enums2.default.symmetric, this.sessionKeyAlgorithm)]);

  var private_key;
  if (this.sessionKey === null) {
    this.sessionKey = _crypto2.default.getRandomBytes(_crypto2.default.cipher[this.sessionKeyAlgorithm].keySize);
  }
  private_key = _util2.default.concatUint8Array([algo_enum, this.sessionKey]);

  this.encrypted = _crypto2.default.cfb.normalEncrypt(algo, key, private_key, null);
};

/**
 * Fix custom types after cloning
 */
SymEncryptedSessionKey.prototype.postCloneTypeFix = function () {
  this.s2k = _s2k2.default.fromClone(this.s2k);
};

},{"../crypto":24,"../enums.js":35,"../type/s2k.js":69,"../util.js":70}],62:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the Symmetrically Encrypted Data Packet (Tag 9)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.7|RFC4880 5.7}: The Symmetrically Encrypted Data packet contains data encrypted
 * with a symmetric-key algorithm. When it has been decrypted, it contains other
 * packets (usually a literal data packet or compressed data packet, but in
 * theory other Symmetrically Encrypted Data packets or sequences of packets
 * that form whole OpenPGP messages).
 * @requires crypto
 * @requires enums
 * @module packet/symmetrically_encrypted
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = SymmetricallyEncrypted;

var _crypto = _dereq_('../crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _enums = _dereq_('../enums.js');

var _enums2 = _interopRequireDefault(_enums);

var _config = _dereq_('../config');

var _config2 = _interopRequireDefault(_config);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @constructor
 */
function SymmetricallyEncrypted() {
  this.tag = _enums2.default.packet.symmetricallyEncrypted;
  this.encrypted = null;
  /** Decrypted packets contained within.
   * @type {module:packet/packetlist} */
  this.packets = null;
  this.ignore_mdc_error = _config2.default.ignore_mdc_error;
}

SymmetricallyEncrypted.prototype.read = function (bytes) {
  this.encrypted = bytes;
};

SymmetricallyEncrypted.prototype.write = function () {
  return this.encrypted;
};

/**
 * Symmetrically decrypt the packet data
 *
 * @param {module:enums.symmetric} sessionKeyAlgorithm
 *             Symmetric key algorithm to use // See {@link http://tools.ietf.org/html/rfc4880#section-9.2|RFC4880 9.2}
 * @param {String} key
 *             Key as string with the corresponding length to the
 *            algorithm
 */
SymmetricallyEncrypted.prototype.decrypt = function (sessionKeyAlgorithm, key) {
  var decrypted = _crypto2.default.cfb.decrypt(sessionKeyAlgorithm, key, this.encrypted, true);
  // for modern cipher (blocklength != 64 bit, except for Twofish) MDC is required
  if (!this.ignore_mdc_error && (sessionKeyAlgorithm === 'aes128' || sessionKeyAlgorithm === 'aes192' || sessionKeyAlgorithm === 'aes256')) {
    throw new Error('Decryption failed due to missing MDC in combination with modern cipher.');
  }
  this.packets.read(decrypted);

  return Promise.resolve();
};

SymmetricallyEncrypted.prototype.encrypt = function (algo, key) {
  var data = this.packets.write();

  this.encrypted = _crypto2.default.cfb.encrypt(_crypto2.default.getPrefixRandom(algo), algo, data, key, true);

  return Promise.resolve();
};

},{"../config":10,"../crypto":24,"../enums.js":35}],63:[function(_dereq_,module,exports){
/**
 * @requires enums
 * @module packet/trust
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = Trust;

var _enums = _dereq_('../enums.js');

var _enums2 = _interopRequireDefault(_enums);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @constructor
 */
function Trust() {
  this.tag = _enums2.default.packet.trust;
}

/**
 * Parsing function for a trust packet (tag 12).
 * Currently empty as we ignore trust packets
 * @param {String} byptes payload of a tag 12 packet
 */
Trust.prototype.read = function () {};

},{"../enums.js":35}],64:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the User Attribute Packet (Tag 17)<br/>
 * <br/>
 * The User Attribute packet is a variation of the User ID packet.  It
 * is capable of storing more types of data than the User ID packet,
 * which is limited to text.  Like the User ID packet, a User Attribute
 * packet may be certified by the key owner ("self-signed") or any other
 * key owner who cares to certify it.  Except as noted, a User Attribute
 * packet may be used anywhere that a User ID packet may be used.
 * <br/>
 * While User Attribute packets are not a required part of the OpenPGP
 * standard, implementations SHOULD provide at least enough
 * compatibility to properly handle a certification signature on the
 * User Attribute packet.  A simple way to do this is by treating the
 * User Attribute packet as a User ID packet with opaque contents, but
 * an implementation may use any method desired.
 * module packet/user_attribute
 * @requires enums
 * @module packet/user_attribute
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = UserAttribute;

var _util = _dereq_('../util.js');

var _util2 = _interopRequireDefault(_util);

var _packet = _dereq_('./packet.js');

var _packet2 = _interopRequireDefault(_packet);

var _enums = _dereq_('../enums.js');

var _enums2 = _interopRequireDefault(_enums);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @constructor
 */
function UserAttribute() {
  this.tag = _enums2.default.packet.userAttribute;
  this.attributes = [];
}

/**
 * parsing function for a user attribute packet (tag 17).
 * @param {Uint8Array} input payload of a tag 17 packet
 */
UserAttribute.prototype.read = function (bytes) {
  var i = 0;
  while (i < bytes.length) {
    var len = _packet2.default.readSimpleLength(bytes.subarray(i, bytes.length));
    i += len.offset;

    this.attributes.push(_util2.default.Uint8Array2str(bytes.subarray(i, i + len.len)));
    i += len.len;
  }
};

/**
 * Creates a binary representation of the user attribute packet
 * @return {Uint8Array} string representation
 */
UserAttribute.prototype.write = function () {
  var arr = [];
  for (var i = 0; i < this.attributes.length; i++) {
    arr.push(_packet2.default.writeSimpleLength(this.attributes[i].length));
    arr.push(_util2.default.str2Uint8Array(this.attributes[i]));
  }
  return _util2.default.concatUint8Array(arr);
};

/**
 * Compare for equality
 * @param  {module:user_attribute~UserAttribute} usrAttr
 * @return {Boolean}         true if equal
 */
UserAttribute.prototype.equals = function (usrAttr) {
  if (!usrAttr || !(usrAttr instanceof UserAttribute)) {
    return false;
  }
  return this.attributes.every(function (attr, index) {
    return attr === usrAttr.attributes[index];
  });
};

},{"../enums.js":35,"../util.js":70,"./packet.js":51}],65:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the User ID Packet (Tag 13)<br/>
 * <br/>
 * A User ID packet consists of UTF-8 text that is intended to represent
 * the name and email address of the key holder.  By convention, it
 * includes an RFC 2822 [RFC2822] mail name-addr, but there are no
 * restrictions on its content.  The packet length in the header
 * specifies the length of the User ID.
 * @requires util
 * @requires enums
 * @module packet/userid
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = Userid;

var _util = _dereq_('../util.js');

var _util2 = _interopRequireDefault(_util);

var _enums = _dereq_('../enums.js');

var _enums2 = _interopRequireDefault(_enums);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @constructor
 */
function Userid() {
  this.tag = _enums2.default.packet.userid;
  /** A string containing the user id. Usually in the form
   * John Doe <john@example.com>
   * @type {String}
   */
  this.userid = '';
}

/**
 * Parsing function for a user id packet (tag 13).
 * @param {Uint8Array} input payload of a tag 13 packet
 */
Userid.prototype.read = function (bytes) {
  this.userid = _util2.default.decode_utf8(_util2.default.Uint8Array2str(bytes));
};

/**
 * Creates a binary representation of the user id packet
 * @return {Uint8Array} binary representation
 */
Userid.prototype.write = function () {
  return _util2.default.str2Uint8Array(_util2.default.encode_utf8(this.userid));
};

},{"../enums.js":35,"../util.js":70}],66:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @requires config
 * @requires crypto
 * @requires encoding/armor
 * @requires enums
 * @requires packet
 * @module signature
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.Signature = Signature;
exports.readArmored = readArmored;
exports.read = read;

var _packet = _dereq_('./packet');

var _packet2 = _interopRequireDefault(_packet);

var _enums = _dereq_('./enums.js');

var _enums2 = _interopRequireDefault(_enums);

var _armor = _dereq_('./encoding/armor.js');

var _armor2 = _interopRequireDefault(_armor);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @class
 * @classdesc Class that represents an OpenPGP signature.
 * @param  {module:packet/packetlist} packetlist The signature packets
 */

function Signature(packetlist) {
  if (!(this instanceof Signature)) {
    return new Signature(packetlist);
  }
  this.packets = packetlist || new _packet2.default.List();
}

/**
 * Returns ASCII armored text of signature
 * @return {String} ASCII armor
 */
Signature.prototype.armor = function () {
  return _armor2.default.encode(_enums2.default.armor.signature, this.packets.write());
};

/**
 * reads an OpenPGP armored signature and returns a signature object
 * @param {String} armoredText text to be parsed
 * @return {Signature} new signature object
 * @static
 */
function readArmored(armoredText) {
  var input = _armor2.default.decode(armoredText).data;
  return read(input);
}

/**
 * reads an OpenPGP signature as byte array and returns a signature object
 * @param {Uint8Array} input   binary signature
 * @return {Signature}         new signature object
 * @static
 */
function read(input) {
  var packetlist = new _packet2.default.List();
  packetlist.read(input);
  return new Signature(packetlist);
}

},{"./encoding/armor.js":33,"./enums.js":35,"./packet":47}],67:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of type key id ({@link http://tools.ietf.org/html/rfc4880#section-3.3|RFC4880 3.3})<br/>
 * <br/>
 * A Key ID is an eight-octet scalar that identifies a key.
 * Implementations SHOULD NOT assume that Key IDs are unique.  The
 * section "Enhanced Key Formats" below describes how Key IDs are
 * formed.
 * @requires util
 * @module type/keyid
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = Keyid;

var _util = _dereq_('../util.js');

var _util2 = _interopRequireDefault(_util);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @constructor
 */
function Keyid() {
  this.bytes = '';
}

/**
 * Parsing method for a key id
 * @param {Uint8Array} input Input to read the key id from
 */
Keyid.prototype.read = function (bytes) {
  this.bytes = _util2.default.Uint8Array2str(bytes.subarray(0, 8));
};

Keyid.prototype.write = function () {
  return _util2.default.str2Uint8Array(this.bytes);
};

Keyid.prototype.toHex = function () {
  return _util2.default.hexstrdump(this.bytes);
};

Keyid.prototype.equals = function (keyid) {
  return this.bytes === keyid.bytes;
};

Keyid.prototype.isNull = function () {
  return this.bytes === '';
};

Keyid.mapToHex = function (keyId) {
  return keyId.toHex();
};

Keyid.fromClone = function (clone) {
  var keyid = new Keyid();
  keyid.bytes = clone.bytes;
  return keyid;
};

Keyid.fromId = function (hex) {
  var keyid = new Keyid();
  keyid.read(_util2.default.str2Uint8Array(_util2.default.hex2bin(hex)));
  return keyid;
};

},{"../util.js":70}],68:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

// Hint: We hold our MPIs as an array of octets in big endian format preceeding a two
// octet scalar: MPI: [a,b,c,d,e,f]
// - MPI size: (a << 8) | b
// - MPI = c | d << 8 | e << ((MPI.length -2)*8) | f ((MPI.length -2)*8)

/**
 * Implementation of type MPI ({@link http://tools.ietf.org/html/rfc4880#section-3.2|RFC4880 3.2})<br/>
 * <br/>
 * Multiprecision integers (also called MPIs) are unsigned integers used
 * to hold large integers such as the ones used in cryptographic
 * calculations.
 * An MPI consists of two pieces: a two-octet scalar that is the length
 * of the MPI in bits followed by a string of octets that contain the
 * actual integer.
 * @requires crypto/public_key/jsbn
 * @requires util
 * @module type/mpi
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = MPI;

var _jsbn = _dereq_('../crypto/public_key/jsbn.js');

var _jsbn2 = _interopRequireDefault(_jsbn);

var _util = _dereq_('../util.js');

var _util2 = _interopRequireDefault(_util);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @constructor
 */
function MPI() {
  /** An implementation dependent integer */
  this.data = null;
}

/**
 * Parsing function for a mpi ({@link http://tools.ietf.org/html/rfc4880#section3.2|RFC 4880 3.2}).
 * @param {String} input Payload of mpi data
 * @return {Integer} Length of data read
 */
MPI.prototype.read = function (bytes) {

  if (typeof bytes === 'string' || String.prototype.isPrototypeOf(bytes)) {
    bytes = _util2.default.str2Uint8Array(bytes);
  }

  var bits = bytes[0] << 8 | bytes[1];

  // Additional rules:
  //
  //    The size of an MPI is ((MPI.length + 7) / 8) + 2 octets.
  //
  //    The length field of an MPI describes the length starting from its
  //    most significant non-zero bit.  Thus, the MPI [00 02 01] is not
  //    formed correctly.  It should be [00 01 01].

  // TODO: Verification of this size method! This size calculation as
  //      specified above is not applicable in JavaScript
  var bytelen = Math.ceil(bits / 8);

  var raw = _util2.default.Uint8Array2str(bytes.subarray(2, 2 + bytelen));
  this.fromBytes(raw);

  return 2 + bytelen;
};

MPI.prototype.fromBytes = function (bytes) {
  this.data = new _jsbn2.default(_util2.default.hexstrdump(bytes), 16);
};

MPI.prototype.toBytes = function () {
  var bytes = _util2.default.Uint8Array2str(this.write());
  return bytes.substr(2);
};

MPI.prototype.byteLength = function () {
  return this.toBytes().length;
};

/**
 * Converts the mpi object to a bytes as specified in {@link http://tools.ietf.org/html/rfc4880#section-3.2|RFC4880 3.2}
 * @return {Uint8Aray} mpi Byte representation
 */
MPI.prototype.write = function () {
  return _util2.default.str2Uint8Array(this.data.toMPI());
};

MPI.prototype.toBigInteger = function () {
  return this.data.clone();
};

MPI.prototype.fromBigInteger = function (bn) {
  this.data = bn.clone();
};

MPI.fromClone = function (clone) {
  clone.data.copyTo = _jsbn2.default.prototype.copyTo;
  var bn = new _jsbn2.default();
  clone.data.copyTo(bn);
  var mpi = new MPI();
  mpi.data = bn;
  return mpi;
};

},{"../crypto/public_key/jsbn.js":29,"../util.js":70}],69:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * Implementation of the String-to-key specifier ({@link http://tools.ietf.org/html/rfc4880#section-3.7|RFC4880 3.7})<br/>
 * <br/>
 * String-to-key (S2K) specifiers are used to convert passphrase strings
 * into symmetric-key encryption/decryption keys.  They are used in two
 * places, currently: to encrypt the secret part of private keys in the
 * private keyring, and to convert passphrases to encryption keys for
 * symmetrically encrypted messages.
 * @requires crypto
 * @requires enums
 * @requires util
 * @module type/s2k
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = S2K;

var _enums = _dereq_('../enums.js');

var _enums2 = _interopRequireDefault(_enums);

var _util = _dereq_('../util.js');

var _util2 = _interopRequireDefault(_util);

var _crypto = _dereq_('../crypto');

var _crypto2 = _interopRequireDefault(_crypto);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @constructor
 */
function S2K() {
  /** @type {module:enums.hash} */
  this.algorithm = 'sha256';
  /** @type {module:enums.s2k} */
  this.type = 'iterated';
  this.c = 96;
  /** Eight bytes of salt in a binary string.
   * @type {String}
   */
  this.salt = _crypto2.default.random.getRandomBytes(8);
}

S2K.prototype.get_count = function () {
  // Exponent bias, defined in RFC4880
  var expbias = 6;

  return 16 + (this.c & 15) << (this.c >> 4) + expbias;
};

/**
 * Parsing function for a string-to-key specifier ({@link http://tools.ietf.org/html/rfc4880#section-3.7|RFC 4880 3.7}).
 * @param {String} input Payload of string-to-key specifier
 * @return {Integer} Actual length of the object
 */
S2K.prototype.read = function (bytes) {
  var i = 0;
  this.type = _enums2.default.read(_enums2.default.s2k, bytes[i++]);
  this.algorithm = _enums2.default.read(_enums2.default.hash, bytes[i++]);

  switch (this.type) {
    case 'simple':
      break;

    case 'salted':
      this.salt = bytes.subarray(i, i + 8);
      i += 8;
      break;

    case 'iterated':
      this.salt = bytes.subarray(i, i + 8);
      i += 8;

      // Octet 10: count, a one-octet, coded value
      this.c = bytes[i++];
      break;

    case 'gnu':
      if (_util2.default.Uint8Array2str(bytes.subarray(i, 3)) === "GNU") {
        i += 3; // GNU
        var gnuExtType = 1000 + bytes[i++];
        if (gnuExtType === 1001) {
          this.type = gnuExtType;
          // GnuPG extension mode 1001 -- don't write secret key at all
        } else {
          throw new Error("Unknown s2k gnu protection mode.");
        }
      } else {
        throw new Error("Unknown s2k type.");
      }
      break;

    default:
      throw new Error("Unknown s2k type.");
  }

  return i;
};

/**
 * Serializes s2k information
 * @return {Uint8Array} binary representation of s2k
 */
S2K.prototype.write = function () {

  var arr = [new Uint8Array([_enums2.default.write(_enums2.default.s2k, this.type), _enums2.default.write(_enums2.default.hash, this.algorithm)])];

  switch (this.type) {
    case 'simple':
      break;
    case 'salted':
      arr.push(this.salt);
      break;
    case 'iterated':
      arr.push(this.salt);
      arr.push(new Uint8Array([this.c]));
      break;
    case 'gnu':
      throw new Error("GNU s2k type not supported.");
    default:
      throw new Error("Unknown s2k type.");
  }

  return _util2.default.concatUint8Array(arr);
};

/**
 * Produces a key using the specified passphrase and the defined
 * hashAlgorithm
 * @param {String} passphrase Passphrase containing user input
 * @return {Uint8Array} Produced key with a length corresponding to
 * hashAlgorithm hash length
 */
S2K.prototype.produce_key = function (passphrase, numBytes) {
  passphrase = _util2.default.str2Uint8Array(_util2.default.encode_utf8(passphrase));

  function round(prefix, s2k) {
    var algorithm = _enums2.default.write(_enums2.default.hash, s2k.algorithm);

    switch (s2k.type) {
      case 'simple':
        return _crypto2.default.hash.digest(algorithm, _util2.default.concatUint8Array([prefix, passphrase]));

      case 'salted':
        return _crypto2.default.hash.digest(algorithm, _util2.default.concatUint8Array([prefix, s2k.salt, passphrase]));

      case 'iterated':
        var isp = [],
            count = s2k.get_count(),
            data = _util2.default.concatUint8Array([s2k.salt, passphrase]);

        while (isp.length * data.length < count) {
          isp.push(data);
        }

        isp = _util2.default.concatUint8Array(isp);

        if (isp.length > count) {
          isp = isp.subarray(0, count);
        }

        return _crypto2.default.hash.digest(algorithm, _util2.default.concatUint8Array([prefix, isp]));

      case 'gnu':
        throw new Error("GNU s2k type not supported.");

      default:
        throw new Error("Unknown s2k type.");
    }
  }

  var arr = [],
      rlength = 0,
      prefix = new Uint8Array(numBytes);

  for (var i = 0; i < numBytes; i++) {
    prefix[i] = 0;
  }
  i = 0;

  while (rlength < numBytes) {
    var result = round(prefix.subarray(0, i), this);
    arr.push(result);
    rlength += result.length;
    i++;
  }

  return _util2.default.concatUint8Array(arr).subarray(0, numBytes);
};

S2K.fromClone = function (clone) {
  var s2k = new S2K();
  s2k.algorithm = clone.algorithm;
  s2k.type = clone.type;
  s2k.c = clone.c;
  s2k.salt = clone.salt;
  return s2k;
};

},{"../crypto":24,"../enums.js":35,"../util.js":70}],70:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * This object contains utility functions
 * @requires config
 * @module util
 */

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _config = _dereq_('./config');

var _config2 = _interopRequireDefault(_config);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = {

  isString: function isString(data) {
    return typeof data === 'string' || String.prototype.isPrototypeOf(data);
  },

  isArray: function isArray(data) {
    return Array.prototype.isPrototypeOf(data);
  },

  isUint8Array: function isUint8Array(data) {
    return Uint8Array.prototype.isPrototypeOf(data);
  },

  isEmailAddress: function isEmailAddress(data) {
    if (!this.isString(data)) {
      return false;
    }
    var re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(data);
  },

  isUserId: function isUserId(data) {
    if (!this.isString(data)) {
      return false;
    }
    return (/</.test(data) && />$/.test(data)
    );
  },

  /**
   * Get transferable objects to pass buffers with zero copy (similar to "pass by reference" in C++)
   *   See: https://developer.mozilla.org/en-US/docs/Web/API/Worker/postMessage
   * @param  {Object} obj           the options object to be passed to the web worker
   * @return {Array<ArrayBuffer>}   an array of binary data to be passed
   */
  getTransferables: function getTransferables(obj) {
    if (_config2.default.zero_copy && Object.prototype.isPrototypeOf(obj)) {
      var transferables = [];
      this.collectBuffers(obj, transferables);
      return transferables.length ? transferables : undefined;
    }
  },

  collectBuffers: function collectBuffers(obj, collection) {
    if (!obj) {
      return;
    }
    if (this.isUint8Array(obj) && collection.indexOf(obj.buffer) === -1) {
      collection.push(obj.buffer);
      return;
    }
    if (Object.prototype.isPrototypeOf(obj)) {
      for (var key in obj) {
        // recursively search all children
        this.collectBuffers(obj[key], collection);
      }
    }
  },

  readNumber: function readNumber(bytes) {
    var n = 0;
    for (var i = 0; i < bytes.length; i++) {
      n += Math.pow(256, i) * bytes[bytes.length - 1 - i];
    }
    return n;
  },

  writeNumber: function writeNumber(n, bytes) {
    var b = new Uint8Array(bytes);
    for (var i = 0; i < bytes; i++) {
      b[i] = n >> 8 * (bytes - i - 1) & 0xFF;
    }

    return b;
  },

  readDate: function readDate(bytes) {
    var n = this.readNumber(bytes);
    var d = new Date();
    d.setTime(n * 1000);
    return d;
  },

  writeDate: function writeDate(time) {
    var numeric = Math.round(time.getTime() / 1000);

    return this.writeNumber(numeric, 4);
  },

  hexdump: function hexdump(str) {
    var r = [];
    var e = str.length;
    var c = 0;
    var h;
    var i = 0;
    while (c < e) {
      h = str.charCodeAt(c++).toString(16);
      while (h.length < 2) {
        h = "0" + h;
      }
      r.push(" " + h);
      i++;
      if (i % 32 === 0) {
        r.push("\n           ");
      }
    }
    return r.join('');
  },

  /**
   * Create hexstring from a binary
   * @param {String} str String to convert
   * @return {String} String containing the hexadecimal values
   */
  hexstrdump: function hexstrdump(str) {
    if (str === null) {
      return "";
    }
    var r = [];
    var e = str.length;
    var c = 0;
    var h;
    while (c < e) {
      h = str.charCodeAt(c++).toString(16);
      while (h.length < 2) {
        h = "0" + h;
      }
      r.push("" + h);
    }
    return r.join('');
  },

  /**
   * Create binary string from a hex encoded string
   * @param {String} str Hex string to convert
   * @return {String} String containing the binary values
   */
  hex2bin: function hex2bin(hex) {
    var str = '';
    for (var i = 0; i < hex.length; i += 2) {
      str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return str;
  },

  /**
   * Creating a hex string from an binary array of integers (0..255)
   * @param {String} str Array of bytes to convert
   * @return {String} Hexadecimal representation of the array
   */
  hexidump: function hexidump(str) {
    var r = [];
    var e = str.length;
    var c = 0;
    var h;
    while (c < e) {
      h = str[c++].toString(16);
      while (h.length < 2) {
        h = "0" + h;
      }
      r.push("" + h);
    }
    return r.join('');
  },

  /**
   * Convert a native javascript string to a string of utf8 bytes
   * @param {String} str The string to convert
   * @return {String} A valid squence of utf8 bytes
   */
  encode_utf8: function encode_utf8(str) {
    return unescape(encodeURIComponent(str));
  },

  /**
   * Convert a string of utf8 bytes to a native javascript string
   * @param {String} utf8 A valid squence of utf8 bytes
   * @return {String} A native javascript string
   */
  decode_utf8: function decode_utf8(utf8) {
    if (typeof utf8 !== 'string') {
      throw new Error('Parameter "utf8" is not of type string');
    }
    try {
      return decodeURIComponent(escape(utf8));
    } catch (e) {
      return utf8;
    }
  },

  /**
   * Convert an array of integers(0.255) to a string
   * @param {Array<Integer>} bin An array of (binary) integers to convert
   * @return {String} The string representation of the array
   */
  bin2str: function bin2str(bin) {
    var result = [];
    for (var i = 0; i < bin.length; i++) {
      result[i] = String.fromCharCode(bin[i]);
    }
    return result.join('');
  },

  /**
   * Convert a string to an array of integers(0.255)
   * @param {String} str String to convert
   * @return {Array<Integer>} An array of (binary) integers
   */
  str2bin: function str2bin(str) {
    var result = [];
    for (var i = 0; i < str.length; i++) {
      result[i] = str.charCodeAt(i);
    }
    return result;
  },

  /**
   * Convert a string to a Uint8Array
   * @param {String} str String to convert
   * @return {Uint8Array} The array of (binary) integers
   */
  str2Uint8Array: function str2Uint8Array(str) {
    if (typeof str !== 'string' && !String.prototype.isPrototypeOf(str)) {
      throw new Error('str2Uint8Array: Data must be in the form of a string');
    }

    var result = new Uint8Array(str.length);
    for (var i = 0; i < str.length; i++) {
      result[i] = str.charCodeAt(i);
    }
    return result;
  },

  /**
   * Convert a Uint8Array to a string. This currently functions
   * the same as bin2str.
   * @function module:util.Uint8Array2str
   * @param {Uint8Array} bin An array of (binary) integers to convert
   * @return {String} String representation of the array
   */
  Uint8Array2str: function Uint8Array2str(bin) {
    if (!Uint8Array.prototype.isPrototypeOf(bin)) {
      throw new Error('Uint8Array2str: Data must be in the form of a Uint8Array');
    }

    var result = [],
        bs = 16384,
        j = bin.length;

    for (var i = 0; i < j; i += bs) {
      result.push(String.fromCharCode.apply(String, bin.subarray(i, i + bs < j ? i + bs : j)));
    }
    return result.join('');
  },

  /**
   * Concat Uint8arrays
   * @function module:util.concatUint8Array
   * @param {Array<Uint8array>} Array of Uint8Arrays to concatenate
   * @return {Uint8array} Concatenated array
   */
  concatUint8Array: function concatUint8Array(arrays) {
    var totalLength = 0;
    arrays.forEach(function (element) {
      if (!Uint8Array.prototype.isPrototypeOf(element)) {
        throw new Error('concatUint8Array: Data must be in the form of a Uint8Array');
      }

      totalLength += element.length;
    });

    var result = new Uint8Array(totalLength);
    var pos = 0;
    arrays.forEach(function (element) {
      result.set(element, pos);
      pos += element.length;
    });

    return result;
  },

  /**
   * Deep copy Uint8Array
   * @function module:util.copyUint8Array
   * @param {Uint8Array} Array to copy
   * @return {Uint8Array} new Uint8Array
   */
  copyUint8Array: function copyUint8Array(array) {
    if (!Uint8Array.prototype.isPrototypeOf(array)) {
      throw new Error('Data must be in the form of a Uint8Array');
    }

    var copy = new Uint8Array(array.length);
    copy.set(array);
    return copy;
  },

  /**
   * Check Uint8Array equality
   * @function module:util.equalsUint8Array
   * @param {Uint8Array} first array
   * @param {Uint8Array} second array
   * @return {Boolean} equality
   */
  equalsUint8Array: function equalsUint8Array(array1, array2) {
    if (!Uint8Array.prototype.isPrototypeOf(array1) || !Uint8Array.prototype.isPrototypeOf(array2)) {
      throw new Error('Data must be in the form of a Uint8Array');
    }

    if (array1.length !== array2.length) {
      return false;
    }

    for (var i = 0; i < array1.length; i++) {
      if (array1[i] !== array2[i]) {
        return false;
      }
    }
    return true;
  },

  /**
   * Calculates a 16bit sum of a Uint8Array by adding each character
   * codes modulus 65535
   * @param {Uint8Array} Uint8Array to create a sum of
   * @return {Integer} An integer containing the sum of all character
   * codes % 65535
   */
  calc_checksum: function calc_checksum(text) {
    var checksum = {
      s: 0,
      add: function add(sadd) {
        this.s = (this.s + sadd) % 65536;
      }
    };
    for (var i = 0; i < text.length; i++) {
      checksum.add(text[i]);
    }
    return checksum.s;
  },

  /**
   * Helper function to print a debug message. Debug
   * messages are only printed if
   * @link module:config/config.debug is set to true.
   * @param {String} str String of the debug message
   */
  print_debug: function print_debug(str) {
    if (_config2.default.debug) {
      console.log(str);
    }
  },

  /**
   * Helper function to print a debug message. Debug
   * messages are only printed if
   * @link module:config/config.debug is set to true.
   * Different than print_debug because will call hexstrdump iff necessary.
   * @param {String} str String of the debug message
   */
  print_debug_hexstr_dump: function print_debug_hexstr_dump(str, strToHex) {
    if (_config2.default.debug) {
      str = str + this.hexstrdump(strToHex);
      console.log(str);
    }
  },

  getLeftNBits: function getLeftNBits(string, bitcount) {
    var rest = bitcount % 8;
    if (rest === 0) {
      return string.substring(0, bitcount / 8);
    }
    var bytes = (bitcount - rest) / 8 + 1;
    var result = string.substring(0, bytes);
    return this.shiftRight(result, 8 - rest); // +String.fromCharCode(string.charCodeAt(bytes -1) << (8-rest) & 0xFF);
  },

  /**
   * Shifting a string to n bits right
   * @param {String} value The string to shift
   * @param {Integer} bitcount Amount of bits to shift (MUST be smaller
   * than 9)
   * @return {String} Resulting string.
   */
  shiftRight: function shiftRight(value, bitcount) {
    var temp = this.str2bin(value);
    if (bitcount % 8 !== 0) {
      for (var i = temp.length - 1; i >= 0; i--) {
        temp[i] >>= bitcount % 8;
        if (i > 0) {
          temp[i] |= temp[i - 1] << 8 - bitcount % 8 & 0xFF;
        }
      }
    } else {
      return value;
    }
    return this.bin2str(temp);
  },

  /**
   * Return the algorithm type as string
   * @return {String} String representing the message type
   */
  get_hashAlgorithmString: function get_hashAlgorithmString(algo) {
    switch (algo) {
      case 1:
        return "MD5";
      case 2:
        return "SHA1";
      case 3:
        return "RIPEMD160";
      case 8:
        return "SHA256";
      case 9:
        return "SHA384";
      case 10:
        return "SHA512";
      case 11:
        return "SHA224";
    }
    return "unknown";
  },

  /**
   * Get native Web Cryptography api, only the current version of the spec.
   * The default configuration is to use the api when available. But it can
   * be deactivated with config.use_native
   * @return {Object}   The SubtleCrypto api or 'undefined'
   */
  getWebCrypto: function getWebCrypto() {
    if (!_config2.default.use_native) {
      return;
    }

    return typeof window !== 'undefined' && window.crypto && window.crypto.subtle;
  },

  /**
   * Get native Web Cryptography api for all browsers, including legacy
   * implementations of the spec e.g IE11 and Safari 8/9. The default
   * configuration is to use the api when available. But it can be deactivated
   * with config.use_native
   * @return {Object}   The SubtleCrypto api or 'undefined'
   */
  getWebCryptoAll: function getWebCryptoAll() {
    if (!_config2.default.use_native) {
      return;
    }

    if (typeof window !== 'undefined') {
      if (window.crypto) {
        return window.crypto.subtle || window.crypto.webkitSubtle;
      }
      if (window.msCrypto) {
        return window.msCrypto.subtle;
      }
    }
  },

  /**
   * Wraps a generic synchronous function in an ES6 Promise.
   * @param  {Function} fn  The function to be wrapped
   * @return {Function}     The function wrapped in a Promise
   */
  promisify: function promisify(fn) {
    return function () {
      var args = arguments;
      return new Promise(function (resolve) {
        var result = fn.apply(null, args);
        resolve(result);
      });
    };
  },

  /**
   * Converts an IE11 web crypro api result to a promise.
   *   This is required since IE11 implements an old version of the
   *   Web Crypto specification that does not use promises.
   * @param  {Object} cryptoOp The return value of an IE11 web cryptro api call
   * @param  {String} errmsg   An error message for a specific operation
   * @return {Promise}         The resulting Promise
   */
  promisifyIE11Op: function promisifyIE11Op(cryptoOp, errmsg) {
    return new Promise(function (resolve, reject) {
      cryptoOp.onerror = function () {
        reject(new Error(errmsg));
      };
      cryptoOp.oncomplete = function (e) {
        resolve(e.target.result);
      };
    });
  },

  /**
   * Detect Node.js runtime.
   */
  detectNode: function detectNode() {
    return typeof window === 'undefined';
  },

  /**
   * Get native Node.js crypto api. The default configuration is to use
   * the api when available. But it can also be deactivated with config.use_native
   * @return {Object}   The crypto module or 'undefined'
   */
  getNodeCrypto: function getNodeCrypto() {
    if (!this.detectNode() || !_config2.default.use_native) {
      return;
    }

    return _dereq_('crypto');
  },

  /**
   * Get native Node.js Buffer constructor. This should be used since
   * Buffer is not available under browserify.
   * @return {Function}   The Buffer constructor or 'undefined'
   */
  getNodeBuffer: function getNodeBuffer() {
    if (!this.detectNode()) {
      return;
    }

    return _dereq_('buffer').Buffer;
  }

};

},{"./config":10,"buffer":"buffer","crypto":"crypto"}],71:[function(_dereq_,module,exports){
// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = AsyncProxy;

var _util = _dereq_('../util.js');

var _util2 = _interopRequireDefault(_util);

var _crypto = _dereq_('../crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _packet = _dereq_('../packet');

var _packet2 = _interopRequireDefault(_packet);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var INITIAL_RANDOM_SEED = 50000,
    // random bytes seeded to worker
RANDOM_SEED_REQUEST = 20000; // random bytes seeded after worker request

/**
 * Initializes a new proxy and loads the web worker
 * @constructor
 * @param {String} path     The path to the worker or 'openpgp.worker.js' by default
 * @param {Object} config   config The worker configuration
 * @param {Object} worker   alternative to path parameter: web worker initialized with 'openpgp.worker.js'
 * @return {Promise}
 */
function AsyncProxy() {
  var _ref = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

  var _ref$path = _ref.path;
  var path = _ref$path === undefined ? 'openpgp.worker.js' : _ref$path;
  var worker = _ref.worker;
  var config = _ref.config;

  this.worker = worker || new Worker(path);
  this.worker.onmessage = this.onMessage.bind(this);
  this.worker.onerror = function (e) {
    throw new Error('Unhandled error in openpgp worker: ' + e.message + ' (' + e.filename + ':' + e.lineno + ')');
  };
  this.seedRandom(INITIAL_RANDOM_SEED);

  if (config) {
    this.worker.postMessage({ event: 'configure', config: config });
  }

  // Cannot rely on task order being maintained, use object keyed by request ID to track tasks
  this.tasks = {};
  this.currentID = 0;
}

/**
 * Get new request ID
 * @return {integer}          New unique request ID
*/
AsyncProxy.prototype.getID = function () {
  return this.currentID++;
};

/**
 * Message handling
 */
AsyncProxy.prototype.onMessage = function (event) {
  var msg = event.data;
  switch (msg.event) {
    case 'method-return':
      if (msg.err) {
        // fail
        this.tasks[msg.id].reject(new Error(msg.err));
      } else {
        // success
        this.tasks[msg.id].resolve(msg.data);
      }
      delete this.tasks[msg.id];
      break;
    case 'request-seed':
      this.seedRandom(RANDOM_SEED_REQUEST);
      break;
    default:
      throw new Error('Unknown Worker Event.');
  }
};

/**
 * Send message to worker with random data
 * @param  {Integer} size Number of bytes to send
 */
AsyncProxy.prototype.seedRandom = function (size) {
  var buf = this.getRandomBuffer(size);
  this.worker.postMessage({ event: 'seed-random', buf: buf }, _util2.default.getTransferables.call(_util2.default, buf));
};

/**
 * Get Uint8Array with random numbers
 * @param  {Integer} size Length of buffer
 * @return {Uint8Array}
 */
AsyncProxy.prototype.getRandomBuffer = function (size) {
  if (!size) {
    return null;
  }
  var buf = new Uint8Array(size);
  _crypto2.default.random.getRandomValues(buf);
  return buf;
};

/**
 * Terminates the worker
 */
AsyncProxy.prototype.terminate = function () {
  this.worker.terminate();
};

/**
 * Generic proxy function that handles all commands from the public api.
 * @param  {String} method    the public api function to be delegated to the worker thread
 * @param  {Object} options   the api function's options
 * @return {Promise}          see the corresponding public api functions for their return types
 */
AsyncProxy.prototype.delegate = function (method, options) {
  var _this = this;

  var id = this.getID();

  return new Promise(function (_resolve, reject) {
    // clone packets (for web worker structured cloning algorithm)
    _this.worker.postMessage({ id: id, event: method, options: _packet2.default.clone.clonePackets(options) }, _util2.default.getTransferables.call(_util2.default, options));

    // remember to handle parsing cloned packets from worker
    _this.tasks[id] = { resolve: function resolve(data) {
        return _resolve(_packet2.default.clone.parseClonedPackets(data, method));
      }, reject: reject };
  });
};

},{"../crypto":24,"../packet":47,"../util.js":70}]},{},[37])(37)
});