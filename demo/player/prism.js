(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./enc-base64"), require("./md5"), require("./evpkdf"), require("./cipher-core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./enc-base64", "./md5", "./evpkdf", "./cipher-core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var BlockCipher = C_lib.BlockCipher;
	    var C_algo = C.algo;

	    // Lookup tables
	    var SBOX = [];
	    var INV_SBOX = [];
	    var SUB_MIX_0 = [];
	    var SUB_MIX_1 = [];
	    var SUB_MIX_2 = [];
	    var SUB_MIX_3 = [];
	    var INV_SUB_MIX_0 = [];
	    var INV_SUB_MIX_1 = [];
	    var INV_SUB_MIX_2 = [];
	    var INV_SUB_MIX_3 = [];

	    // Compute lookup tables
	    (function () {
	        // Compute double table
	        var d = [];
	        for (var i = 0; i < 256; i++) {
	            if (i < 128) {
	                d[i] = i << 1;
	            } else {
	                d[i] = (i << 1) ^ 0x11b;
	            }
	        }

	        // Walk GF(2^8)
	        var x = 0;
	        var xi = 0;
	        for (var i = 0; i < 256; i++) {
	            // Compute sbox
	            var sx = xi ^ (xi << 1) ^ (xi << 2) ^ (xi << 3) ^ (xi << 4);
	            sx = (sx >>> 8) ^ (sx & 0xff) ^ 0x63;
	            SBOX[x] = sx;
	            INV_SBOX[sx] = x;

	            // Compute multiplication
	            var x2 = d[x];
	            var x4 = d[x2];
	            var x8 = d[x4];

	            // Compute sub bytes, mix columns tables
	            var t = (d[sx] * 0x101) ^ (sx * 0x1010100);
	            SUB_MIX_0[x] = (t << 24) | (t >>> 8);
	            SUB_MIX_1[x] = (t << 16) | (t >>> 16);
	            SUB_MIX_2[x] = (t << 8)  | (t >>> 24);
	            SUB_MIX_3[x] = t;

	            // Compute inv sub bytes, inv mix columns tables
	            var t = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (x * 0x1010100);
	            INV_SUB_MIX_0[sx] = (t << 24) | (t >>> 8);
	            INV_SUB_MIX_1[sx] = (t << 16) | (t >>> 16);
	            INV_SUB_MIX_2[sx] = (t << 8)  | (t >>> 24);
	            INV_SUB_MIX_3[sx] = t;

	            // Compute next counter
	            if (!x) {
	                x = xi = 1;
	            } else {
	                x = x2 ^ d[d[d[x8 ^ x2]]];
	                xi ^= d[d[xi]];
	            }
	        }
	    }());

	    // Precomputed Rcon lookup
	    var RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

	    /**
	     * AES block cipher algorithm.
	     */
	    var AES = C_algo.AES = BlockCipher.extend({
	        _doReset: function () {
	            // Skip reset of nRounds has been set before and key did not change
	            if (this._nRounds && this._keyPriorReset === this._key) {
	                return;
	            }

	            // Shortcuts
	            var key = this._keyPriorReset = this._key;
	            var keyWords = key.words;
	            var keySize = key.sigBytes / 4;

	            // Compute number of rounds
	            var nRounds = this._nRounds = keySize + 6;

	            // Compute number of key schedule rows
	            var ksRows = (nRounds + 1) * 4;

	            // Compute key schedule
	            var keySchedule = this._keySchedule = [];
	            for (var ksRow = 0; ksRow < ksRows; ksRow++) {
	                if (ksRow < keySize) {
	                    keySchedule[ksRow] = keyWords[ksRow];
	                } else {
	                    var t = keySchedule[ksRow - 1];

	                    if (!(ksRow % keySize)) {
	                        // Rot word
	                        t = (t << 8) | (t >>> 24);

	                        // Sub word
	                        t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];

	                        // Mix Rcon
	                        t ^= RCON[(ksRow / keySize) | 0] << 24;
	                    } else if (keySize > 6 && ksRow % keySize == 4) {
	                        // Sub word
	                        t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];
	                    }

	                    keySchedule[ksRow] = keySchedule[ksRow - keySize] ^ t;
	                }
	            }

	            // Compute inv key schedule
	            var invKeySchedule = this._invKeySchedule = [];
	            for (var invKsRow = 0; invKsRow < ksRows; invKsRow++) {
	                var ksRow = ksRows - invKsRow;

	                if (invKsRow % 4) {
	                    var t = keySchedule[ksRow];
	                } else {
	                    var t = keySchedule[ksRow - 4];
	                }

	                if (invKsRow < 4 || ksRow <= 4) {
	                    invKeySchedule[invKsRow] = t;
	                } else {
	                    invKeySchedule[invKsRow] = INV_SUB_MIX_0[SBOX[t >>> 24]] ^ INV_SUB_MIX_1[SBOX[(t >>> 16) & 0xff]] ^
	                                               INV_SUB_MIX_2[SBOX[(t >>> 8) & 0xff]] ^ INV_SUB_MIX_3[SBOX[t & 0xff]];
	                }
	            }
	        },

	        encryptBlock: function (M, offset) {
	            this._doCryptBlock(M, offset, this._keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX);
	        },

	        decryptBlock: function (M, offset) {
	            // Swap 2nd and 4th rows
	            var t = M[offset + 1];
	            M[offset + 1] = M[offset + 3];
	            M[offset + 3] = t;

	            this._doCryptBlock(M, offset, this._invKeySchedule, INV_SUB_MIX_0, INV_SUB_MIX_1, INV_SUB_MIX_2, INV_SUB_MIX_3, INV_SBOX);

	            // Inv swap 2nd and 4th rows
	            var t = M[offset + 1];
	            M[offset + 1] = M[offset + 3];
	            M[offset + 3] = t;
	        },

	        _doCryptBlock: function (M, offset, keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX) {
	            // Shortcut
	            var nRounds = this._nRounds;

	            // Get input, add round key
	            var s0 = M[offset]     ^ keySchedule[0];
	            var s1 = M[offset + 1] ^ keySchedule[1];
	            var s2 = M[offset + 2] ^ keySchedule[2];
	            var s3 = M[offset + 3] ^ keySchedule[3];

	            // Key schedule row counter
	            var ksRow = 4;

	            // Rounds
	            for (var round = 1; round < nRounds; round++) {
	                // Shift rows, sub bytes, mix columns, add round key
	                var t0 = SUB_MIX_0[s0 >>> 24] ^ SUB_MIX_1[(s1 >>> 16) & 0xff] ^ SUB_MIX_2[(s2 >>> 8) & 0xff] ^ SUB_MIX_3[s3 & 0xff] ^ keySchedule[ksRow++];
	                var t1 = SUB_MIX_0[s1 >>> 24] ^ SUB_MIX_1[(s2 >>> 16) & 0xff] ^ SUB_MIX_2[(s3 >>> 8) & 0xff] ^ SUB_MIX_3[s0 & 0xff] ^ keySchedule[ksRow++];
	                var t2 = SUB_MIX_0[s2 >>> 24] ^ SUB_MIX_1[(s3 >>> 16) & 0xff] ^ SUB_MIX_2[(s0 >>> 8) & 0xff] ^ SUB_MIX_3[s1 & 0xff] ^ keySchedule[ksRow++];
	                var t3 = SUB_MIX_0[s3 >>> 24] ^ SUB_MIX_1[(s0 >>> 16) & 0xff] ^ SUB_MIX_2[(s1 >>> 8) & 0xff] ^ SUB_MIX_3[s2 & 0xff] ^ keySchedule[ksRow++];

	                // Update state
	                s0 = t0;
	                s1 = t1;
	                s2 = t2;
	                s3 = t3;
	            }

	            // Shift rows, sub bytes, add round key
	            var t0 = ((SBOX[s0 >>> 24] << 24) | (SBOX[(s1 >>> 16) & 0xff] << 16) | (SBOX[(s2 >>> 8) & 0xff] << 8) | SBOX[s3 & 0xff]) ^ keySchedule[ksRow++];
	            var t1 = ((SBOX[s1 >>> 24] << 24) | (SBOX[(s2 >>> 16) & 0xff] << 16) | (SBOX[(s3 >>> 8) & 0xff] << 8) | SBOX[s0 & 0xff]) ^ keySchedule[ksRow++];
	            var t2 = ((SBOX[s2 >>> 24] << 24) | (SBOX[(s3 >>> 16) & 0xff] << 16) | (SBOX[(s0 >>> 8) & 0xff] << 8) | SBOX[s1 & 0xff]) ^ keySchedule[ksRow++];
	            var t3 = ((SBOX[s3 >>> 24] << 24) | (SBOX[(s0 >>> 16) & 0xff] << 16) | (SBOX[(s1 >>> 8) & 0xff] << 8) | SBOX[s2 & 0xff]) ^ keySchedule[ksRow++];

	            // Set output
	            M[offset]     = t0;
	            M[offset + 1] = t1;
	            M[offset + 2] = t2;
	            M[offset + 3] = t3;
	        },

	        keySize: 256/32
	    });

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.AES.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.AES.decrypt(ciphertext, key, cfg);
	     */
	    C.AES = BlockCipher._createHelper(AES);
	}());


	return CryptoJS.AES;

}));
},{"./cipher-core":2,"./core":3,"./enc-base64":4,"./evpkdf":6,"./md5":11}],2:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./evpkdf"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./evpkdf"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	/**
	 * Cipher core components.
	 */
	CryptoJS.lib.Cipher || (function (undefined) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var WordArray = C_lib.WordArray;
	    var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm;
	    var C_enc = C.enc;
	    var Utf8 = C_enc.Utf8;
	    var Base64 = C_enc.Base64;
	    var C_algo = C.algo;
	    var EvpKDF = C_algo.EvpKDF;

	    /**
	     * Abstract base cipher template.
	     *
	     * @property {number} keySize This cipher's key size. Default: 4 (128 bits)
	     * @property {number} ivSize This cipher's IV size. Default: 4 (128 bits)
	     * @property {number} _ENC_XFORM_MODE A constant representing encryption mode.
	     * @property {number} _DEC_XFORM_MODE A constant representing decryption mode.
	     */
	    var Cipher = C_lib.Cipher = BufferedBlockAlgorithm.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {WordArray} iv The IV to use for this operation.
	         */
	        cfg: Base.extend(),

	        /**
	         * Creates this cipher in encryption mode.
	         *
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {Cipher} A cipher instance.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var cipher = CryptoJS.algo.AES.createEncryptor(keyWordArray, { iv: ivWordArray });
	         */
	        createEncryptor: function (key, cfg) {
	            return this.create(this._ENC_XFORM_MODE, key, cfg);
	        },

	        /**
	         * Creates this cipher in decryption mode.
	         *
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {Cipher} A cipher instance.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var cipher = CryptoJS.algo.AES.createDecryptor(keyWordArray, { iv: ivWordArray });
	         */
	        createDecryptor: function (key, cfg) {
	            return this.create(this._DEC_XFORM_MODE, key, cfg);
	        },

	        /**
	         * Initializes a newly created cipher.
	         *
	         * @param {number} xformMode Either the encryption or decryption transormation mode constant.
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @example
	         *
	         *     var cipher = CryptoJS.algo.AES.create(CryptoJS.algo.AES._ENC_XFORM_MODE, keyWordArray, { iv: ivWordArray });
	         */
	        init: function (xformMode, key, cfg) {
	            // Apply config defaults
	            this.cfg = this.cfg.extend(cfg);

	            // Store transform mode and key
	            this._xformMode = xformMode;
	            this._key = key;

	            // Set initial values
	            this.reset();
	        },

	        /**
	         * Resets this cipher to its initial state.
	         *
	         * @example
	         *
	         *     cipher.reset();
	         */
	        reset: function () {
	            // Reset data buffer
	            BufferedBlockAlgorithm.reset.call(this);

	            // Perform concrete-cipher logic
	            this._doReset();
	        },

	        /**
	         * Adds data to be encrypted or decrypted.
	         *
	         * @param {WordArray|string} dataUpdate The data to encrypt or decrypt.
	         *
	         * @return {WordArray} The data after processing.
	         *
	         * @example
	         *
	         *     var encrypted = cipher.process('data');
	         *     var encrypted = cipher.process(wordArray);
	         */
	        process: function (dataUpdate) {
	            // Append
	            this._append(dataUpdate);

	            // Process available blocks
	            return this._process();
	        },

	        /**
	         * Finalizes the encryption or decryption process.
	         * Note that the finalize operation is effectively a destructive, read-once operation.
	         *
	         * @param {WordArray|string} dataUpdate The final data to encrypt or decrypt.
	         *
	         * @return {WordArray} The data after final processing.
	         *
	         * @example
	         *
	         *     var encrypted = cipher.finalize();
	         *     var encrypted = cipher.finalize('data');
	         *     var encrypted = cipher.finalize(wordArray);
	         */
	        finalize: function (dataUpdate) {
	            // Final data update
	            if (dataUpdate) {
	                this._append(dataUpdate);
	            }

	            // Perform concrete-cipher logic
	            var finalProcessedData = this._doFinalize();

	            return finalProcessedData;
	        },

	        keySize: 128/32,

	        ivSize: 128/32,

	        _ENC_XFORM_MODE: 1,

	        _DEC_XFORM_MODE: 2,

	        /**
	         * Creates shortcut functions to a cipher's object interface.
	         *
	         * @param {Cipher} cipher The cipher to create a helper for.
	         *
	         * @return {Object} An object with encrypt and decrypt shortcut functions.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var AES = CryptoJS.lib.Cipher._createHelper(CryptoJS.algo.AES);
	         */
	        _createHelper: (function () {
	            function selectCipherStrategy(key) {
	                if (typeof key == 'string') {
	                    return PasswordBasedCipher;
	                } else {
	                    return SerializableCipher;
	                }
	            }

	            return function (cipher) {
	                return {
	                    encrypt: function (message, key, cfg) {
	                        return selectCipherStrategy(key).encrypt(cipher, message, key, cfg);
	                    },

	                    decrypt: function (ciphertext, key, cfg) {
	                        return selectCipherStrategy(key).decrypt(cipher, ciphertext, key, cfg);
	                    }
	                };
	            };
	        }())
	    });

	    /**
	     * Abstract base stream cipher template.
	     *
	     * @property {number} blockSize The number of 32-bit words this cipher operates on. Default: 1 (32 bits)
	     */
	    var StreamCipher = C_lib.StreamCipher = Cipher.extend({
	        _doFinalize: function () {
	            // Process partial blocks
	            var finalProcessedBlocks = this._process(!!'flush');

	            return finalProcessedBlocks;
	        },

	        blockSize: 1
	    });

	    /**
	     * Mode namespace.
	     */
	    var C_mode = C.mode = {};

	    /**
	     * Abstract base block cipher mode template.
	     */
	    var BlockCipherMode = C_lib.BlockCipherMode = Base.extend({
	        /**
	         * Creates this mode for encryption.
	         *
	         * @param {Cipher} cipher A block cipher instance.
	         * @param {Array} iv The IV words.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var mode = CryptoJS.mode.CBC.createEncryptor(cipher, iv.words);
	         */
	        createEncryptor: function (cipher, iv) {
	            return this.Encryptor.create(cipher, iv);
	        },

	        /**
	         * Creates this mode for decryption.
	         *
	         * @param {Cipher} cipher A block cipher instance.
	         * @param {Array} iv The IV words.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var mode = CryptoJS.mode.CBC.createDecryptor(cipher, iv.words);
	         */
	        createDecryptor: function (cipher, iv) {
	            return this.Decryptor.create(cipher, iv);
	        },

	        /**
	         * Initializes a newly created mode.
	         *
	         * @param {Cipher} cipher A block cipher instance.
	         * @param {Array} iv The IV words.
	         *
	         * @example
	         *
	         *     var mode = CryptoJS.mode.CBC.Encryptor.create(cipher, iv.words);
	         */
	        init: function (cipher, iv) {
	            this._cipher = cipher;
	            this._iv = iv;
	        }
	    });

	    /**
	     * Cipher Block Chaining mode.
	     */
	    var CBC = C_mode.CBC = (function () {
	        /**
	         * Abstract base CBC mode.
	         */
	        var CBC = BlockCipherMode.extend();

	        /**
	         * CBC encryptor.
	         */
	        CBC.Encryptor = CBC.extend({
	            /**
	             * Processes the data block at offset.
	             *
	             * @param {Array} words The data words to operate on.
	             * @param {number} offset The offset where the block starts.
	             *
	             * @example
	             *
	             *     mode.processBlock(data.words, offset);
	             */
	            processBlock: function (words, offset) {
	                // Shortcuts
	                var cipher = this._cipher;
	                var blockSize = cipher.blockSize;

	                // XOR and encrypt
	                xorBlock.call(this, words, offset, blockSize);
	                cipher.encryptBlock(words, offset);

	                // Remember this block to use with next block
	                this._prevBlock = words.slice(offset, offset + blockSize);
	            }
	        });

	        /**
	         * CBC decryptor.
	         */
	        CBC.Decryptor = CBC.extend({
	            /**
	             * Processes the data block at offset.
	             *
	             * @param {Array} words The data words to operate on.
	             * @param {number} offset The offset where the block starts.
	             *
	             * @example
	             *
	             *     mode.processBlock(data.words, offset);
	             */
	            processBlock: function (words, offset) {
	                // Shortcuts
	                var cipher = this._cipher;
	                var blockSize = cipher.blockSize;

	                // Remember this block to use with next block
	                var thisBlock = words.slice(offset, offset + blockSize);

	                // Decrypt and XOR
	                cipher.decryptBlock(words, offset);
	                xorBlock.call(this, words, offset, blockSize);

	                // This block becomes the previous block
	                this._prevBlock = thisBlock;
	            }
	        });

	        function xorBlock(words, offset, blockSize) {
	            // Shortcut
	            var iv = this._iv;

	            // Choose mixing block
	            if (iv) {
	                var block = iv;

	                // Remove IV for subsequent blocks
	                this._iv = undefined;
	            } else {
	                var block = this._prevBlock;
	            }

	            // XOR blocks
	            for (var i = 0; i < blockSize; i++) {
	                words[offset + i] ^= block[i];
	            }
	        }

	        return CBC;
	    }());

	    /**
	     * Padding namespace.
	     */
	    var C_pad = C.pad = {};

	    /**
	     * PKCS #5/7 padding strategy.
	     */
	    var Pkcs7 = C_pad.Pkcs7 = {
	        /**
	         * Pads data using the algorithm defined in PKCS #5/7.
	         *
	         * @param {WordArray} data The data to pad.
	         * @param {number} blockSize The multiple that the data should be padded to.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     CryptoJS.pad.Pkcs7.pad(wordArray, 4);
	         */
	        pad: function (data, blockSize) {
	            // Shortcut
	            var blockSizeBytes = blockSize * 4;

	            // Count padding bytes
	            var nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

	            // Create padding word
	            var paddingWord = (nPaddingBytes << 24) | (nPaddingBytes << 16) | (nPaddingBytes << 8) | nPaddingBytes;

	            // Create padding
	            var paddingWords = [];
	            for (var i = 0; i < nPaddingBytes; i += 4) {
	                paddingWords.push(paddingWord);
	            }
	            var padding = WordArray.create(paddingWords, nPaddingBytes);

	            // Add padding
	            data.concat(padding);
	        },

	        /**
	         * Unpads data that had been padded using the algorithm defined in PKCS #5/7.
	         *
	         * @param {WordArray} data The data to unpad.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     CryptoJS.pad.Pkcs7.unpad(wordArray);
	         */
	        unpad: function (data) {
	            // Get number of padding bytes from last byte
	            var nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;

	            // Remove padding
	            data.sigBytes -= nPaddingBytes;
	        }
	    };

	    /**
	     * Abstract base block cipher template.
	     *
	     * @property {number} blockSize The number of 32-bit words this cipher operates on. Default: 4 (128 bits)
	     */
	    var BlockCipher = C_lib.BlockCipher = Cipher.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {Mode} mode The block mode to use. Default: CBC
	         * @property {Padding} padding The padding strategy to use. Default: Pkcs7
	         */
	        cfg: Cipher.cfg.extend({
	            mode: CBC,
	            padding: Pkcs7
	        }),

	        reset: function () {
	            // Reset cipher
	            Cipher.reset.call(this);

	            // Shortcuts
	            var cfg = this.cfg;
	            var iv = cfg.iv;
	            var mode = cfg.mode;

	            // Reset block mode
	            if (this._xformMode == this._ENC_XFORM_MODE) {
	                var modeCreator = mode.createEncryptor;
	            } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
	                var modeCreator = mode.createDecryptor;
	                // Keep at least one block in the buffer for unpadding
	                this._minBufferSize = 1;
	            }

	            if (this._mode && this._mode.__creator == modeCreator) {
	                this._mode.init(this, iv && iv.words);
	            } else {
	                this._mode = modeCreator.call(mode, this, iv && iv.words);
	                this._mode.__creator = modeCreator;
	            }
	        },

	        _doProcessBlock: function (words, offset) {
	            this._mode.processBlock(words, offset);
	        },

	        _doFinalize: function () {
	            // Shortcut
	            var padding = this.cfg.padding;

	            // Finalize
	            if (this._xformMode == this._ENC_XFORM_MODE) {
	                // Pad data
	                padding.pad(this._data, this.blockSize);

	                // Process final blocks
	                var finalProcessedBlocks = this._process(!!'flush');
	            } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
	                // Process final blocks
	                var finalProcessedBlocks = this._process(!!'flush');

	                // Unpad data
	                padding.unpad(finalProcessedBlocks);
	            }

	            return finalProcessedBlocks;
	        },

	        blockSize: 128/32
	    });

	    /**
	     * A collection of cipher parameters.
	     *
	     * @property {WordArray} ciphertext The raw ciphertext.
	     * @property {WordArray} key The key to this ciphertext.
	     * @property {WordArray} iv The IV used in the ciphering operation.
	     * @property {WordArray} salt The salt used with a key derivation function.
	     * @property {Cipher} algorithm The cipher algorithm.
	     * @property {Mode} mode The block mode used in the ciphering operation.
	     * @property {Padding} padding The padding scheme used in the ciphering operation.
	     * @property {number} blockSize The block size of the cipher.
	     * @property {Format} formatter The default formatting strategy to convert this cipher params object to a string.
	     */
	    var CipherParams = C_lib.CipherParams = Base.extend({
	        /**
	         * Initializes a newly created cipher params object.
	         *
	         * @param {Object} cipherParams An object with any of the possible cipher parameters.
	         *
	         * @example
	         *
	         *     var cipherParams = CryptoJS.lib.CipherParams.create({
	         *         ciphertext: ciphertextWordArray,
	         *         key: keyWordArray,
	         *         iv: ivWordArray,
	         *         salt: saltWordArray,
	         *         algorithm: CryptoJS.algo.AES,
	         *         mode: CryptoJS.mode.CBC,
	         *         padding: CryptoJS.pad.PKCS7,
	         *         blockSize: 4,
	         *         formatter: CryptoJS.format.OpenSSL
	         *     });
	         */
	        init: function (cipherParams) {
	            this.mixIn(cipherParams);
	        },

	        /**
	         * Converts this cipher params object to a string.
	         *
	         * @param {Format} formatter (Optional) The formatting strategy to use.
	         *
	         * @return {string} The stringified cipher params.
	         *
	         * @throws Error If neither the formatter nor the default formatter is set.
	         *
	         * @example
	         *
	         *     var string = cipherParams + '';
	         *     var string = cipherParams.toString();
	         *     var string = cipherParams.toString(CryptoJS.format.OpenSSL);
	         */
	        toString: function (formatter) {
	            return (formatter || this.formatter).stringify(this);
	        }
	    });

	    /**
	     * Format namespace.
	     */
	    var C_format = C.format = {};

	    /**
	     * OpenSSL formatting strategy.
	     */
	    var OpenSSLFormatter = C_format.OpenSSL = {
	        /**
	         * Converts a cipher params object to an OpenSSL-compatible string.
	         *
	         * @param {CipherParams} cipherParams The cipher params object.
	         *
	         * @return {string} The OpenSSL-compatible string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var openSSLString = CryptoJS.format.OpenSSL.stringify(cipherParams);
	         */
	        stringify: function (cipherParams) {
	            // Shortcuts
	            var ciphertext = cipherParams.ciphertext;
	            var salt = cipherParams.salt;

	            // Format
	            if (salt) {
	                var wordArray = WordArray.create([0x53616c74, 0x65645f5f]).concat(salt).concat(ciphertext);
	            } else {
	                var wordArray = ciphertext;
	            }

	            return wordArray.toString(Base64);
	        },

	        /**
	         * Converts an OpenSSL-compatible string to a cipher params object.
	         *
	         * @param {string} openSSLStr The OpenSSL-compatible string.
	         *
	         * @return {CipherParams} The cipher params object.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var cipherParams = CryptoJS.format.OpenSSL.parse(openSSLString);
	         */
	        parse: function (openSSLStr) {
	            // Parse base64
	            var ciphertext = Base64.parse(openSSLStr);

	            // Shortcut
	            var ciphertextWords = ciphertext.words;

	            // Test for salt
	            if (ciphertextWords[0] == 0x53616c74 && ciphertextWords[1] == 0x65645f5f) {
	                // Extract salt
	                var salt = WordArray.create(ciphertextWords.slice(2, 4));

	                // Remove salt from ciphertext
	                ciphertextWords.splice(0, 4);
	                ciphertext.sigBytes -= 16;
	            }

	            return CipherParams.create({ ciphertext: ciphertext, salt: salt });
	        }
	    };

	    /**
	     * A cipher wrapper that returns ciphertext as a serializable cipher params object.
	     */
	    var SerializableCipher = C_lib.SerializableCipher = Base.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {Formatter} format The formatting strategy to convert cipher param objects to and from a string. Default: OpenSSL
	         */
	        cfg: Base.extend({
	            format: OpenSSLFormatter
	        }),

	        /**
	         * Encrypts a message.
	         *
	         * @param {Cipher} cipher The cipher algorithm to use.
	         * @param {WordArray|string} message The message to encrypt.
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {CipherParams} A cipher params object.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key);
	         *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key, { iv: iv });
	         *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key, { iv: iv, format: CryptoJS.format.OpenSSL });
	         */
	        encrypt: function (cipher, message, key, cfg) {
	            // Apply config defaults
	            cfg = this.cfg.extend(cfg);

	            // Encrypt
	            var encryptor = cipher.createEncryptor(key, cfg);
	            var ciphertext = encryptor.finalize(message);

	            // Shortcut
	            var cipherCfg = encryptor.cfg;

	            // Create and return serializable cipher params
	            return CipherParams.create({
	                ciphertext: ciphertext,
	                key: key,
	                iv: cipherCfg.iv,
	                algorithm: cipher,
	                mode: cipherCfg.mode,
	                padding: cipherCfg.padding,
	                blockSize: cipher.blockSize,
	                formatter: cfg.format
	            });
	        },

	        /**
	         * Decrypts serialized ciphertext.
	         *
	         * @param {Cipher} cipher The cipher algorithm to use.
	         * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {WordArray} The plaintext.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var plaintext = CryptoJS.lib.SerializableCipher.decrypt(CryptoJS.algo.AES, formattedCiphertext, key, { iv: iv, format: CryptoJS.format.OpenSSL });
	         *     var plaintext = CryptoJS.lib.SerializableCipher.decrypt(CryptoJS.algo.AES, ciphertextParams, key, { iv: iv, format: CryptoJS.format.OpenSSL });
	         */
	        decrypt: function (cipher, ciphertext, key, cfg) {
	            // Apply config defaults
	            cfg = this.cfg.extend(cfg);

	            // Convert string to CipherParams
	            ciphertext = this._parse(ciphertext, cfg.format);

	            // Decrypt
	            var plaintext = cipher.createDecryptor(key, cfg).finalize(ciphertext.ciphertext);

	            return plaintext;
	        },

	        /**
	         * Converts serialized ciphertext to CipherParams,
	         * else assumed CipherParams already and returns ciphertext unchanged.
	         *
	         * @param {CipherParams|string} ciphertext The ciphertext.
	         * @param {Formatter} format The formatting strategy to use to parse serialized ciphertext.
	         *
	         * @return {CipherParams} The unserialized ciphertext.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var ciphertextParams = CryptoJS.lib.SerializableCipher._parse(ciphertextStringOrParams, format);
	         */
	        _parse: function (ciphertext, format) {
	            if (typeof ciphertext == 'string') {
	                return format.parse(ciphertext, this);
	            } else {
	                return ciphertext;
	            }
	        }
	    });

	    /**
	     * Key derivation function namespace.
	     */
	    var C_kdf = C.kdf = {};

	    /**
	     * OpenSSL key derivation function.
	     */
	    var OpenSSLKdf = C_kdf.OpenSSL = {
	        /**
	         * Derives a key and IV from a password.
	         *
	         * @param {string} password The password to derive from.
	         * @param {number} keySize The size in words of the key to generate.
	         * @param {number} ivSize The size in words of the IV to generate.
	         * @param {WordArray|string} salt (Optional) A 64-bit salt to use. If omitted, a salt will be generated randomly.
	         *
	         * @return {CipherParams} A cipher params object with the key, IV, and salt.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32);
	         *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32, 'saltsalt');
	         */
	        execute: function (password, keySize, ivSize, salt) {
	            // Generate random salt
	            if (!salt) {
	                salt = WordArray.random(64/8);
	            }

	            // Derive key and IV
	            var key = EvpKDF.create({ keySize: keySize + ivSize }).compute(password, salt);

	            // Separate key and IV
	            var iv = WordArray.create(key.words.slice(keySize), ivSize * 4);
	            key.sigBytes = keySize * 4;

	            // Return params
	            return CipherParams.create({ key: key, iv: iv, salt: salt });
	        }
	    };

	    /**
	     * A serializable cipher wrapper that derives the key from a password,
	     * and returns ciphertext as a serializable cipher params object.
	     */
	    var PasswordBasedCipher = C_lib.PasswordBasedCipher = SerializableCipher.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {KDF} kdf The key derivation function to use to generate a key and IV from a password. Default: OpenSSL
	         */
	        cfg: SerializableCipher.cfg.extend({
	            kdf: OpenSSLKdf
	        }),

	        /**
	         * Encrypts a message using a password.
	         *
	         * @param {Cipher} cipher The cipher algorithm to use.
	         * @param {WordArray|string} message The message to encrypt.
	         * @param {string} password The password.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {CipherParams} A cipher params object.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher.encrypt(CryptoJS.algo.AES, message, 'password');
	         *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher.encrypt(CryptoJS.algo.AES, message, 'password', { format: CryptoJS.format.OpenSSL });
	         */
	        encrypt: function (cipher, message, password, cfg) {
	            // Apply config defaults
	            cfg = this.cfg.extend(cfg);

	            // Derive key and other params
	            var derivedParams = cfg.kdf.execute(password, cipher.keySize, cipher.ivSize);

	            // Add IV to config
	            cfg.iv = derivedParams.iv;

	            // Encrypt
	            var ciphertext = SerializableCipher.encrypt.call(this, cipher, message, derivedParams.key, cfg);

	            // Mix in derived params
	            ciphertext.mixIn(derivedParams);

	            return ciphertext;
	        },

	        /**
	         * Decrypts serialized ciphertext using a password.
	         *
	         * @param {Cipher} cipher The cipher algorithm to use.
	         * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
	         * @param {string} password The password.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {WordArray} The plaintext.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var plaintext = CryptoJS.lib.PasswordBasedCipher.decrypt(CryptoJS.algo.AES, formattedCiphertext, 'password', { format: CryptoJS.format.OpenSSL });
	         *     var plaintext = CryptoJS.lib.PasswordBasedCipher.decrypt(CryptoJS.algo.AES, ciphertextParams, 'password', { format: CryptoJS.format.OpenSSL });
	         */
	        decrypt: function (cipher, ciphertext, password, cfg) {
	            // Apply config defaults
	            cfg = this.cfg.extend(cfg);

	            // Convert string to CipherParams
	            ciphertext = this._parse(ciphertext, cfg.format);

	            // Derive key and other params
	            var derivedParams = cfg.kdf.execute(password, cipher.keySize, cipher.ivSize, ciphertext.salt);

	            // Add IV to config
	            cfg.iv = derivedParams.iv;

	            // Decrypt
	            var plaintext = SerializableCipher.decrypt.call(this, cipher, ciphertext, derivedParams.key, cfg);

	            return plaintext;
	        }
	    });
	}());


}));
},{"./core":3,"./evpkdf":6}],3:[function(require,module,exports){
;(function (root, factory) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory();
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define([], factory);
	}
	else {
		// Global (browser)
		root.CryptoJS = factory();
	}
}(this, function () {

	/**
	 * CryptoJS core components.
	 */
	var CryptoJS = CryptoJS || (function (Math, undefined) {
	    /*
	     * Local polyfil of Object.create
	     */
	    var create = Object.create || (function () {
	        function F() {};

	        return function (obj) {
	            var subtype;

	            F.prototype = obj;

	            subtype = new F();

	            F.prototype = null;

	            return subtype;
	        };
	    }())

	    /**
	     * CryptoJS namespace.
	     */
	    var C = {};

	    /**
	     * Library namespace.
	     */
	    var C_lib = C.lib = {};

	    /**
	     * Base object for prototypal inheritance.
	     */
	    var Base = C_lib.Base = (function () {


	        return {
	            /**
	             * Creates a new object that inherits from this object.
	             *
	             * @param {Object} overrides Properties to copy into the new object.
	             *
	             * @return {Object} The new object.
	             *
	             * @static
	             *
	             * @example
	             *
	             *     var MyType = CryptoJS.lib.Base.extend({
	             *         field: 'value',
	             *
	             *         method: function () {
	             *         }
	             *     });
	             */
	            extend: function (overrides) {
	                // Spawn
	                var subtype = create(this);

	                // Augment
	                if (overrides) {
	                    subtype.mixIn(overrides);
	                }

	                // Create default initializer
	                if (!subtype.hasOwnProperty('init') || this.init === subtype.init) {
	                    subtype.init = function () {
	                        subtype.$super.init.apply(this, arguments);
	                    };
	                }

	                // Initializer's prototype is the subtype object
	                subtype.init.prototype = subtype;

	                // Reference supertype
	                subtype.$super = this;

	                return subtype;
	            },

	            /**
	             * Extends this object and runs the init method.
	             * Arguments to create() will be passed to init().
	             *
	             * @return {Object} The new object.
	             *
	             * @static
	             *
	             * @example
	             *
	             *     var instance = MyType.create();
	             */
	            create: function () {
	                var instance = this.extend();
	                instance.init.apply(instance, arguments);

	                return instance;
	            },

	            /**
	             * Initializes a newly created object.
	             * Override this method to add some logic when your objects are created.
	             *
	             * @example
	             *
	             *     var MyType = CryptoJS.lib.Base.extend({
	             *         init: function () {
	             *             // ...
	             *         }
	             *     });
	             */
	            init: function () {
	            },

	            /**
	             * Copies properties into this object.
	             *
	             * @param {Object} properties The properties to mix in.
	             *
	             * @example
	             *
	             *     MyType.mixIn({
	             *         field: 'value'
	             *     });
	             */
	            mixIn: function (properties) {
	                for (var propertyName in properties) {
	                    if (properties.hasOwnProperty(propertyName)) {
	                        this[propertyName] = properties[propertyName];
	                    }
	                }

	                // IE won't copy toString using the loop above
	                if (properties.hasOwnProperty('toString')) {
	                    this.toString = properties.toString;
	                }
	            },

	            /**
	             * Creates a copy of this object.
	             *
	             * @return {Object} The clone.
	             *
	             * @example
	             *
	             *     var clone = instance.clone();
	             */
	            clone: function () {
	                return this.init.prototype.extend(this);
	            }
	        };
	    }());

	    /**
	     * An array of 32-bit words.
	     *
	     * @property {Array} words The array of 32-bit words.
	     * @property {number} sigBytes The number of significant bytes in this word array.
	     */
	    var WordArray = C_lib.WordArray = Base.extend({
	        /**
	         * Initializes a newly created word array.
	         *
	         * @param {Array} words (Optional) An array of 32-bit words.
	         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.lib.WordArray.create();
	         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607]);
	         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607], 6);
	         */
	        init: function (words, sigBytes) {
	            words = this.words = words || [];

	            if (sigBytes != undefined) {
	                this.sigBytes = sigBytes;
	            } else {
	                this.sigBytes = words.length * 4;
	            }
	        },

	        /**
	         * Converts this word array to a string.
	         *
	         * @param {Encoder} encoder (Optional) The encoding strategy to use. Default: CryptoJS.enc.Hex
	         *
	         * @return {string} The stringified word array.
	         *
	         * @example
	         *
	         *     var string = wordArray + '';
	         *     var string = wordArray.toString();
	         *     var string = wordArray.toString(CryptoJS.enc.Utf8);
	         */
	        toString: function (encoder) {
	            return (encoder || Hex).stringify(this);
	        },

	        /**
	         * Concatenates a word array to this word array.
	         *
	         * @param {WordArray} wordArray The word array to append.
	         *
	         * @return {WordArray} This word array.
	         *
	         * @example
	         *
	         *     wordArray1.concat(wordArray2);
	         */
	        concat: function (wordArray) {
	            // Shortcuts
	            var thisWords = this.words;
	            var thatWords = wordArray.words;
	            var thisSigBytes = this.sigBytes;
	            var thatSigBytes = wordArray.sigBytes;

	            // Clamp excess bits
	            this.clamp();

	            // Concat
	            if (thisSigBytes % 4) {
	                // Copy one byte at a time
	                for (var i = 0; i < thatSigBytes; i++) {
	                    var thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
	                    thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
	                }
	            } else {
	                // Copy one word at a time
	                for (var i = 0; i < thatSigBytes; i += 4) {
	                    thisWords[(thisSigBytes + i) >>> 2] = thatWords[i >>> 2];
	                }
	            }
	            this.sigBytes += thatSigBytes;

	            // Chainable
	            return this;
	        },

	        /**
	         * Removes insignificant bits.
	         *
	         * @example
	         *
	         *     wordArray.clamp();
	         */
	        clamp: function () {
	            // Shortcuts
	            var words = this.words;
	            var sigBytes = this.sigBytes;

	            // Clamp
	            words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
	            words.length = Math.ceil(sigBytes / 4);
	        },

	        /**
	         * Creates a copy of this word array.
	         *
	         * @return {WordArray} The clone.
	         *
	         * @example
	         *
	         *     var clone = wordArray.clone();
	         */
	        clone: function () {
	            var clone = Base.clone.call(this);
	            clone.words = this.words.slice(0);

	            return clone;
	        },

	        /**
	         * Creates a word array filled with random bytes.
	         *
	         * @param {number} nBytes The number of random bytes to generate.
	         *
	         * @return {WordArray} The random word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.lib.WordArray.random(16);
	         */
	        random: function (nBytes) {
	            var words = [];

	            var r = (function (m_w) {
	                var m_w = m_w;
	                var m_z = 0x3ade68b1;
	                var mask = 0xffffffff;

	                return function () {
	                    m_z = (0x9069 * (m_z & 0xFFFF) + (m_z >> 0x10)) & mask;
	                    m_w = (0x4650 * (m_w & 0xFFFF) + (m_w >> 0x10)) & mask;
	                    var result = ((m_z << 0x10) + m_w) & mask;
	                    result /= 0x100000000;
	                    result += 0.5;
	                    return result * (Math.random() > .5 ? 1 : -1);
	                }
	            });

	            for (var i = 0, rcache; i < nBytes; i += 4) {
	                var _r = r((rcache || Math.random()) * 0x100000000);

	                rcache = _r() * 0x3ade67b7;
	                words.push((_r() * 0x100000000) | 0);
	            }

	            return new WordArray.init(words, nBytes);
	        }
	    });

	    /**
	     * Encoder namespace.
	     */
	    var C_enc = C.enc = {};

	    /**
	     * Hex encoding strategy.
	     */
	    var Hex = C_enc.Hex = {
	        /**
	         * Converts a word array to a hex string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The hex string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var hexString = CryptoJS.enc.Hex.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;

	            // Convert
	            var hexChars = [];
	            for (var i = 0; i < sigBytes; i++) {
	                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
	                hexChars.push((bite >>> 4).toString(16));
	                hexChars.push((bite & 0x0f).toString(16));
	            }

	            return hexChars.join('');
	        },

	        /**
	         * Converts a hex string to a word array.
	         *
	         * @param {string} hexStr The hex string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Hex.parse(hexString);
	         */
	        parse: function (hexStr) {
	            // Shortcut
	            var hexStrLength = hexStr.length;

	            // Convert
	            var words = [];
	            for (var i = 0; i < hexStrLength; i += 2) {
	                words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << (24 - (i % 8) * 4);
	            }

	            return new WordArray.init(words, hexStrLength / 2);
	        }
	    };

	    /**
	     * Latin1 encoding strategy.
	     */
	    var Latin1 = C_enc.Latin1 = {
	        /**
	         * Converts a word array to a Latin1 string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The Latin1 string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var latin1String = CryptoJS.enc.Latin1.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;

	            // Convert
	            var latin1Chars = [];
	            for (var i = 0; i < sigBytes; i++) {
	                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
	                latin1Chars.push(String.fromCharCode(bite));
	            }

	            return latin1Chars.join('');
	        },

	        /**
	         * Converts a Latin1 string to a word array.
	         *
	         * @param {string} latin1Str The Latin1 string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Latin1.parse(latin1String);
	         */
	        parse: function (latin1Str) {
	            // Shortcut
	            var latin1StrLength = latin1Str.length;

	            // Convert
	            var words = [];
	            for (var i = 0; i < latin1StrLength; i++) {
	                words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
	            }

	            return new WordArray.init(words, latin1StrLength);
	        }
	    };

	    /**
	     * UTF-8 encoding strategy.
	     */
	    var Utf8 = C_enc.Utf8 = {
	        /**
	         * Converts a word array to a UTF-8 string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The UTF-8 string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var utf8String = CryptoJS.enc.Utf8.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            try {
	                return decodeURIComponent(escape(Latin1.stringify(wordArray)));
	            } catch (e) {
	                throw new Error('Malformed UTF-8 data');
	            }
	        },

	        /**
	         * Converts a UTF-8 string to a word array.
	         *
	         * @param {string} utf8Str The UTF-8 string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Utf8.parse(utf8String);
	         */
	        parse: function (utf8Str) {
	            return Latin1.parse(unescape(encodeURIComponent(utf8Str)));
	        }
	    };

	    /**
	     * Abstract buffered block algorithm template.
	     *
	     * The property blockSize must be implemented in a concrete subtype.
	     *
	     * @property {number} _minBufferSize The number of blocks that should be kept unprocessed in the buffer. Default: 0
	     */
	    var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm = Base.extend({
	        /**
	         * Resets this block algorithm's data buffer to its initial state.
	         *
	         * @example
	         *
	         *     bufferedBlockAlgorithm.reset();
	         */
	        reset: function () {
	            // Initial values
	            this._data = new WordArray.init();
	            this._nDataBytes = 0;
	        },

	        /**
	         * Adds new data to this block algorithm's buffer.
	         *
	         * @param {WordArray|string} data The data to append. Strings are converted to a WordArray using UTF-8.
	         *
	         * @example
	         *
	         *     bufferedBlockAlgorithm._append('data');
	         *     bufferedBlockAlgorithm._append(wordArray);
	         */
	        _append: function (data) {
	            // Convert string to WordArray, else assume WordArray already
	            if (typeof data == 'string') {
	                data = Utf8.parse(data);
	            }

	            // Append
	            this._data.concat(data);
	            this._nDataBytes += data.sigBytes;
	        },

	        /**
	         * Processes available data blocks.
	         *
	         * This method invokes _doProcessBlock(offset), which must be implemented by a concrete subtype.
	         *
	         * @param {boolean} doFlush Whether all blocks and partial blocks should be processed.
	         *
	         * @return {WordArray} The processed data.
	         *
	         * @example
	         *
	         *     var processedData = bufferedBlockAlgorithm._process();
	         *     var processedData = bufferedBlockAlgorithm._process(!!'flush');
	         */
	        _process: function (doFlush) {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;
	            var dataSigBytes = data.sigBytes;
	            var blockSize = this.blockSize;
	            var blockSizeBytes = blockSize * 4;

	            // Count blocks ready
	            var nBlocksReady = dataSigBytes / blockSizeBytes;
	            if (doFlush) {
	                // Round up to include partial blocks
	                nBlocksReady = Math.ceil(nBlocksReady);
	            } else {
	                // Round down to include only full blocks,
	                // less the number of blocks that must remain in the buffer
	                nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
	            }

	            // Count words ready
	            var nWordsReady = nBlocksReady * blockSize;

	            // Count bytes ready
	            var nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

	            // Process blocks
	            if (nWordsReady) {
	                for (var offset = 0; offset < nWordsReady; offset += blockSize) {
	                    // Perform concrete-algorithm logic
	                    this._doProcessBlock(dataWords, offset);
	                }

	                // Remove processed words
	                var processedWords = dataWords.splice(0, nWordsReady);
	                data.sigBytes -= nBytesReady;
	            }

	            // Return processed words
	            return new WordArray.init(processedWords, nBytesReady);
	        },

	        /**
	         * Creates a copy of this object.
	         *
	         * @return {Object} The clone.
	         *
	         * @example
	         *
	         *     var clone = bufferedBlockAlgorithm.clone();
	         */
	        clone: function () {
	            var clone = Base.clone.call(this);
	            clone._data = this._data.clone();

	            return clone;
	        },

	        _minBufferSize: 0
	    });

	    /**
	     * Abstract hasher template.
	     *
	     * @property {number} blockSize The number of 32-bit words this hasher operates on. Default: 16 (512 bits)
	     */
	    var Hasher = C_lib.Hasher = BufferedBlockAlgorithm.extend({
	        /**
	         * Configuration options.
	         */
	        cfg: Base.extend(),

	        /**
	         * Initializes a newly created hasher.
	         *
	         * @param {Object} cfg (Optional) The configuration options to use for this hash computation.
	         *
	         * @example
	         *
	         *     var hasher = CryptoJS.algo.SHA256.create();
	         */
	        init: function (cfg) {
	            // Apply config defaults
	            this.cfg = this.cfg.extend(cfg);

	            // Set initial values
	            this.reset();
	        },

	        /**
	         * Resets this hasher to its initial state.
	         *
	         * @example
	         *
	         *     hasher.reset();
	         */
	        reset: function () {
	            // Reset data buffer
	            BufferedBlockAlgorithm.reset.call(this);

	            // Perform concrete-hasher logic
	            this._doReset();
	        },

	        /**
	         * Updates this hasher with a message.
	         *
	         * @param {WordArray|string} messageUpdate The message to append.
	         *
	         * @return {Hasher} This hasher.
	         *
	         * @example
	         *
	         *     hasher.update('message');
	         *     hasher.update(wordArray);
	         */
	        update: function (messageUpdate) {
	            // Append
	            this._append(messageUpdate);

	            // Update the hash
	            this._process();

	            // Chainable
	            return this;
	        },

	        /**
	         * Finalizes the hash computation.
	         * Note that the finalize operation is effectively a destructive, read-once operation.
	         *
	         * @param {WordArray|string} messageUpdate (Optional) A final message update.
	         *
	         * @return {WordArray} The hash.
	         *
	         * @example
	         *
	         *     var hash = hasher.finalize();
	         *     var hash = hasher.finalize('message');
	         *     var hash = hasher.finalize(wordArray);
	         */
	        finalize: function (messageUpdate) {
	            // Final message update
	            if (messageUpdate) {
	                this._append(messageUpdate);
	            }

	            // Perform concrete-hasher logic
	            var hash = this._doFinalize();

	            return hash;
	        },

	        blockSize: 512/32,

	        /**
	         * Creates a shortcut function to a hasher's object interface.
	         *
	         * @param {Hasher} hasher The hasher to create a helper for.
	         *
	         * @return {Function} The shortcut function.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var SHA256 = CryptoJS.lib.Hasher._createHelper(CryptoJS.algo.SHA256);
	         */
	        _createHelper: function (hasher) {
	            return function (message, cfg) {
	                return new hasher.init(cfg).finalize(message);
	            };
	        },

	        /**
	         * Creates a shortcut function to the HMAC's object interface.
	         *
	         * @param {Hasher} hasher The hasher to use in this HMAC helper.
	         *
	         * @return {Function} The shortcut function.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var HmacSHA256 = CryptoJS.lib.Hasher._createHmacHelper(CryptoJS.algo.SHA256);
	         */
	        _createHmacHelper: function (hasher) {
	            return function (message, key) {
	                return new C_algo.HMAC.init(hasher, key).finalize(message);
	            };
	        }
	    });

	    /**
	     * Algorithm namespace.
	     */
	    var C_algo = C.algo = {};

	    return C;
	}(Math));


	return CryptoJS;

}));
},{}],4:[function(require,module,exports){
;(function (root, factory) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var C_enc = C.enc;

	    /**
	     * Base64 encoding strategy.
	     */
	    var Base64 = C_enc.Base64 = {
	        /**
	         * Converts a word array to a Base64 string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The Base64 string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var base64String = CryptoJS.enc.Base64.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;
	            var map = this._map;

	            // Clamp excess bits
	            wordArray.clamp();

	            // Convert
	            var base64Chars = [];
	            for (var i = 0; i < sigBytes; i += 3) {
	                var byte1 = (words[i >>> 2]       >>> (24 - (i % 4) * 8))       & 0xff;
	                var byte2 = (words[(i + 1) >>> 2] >>> (24 - ((i + 1) % 4) * 8)) & 0xff;
	                var byte3 = (words[(i + 2) >>> 2] >>> (24 - ((i + 2) % 4) * 8)) & 0xff;

	                var triplet = (byte1 << 16) | (byte2 << 8) | byte3;

	                for (var j = 0; (j < 4) && (i + j * 0.75 < sigBytes); j++) {
	                    base64Chars.push(map.charAt((triplet >>> (6 * (3 - j))) & 0x3f));
	                }
	            }

	            // Add padding
	            var paddingChar = map.charAt(64);
	            if (paddingChar) {
	                while (base64Chars.length % 4) {
	                    base64Chars.push(paddingChar);
	                }
	            }

	            return base64Chars.join('');
	        },

	        /**
	         * Converts a Base64 string to a word array.
	         *
	         * @param {string} base64Str The Base64 string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Base64.parse(base64String);
	         */
	        parse: function (base64Str) {
	            // Shortcuts
	            var base64StrLength = base64Str.length;
	            var map = this._map;
	            var reverseMap = this._reverseMap;

	            if (!reverseMap) {
	                    reverseMap = this._reverseMap = [];
	                    for (var j = 0; j < map.length; j++) {
	                        reverseMap[map.charCodeAt(j)] = j;
	                    }
	            }

	            // Ignore padding
	            var paddingChar = map.charAt(64);
	            if (paddingChar) {
	                var paddingIndex = base64Str.indexOf(paddingChar);
	                if (paddingIndex !== -1) {
	                    base64StrLength = paddingIndex;
	                }
	            }

	            // Convert
	            return parseLoop(base64Str, base64StrLength, reverseMap);

	        },

	        _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
	    };

	    function parseLoop(base64Str, base64StrLength, reverseMap) {
	      var words = [];
	      var nBytes = 0;
	      for (var i = 0; i < base64StrLength; i++) {
	          if (i % 4) {
	              var bits1 = reverseMap[base64Str.charCodeAt(i - 1)] << ((i % 4) * 2);
	              var bits2 = reverseMap[base64Str.charCodeAt(i)] >>> (6 - (i % 4) * 2);
	              words[nBytes >>> 2] |= (bits1 | bits2) << (24 - (nBytes % 4) * 8);
	              nBytes++;
	          }
	      }
	      return WordArray.create(words, nBytes);
	    }
	}());


	return CryptoJS.enc.Base64;

}));
},{"./core":3}],5:[function(require,module,exports){
;(function (root, factory) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var C_enc = C.enc;

	    /**
	     * UTF-16 BE encoding strategy.
	     */
	    var Utf16BE = C_enc.Utf16 = C_enc.Utf16BE = {
	        /**
	         * Converts a word array to a UTF-16 BE string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The UTF-16 BE string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var utf16String = CryptoJS.enc.Utf16.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;

	            // Convert
	            var utf16Chars = [];
	            for (var i = 0; i < sigBytes; i += 2) {
	                var codePoint = (words[i >>> 2] >>> (16 - (i % 4) * 8)) & 0xffff;
	                utf16Chars.push(String.fromCharCode(codePoint));
	            }

	            return utf16Chars.join('');
	        },

	        /**
	         * Converts a UTF-16 BE string to a word array.
	         *
	         * @param {string} utf16Str The UTF-16 BE string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Utf16.parse(utf16String);
	         */
	        parse: function (utf16Str) {
	            // Shortcut
	            var utf16StrLength = utf16Str.length;

	            // Convert
	            var words = [];
	            for (var i = 0; i < utf16StrLength; i++) {
	                words[i >>> 1] |= utf16Str.charCodeAt(i) << (16 - (i % 2) * 16);
	            }

	            return WordArray.create(words, utf16StrLength * 2);
	        }
	    };

	    /**
	     * UTF-16 LE encoding strategy.
	     */
	    C_enc.Utf16LE = {
	        /**
	         * Converts a word array to a UTF-16 LE string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The UTF-16 LE string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var utf16Str = CryptoJS.enc.Utf16LE.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;

	            // Convert
	            var utf16Chars = [];
	            for (var i = 0; i < sigBytes; i += 2) {
	                var codePoint = swapEndian((words[i >>> 2] >>> (16 - (i % 4) * 8)) & 0xffff);
	                utf16Chars.push(String.fromCharCode(codePoint));
	            }

	            return utf16Chars.join('');
	        },

	        /**
	         * Converts a UTF-16 LE string to a word array.
	         *
	         * @param {string} utf16Str The UTF-16 LE string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Utf16LE.parse(utf16Str);
	         */
	        parse: function (utf16Str) {
	            // Shortcut
	            var utf16StrLength = utf16Str.length;

	            // Convert
	            var words = [];
	            for (var i = 0; i < utf16StrLength; i++) {
	                words[i >>> 1] |= swapEndian(utf16Str.charCodeAt(i) << (16 - (i % 2) * 16));
	            }

	            return WordArray.create(words, utf16StrLength * 2);
	        }
	    };

	    function swapEndian(word) {
	        return ((word << 8) & 0xff00ff00) | ((word >>> 8) & 0x00ff00ff);
	    }
	}());


	return CryptoJS.enc.Utf16;

}));
},{"./core":3}],6:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./sha1"), require("./hmac"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./sha1", "./hmac"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var WordArray = C_lib.WordArray;
	    var C_algo = C.algo;
	    var MD5 = C_algo.MD5;

	    /**
	     * This key derivation function is meant to conform with EVP_BytesToKey.
	     * www.openssl.org/docs/crypto/EVP_BytesToKey.html
	     */
	    var EvpKDF = C_algo.EvpKDF = Base.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
	         * @property {Hasher} hasher The hash algorithm to use. Default: MD5
	         * @property {number} iterations The number of iterations to perform. Default: 1
	         */
	        cfg: Base.extend({
	            keySize: 128/32,
	            hasher: MD5,
	            iterations: 1
	        }),

	        /**
	         * Initializes a newly created key derivation function.
	         *
	         * @param {Object} cfg (Optional) The configuration options to use for the derivation.
	         *
	         * @example
	         *
	         *     var kdf = CryptoJS.algo.EvpKDF.create();
	         *     var kdf = CryptoJS.algo.EvpKDF.create({ keySize: 8 });
	         *     var kdf = CryptoJS.algo.EvpKDF.create({ keySize: 8, iterations: 1000 });
	         */
	        init: function (cfg) {
	            this.cfg = this.cfg.extend(cfg);
	        },

	        /**
	         * Derives a key from a password.
	         *
	         * @param {WordArray|string} password The password.
	         * @param {WordArray|string} salt A salt.
	         *
	         * @return {WordArray} The derived key.
	         *
	         * @example
	         *
	         *     var key = kdf.compute(password, salt);
	         */
	        compute: function (password, salt) {
	            // Shortcut
	            var cfg = this.cfg;

	            // Init hasher
	            var hasher = cfg.hasher.create();

	            // Initial values
	            var derivedKey = WordArray.create();

	            // Shortcuts
	            var derivedKeyWords = derivedKey.words;
	            var keySize = cfg.keySize;
	            var iterations = cfg.iterations;

	            // Generate key
	            while (derivedKeyWords.length < keySize) {
	                if (block) {
	                    hasher.update(block);
	                }
	                var block = hasher.update(password).finalize(salt);
	                hasher.reset();

	                // Iterations
	                for (var i = 1; i < iterations; i++) {
	                    block = hasher.finalize(block);
	                    hasher.reset();
	                }

	                derivedKey.concat(block);
	            }
	            derivedKey.sigBytes = keySize * 4;

	            return derivedKey;
	        }
	    });

	    /**
	     * Derives a key from a password.
	     *
	     * @param {WordArray|string} password The password.
	     * @param {WordArray|string} salt A salt.
	     * @param {Object} cfg (Optional) The configuration options to use for this computation.
	     *
	     * @return {WordArray} The derived key.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var key = CryptoJS.EvpKDF(password, salt);
	     *     var key = CryptoJS.EvpKDF(password, salt, { keySize: 8 });
	     *     var key = CryptoJS.EvpKDF(password, salt, { keySize: 8, iterations: 1000 });
	     */
	    C.EvpKDF = function (password, salt, cfg) {
	        return EvpKDF.create(cfg).compute(password, salt);
	    };
	}());


	return CryptoJS.EvpKDF;

}));
},{"./core":3,"./hmac":8,"./sha1":27}],7:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./cipher-core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./cipher-core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	(function (undefined) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var CipherParams = C_lib.CipherParams;
	    var C_enc = C.enc;
	    var Hex = C_enc.Hex;
	    var C_format = C.format;

	    var HexFormatter = C_format.Hex = {
	        /**
	         * Converts the ciphertext of a cipher params object to a hexadecimally encoded string.
	         *
	         * @param {CipherParams} cipherParams The cipher params object.
	         *
	         * @return {string} The hexadecimally encoded string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var hexString = CryptoJS.format.Hex.stringify(cipherParams);
	         */
	        stringify: function (cipherParams) {
	            return cipherParams.ciphertext.toString(Hex);
	        },

	        /**
	         * Converts a hexadecimally encoded ciphertext string to a cipher params object.
	         *
	         * @param {string} input The hexadecimally encoded string.
	         *
	         * @return {CipherParams} The cipher params object.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var cipherParams = CryptoJS.format.Hex.parse(hexString);
	         */
	        parse: function (input) {
	            var ciphertext = Hex.parse(input);
	            return CipherParams.create({ ciphertext: ciphertext });
	        }
	    };
	}());


	return CryptoJS.format.Hex;

}));
},{"./cipher-core":2,"./core":3}],8:[function(require,module,exports){
;(function (root, factory) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var C_enc = C.enc;
	    var Utf8 = C_enc.Utf8;
	    var C_algo = C.algo;

	    /**
	     * HMAC algorithm.
	     */
	    var HMAC = C_algo.HMAC = Base.extend({
	        /**
	         * Initializes a newly created HMAC.
	         *
	         * @param {Hasher} hasher The hash algorithm to use.
	         * @param {WordArray|string} key The secret key.
	         *
	         * @example
	         *
	         *     var hmacHasher = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, key);
	         */
	        init: function (hasher, key) {
	            // Init hasher
	            hasher = this._hasher = new hasher.init();

	            // Convert string to WordArray, else assume WordArray already
	            if (typeof key == 'string') {
	                key = Utf8.parse(key);
	            }

	            // Shortcuts
	            var hasherBlockSize = hasher.blockSize;
	            var hasherBlockSizeBytes = hasherBlockSize * 4;

	            // Allow arbitrary length keys
	            if (key.sigBytes > hasherBlockSizeBytes) {
	                key = hasher.finalize(key);
	            }

	            // Clamp excess bits
	            key.clamp();

	            // Clone key for inner and outer pads
	            var oKey = this._oKey = key.clone();
	            var iKey = this._iKey = key.clone();

	            // Shortcuts
	            var oKeyWords = oKey.words;
	            var iKeyWords = iKey.words;

	            // XOR keys with pad constants
	            for (var i = 0; i < hasherBlockSize; i++) {
	                oKeyWords[i] ^= 0x5c5c5c5c;
	                iKeyWords[i] ^= 0x36363636;
	            }
	            oKey.sigBytes = iKey.sigBytes = hasherBlockSizeBytes;

	            // Set initial values
	            this.reset();
	        },

	        /**
	         * Resets this HMAC to its initial state.
	         *
	         * @example
	         *
	         *     hmacHasher.reset();
	         */
	        reset: function () {
	            // Shortcut
	            var hasher = this._hasher;

	            // Reset
	            hasher.reset();
	            hasher.update(this._iKey);
	        },

	        /**
	         * Updates this HMAC with a message.
	         *
	         * @param {WordArray|string} messageUpdate The message to append.
	         *
	         * @return {HMAC} This HMAC instance.
	         *
	         * @example
	         *
	         *     hmacHasher.update('message');
	         *     hmacHasher.update(wordArray);
	         */
	        update: function (messageUpdate) {
	            this._hasher.update(messageUpdate);

	            // Chainable
	            return this;
	        },

	        /**
	         * Finalizes the HMAC computation.
	         * Note that the finalize operation is effectively a destructive, read-once operation.
	         *
	         * @param {WordArray|string} messageUpdate (Optional) A final message update.
	         *
	         * @return {WordArray} The HMAC.
	         *
	         * @example
	         *
	         *     var hmac = hmacHasher.finalize();
	         *     var hmac = hmacHasher.finalize('message');
	         *     var hmac = hmacHasher.finalize(wordArray);
	         */
	        finalize: function (messageUpdate) {
	            // Shortcut
	            var hasher = this._hasher;

	            // Compute HMAC
	            var innerHash = hasher.finalize(messageUpdate);
	            hasher.reset();
	            var hmac = hasher.finalize(this._oKey.clone().concat(innerHash));

	            return hmac;
	        }
	    });
	}());


}));
},{"./core":3}],9:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./x64-core"), require("./lib-typedarrays"), require("./enc-utf16"), require("./enc-base64"), require("./md5"), require("./sha1"), require("./sha256"), require("./sha224"), require("./sha512"), require("./sha384"), require("./sha3"), require("./ripemd160"), require("./hmac"), require("./pbkdf2"), require("./evpkdf"), require("./cipher-core"), require("./mode-cfb"), require("./mode-ctr"), require("./mode-ctr-gladman"), require("./mode-ofb"), require("./mode-ecb"), require("./pad-ansix923"), require("./pad-iso10126"), require("./pad-iso97971"), require("./pad-zeropadding"), require("./pad-nopadding"), require("./format-hex"), require("./aes"), require("./tripledes"), require("./rc4"), require("./rabbit"), require("./rabbit-legacy"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./x64-core", "./lib-typedarrays", "./enc-utf16", "./enc-base64", "./md5", "./sha1", "./sha256", "./sha224", "./sha512", "./sha384", "./sha3", "./ripemd160", "./hmac", "./pbkdf2", "./evpkdf", "./cipher-core", "./mode-cfb", "./mode-ctr", "./mode-ctr-gladman", "./mode-ofb", "./mode-ecb", "./pad-ansix923", "./pad-iso10126", "./pad-iso97971", "./pad-zeropadding", "./pad-nopadding", "./format-hex", "./aes", "./tripledes", "./rc4", "./rabbit", "./rabbit-legacy"], factory);
	}
	else {
		// Global (browser)
		root.CryptoJS = factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	return CryptoJS;

}));
},{"./aes":1,"./cipher-core":2,"./core":3,"./enc-base64":4,"./enc-utf16":5,"./evpkdf":6,"./format-hex":7,"./hmac":8,"./lib-typedarrays":10,"./md5":11,"./mode-cfb":12,"./mode-ctr":14,"./mode-ctr-gladman":13,"./mode-ecb":15,"./mode-ofb":16,"./pad-ansix923":17,"./pad-iso10126":18,"./pad-iso97971":19,"./pad-nopadding":20,"./pad-zeropadding":21,"./pbkdf2":22,"./rabbit":24,"./rabbit-legacy":23,"./rc4":25,"./ripemd160":26,"./sha1":27,"./sha224":28,"./sha256":29,"./sha3":30,"./sha384":31,"./sha512":32,"./tripledes":33,"./x64-core":34}],10:[function(require,module,exports){
;(function (root, factory) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	(function () {
	    // Check if typed arrays are supported
	    if (typeof ArrayBuffer != 'function') {
	        return;
	    }

	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;

	    // Reference original init
	    var superInit = WordArray.init;

	    // Augment WordArray.init to handle typed arrays
	    var subInit = WordArray.init = function (typedArray) {
	        // Convert buffers to uint8
	        if (typedArray instanceof ArrayBuffer) {
	            typedArray = new Uint8Array(typedArray);
	        }

	        // Convert other array views to uint8
	        if (
	            typedArray instanceof Int8Array ||
	            (typeof Uint8ClampedArray !== "undefined" && typedArray instanceof Uint8ClampedArray) ||
	            typedArray instanceof Int16Array ||
	            typedArray instanceof Uint16Array ||
	            typedArray instanceof Int32Array ||
	            typedArray instanceof Uint32Array ||
	            typedArray instanceof Float32Array ||
	            typedArray instanceof Float64Array
	        ) {
	            typedArray = new Uint8Array(typedArray.buffer, typedArray.byteOffset, typedArray.byteLength);
	        }

	        // Handle Uint8Array
	        if (typedArray instanceof Uint8Array) {
	            // Shortcut
	            var typedArrayByteLength = typedArray.byteLength;

	            // Extract bytes
	            var words = [];
	            for (var i = 0; i < typedArrayByteLength; i++) {
	                words[i >>> 2] |= typedArray[i] << (24 - (i % 4) * 8);
	            }

	            // Initialize this word array
	            superInit.call(this, words, typedArrayByteLength);
	        } else {
	            // Else call normal init
	            superInit.apply(this, arguments);
	        }
	    };

	    subInit.prototype = WordArray;
	}());


	return CryptoJS.lib.WordArray;

}));
},{"./core":3}],11:[function(require,module,exports){
;(function (root, factory) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	(function (Math) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var Hasher = C_lib.Hasher;
	    var C_algo = C.algo;

	    // Constants table
	    var T = [];

	    // Compute constants
	    (function () {
	        for (var i = 0; i < 64; i++) {
	            T[i] = (Math.abs(Math.sin(i + 1)) * 0x100000000) | 0;
	        }
	    }());

	    /**
	     * MD5 hash algorithm.
	     */
	    var MD5 = C_algo.MD5 = Hasher.extend({
	        _doReset: function () {
	            this._hash = new WordArray.init([
	                0x67452301, 0xefcdab89,
	                0x98badcfe, 0x10325476
	            ]);
	        },

	        _doProcessBlock: function (M, offset) {
	            // Swap endian
	            for (var i = 0; i < 16; i++) {
	                // Shortcuts
	                var offset_i = offset + i;
	                var M_offset_i = M[offset_i];

	                M[offset_i] = (
	                    (((M_offset_i << 8)  | (M_offset_i >>> 24)) & 0x00ff00ff) |
	                    (((M_offset_i << 24) | (M_offset_i >>> 8))  & 0xff00ff00)
	                );
	            }

	            // Shortcuts
	            var H = this._hash.words;

	            var M_offset_0  = M[offset + 0];
	            var M_offset_1  = M[offset + 1];
	            var M_offset_2  = M[offset + 2];
	            var M_offset_3  = M[offset + 3];
	            var M_offset_4  = M[offset + 4];
	            var M_offset_5  = M[offset + 5];
	            var M_offset_6  = M[offset + 6];
	            var M_offset_7  = M[offset + 7];
	            var M_offset_8  = M[offset + 8];
	            var M_offset_9  = M[offset + 9];
	            var M_offset_10 = M[offset + 10];
	            var M_offset_11 = M[offset + 11];
	            var M_offset_12 = M[offset + 12];
	            var M_offset_13 = M[offset + 13];
	            var M_offset_14 = M[offset + 14];
	            var M_offset_15 = M[offset + 15];

	            // Working varialbes
	            var a = H[0];
	            var b = H[1];
	            var c = H[2];
	            var d = H[3];

	            // Computation
	            a = FF(a, b, c, d, M_offset_0,  7,  T[0]);
	            d = FF(d, a, b, c, M_offset_1,  12, T[1]);
	            c = FF(c, d, a, b, M_offset_2,  17, T[2]);
	            b = FF(b, c, d, a, M_offset_3,  22, T[3]);
	            a = FF(a, b, c, d, M_offset_4,  7,  T[4]);
	            d = FF(d, a, b, c, M_offset_5,  12, T[5]);
	            c = FF(c, d, a, b, M_offset_6,  17, T[6]);
	            b = FF(b, c, d, a, M_offset_7,  22, T[7]);
	            a = FF(a, b, c, d, M_offset_8,  7,  T[8]);
	            d = FF(d, a, b, c, M_offset_9,  12, T[9]);
	            c = FF(c, d, a, b, M_offset_10, 17, T[10]);
	            b = FF(b, c, d, a, M_offset_11, 22, T[11]);
	            a = FF(a, b, c, d, M_offset_12, 7,  T[12]);
	            d = FF(d, a, b, c, M_offset_13, 12, T[13]);
	            c = FF(c, d, a, b, M_offset_14, 17, T[14]);
	            b = FF(b, c, d, a, M_offset_15, 22, T[15]);

	            a = GG(a, b, c, d, M_offset_1,  5,  T[16]);
	            d = GG(d, a, b, c, M_offset_6,  9,  T[17]);
	            c = GG(c, d, a, b, M_offset_11, 14, T[18]);
	            b = GG(b, c, d, a, M_offset_0,  20, T[19]);
	            a = GG(a, b, c, d, M_offset_5,  5,  T[20]);
	            d = GG(d, a, b, c, M_offset_10, 9,  T[21]);
	            c = GG(c, d, a, b, M_offset_15, 14, T[22]);
	            b = GG(b, c, d, a, M_offset_4,  20, T[23]);
	            a = GG(a, b, c, d, M_offset_9,  5,  T[24]);
	            d = GG(d, a, b, c, M_offset_14, 9,  T[25]);
	            c = GG(c, d, a, b, M_offset_3,  14, T[26]);
	            b = GG(b, c, d, a, M_offset_8,  20, T[27]);
	            a = GG(a, b, c, d, M_offset_13, 5,  T[28]);
	            d = GG(d, a, b, c, M_offset_2,  9,  T[29]);
	            c = GG(c, d, a, b, M_offset_7,  14, T[30]);
	            b = GG(b, c, d, a, M_offset_12, 20, T[31]);

	            a = HH(a, b, c, d, M_offset_5,  4,  T[32]);
	            d = HH(d, a, b, c, M_offset_8,  11, T[33]);
	            c = HH(c, d, a, b, M_offset_11, 16, T[34]);
	            b = HH(b, c, d, a, M_offset_14, 23, T[35]);
	            a = HH(a, b, c, d, M_offset_1,  4,  T[36]);
	            d = HH(d, a, b, c, M_offset_4,  11, T[37]);
	            c = HH(c, d, a, b, M_offset_7,  16, T[38]);
	            b = HH(b, c, d, a, M_offset_10, 23, T[39]);
	            a = HH(a, b, c, d, M_offset_13, 4,  T[40]);
	            d = HH(d, a, b, c, M_offset_0,  11, T[41]);
	            c = HH(c, d, a, b, M_offset_3,  16, T[42]);
	            b = HH(b, c, d, a, M_offset_6,  23, T[43]);
	            a = HH(a, b, c, d, M_offset_9,  4,  T[44]);
	            d = HH(d, a, b, c, M_offset_12, 11, T[45]);
	            c = HH(c, d, a, b, M_offset_15, 16, T[46]);
	            b = HH(b, c, d, a, M_offset_2,  23, T[47]);

	            a = II(a, b, c, d, M_offset_0,  6,  T[48]);
	            d = II(d, a, b, c, M_offset_7,  10, T[49]);
	            c = II(c, d, a, b, M_offset_14, 15, T[50]);
	            b = II(b, c, d, a, M_offset_5,  21, T[51]);
	            a = II(a, b, c, d, M_offset_12, 6,  T[52]);
	            d = II(d, a, b, c, M_offset_3,  10, T[53]);
	            c = II(c, d, a, b, M_offset_10, 15, T[54]);
	            b = II(b, c, d, a, M_offset_1,  21, T[55]);
	            a = II(a, b, c, d, M_offset_8,  6,  T[56]);
	            d = II(d, a, b, c, M_offset_15, 10, T[57]);
	            c = II(c, d, a, b, M_offset_6,  15, T[58]);
	            b = II(b, c, d, a, M_offset_13, 21, T[59]);
	            a = II(a, b, c, d, M_offset_4,  6,  T[60]);
	            d = II(d, a, b, c, M_offset_11, 10, T[61]);
	            c = II(c, d, a, b, M_offset_2,  15, T[62]);
	            b = II(b, c, d, a, M_offset_9,  21, T[63]);

	            // Intermediate hash value
	            H[0] = (H[0] + a) | 0;
	            H[1] = (H[1] + b) | 0;
	            H[2] = (H[2] + c) | 0;
	            H[3] = (H[3] + d) | 0;
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;

	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);

	            var nBitsTotalH = Math.floor(nBitsTotal / 0x100000000);
	            var nBitsTotalL = nBitsTotal;
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = (
	                (((nBitsTotalH << 8)  | (nBitsTotalH >>> 24)) & 0x00ff00ff) |
	                (((nBitsTotalH << 24) | (nBitsTotalH >>> 8))  & 0xff00ff00)
	            );
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = (
	                (((nBitsTotalL << 8)  | (nBitsTotalL >>> 24)) & 0x00ff00ff) |
	                (((nBitsTotalL << 24) | (nBitsTotalL >>> 8))  & 0xff00ff00)
	            );

	            data.sigBytes = (dataWords.length + 1) * 4;

	            // Hash final blocks
	            this._process();

	            // Shortcuts
	            var hash = this._hash;
	            var H = hash.words;

	            // Swap endian
	            for (var i = 0; i < 4; i++) {
	                // Shortcut
	                var H_i = H[i];

	                H[i] = (((H_i << 8)  | (H_i >>> 24)) & 0x00ff00ff) |
	                       (((H_i << 24) | (H_i >>> 8))  & 0xff00ff00);
	            }

	            // Return final computed hash
	            return hash;
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);
	            clone._hash = this._hash.clone();

	            return clone;
	        }
	    });

	    function FF(a, b, c, d, x, s, t) {
	        var n = a + ((b & c) | (~b & d)) + x + t;
	        return ((n << s) | (n >>> (32 - s))) + b;
	    }

	    function GG(a, b, c, d, x, s, t) {
	        var n = a + ((b & d) | (c & ~d)) + x + t;
	        return ((n << s) | (n >>> (32 - s))) + b;
	    }

	    function HH(a, b, c, d, x, s, t) {
	        var n = a + (b ^ c ^ d) + x + t;
	        return ((n << s) | (n >>> (32 - s))) + b;
	    }

	    function II(a, b, c, d, x, s, t) {
	        var n = a + (c ^ (b | ~d)) + x + t;
	        return ((n << s) | (n >>> (32 - s))) + b;
	    }

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.MD5('message');
	     *     var hash = CryptoJS.MD5(wordArray);
	     */
	    C.MD5 = Hasher._createHelper(MD5);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacMD5(message, key);
	     */
	    C.HmacMD5 = Hasher._createHmacHelper(MD5);
	}(Math));


	return CryptoJS.MD5;

}));
},{"./core":3}],12:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./cipher-core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./cipher-core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	/**
	 * Cipher Feedback block mode.
	 */
	CryptoJS.mode.CFB = (function () {
	    var CFB = CryptoJS.lib.BlockCipherMode.extend();

	    CFB.Encryptor = CFB.extend({
	        processBlock: function (words, offset) {
	            // Shortcuts
	            var cipher = this._cipher;
	            var blockSize = cipher.blockSize;

	            generateKeystreamAndEncrypt.call(this, words, offset, blockSize, cipher);

	            // Remember this block to use with next block
	            this._prevBlock = words.slice(offset, offset + blockSize);
	        }
	    });

	    CFB.Decryptor = CFB.extend({
	        processBlock: function (words, offset) {
	            // Shortcuts
	            var cipher = this._cipher;
	            var blockSize = cipher.blockSize;

	            // Remember this block to use with next block
	            var thisBlock = words.slice(offset, offset + blockSize);

	            generateKeystreamAndEncrypt.call(this, words, offset, blockSize, cipher);

	            // This block becomes the previous block
	            this._prevBlock = thisBlock;
	        }
	    });

	    function generateKeystreamAndEncrypt(words, offset, blockSize, cipher) {
	        // Shortcut
	        var iv = this._iv;

	        // Generate keystream
	        if (iv) {
	            var keystream = iv.slice(0);

	            // Remove IV for subsequent blocks
	            this._iv = undefined;
	        } else {
	            var keystream = this._prevBlock;
	        }
	        cipher.encryptBlock(keystream, 0);

	        // Encrypt
	        for (var i = 0; i < blockSize; i++) {
	            words[offset + i] ^= keystream[i];
	        }
	    }

	    return CFB;
	}());


	return CryptoJS.mode.CFB;

}));
},{"./cipher-core":2,"./core":3}],13:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./cipher-core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./cipher-core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	/** @preserve
	 * Counter block mode compatible with  Dr Brian Gladman fileenc.c
	 * derived from CryptoJS.mode.CTR
	 * Jan Hruby jhruby.web@gmail.com
	 */
	CryptoJS.mode.CTRGladman = (function () {
	    var CTRGladman = CryptoJS.lib.BlockCipherMode.extend();

		function incWord(word)
		{
			if (((word >> 24) & 0xff) === 0xff) { //overflow
			var b1 = (word >> 16)&0xff;
			var b2 = (word >> 8)&0xff;
			var b3 = word & 0xff;

			if (b1 === 0xff) // overflow b1
			{
			b1 = 0;
			if (b2 === 0xff)
			{
				b2 = 0;
				if (b3 === 0xff)
				{
					b3 = 0;
				}
				else
				{
					++b3;
				}
			}
			else
			{
				++b2;
			}
			}
			else
			{
			++b1;
			}

			word = 0;
			word += (b1 << 16);
			word += (b2 << 8);
			word += b3;
			}
			else
			{
			word += (0x01 << 24);
			}
			return word;
		}

		function incCounter(counter)
		{
			if ((counter[0] = incWord(counter[0])) === 0)
			{
				// encr_data in fileenc.c from  Dr Brian Gladman's counts only with DWORD j < 8
				counter[1] = incWord(counter[1]);
			}
			return counter;
		}

	    var Encryptor = CTRGladman.Encryptor = CTRGladman.extend({
	        processBlock: function (words, offset) {
	            // Shortcuts
	            var cipher = this._cipher
	            var blockSize = cipher.blockSize;
	            var iv = this._iv;
	            var counter = this._counter;

	            // Generate keystream
	            if (iv) {
	                counter = this._counter = iv.slice(0);

	                // Remove IV for subsequent blocks
	                this._iv = undefined;
	            }

				incCounter(counter);

				var keystream = counter.slice(0);
	            cipher.encryptBlock(keystream, 0);

	            // Encrypt
	            for (var i = 0; i < blockSize; i++) {
	                words[offset + i] ^= keystream[i];
	            }
	        }
	    });

	    CTRGladman.Decryptor = Encryptor;

	    return CTRGladman;
	}());




	return CryptoJS.mode.CTRGladman;

}));
},{"./cipher-core":2,"./core":3}],14:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./cipher-core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./cipher-core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	/**
	 * Counter block mode.
	 */
	CryptoJS.mode.CTR = (function () {
	    var CTR = CryptoJS.lib.BlockCipherMode.extend();

	    var Encryptor = CTR.Encryptor = CTR.extend({
	        processBlock: function (words, offset) {
	            // Shortcuts
	            var cipher = this._cipher
	            var blockSize = cipher.blockSize;
	            var iv = this._iv;
	            var counter = this._counter;

	            // Generate keystream
	            if (iv) {
	                counter = this._counter = iv.slice(0);

	                // Remove IV for subsequent blocks
	                this._iv = undefined;
	            }
	            var keystream = counter.slice(0);
	            cipher.encryptBlock(keystream, 0);

	            // Increment counter
	            counter[blockSize - 1] = (counter[blockSize - 1] + 1) | 0

	            // Encrypt
	            for (var i = 0; i < blockSize; i++) {
	                words[offset + i] ^= keystream[i];
	            }
	        }
	    });

	    CTR.Decryptor = Encryptor;

	    return CTR;
	}());


	return CryptoJS.mode.CTR;

}));
},{"./cipher-core":2,"./core":3}],15:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./cipher-core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./cipher-core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	/**
	 * Electronic Codebook block mode.
	 */
	CryptoJS.mode.ECB = (function () {
	    var ECB = CryptoJS.lib.BlockCipherMode.extend();

	    ECB.Encryptor = ECB.extend({
	        processBlock: function (words, offset) {
	            this._cipher.encryptBlock(words, offset);
	        }
	    });

	    ECB.Decryptor = ECB.extend({
	        processBlock: function (words, offset) {
	            this._cipher.decryptBlock(words, offset);
	        }
	    });

	    return ECB;
	}());


	return CryptoJS.mode.ECB;

}));
},{"./cipher-core":2,"./core":3}],16:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./cipher-core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./cipher-core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	/**
	 * Output Feedback block mode.
	 */
	CryptoJS.mode.OFB = (function () {
	    var OFB = CryptoJS.lib.BlockCipherMode.extend();

	    var Encryptor = OFB.Encryptor = OFB.extend({
	        processBlock: function (words, offset) {
	            // Shortcuts
	            var cipher = this._cipher
	            var blockSize = cipher.blockSize;
	            var iv = this._iv;
	            var keystream = this._keystream;

	            // Generate keystream
	            if (iv) {
	                keystream = this._keystream = iv.slice(0);

	                // Remove IV for subsequent blocks
	                this._iv = undefined;
	            }
	            cipher.encryptBlock(keystream, 0);

	            // Encrypt
	            for (var i = 0; i < blockSize; i++) {
	                words[offset + i] ^= keystream[i];
	            }
	        }
	    });

	    OFB.Decryptor = Encryptor;

	    return OFB;
	}());


	return CryptoJS.mode.OFB;

}));
},{"./cipher-core":2,"./core":3}],17:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./cipher-core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./cipher-core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	/**
	 * ANSI X.923 padding strategy.
	 */
	CryptoJS.pad.AnsiX923 = {
	    pad: function (data, blockSize) {
	        // Shortcuts
	        var dataSigBytes = data.sigBytes;
	        var blockSizeBytes = blockSize * 4;

	        // Count padding bytes
	        var nPaddingBytes = blockSizeBytes - dataSigBytes % blockSizeBytes;

	        // Compute last byte position
	        var lastBytePos = dataSigBytes + nPaddingBytes - 1;

	        // Pad
	        data.clamp();
	        data.words[lastBytePos >>> 2] |= nPaddingBytes << (24 - (lastBytePos % 4) * 8);
	        data.sigBytes += nPaddingBytes;
	    },

	    unpad: function (data) {
	        // Get number of padding bytes from last byte
	        var nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;

	        // Remove padding
	        data.sigBytes -= nPaddingBytes;
	    }
	};


	return CryptoJS.pad.Ansix923;

}));
},{"./cipher-core":2,"./core":3}],18:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./cipher-core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./cipher-core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	/**
	 * ISO 10126 padding strategy.
	 */
	CryptoJS.pad.Iso10126 = {
	    pad: function (data, blockSize) {
	        // Shortcut
	        var blockSizeBytes = blockSize * 4;

	        // Count padding bytes
	        var nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

	        // Pad
	        data.concat(CryptoJS.lib.WordArray.random(nPaddingBytes - 1)).
	             concat(CryptoJS.lib.WordArray.create([nPaddingBytes << 24], 1));
	    },

	    unpad: function (data) {
	        // Get number of padding bytes from last byte
	        var nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;

	        // Remove padding
	        data.sigBytes -= nPaddingBytes;
	    }
	};


	return CryptoJS.pad.Iso10126;

}));
},{"./cipher-core":2,"./core":3}],19:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./cipher-core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./cipher-core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	/**
	 * ISO/IEC 9797-1 Padding Method 2.
	 */
	CryptoJS.pad.Iso97971 = {
	    pad: function (data, blockSize) {
	        // Add 0x80 byte
	        data.concat(CryptoJS.lib.WordArray.create([0x80000000], 1));

	        // Zero pad the rest
	        CryptoJS.pad.ZeroPadding.pad(data, blockSize);
	    },

	    unpad: function (data) {
	        // Remove zero padding
	        CryptoJS.pad.ZeroPadding.unpad(data);

	        // Remove one more byte -- the 0x80 byte
	        data.sigBytes--;
	    }
	};


	return CryptoJS.pad.Iso97971;

}));
},{"./cipher-core":2,"./core":3}],20:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./cipher-core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./cipher-core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	/**
	 * A noop padding strategy.
	 */
	CryptoJS.pad.NoPadding = {
	    pad: function () {
	    },

	    unpad: function () {
	    }
	};


	return CryptoJS.pad.NoPadding;

}));
},{"./cipher-core":2,"./core":3}],21:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./cipher-core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./cipher-core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	/**
	 * Zero padding strategy.
	 */
	CryptoJS.pad.ZeroPadding = {
	    pad: function (data, blockSize) {
	        // Shortcut
	        var blockSizeBytes = blockSize * 4;

	        // Pad
	        data.clamp();
	        data.sigBytes += blockSizeBytes - ((data.sigBytes % blockSizeBytes) || blockSizeBytes);
	    },

	    unpad: function (data) {
	        // Shortcut
	        var dataWords = data.words;

	        // Unpad
	        var i = data.sigBytes - 1;
	        while (!((dataWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff)) {
	            i--;
	        }
	        data.sigBytes = i + 1;
	    }
	};


	return CryptoJS.pad.ZeroPadding;

}));
},{"./cipher-core":2,"./core":3}],22:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./sha1"), require("./hmac"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./sha1", "./hmac"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var WordArray = C_lib.WordArray;
	    var C_algo = C.algo;
	    var SHA1 = C_algo.SHA1;
	    var HMAC = C_algo.HMAC;

	    /**
	     * Password-Based Key Derivation Function 2 algorithm.
	     */
	    var PBKDF2 = C_algo.PBKDF2 = Base.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
	         * @property {Hasher} hasher The hasher to use. Default: SHA1
	         * @property {number} iterations The number of iterations to perform. Default: 1
	         */
	        cfg: Base.extend({
	            keySize: 128/32,
	            hasher: SHA1,
	            iterations: 1
	        }),

	        /**
	         * Initializes a newly created key derivation function.
	         *
	         * @param {Object} cfg (Optional) The configuration options to use for the derivation.
	         *
	         * @example
	         *
	         *     var kdf = CryptoJS.algo.PBKDF2.create();
	         *     var kdf = CryptoJS.algo.PBKDF2.create({ keySize: 8 });
	         *     var kdf = CryptoJS.algo.PBKDF2.create({ keySize: 8, iterations: 1000 });
	         */
	        init: function (cfg) {
	            this.cfg = this.cfg.extend(cfg);
	        },

	        /**
	         * Computes the Password-Based Key Derivation Function 2.
	         *
	         * @param {WordArray|string} password The password.
	         * @param {WordArray|string} salt A salt.
	         *
	         * @return {WordArray} The derived key.
	         *
	         * @example
	         *
	         *     var key = kdf.compute(password, salt);
	         */
	        compute: function (password, salt) {
	            // Shortcut
	            var cfg = this.cfg;

	            // Init HMAC
	            var hmac = HMAC.create(cfg.hasher, password);

	            // Initial values
	            var derivedKey = WordArray.create();
	            var blockIndex = WordArray.create([0x00000001]);

	            // Shortcuts
	            var derivedKeyWords = derivedKey.words;
	            var blockIndexWords = blockIndex.words;
	            var keySize = cfg.keySize;
	            var iterations = cfg.iterations;

	            // Generate key
	            while (derivedKeyWords.length < keySize) {
	                var block = hmac.update(salt).finalize(blockIndex);
	                hmac.reset();

	                // Shortcuts
	                var blockWords = block.words;
	                var blockWordsLength = blockWords.length;

	                // Iterations
	                var intermediate = block;
	                for (var i = 1; i < iterations; i++) {
	                    intermediate = hmac.finalize(intermediate);
	                    hmac.reset();

	                    // Shortcut
	                    var intermediateWords = intermediate.words;

	                    // XOR intermediate with block
	                    for (var j = 0; j < blockWordsLength; j++) {
	                        blockWords[j] ^= intermediateWords[j];
	                    }
	                }

	                derivedKey.concat(block);
	                blockIndexWords[0]++;
	            }
	            derivedKey.sigBytes = keySize * 4;

	            return derivedKey;
	        }
	    });

	    /**
	     * Computes the Password-Based Key Derivation Function 2.
	     *
	     * @param {WordArray|string} password The password.
	     * @param {WordArray|string} salt A salt.
	     * @param {Object} cfg (Optional) The configuration options to use for this computation.
	     *
	     * @return {WordArray} The derived key.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var key = CryptoJS.PBKDF2(password, salt);
	     *     var key = CryptoJS.PBKDF2(password, salt, { keySize: 8 });
	     *     var key = CryptoJS.PBKDF2(password, salt, { keySize: 8, iterations: 1000 });
	     */
	    C.PBKDF2 = function (password, salt, cfg) {
	        return PBKDF2.create(cfg).compute(password, salt);
	    };
	}());


	return CryptoJS.PBKDF2;

}));
},{"./core":3,"./hmac":8,"./sha1":27}],23:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./enc-base64"), require("./md5"), require("./evpkdf"), require("./cipher-core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./enc-base64", "./md5", "./evpkdf", "./cipher-core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var StreamCipher = C_lib.StreamCipher;
	    var C_algo = C.algo;

	    // Reusable objects
	    var S  = [];
	    var C_ = [];
	    var G  = [];

	    /**
	     * Rabbit stream cipher algorithm.
	     *
	     * This is a legacy version that neglected to convert the key to little-endian.
	     * This error doesn't affect the cipher's security,
	     * but it does affect its compatibility with other implementations.
	     */
	    var RabbitLegacy = C_algo.RabbitLegacy = StreamCipher.extend({
	        _doReset: function () {
	            // Shortcuts
	            var K = this._key.words;
	            var iv = this.cfg.iv;

	            // Generate initial state values
	            var X = this._X = [
	                K[0], (K[3] << 16) | (K[2] >>> 16),
	                K[1], (K[0] << 16) | (K[3] >>> 16),
	                K[2], (K[1] << 16) | (K[0] >>> 16),
	                K[3], (K[2] << 16) | (K[1] >>> 16)
	            ];

	            // Generate initial counter values
	            var C = this._C = [
	                (K[2] << 16) | (K[2] >>> 16), (K[0] & 0xffff0000) | (K[1] & 0x0000ffff),
	                (K[3] << 16) | (K[3] >>> 16), (K[1] & 0xffff0000) | (K[2] & 0x0000ffff),
	                (K[0] << 16) | (K[0] >>> 16), (K[2] & 0xffff0000) | (K[3] & 0x0000ffff),
	                (K[1] << 16) | (K[1] >>> 16), (K[3] & 0xffff0000) | (K[0] & 0x0000ffff)
	            ];

	            // Carry bit
	            this._b = 0;

	            // Iterate the system four times
	            for (var i = 0; i < 4; i++) {
	                nextState.call(this);
	            }

	            // Modify the counters
	            for (var i = 0; i < 8; i++) {
	                C[i] ^= X[(i + 4) & 7];
	            }

	            // IV setup
	            if (iv) {
	                // Shortcuts
	                var IV = iv.words;
	                var IV_0 = IV[0];
	                var IV_1 = IV[1];

	                // Generate four subvectors
	                var i0 = (((IV_0 << 8) | (IV_0 >>> 24)) & 0x00ff00ff) | (((IV_0 << 24) | (IV_0 >>> 8)) & 0xff00ff00);
	                var i2 = (((IV_1 << 8) | (IV_1 >>> 24)) & 0x00ff00ff) | (((IV_1 << 24) | (IV_1 >>> 8)) & 0xff00ff00);
	                var i1 = (i0 >>> 16) | (i2 & 0xffff0000);
	                var i3 = (i2 << 16)  | (i0 & 0x0000ffff);

	                // Modify counter values
	                C[0] ^= i0;
	                C[1] ^= i1;
	                C[2] ^= i2;
	                C[3] ^= i3;
	                C[4] ^= i0;
	                C[5] ^= i1;
	                C[6] ^= i2;
	                C[7] ^= i3;

	                // Iterate the system four times
	                for (var i = 0; i < 4; i++) {
	                    nextState.call(this);
	                }
	            }
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcut
	            var X = this._X;

	            // Iterate the system
	            nextState.call(this);

	            // Generate four keystream words
	            S[0] = X[0] ^ (X[5] >>> 16) ^ (X[3] << 16);
	            S[1] = X[2] ^ (X[7] >>> 16) ^ (X[5] << 16);
	            S[2] = X[4] ^ (X[1] >>> 16) ^ (X[7] << 16);
	            S[3] = X[6] ^ (X[3] >>> 16) ^ (X[1] << 16);

	            for (var i = 0; i < 4; i++) {
	                // Swap endian
	                S[i] = (((S[i] << 8)  | (S[i] >>> 24)) & 0x00ff00ff) |
	                       (((S[i] << 24) | (S[i] >>> 8))  & 0xff00ff00);

	                // Encrypt
	                M[offset + i] ^= S[i];
	            }
	        },

	        blockSize: 128/32,

	        ivSize: 64/32
	    });

	    function nextState() {
	        // Shortcuts
	        var X = this._X;
	        var C = this._C;

	        // Save old counter values
	        for (var i = 0; i < 8; i++) {
	            C_[i] = C[i];
	        }

	        // Calculate new counter values
	        C[0] = (C[0] + 0x4d34d34d + this._b) | 0;
	        C[1] = (C[1] + 0xd34d34d3 + ((C[0] >>> 0) < (C_[0] >>> 0) ? 1 : 0)) | 0;
	        C[2] = (C[2] + 0x34d34d34 + ((C[1] >>> 0) < (C_[1] >>> 0) ? 1 : 0)) | 0;
	        C[3] = (C[3] + 0x4d34d34d + ((C[2] >>> 0) < (C_[2] >>> 0) ? 1 : 0)) | 0;
	        C[4] = (C[4] + 0xd34d34d3 + ((C[3] >>> 0) < (C_[3] >>> 0) ? 1 : 0)) | 0;
	        C[5] = (C[5] + 0x34d34d34 + ((C[4] >>> 0) < (C_[4] >>> 0) ? 1 : 0)) | 0;
	        C[6] = (C[6] + 0x4d34d34d + ((C[5] >>> 0) < (C_[5] >>> 0) ? 1 : 0)) | 0;
	        C[7] = (C[7] + 0xd34d34d3 + ((C[6] >>> 0) < (C_[6] >>> 0) ? 1 : 0)) | 0;
	        this._b = (C[7] >>> 0) < (C_[7] >>> 0) ? 1 : 0;

	        // Calculate the g-values
	        for (var i = 0; i < 8; i++) {
	            var gx = X[i] + C[i];

	            // Construct high and low argument for squaring
	            var ga = gx & 0xffff;
	            var gb = gx >>> 16;

	            // Calculate high and low result of squaring
	            var gh = ((((ga * ga) >>> 17) + ga * gb) >>> 15) + gb * gb;
	            var gl = (((gx & 0xffff0000) * gx) | 0) + (((gx & 0x0000ffff) * gx) | 0);

	            // High XOR low
	            G[i] = gh ^ gl;
	        }

	        // Calculate new state values
	        X[0] = (G[0] + ((G[7] << 16) | (G[7] >>> 16)) + ((G[6] << 16) | (G[6] >>> 16))) | 0;
	        X[1] = (G[1] + ((G[0] << 8)  | (G[0] >>> 24)) + G[7]) | 0;
	        X[2] = (G[2] + ((G[1] << 16) | (G[1] >>> 16)) + ((G[0] << 16) | (G[0] >>> 16))) | 0;
	        X[3] = (G[3] + ((G[2] << 8)  | (G[2] >>> 24)) + G[1]) | 0;
	        X[4] = (G[4] + ((G[3] << 16) | (G[3] >>> 16)) + ((G[2] << 16) | (G[2] >>> 16))) | 0;
	        X[5] = (G[5] + ((G[4] << 8)  | (G[4] >>> 24)) + G[3]) | 0;
	        X[6] = (G[6] + ((G[5] << 16) | (G[5] >>> 16)) + ((G[4] << 16) | (G[4] >>> 16))) | 0;
	        X[7] = (G[7] + ((G[6] << 8)  | (G[6] >>> 24)) + G[5]) | 0;
	    }

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.RabbitLegacy.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.RabbitLegacy.decrypt(ciphertext, key, cfg);
	     */
	    C.RabbitLegacy = StreamCipher._createHelper(RabbitLegacy);
	}());


	return CryptoJS.RabbitLegacy;

}));
},{"./cipher-core":2,"./core":3,"./enc-base64":4,"./evpkdf":6,"./md5":11}],24:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./enc-base64"), require("./md5"), require("./evpkdf"), require("./cipher-core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./enc-base64", "./md5", "./evpkdf", "./cipher-core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var StreamCipher = C_lib.StreamCipher;
	    var C_algo = C.algo;

	    // Reusable objects
	    var S  = [];
	    var C_ = [];
	    var G  = [];

	    /**
	     * Rabbit stream cipher algorithm
	     */
	    var Rabbit = C_algo.Rabbit = StreamCipher.extend({
	        _doReset: function () {
	            // Shortcuts
	            var K = this._key.words;
	            var iv = this.cfg.iv;

	            // Swap endian
	            for (var i = 0; i < 4; i++) {
	                K[i] = (((K[i] << 8)  | (K[i] >>> 24)) & 0x00ff00ff) |
	                       (((K[i] << 24) | (K[i] >>> 8))  & 0xff00ff00);
	            }

	            // Generate initial state values
	            var X = this._X = [
	                K[0], (K[3] << 16) | (K[2] >>> 16),
	                K[1], (K[0] << 16) | (K[3] >>> 16),
	                K[2], (K[1] << 16) | (K[0] >>> 16),
	                K[3], (K[2] << 16) | (K[1] >>> 16)
	            ];

	            // Generate initial counter values
	            var C = this._C = [
	                (K[2] << 16) | (K[2] >>> 16), (K[0] & 0xffff0000) | (K[1] & 0x0000ffff),
	                (K[3] << 16) | (K[3] >>> 16), (K[1] & 0xffff0000) | (K[2] & 0x0000ffff),
	                (K[0] << 16) | (K[0] >>> 16), (K[2] & 0xffff0000) | (K[3] & 0x0000ffff),
	                (K[1] << 16) | (K[1] >>> 16), (K[3] & 0xffff0000) | (K[0] & 0x0000ffff)
	            ];

	            // Carry bit
	            this._b = 0;

	            // Iterate the system four times
	            for (var i = 0; i < 4; i++) {
	                nextState.call(this);
	            }

	            // Modify the counters
	            for (var i = 0; i < 8; i++) {
	                C[i] ^= X[(i + 4) & 7];
	            }

	            // IV setup
	            if (iv) {
	                // Shortcuts
	                var IV = iv.words;
	                var IV_0 = IV[0];
	                var IV_1 = IV[1];

	                // Generate four subvectors
	                var i0 = (((IV_0 << 8) | (IV_0 >>> 24)) & 0x00ff00ff) | (((IV_0 << 24) | (IV_0 >>> 8)) & 0xff00ff00);
	                var i2 = (((IV_1 << 8) | (IV_1 >>> 24)) & 0x00ff00ff) | (((IV_1 << 24) | (IV_1 >>> 8)) & 0xff00ff00);
	                var i1 = (i0 >>> 16) | (i2 & 0xffff0000);
	                var i3 = (i2 << 16)  | (i0 & 0x0000ffff);

	                // Modify counter values
	                C[0] ^= i0;
	                C[1] ^= i1;
	                C[2] ^= i2;
	                C[3] ^= i3;
	                C[4] ^= i0;
	                C[5] ^= i1;
	                C[6] ^= i2;
	                C[7] ^= i3;

	                // Iterate the system four times
	                for (var i = 0; i < 4; i++) {
	                    nextState.call(this);
	                }
	            }
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcut
	            var X = this._X;

	            // Iterate the system
	            nextState.call(this);

	            // Generate four keystream words
	            S[0] = X[0] ^ (X[5] >>> 16) ^ (X[3] << 16);
	            S[1] = X[2] ^ (X[7] >>> 16) ^ (X[5] << 16);
	            S[2] = X[4] ^ (X[1] >>> 16) ^ (X[7] << 16);
	            S[3] = X[6] ^ (X[3] >>> 16) ^ (X[1] << 16);

	            for (var i = 0; i < 4; i++) {
	                // Swap endian
	                S[i] = (((S[i] << 8)  | (S[i] >>> 24)) & 0x00ff00ff) |
	                       (((S[i] << 24) | (S[i] >>> 8))  & 0xff00ff00);

	                // Encrypt
	                M[offset + i] ^= S[i];
	            }
	        },

	        blockSize: 128/32,

	        ivSize: 64/32
	    });

	    function nextState() {
	        // Shortcuts
	        var X = this._X;
	        var C = this._C;

	        // Save old counter values
	        for (var i = 0; i < 8; i++) {
	            C_[i] = C[i];
	        }

	        // Calculate new counter values
	        C[0] = (C[0] + 0x4d34d34d + this._b) | 0;
	        C[1] = (C[1] + 0xd34d34d3 + ((C[0] >>> 0) < (C_[0] >>> 0) ? 1 : 0)) | 0;
	        C[2] = (C[2] + 0x34d34d34 + ((C[1] >>> 0) < (C_[1] >>> 0) ? 1 : 0)) | 0;
	        C[3] = (C[3] + 0x4d34d34d + ((C[2] >>> 0) < (C_[2] >>> 0) ? 1 : 0)) | 0;
	        C[4] = (C[4] + 0xd34d34d3 + ((C[3] >>> 0) < (C_[3] >>> 0) ? 1 : 0)) | 0;
	        C[5] = (C[5] + 0x34d34d34 + ((C[4] >>> 0) < (C_[4] >>> 0) ? 1 : 0)) | 0;
	        C[6] = (C[6] + 0x4d34d34d + ((C[5] >>> 0) < (C_[5] >>> 0) ? 1 : 0)) | 0;
	        C[7] = (C[7] + 0xd34d34d3 + ((C[6] >>> 0) < (C_[6] >>> 0) ? 1 : 0)) | 0;
	        this._b = (C[7] >>> 0) < (C_[7] >>> 0) ? 1 : 0;

	        // Calculate the g-values
	        for (var i = 0; i < 8; i++) {
	            var gx = X[i] + C[i];

	            // Construct high and low argument for squaring
	            var ga = gx & 0xffff;
	            var gb = gx >>> 16;

	            // Calculate high and low result of squaring
	            var gh = ((((ga * ga) >>> 17) + ga * gb) >>> 15) + gb * gb;
	            var gl = (((gx & 0xffff0000) * gx) | 0) + (((gx & 0x0000ffff) * gx) | 0);

	            // High XOR low
	            G[i] = gh ^ gl;
	        }

	        // Calculate new state values
	        X[0] = (G[0] + ((G[7] << 16) | (G[7] >>> 16)) + ((G[6] << 16) | (G[6] >>> 16))) | 0;
	        X[1] = (G[1] + ((G[0] << 8)  | (G[0] >>> 24)) + G[7]) | 0;
	        X[2] = (G[2] + ((G[1] << 16) | (G[1] >>> 16)) + ((G[0] << 16) | (G[0] >>> 16))) | 0;
	        X[3] = (G[3] + ((G[2] << 8)  | (G[2] >>> 24)) + G[1]) | 0;
	        X[4] = (G[4] + ((G[3] << 16) | (G[3] >>> 16)) + ((G[2] << 16) | (G[2] >>> 16))) | 0;
	        X[5] = (G[5] + ((G[4] << 8)  | (G[4] >>> 24)) + G[3]) | 0;
	        X[6] = (G[6] + ((G[5] << 16) | (G[5] >>> 16)) + ((G[4] << 16) | (G[4] >>> 16))) | 0;
	        X[7] = (G[7] + ((G[6] << 8)  | (G[6] >>> 24)) + G[5]) | 0;
	    }

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.Rabbit.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.Rabbit.decrypt(ciphertext, key, cfg);
	     */
	    C.Rabbit = StreamCipher._createHelper(Rabbit);
	}());


	return CryptoJS.Rabbit;

}));
},{"./cipher-core":2,"./core":3,"./enc-base64":4,"./evpkdf":6,"./md5":11}],25:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./enc-base64"), require("./md5"), require("./evpkdf"), require("./cipher-core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./enc-base64", "./md5", "./evpkdf", "./cipher-core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var StreamCipher = C_lib.StreamCipher;
	    var C_algo = C.algo;

	    /**
	     * RC4 stream cipher algorithm.
	     */
	    var RC4 = C_algo.RC4 = StreamCipher.extend({
	        _doReset: function () {
	            // Shortcuts
	            var key = this._key;
	            var keyWords = key.words;
	            var keySigBytes = key.sigBytes;

	            // Init sbox
	            var S = this._S = [];
	            for (var i = 0; i < 256; i++) {
	                S[i] = i;
	            }

	            // Key setup
	            for (var i = 0, j = 0; i < 256; i++) {
	                var keyByteIndex = i % keySigBytes;
	                var keyByte = (keyWords[keyByteIndex >>> 2] >>> (24 - (keyByteIndex % 4) * 8)) & 0xff;

	                j = (j + S[i] + keyByte) % 256;

	                // Swap
	                var t = S[i];
	                S[i] = S[j];
	                S[j] = t;
	            }

	            // Counters
	            this._i = this._j = 0;
	        },

	        _doProcessBlock: function (M, offset) {
	            M[offset] ^= generateKeystreamWord.call(this);
	        },

	        keySize: 256/32,

	        ivSize: 0
	    });

	    function generateKeystreamWord() {
	        // Shortcuts
	        var S = this._S;
	        var i = this._i;
	        var j = this._j;

	        // Generate keystream word
	        var keystreamWord = 0;
	        for (var n = 0; n < 4; n++) {
	            i = (i + 1) % 256;
	            j = (j + S[i]) % 256;

	            // Swap
	            var t = S[i];
	            S[i] = S[j];
	            S[j] = t;

	            keystreamWord |= S[(S[i] + S[j]) % 256] << (24 - n * 8);
	        }

	        // Update counters
	        this._i = i;
	        this._j = j;

	        return keystreamWord;
	    }

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.RC4.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.RC4.decrypt(ciphertext, key, cfg);
	     */
	    C.RC4 = StreamCipher._createHelper(RC4);

	    /**
	     * Modified RC4 stream cipher algorithm.
	     */
	    var RC4Drop = C_algo.RC4Drop = RC4.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {number} drop The number of keystream words to drop. Default 192
	         */
	        cfg: RC4.cfg.extend({
	            drop: 192
	        }),

	        _doReset: function () {
	            RC4._doReset.call(this);

	            // Drop
	            for (var i = this.cfg.drop; i > 0; i--) {
	                generateKeystreamWord.call(this);
	            }
	        }
	    });

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.RC4Drop.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.RC4Drop.decrypt(ciphertext, key, cfg);
	     */
	    C.RC4Drop = StreamCipher._createHelper(RC4Drop);
	}());


	return CryptoJS.RC4;

}));
},{"./cipher-core":2,"./core":3,"./enc-base64":4,"./evpkdf":6,"./md5":11}],26:[function(require,module,exports){
;(function (root, factory) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	/** @preserve
	(c) 2012 by Cédric Mesnil. All rights reserved.

	Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

	    - Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
	    - Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
	*/

	(function (Math) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var Hasher = C_lib.Hasher;
	    var C_algo = C.algo;

	    // Constants table
	    var _zl = WordArray.create([
	        0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
	        7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
	        3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
	        1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
	        4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13]);
	    var _zr = WordArray.create([
	        5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
	        6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
	        15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
	        8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
	        12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11]);
	    var _sl = WordArray.create([
	         11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
	        7, 6,   8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
	        11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
	          11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
	        9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6 ]);
	    var _sr = WordArray.create([
	        8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
	        9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
	        9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
	        15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
	        8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11 ]);

	    var _hl =  WordArray.create([ 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]);
	    var _hr =  WordArray.create([ 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]);

	    /**
	     * RIPEMD160 hash algorithm.
	     */
	    var RIPEMD160 = C_algo.RIPEMD160 = Hasher.extend({
	        _doReset: function () {
	            this._hash  = WordArray.create([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);
	        },

	        _doProcessBlock: function (M, offset) {

	            // Swap endian
	            for (var i = 0; i < 16; i++) {
	                // Shortcuts
	                var offset_i = offset + i;
	                var M_offset_i = M[offset_i];

	                // Swap
	                M[offset_i] = (
	                    (((M_offset_i << 8)  | (M_offset_i >>> 24)) & 0x00ff00ff) |
	                    (((M_offset_i << 24) | (M_offset_i >>> 8))  & 0xff00ff00)
	                );
	            }
	            // Shortcut
	            var H  = this._hash.words;
	            var hl = _hl.words;
	            var hr = _hr.words;
	            var zl = _zl.words;
	            var zr = _zr.words;
	            var sl = _sl.words;
	            var sr = _sr.words;

	            // Working variables
	            var al, bl, cl, dl, el;
	            var ar, br, cr, dr, er;

	            ar = al = H[0];
	            br = bl = H[1];
	            cr = cl = H[2];
	            dr = dl = H[3];
	            er = el = H[4];
	            // Computation
	            var t;
	            for (var i = 0; i < 80; i += 1) {
	                t = (al +  M[offset+zl[i]])|0;
	                if (i<16){
		            t +=  f1(bl,cl,dl) + hl[0];
	                } else if (i<32) {
		            t +=  f2(bl,cl,dl) + hl[1];
	                } else if (i<48) {
		            t +=  f3(bl,cl,dl) + hl[2];
	                } else if (i<64) {
		            t +=  f4(bl,cl,dl) + hl[3];
	                } else {// if (i<80) {
		            t +=  f5(bl,cl,dl) + hl[4];
	                }
	                t = t|0;
	                t =  rotl(t,sl[i]);
	                t = (t+el)|0;
	                al = el;
	                el = dl;
	                dl = rotl(cl, 10);
	                cl = bl;
	                bl = t;

	                t = (ar + M[offset+zr[i]])|0;
	                if (i<16){
		            t +=  f5(br,cr,dr) + hr[0];
	                } else if (i<32) {
		            t +=  f4(br,cr,dr) + hr[1];
	                } else if (i<48) {
		            t +=  f3(br,cr,dr) + hr[2];
	                } else if (i<64) {
		            t +=  f2(br,cr,dr) + hr[3];
	                } else {// if (i<80) {
		            t +=  f1(br,cr,dr) + hr[4];
	                }
	                t = t|0;
	                t =  rotl(t,sr[i]) ;
	                t = (t+er)|0;
	                ar = er;
	                er = dr;
	                dr = rotl(cr, 10);
	                cr = br;
	                br = t;
	            }
	            // Intermediate hash value
	            t    = (H[1] + cl + dr)|0;
	            H[1] = (H[2] + dl + er)|0;
	            H[2] = (H[3] + el + ar)|0;
	            H[3] = (H[4] + al + br)|0;
	            H[4] = (H[0] + bl + cr)|0;
	            H[0] =  t;
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;

	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = (
	                (((nBitsTotal << 8)  | (nBitsTotal >>> 24)) & 0x00ff00ff) |
	                (((nBitsTotal << 24) | (nBitsTotal >>> 8))  & 0xff00ff00)
	            );
	            data.sigBytes = (dataWords.length + 1) * 4;

	            // Hash final blocks
	            this._process();

	            // Shortcuts
	            var hash = this._hash;
	            var H = hash.words;

	            // Swap endian
	            for (var i = 0; i < 5; i++) {
	                // Shortcut
	                var H_i = H[i];

	                // Swap
	                H[i] = (((H_i << 8)  | (H_i >>> 24)) & 0x00ff00ff) |
	                       (((H_i << 24) | (H_i >>> 8))  & 0xff00ff00);
	            }

	            // Return final computed hash
	            return hash;
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);
	            clone._hash = this._hash.clone();

	            return clone;
	        }
	    });


	    function f1(x, y, z) {
	        return ((x) ^ (y) ^ (z));

	    }

	    function f2(x, y, z) {
	        return (((x)&(y)) | ((~x)&(z)));
	    }

	    function f3(x, y, z) {
	        return (((x) | (~(y))) ^ (z));
	    }

	    function f4(x, y, z) {
	        return (((x) & (z)) | ((y)&(~(z))));
	    }

	    function f5(x, y, z) {
	        return ((x) ^ ((y) |(~(z))));

	    }

	    function rotl(x,n) {
	        return (x<<n) | (x>>>(32-n));
	    }


	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.RIPEMD160('message');
	     *     var hash = CryptoJS.RIPEMD160(wordArray);
	     */
	    C.RIPEMD160 = Hasher._createHelper(RIPEMD160);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacRIPEMD160(message, key);
	     */
	    C.HmacRIPEMD160 = Hasher._createHmacHelper(RIPEMD160);
	}(Math));


	return CryptoJS.RIPEMD160;

}));
},{"./core":3}],27:[function(require,module,exports){
;(function (root, factory) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var Hasher = C_lib.Hasher;
	    var C_algo = C.algo;

	    // Reusable object
	    var W = [];

	    /**
	     * SHA-1 hash algorithm.
	     */
	    var SHA1 = C_algo.SHA1 = Hasher.extend({
	        _doReset: function () {
	            this._hash = new WordArray.init([
	                0x67452301, 0xefcdab89,
	                0x98badcfe, 0x10325476,
	                0xc3d2e1f0
	            ]);
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcut
	            var H = this._hash.words;

	            // Working variables
	            var a = H[0];
	            var b = H[1];
	            var c = H[2];
	            var d = H[3];
	            var e = H[4];

	            // Computation
	            for (var i = 0; i < 80; i++) {
	                if (i < 16) {
	                    W[i] = M[offset + i] | 0;
	                } else {
	                    var n = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
	                    W[i] = (n << 1) | (n >>> 31);
	                }

	                var t = ((a << 5) | (a >>> 27)) + e + W[i];
	                if (i < 20) {
	                    t += ((b & c) | (~b & d)) + 0x5a827999;
	                } else if (i < 40) {
	                    t += (b ^ c ^ d) + 0x6ed9eba1;
	                } else if (i < 60) {
	                    t += ((b & c) | (b & d) | (c & d)) - 0x70e44324;
	                } else /* if (i < 80) */ {
	                    t += (b ^ c ^ d) - 0x359d3e2a;
	                }

	                e = d;
	                d = c;
	                c = (b << 30) | (b >>> 2);
	                b = a;
	                a = t;
	            }

	            // Intermediate hash value
	            H[0] = (H[0] + a) | 0;
	            H[1] = (H[1] + b) | 0;
	            H[2] = (H[2] + c) | 0;
	            H[3] = (H[3] + d) | 0;
	            H[4] = (H[4] + e) | 0;
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;

	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
	            data.sigBytes = dataWords.length * 4;

	            // Hash final blocks
	            this._process();

	            // Return final computed hash
	            return this._hash;
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);
	            clone._hash = this._hash.clone();

	            return clone;
	        }
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA1('message');
	     *     var hash = CryptoJS.SHA1(wordArray);
	     */
	    C.SHA1 = Hasher._createHelper(SHA1);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA1(message, key);
	     */
	    C.HmacSHA1 = Hasher._createHmacHelper(SHA1);
	}());


	return CryptoJS.SHA1;

}));
},{"./core":3}],28:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./sha256"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./sha256"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var C_algo = C.algo;
	    var SHA256 = C_algo.SHA256;

	    /**
	     * SHA-224 hash algorithm.
	     */
	    var SHA224 = C_algo.SHA224 = SHA256.extend({
	        _doReset: function () {
	            this._hash = new WordArray.init([
	                0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
	                0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
	            ]);
	        },

	        _doFinalize: function () {
	            var hash = SHA256._doFinalize.call(this);

	            hash.sigBytes -= 4;

	            return hash;
	        }
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA224('message');
	     *     var hash = CryptoJS.SHA224(wordArray);
	     */
	    C.SHA224 = SHA256._createHelper(SHA224);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA224(message, key);
	     */
	    C.HmacSHA224 = SHA256._createHmacHelper(SHA224);
	}());


	return CryptoJS.SHA224;

}));
},{"./core":3,"./sha256":29}],29:[function(require,module,exports){
;(function (root, factory) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	(function (Math) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var Hasher = C_lib.Hasher;
	    var C_algo = C.algo;

	    // Initialization and round constants tables
	    var H = [];
	    var K = [];

	    // Compute constants
	    (function () {
	        function isPrime(n) {
	            var sqrtN = Math.sqrt(n);
	            for (var factor = 2; factor <= sqrtN; factor++) {
	                if (!(n % factor)) {
	                    return false;
	                }
	            }

	            return true;
	        }

	        function getFractionalBits(n) {
	            return ((n - (n | 0)) * 0x100000000) | 0;
	        }

	        var n = 2;
	        var nPrime = 0;
	        while (nPrime < 64) {
	            if (isPrime(n)) {
	                if (nPrime < 8) {
	                    H[nPrime] = getFractionalBits(Math.pow(n, 1 / 2));
	                }
	                K[nPrime] = getFractionalBits(Math.pow(n, 1 / 3));

	                nPrime++;
	            }

	            n++;
	        }
	    }());

	    // Reusable object
	    var W = [];

	    /**
	     * SHA-256 hash algorithm.
	     */
	    var SHA256 = C_algo.SHA256 = Hasher.extend({
	        _doReset: function () {
	            this._hash = new WordArray.init(H.slice(0));
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcut
	            var H = this._hash.words;

	            // Working variables
	            var a = H[0];
	            var b = H[1];
	            var c = H[2];
	            var d = H[3];
	            var e = H[4];
	            var f = H[5];
	            var g = H[6];
	            var h = H[7];

	            // Computation
	            for (var i = 0; i < 64; i++) {
	                if (i < 16) {
	                    W[i] = M[offset + i] | 0;
	                } else {
	                    var gamma0x = W[i - 15];
	                    var gamma0  = ((gamma0x << 25) | (gamma0x >>> 7))  ^
	                                  ((gamma0x << 14) | (gamma0x >>> 18)) ^
	                                   (gamma0x >>> 3);

	                    var gamma1x = W[i - 2];
	                    var gamma1  = ((gamma1x << 15) | (gamma1x >>> 17)) ^
	                                  ((gamma1x << 13) | (gamma1x >>> 19)) ^
	                                   (gamma1x >>> 10);

	                    W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16];
	                }

	                var ch  = (e & f) ^ (~e & g);
	                var maj = (a & b) ^ (a & c) ^ (b & c);

	                var sigma0 = ((a << 30) | (a >>> 2)) ^ ((a << 19) | (a >>> 13)) ^ ((a << 10) | (a >>> 22));
	                var sigma1 = ((e << 26) | (e >>> 6)) ^ ((e << 21) | (e >>> 11)) ^ ((e << 7)  | (e >>> 25));

	                var t1 = h + sigma1 + ch + K[i] + W[i];
	                var t2 = sigma0 + maj;

	                h = g;
	                g = f;
	                f = e;
	                e = (d + t1) | 0;
	                d = c;
	                c = b;
	                b = a;
	                a = (t1 + t2) | 0;
	            }

	            // Intermediate hash value
	            H[0] = (H[0] + a) | 0;
	            H[1] = (H[1] + b) | 0;
	            H[2] = (H[2] + c) | 0;
	            H[3] = (H[3] + d) | 0;
	            H[4] = (H[4] + e) | 0;
	            H[5] = (H[5] + f) | 0;
	            H[6] = (H[6] + g) | 0;
	            H[7] = (H[7] + h) | 0;
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;

	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
	            data.sigBytes = dataWords.length * 4;

	            // Hash final blocks
	            this._process();

	            // Return final computed hash
	            return this._hash;
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);
	            clone._hash = this._hash.clone();

	            return clone;
	        }
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA256('message');
	     *     var hash = CryptoJS.SHA256(wordArray);
	     */
	    C.SHA256 = Hasher._createHelper(SHA256);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA256(message, key);
	     */
	    C.HmacSHA256 = Hasher._createHmacHelper(SHA256);
	}(Math));


	return CryptoJS.SHA256;

}));
},{"./core":3}],30:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./x64-core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./x64-core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	(function (Math) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var Hasher = C_lib.Hasher;
	    var C_x64 = C.x64;
	    var X64Word = C_x64.Word;
	    var C_algo = C.algo;

	    // Constants tables
	    var RHO_OFFSETS = [];
	    var PI_INDEXES  = [];
	    var ROUND_CONSTANTS = [];

	    // Compute Constants
	    (function () {
	        // Compute rho offset constants
	        var x = 1, y = 0;
	        for (var t = 0; t < 24; t++) {
	            RHO_OFFSETS[x + 5 * y] = ((t + 1) * (t + 2) / 2) % 64;

	            var newX = y % 5;
	            var newY = (2 * x + 3 * y) % 5;
	            x = newX;
	            y = newY;
	        }

	        // Compute pi index constants
	        for (var x = 0; x < 5; x++) {
	            for (var y = 0; y < 5; y++) {
	                PI_INDEXES[x + 5 * y] = y + ((2 * x + 3 * y) % 5) * 5;
	            }
	        }

	        // Compute round constants
	        var LFSR = 0x01;
	        for (var i = 0; i < 24; i++) {
	            var roundConstantMsw = 0;
	            var roundConstantLsw = 0;

	            for (var j = 0; j < 7; j++) {
	                if (LFSR & 0x01) {
	                    var bitPosition = (1 << j) - 1;
	                    if (bitPosition < 32) {
	                        roundConstantLsw ^= 1 << bitPosition;
	                    } else /* if (bitPosition >= 32) */ {
	                        roundConstantMsw ^= 1 << (bitPosition - 32);
	                    }
	                }

	                // Compute next LFSR
	                if (LFSR & 0x80) {
	                    // Primitive polynomial over GF(2): x^8 + x^6 + x^5 + x^4 + 1
	                    LFSR = (LFSR << 1) ^ 0x71;
	                } else {
	                    LFSR <<= 1;
	                }
	            }

	            ROUND_CONSTANTS[i] = X64Word.create(roundConstantMsw, roundConstantLsw);
	        }
	    }());

	    // Reusable objects for temporary values
	    var T = [];
	    (function () {
	        for (var i = 0; i < 25; i++) {
	            T[i] = X64Word.create();
	        }
	    }());

	    /**
	     * SHA-3 hash algorithm.
	     */
	    var SHA3 = C_algo.SHA3 = Hasher.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {number} outputLength
	         *   The desired number of bits in the output hash.
	         *   Only values permitted are: 224, 256, 384, 512.
	         *   Default: 512
	         */
	        cfg: Hasher.cfg.extend({
	            outputLength: 512
	        }),

	        _doReset: function () {
	            var state = this._state = []
	            for (var i = 0; i < 25; i++) {
	                state[i] = new X64Word.init();
	            }

	            this.blockSize = (1600 - 2 * this.cfg.outputLength) / 32;
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcuts
	            var state = this._state;
	            var nBlockSizeLanes = this.blockSize / 2;

	            // Absorb
	            for (var i = 0; i < nBlockSizeLanes; i++) {
	                // Shortcuts
	                var M2i  = M[offset + 2 * i];
	                var M2i1 = M[offset + 2 * i + 1];

	                // Swap endian
	                M2i = (
	                    (((M2i << 8)  | (M2i >>> 24)) & 0x00ff00ff) |
	                    (((M2i << 24) | (M2i >>> 8))  & 0xff00ff00)
	                );
	                M2i1 = (
	                    (((M2i1 << 8)  | (M2i1 >>> 24)) & 0x00ff00ff) |
	                    (((M2i1 << 24) | (M2i1 >>> 8))  & 0xff00ff00)
	                );

	                // Absorb message into state
	                var lane = state[i];
	                lane.high ^= M2i1;
	                lane.low  ^= M2i;
	            }

	            // Rounds
	            for (var round = 0; round < 24; round++) {
	                // Theta
	                for (var x = 0; x < 5; x++) {
	                    // Mix column lanes
	                    var tMsw = 0, tLsw = 0;
	                    for (var y = 0; y < 5; y++) {
	                        var lane = state[x + 5 * y];
	                        tMsw ^= lane.high;
	                        tLsw ^= lane.low;
	                    }

	                    // Temporary values
	                    var Tx = T[x];
	                    Tx.high = tMsw;
	                    Tx.low  = tLsw;
	                }
	                for (var x = 0; x < 5; x++) {
	                    // Shortcuts
	                    var Tx4 = T[(x + 4) % 5];
	                    var Tx1 = T[(x + 1) % 5];
	                    var Tx1Msw = Tx1.high;
	                    var Tx1Lsw = Tx1.low;

	                    // Mix surrounding columns
	                    var tMsw = Tx4.high ^ ((Tx1Msw << 1) | (Tx1Lsw >>> 31));
	                    var tLsw = Tx4.low  ^ ((Tx1Lsw << 1) | (Tx1Msw >>> 31));
	                    for (var y = 0; y < 5; y++) {
	                        var lane = state[x + 5 * y];
	                        lane.high ^= tMsw;
	                        lane.low  ^= tLsw;
	                    }
	                }

	                // Rho Pi
	                for (var laneIndex = 1; laneIndex < 25; laneIndex++) {
	                    // Shortcuts
	                    var lane = state[laneIndex];
	                    var laneMsw = lane.high;
	                    var laneLsw = lane.low;
	                    var rhoOffset = RHO_OFFSETS[laneIndex];

	                    // Rotate lanes
	                    if (rhoOffset < 32) {
	                        var tMsw = (laneMsw << rhoOffset) | (laneLsw >>> (32 - rhoOffset));
	                        var tLsw = (laneLsw << rhoOffset) | (laneMsw >>> (32 - rhoOffset));
	                    } else /* if (rhoOffset >= 32) */ {
	                        var tMsw = (laneLsw << (rhoOffset - 32)) | (laneMsw >>> (64 - rhoOffset));
	                        var tLsw = (laneMsw << (rhoOffset - 32)) | (laneLsw >>> (64 - rhoOffset));
	                    }

	                    // Transpose lanes
	                    var TPiLane = T[PI_INDEXES[laneIndex]];
	                    TPiLane.high = tMsw;
	                    TPiLane.low  = tLsw;
	                }

	                // Rho pi at x = y = 0
	                var T0 = T[0];
	                var state0 = state[0];
	                T0.high = state0.high;
	                T0.low  = state0.low;

	                // Chi
	                for (var x = 0; x < 5; x++) {
	                    for (var y = 0; y < 5; y++) {
	                        // Shortcuts
	                        var laneIndex = x + 5 * y;
	                        var lane = state[laneIndex];
	                        var TLane = T[laneIndex];
	                        var Tx1Lane = T[((x + 1) % 5) + 5 * y];
	                        var Tx2Lane = T[((x + 2) % 5) + 5 * y];

	                        // Mix rows
	                        lane.high = TLane.high ^ (~Tx1Lane.high & Tx2Lane.high);
	                        lane.low  = TLane.low  ^ (~Tx1Lane.low  & Tx2Lane.low);
	                    }
	                }

	                // Iota
	                var lane = state[0];
	                var roundConstant = ROUND_CONSTANTS[round];
	                lane.high ^= roundConstant.high;
	                lane.low  ^= roundConstant.low;;
	            }
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;
	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;
	            var blockSizeBits = this.blockSize * 32;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x1 << (24 - nBitsLeft % 32);
	            dataWords[((Math.ceil((nBitsLeft + 1) / blockSizeBits) * blockSizeBits) >>> 5) - 1] |= 0x80;
	            data.sigBytes = dataWords.length * 4;

	            // Hash final blocks
	            this._process();

	            // Shortcuts
	            var state = this._state;
	            var outputLengthBytes = this.cfg.outputLength / 8;
	            var outputLengthLanes = outputLengthBytes / 8;

	            // Squeeze
	            var hashWords = [];
	            for (var i = 0; i < outputLengthLanes; i++) {
	                // Shortcuts
	                var lane = state[i];
	                var laneMsw = lane.high;
	                var laneLsw = lane.low;

	                // Swap endian
	                laneMsw = (
	                    (((laneMsw << 8)  | (laneMsw >>> 24)) & 0x00ff00ff) |
	                    (((laneMsw << 24) | (laneMsw >>> 8))  & 0xff00ff00)
	                );
	                laneLsw = (
	                    (((laneLsw << 8)  | (laneLsw >>> 24)) & 0x00ff00ff) |
	                    (((laneLsw << 24) | (laneLsw >>> 8))  & 0xff00ff00)
	                );

	                // Squeeze state to retrieve hash
	                hashWords.push(laneLsw);
	                hashWords.push(laneMsw);
	            }

	            // Return final computed hash
	            return new WordArray.init(hashWords, outputLengthBytes);
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);

	            var state = clone._state = this._state.slice(0);
	            for (var i = 0; i < 25; i++) {
	                state[i] = state[i].clone();
	            }

	            return clone;
	        }
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA3('message');
	     *     var hash = CryptoJS.SHA3(wordArray);
	     */
	    C.SHA3 = Hasher._createHelper(SHA3);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA3(message, key);
	     */
	    C.HmacSHA3 = Hasher._createHmacHelper(SHA3);
	}(Math));


	return CryptoJS.SHA3;

}));
},{"./core":3,"./x64-core":34}],31:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./x64-core"), require("./sha512"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./x64-core", "./sha512"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_x64 = C.x64;
	    var X64Word = C_x64.Word;
	    var X64WordArray = C_x64.WordArray;
	    var C_algo = C.algo;
	    var SHA512 = C_algo.SHA512;

	    /**
	     * SHA-384 hash algorithm.
	     */
	    var SHA384 = C_algo.SHA384 = SHA512.extend({
	        _doReset: function () {
	            this._hash = new X64WordArray.init([
	                new X64Word.init(0xcbbb9d5d, 0xc1059ed8), new X64Word.init(0x629a292a, 0x367cd507),
	                new X64Word.init(0x9159015a, 0x3070dd17), new X64Word.init(0x152fecd8, 0xf70e5939),
	                new X64Word.init(0x67332667, 0xffc00b31), new X64Word.init(0x8eb44a87, 0x68581511),
	                new X64Word.init(0xdb0c2e0d, 0x64f98fa7), new X64Word.init(0x47b5481d, 0xbefa4fa4)
	            ]);
	        },

	        _doFinalize: function () {
	            var hash = SHA512._doFinalize.call(this);

	            hash.sigBytes -= 16;

	            return hash;
	        }
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA384('message');
	     *     var hash = CryptoJS.SHA384(wordArray);
	     */
	    C.SHA384 = SHA512._createHelper(SHA384);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA384(message, key);
	     */
	    C.HmacSHA384 = SHA512._createHmacHelper(SHA384);
	}());


	return CryptoJS.SHA384;

}));
},{"./core":3,"./sha512":32,"./x64-core":34}],32:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./x64-core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./x64-core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Hasher = C_lib.Hasher;
	    var C_x64 = C.x64;
	    var X64Word = C_x64.Word;
	    var X64WordArray = C_x64.WordArray;
	    var C_algo = C.algo;

	    function X64Word_create() {
	        return X64Word.create.apply(X64Word, arguments);
	    }

	    // Constants
	    var K = [
	        X64Word_create(0x428a2f98, 0xd728ae22), X64Word_create(0x71374491, 0x23ef65cd),
	        X64Word_create(0xb5c0fbcf, 0xec4d3b2f), X64Word_create(0xe9b5dba5, 0x8189dbbc),
	        X64Word_create(0x3956c25b, 0xf348b538), X64Word_create(0x59f111f1, 0xb605d019),
	        X64Word_create(0x923f82a4, 0xaf194f9b), X64Word_create(0xab1c5ed5, 0xda6d8118),
	        X64Word_create(0xd807aa98, 0xa3030242), X64Word_create(0x12835b01, 0x45706fbe),
	        X64Word_create(0x243185be, 0x4ee4b28c), X64Word_create(0x550c7dc3, 0xd5ffb4e2),
	        X64Word_create(0x72be5d74, 0xf27b896f), X64Word_create(0x80deb1fe, 0x3b1696b1),
	        X64Word_create(0x9bdc06a7, 0x25c71235), X64Word_create(0xc19bf174, 0xcf692694),
	        X64Word_create(0xe49b69c1, 0x9ef14ad2), X64Word_create(0xefbe4786, 0x384f25e3),
	        X64Word_create(0x0fc19dc6, 0x8b8cd5b5), X64Word_create(0x240ca1cc, 0x77ac9c65),
	        X64Word_create(0x2de92c6f, 0x592b0275), X64Word_create(0x4a7484aa, 0x6ea6e483),
	        X64Word_create(0x5cb0a9dc, 0xbd41fbd4), X64Word_create(0x76f988da, 0x831153b5),
	        X64Word_create(0x983e5152, 0xee66dfab), X64Word_create(0xa831c66d, 0x2db43210),
	        X64Word_create(0xb00327c8, 0x98fb213f), X64Word_create(0xbf597fc7, 0xbeef0ee4),
	        X64Word_create(0xc6e00bf3, 0x3da88fc2), X64Word_create(0xd5a79147, 0x930aa725),
	        X64Word_create(0x06ca6351, 0xe003826f), X64Word_create(0x14292967, 0x0a0e6e70),
	        X64Word_create(0x27b70a85, 0x46d22ffc), X64Word_create(0x2e1b2138, 0x5c26c926),
	        X64Word_create(0x4d2c6dfc, 0x5ac42aed), X64Word_create(0x53380d13, 0x9d95b3df),
	        X64Word_create(0x650a7354, 0x8baf63de), X64Word_create(0x766a0abb, 0x3c77b2a8),
	        X64Word_create(0x81c2c92e, 0x47edaee6), X64Word_create(0x92722c85, 0x1482353b),
	        X64Word_create(0xa2bfe8a1, 0x4cf10364), X64Word_create(0xa81a664b, 0xbc423001),
	        X64Word_create(0xc24b8b70, 0xd0f89791), X64Word_create(0xc76c51a3, 0x0654be30),
	        X64Word_create(0xd192e819, 0xd6ef5218), X64Word_create(0xd6990624, 0x5565a910),
	        X64Word_create(0xf40e3585, 0x5771202a), X64Word_create(0x106aa070, 0x32bbd1b8),
	        X64Word_create(0x19a4c116, 0xb8d2d0c8), X64Word_create(0x1e376c08, 0x5141ab53),
	        X64Word_create(0x2748774c, 0xdf8eeb99), X64Word_create(0x34b0bcb5, 0xe19b48a8),
	        X64Word_create(0x391c0cb3, 0xc5c95a63), X64Word_create(0x4ed8aa4a, 0xe3418acb),
	        X64Word_create(0x5b9cca4f, 0x7763e373), X64Word_create(0x682e6ff3, 0xd6b2b8a3),
	        X64Word_create(0x748f82ee, 0x5defb2fc), X64Word_create(0x78a5636f, 0x43172f60),
	        X64Word_create(0x84c87814, 0xa1f0ab72), X64Word_create(0x8cc70208, 0x1a6439ec),
	        X64Word_create(0x90befffa, 0x23631e28), X64Word_create(0xa4506ceb, 0xde82bde9),
	        X64Word_create(0xbef9a3f7, 0xb2c67915), X64Word_create(0xc67178f2, 0xe372532b),
	        X64Word_create(0xca273ece, 0xea26619c), X64Word_create(0xd186b8c7, 0x21c0c207),
	        X64Word_create(0xeada7dd6, 0xcde0eb1e), X64Word_create(0xf57d4f7f, 0xee6ed178),
	        X64Word_create(0x06f067aa, 0x72176fba), X64Word_create(0x0a637dc5, 0xa2c898a6),
	        X64Word_create(0x113f9804, 0xbef90dae), X64Word_create(0x1b710b35, 0x131c471b),
	        X64Word_create(0x28db77f5, 0x23047d84), X64Word_create(0x32caab7b, 0x40c72493),
	        X64Word_create(0x3c9ebe0a, 0x15c9bebc), X64Word_create(0x431d67c4, 0x9c100d4c),
	        X64Word_create(0x4cc5d4be, 0xcb3e42b6), X64Word_create(0x597f299c, 0xfc657e2a),
	        X64Word_create(0x5fcb6fab, 0x3ad6faec), X64Word_create(0x6c44198c, 0x4a475817)
	    ];

	    // Reusable objects
	    var W = [];
	    (function () {
	        for (var i = 0; i < 80; i++) {
	            W[i] = X64Word_create();
	        }
	    }());

	    /**
	     * SHA-512 hash algorithm.
	     */
	    var SHA512 = C_algo.SHA512 = Hasher.extend({
	        _doReset: function () {
	            this._hash = new X64WordArray.init([
	                new X64Word.init(0x6a09e667, 0xf3bcc908), new X64Word.init(0xbb67ae85, 0x84caa73b),
	                new X64Word.init(0x3c6ef372, 0xfe94f82b), new X64Word.init(0xa54ff53a, 0x5f1d36f1),
	                new X64Word.init(0x510e527f, 0xade682d1), new X64Word.init(0x9b05688c, 0x2b3e6c1f),
	                new X64Word.init(0x1f83d9ab, 0xfb41bd6b), new X64Word.init(0x5be0cd19, 0x137e2179)
	            ]);
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcuts
	            var H = this._hash.words;

	            var H0 = H[0];
	            var H1 = H[1];
	            var H2 = H[2];
	            var H3 = H[3];
	            var H4 = H[4];
	            var H5 = H[5];
	            var H6 = H[6];
	            var H7 = H[7];

	            var H0h = H0.high;
	            var H0l = H0.low;
	            var H1h = H1.high;
	            var H1l = H1.low;
	            var H2h = H2.high;
	            var H2l = H2.low;
	            var H3h = H3.high;
	            var H3l = H3.low;
	            var H4h = H4.high;
	            var H4l = H4.low;
	            var H5h = H5.high;
	            var H5l = H5.low;
	            var H6h = H6.high;
	            var H6l = H6.low;
	            var H7h = H7.high;
	            var H7l = H7.low;

	            // Working variables
	            var ah = H0h;
	            var al = H0l;
	            var bh = H1h;
	            var bl = H1l;
	            var ch = H2h;
	            var cl = H2l;
	            var dh = H3h;
	            var dl = H3l;
	            var eh = H4h;
	            var el = H4l;
	            var fh = H5h;
	            var fl = H5l;
	            var gh = H6h;
	            var gl = H6l;
	            var hh = H7h;
	            var hl = H7l;

	            // Rounds
	            for (var i = 0; i < 80; i++) {
	                // Shortcut
	                var Wi = W[i];

	                // Extend message
	                if (i < 16) {
	                    var Wih = Wi.high = M[offset + i * 2]     | 0;
	                    var Wil = Wi.low  = M[offset + i * 2 + 1] | 0;
	                } else {
	                    // Gamma0
	                    var gamma0x  = W[i - 15];
	                    var gamma0xh = gamma0x.high;
	                    var gamma0xl = gamma0x.low;
	                    var gamma0h  = ((gamma0xh >>> 1) | (gamma0xl << 31)) ^ ((gamma0xh >>> 8) | (gamma0xl << 24)) ^ (gamma0xh >>> 7);
	                    var gamma0l  = ((gamma0xl >>> 1) | (gamma0xh << 31)) ^ ((gamma0xl >>> 8) | (gamma0xh << 24)) ^ ((gamma0xl >>> 7) | (gamma0xh << 25));

	                    // Gamma1
	                    var gamma1x  = W[i - 2];
	                    var gamma1xh = gamma1x.high;
	                    var gamma1xl = gamma1x.low;
	                    var gamma1h  = ((gamma1xh >>> 19) | (gamma1xl << 13)) ^ ((gamma1xh << 3) | (gamma1xl >>> 29)) ^ (gamma1xh >>> 6);
	                    var gamma1l  = ((gamma1xl >>> 19) | (gamma1xh << 13)) ^ ((gamma1xl << 3) | (gamma1xh >>> 29)) ^ ((gamma1xl >>> 6) | (gamma1xh << 26));

	                    // W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16]
	                    var Wi7  = W[i - 7];
	                    var Wi7h = Wi7.high;
	                    var Wi7l = Wi7.low;

	                    var Wi16  = W[i - 16];
	                    var Wi16h = Wi16.high;
	                    var Wi16l = Wi16.low;

	                    var Wil = gamma0l + Wi7l;
	                    var Wih = gamma0h + Wi7h + ((Wil >>> 0) < (gamma0l >>> 0) ? 1 : 0);
	                    var Wil = Wil + gamma1l;
	                    var Wih = Wih + gamma1h + ((Wil >>> 0) < (gamma1l >>> 0) ? 1 : 0);
	                    var Wil = Wil + Wi16l;
	                    var Wih = Wih + Wi16h + ((Wil >>> 0) < (Wi16l >>> 0) ? 1 : 0);

	                    Wi.high = Wih;
	                    Wi.low  = Wil;
	                }

	                var chh  = (eh & fh) ^ (~eh & gh);
	                var chl  = (el & fl) ^ (~el & gl);
	                var majh = (ah & bh) ^ (ah & ch) ^ (bh & ch);
	                var majl = (al & bl) ^ (al & cl) ^ (bl & cl);

	                var sigma0h = ((ah >>> 28) | (al << 4))  ^ ((ah << 30)  | (al >>> 2)) ^ ((ah << 25) | (al >>> 7));
	                var sigma0l = ((al >>> 28) | (ah << 4))  ^ ((al << 30)  | (ah >>> 2)) ^ ((al << 25) | (ah >>> 7));
	                var sigma1h = ((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9));
	                var sigma1l = ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9));

	                // t1 = h + sigma1 + ch + K[i] + W[i]
	                var Ki  = K[i];
	                var Kih = Ki.high;
	                var Kil = Ki.low;

	                var t1l = hl + sigma1l;
	                var t1h = hh + sigma1h + ((t1l >>> 0) < (hl >>> 0) ? 1 : 0);
	                var t1l = t1l + chl;
	                var t1h = t1h + chh + ((t1l >>> 0) < (chl >>> 0) ? 1 : 0);
	                var t1l = t1l + Kil;
	                var t1h = t1h + Kih + ((t1l >>> 0) < (Kil >>> 0) ? 1 : 0);
	                var t1l = t1l + Wil;
	                var t1h = t1h + Wih + ((t1l >>> 0) < (Wil >>> 0) ? 1 : 0);

	                // t2 = sigma0 + maj
	                var t2l = sigma0l + majl;
	                var t2h = sigma0h + majh + ((t2l >>> 0) < (sigma0l >>> 0) ? 1 : 0);

	                // Update working variables
	                hh = gh;
	                hl = gl;
	                gh = fh;
	                gl = fl;
	                fh = eh;
	                fl = el;
	                el = (dl + t1l) | 0;
	                eh = (dh + t1h + ((el >>> 0) < (dl >>> 0) ? 1 : 0)) | 0;
	                dh = ch;
	                dl = cl;
	                ch = bh;
	                cl = bl;
	                bh = ah;
	                bl = al;
	                al = (t1l + t2l) | 0;
	                ah = (t1h + t2h + ((al >>> 0) < (t1l >>> 0) ? 1 : 0)) | 0;
	            }

	            // Intermediate hash value
	            H0l = H0.low  = (H0l + al);
	            H0.high = (H0h + ah + ((H0l >>> 0) < (al >>> 0) ? 1 : 0));
	            H1l = H1.low  = (H1l + bl);
	            H1.high = (H1h + bh + ((H1l >>> 0) < (bl >>> 0) ? 1 : 0));
	            H2l = H2.low  = (H2l + cl);
	            H2.high = (H2h + ch + ((H2l >>> 0) < (cl >>> 0) ? 1 : 0));
	            H3l = H3.low  = (H3l + dl);
	            H3.high = (H3h + dh + ((H3l >>> 0) < (dl >>> 0) ? 1 : 0));
	            H4l = H4.low  = (H4l + el);
	            H4.high = (H4h + eh + ((H4l >>> 0) < (el >>> 0) ? 1 : 0));
	            H5l = H5.low  = (H5l + fl);
	            H5.high = (H5h + fh + ((H5l >>> 0) < (fl >>> 0) ? 1 : 0));
	            H6l = H6.low  = (H6l + gl);
	            H6.high = (H6h + gh + ((H6l >>> 0) < (gl >>> 0) ? 1 : 0));
	            H7l = H7.low  = (H7l + hl);
	            H7.high = (H7h + hh + ((H7l >>> 0) < (hl >>> 0) ? 1 : 0));
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;

	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
	            dataWords[(((nBitsLeft + 128) >>> 10) << 5) + 30] = Math.floor(nBitsTotal / 0x100000000);
	            dataWords[(((nBitsLeft + 128) >>> 10) << 5) + 31] = nBitsTotal;
	            data.sigBytes = dataWords.length * 4;

	            // Hash final blocks
	            this._process();

	            // Convert hash to 32-bit word array before returning
	            var hash = this._hash.toX32();

	            // Return final computed hash
	            return hash;
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);
	            clone._hash = this._hash.clone();

	            return clone;
	        },

	        blockSize: 1024/32
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA512('message');
	     *     var hash = CryptoJS.SHA512(wordArray);
	     */
	    C.SHA512 = Hasher._createHelper(SHA512);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA512(message, key);
	     */
	    C.HmacSHA512 = Hasher._createHmacHelper(SHA512);
	}());


	return CryptoJS.SHA512;

}));
},{"./core":3,"./x64-core":34}],33:[function(require,module,exports){
;(function (root, factory, undef) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"), require("./enc-base64"), require("./md5"), require("./evpkdf"), require("./cipher-core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core", "./enc-base64", "./md5", "./evpkdf", "./cipher-core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var BlockCipher = C_lib.BlockCipher;
	    var C_algo = C.algo;

	    // Permuted Choice 1 constants
	    var PC1 = [
	        57, 49, 41, 33, 25, 17, 9,  1,
	        58, 50, 42, 34, 26, 18, 10, 2,
	        59, 51, 43, 35, 27, 19, 11, 3,
	        60, 52, 44, 36, 63, 55, 47, 39,
	        31, 23, 15, 7,  62, 54, 46, 38,
	        30, 22, 14, 6,  61, 53, 45, 37,
	        29, 21, 13, 5,  28, 20, 12, 4
	    ];

	    // Permuted Choice 2 constants
	    var PC2 = [
	        14, 17, 11, 24, 1,  5,
	        3,  28, 15, 6,  21, 10,
	        23, 19, 12, 4,  26, 8,
	        16, 7,  27, 20, 13, 2,
	        41, 52, 31, 37, 47, 55,
	        30, 40, 51, 45, 33, 48,
	        44, 49, 39, 56, 34, 53,
	        46, 42, 50, 36, 29, 32
	    ];

	    // Cumulative bit shift constants
	    var BIT_SHIFTS = [1,  2,  4,  6,  8,  10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28];

	    // SBOXes and round permutation constants
	    var SBOX_P = [
	        {
	            0x0: 0x808200,
	            0x10000000: 0x8000,
	            0x20000000: 0x808002,
	            0x30000000: 0x2,
	            0x40000000: 0x200,
	            0x50000000: 0x808202,
	            0x60000000: 0x800202,
	            0x70000000: 0x800000,
	            0x80000000: 0x202,
	            0x90000000: 0x800200,
	            0xa0000000: 0x8200,
	            0xb0000000: 0x808000,
	            0xc0000000: 0x8002,
	            0xd0000000: 0x800002,
	            0xe0000000: 0x0,
	            0xf0000000: 0x8202,
	            0x8000000: 0x0,
	            0x18000000: 0x808202,
	            0x28000000: 0x8202,
	            0x38000000: 0x8000,
	            0x48000000: 0x808200,
	            0x58000000: 0x200,
	            0x68000000: 0x808002,
	            0x78000000: 0x2,
	            0x88000000: 0x800200,
	            0x98000000: 0x8200,
	            0xa8000000: 0x808000,
	            0xb8000000: 0x800202,
	            0xc8000000: 0x800002,
	            0xd8000000: 0x8002,
	            0xe8000000: 0x202,
	            0xf8000000: 0x800000,
	            0x1: 0x8000,
	            0x10000001: 0x2,
	            0x20000001: 0x808200,
	            0x30000001: 0x800000,
	            0x40000001: 0x808002,
	            0x50000001: 0x8200,
	            0x60000001: 0x200,
	            0x70000001: 0x800202,
	            0x80000001: 0x808202,
	            0x90000001: 0x808000,
	            0xa0000001: 0x800002,
	            0xb0000001: 0x8202,
	            0xc0000001: 0x202,
	            0xd0000001: 0x800200,
	            0xe0000001: 0x8002,
	            0xf0000001: 0x0,
	            0x8000001: 0x808202,
	            0x18000001: 0x808000,
	            0x28000001: 0x800000,
	            0x38000001: 0x200,
	            0x48000001: 0x8000,
	            0x58000001: 0x800002,
	            0x68000001: 0x2,
	            0x78000001: 0x8202,
	            0x88000001: 0x8002,
	            0x98000001: 0x800202,
	            0xa8000001: 0x202,
	            0xb8000001: 0x808200,
	            0xc8000001: 0x800200,
	            0xd8000001: 0x0,
	            0xe8000001: 0x8200,
	            0xf8000001: 0x808002
	        },
	        {
	            0x0: 0x40084010,
	            0x1000000: 0x4000,
	            0x2000000: 0x80000,
	            0x3000000: 0x40080010,
	            0x4000000: 0x40000010,
	            0x5000000: 0x40084000,
	            0x6000000: 0x40004000,
	            0x7000000: 0x10,
	            0x8000000: 0x84000,
	            0x9000000: 0x40004010,
	            0xa000000: 0x40000000,
	            0xb000000: 0x84010,
	            0xc000000: 0x80010,
	            0xd000000: 0x0,
	            0xe000000: 0x4010,
	            0xf000000: 0x40080000,
	            0x800000: 0x40004000,
	            0x1800000: 0x84010,
	            0x2800000: 0x10,
	            0x3800000: 0x40004010,
	            0x4800000: 0x40084010,
	            0x5800000: 0x40000000,
	            0x6800000: 0x80000,
	            0x7800000: 0x40080010,
	            0x8800000: 0x80010,
	            0x9800000: 0x0,
	            0xa800000: 0x4000,
	            0xb800000: 0x40080000,
	            0xc800000: 0x40000010,
	            0xd800000: 0x84000,
	            0xe800000: 0x40084000,
	            0xf800000: 0x4010,
	            0x10000000: 0x0,
	            0x11000000: 0x40080010,
	            0x12000000: 0x40004010,
	            0x13000000: 0x40084000,
	            0x14000000: 0x40080000,
	            0x15000000: 0x10,
	            0x16000000: 0x84010,
	            0x17000000: 0x4000,
	            0x18000000: 0x4010,
	            0x19000000: 0x80000,
	            0x1a000000: 0x80010,
	            0x1b000000: 0x40000010,
	            0x1c000000: 0x84000,
	            0x1d000000: 0x40004000,
	            0x1e000000: 0x40000000,
	            0x1f000000: 0x40084010,
	            0x10800000: 0x84010,
	            0x11800000: 0x80000,
	            0x12800000: 0x40080000,
	            0x13800000: 0x4000,
	            0x14800000: 0x40004000,
	            0x15800000: 0x40084010,
	            0x16800000: 0x10,
	            0x17800000: 0x40000000,
	            0x18800000: 0x40084000,
	            0x19800000: 0x40000010,
	            0x1a800000: 0x40004010,
	            0x1b800000: 0x80010,
	            0x1c800000: 0x0,
	            0x1d800000: 0x4010,
	            0x1e800000: 0x40080010,
	            0x1f800000: 0x84000
	        },
	        {
	            0x0: 0x104,
	            0x100000: 0x0,
	            0x200000: 0x4000100,
	            0x300000: 0x10104,
	            0x400000: 0x10004,
	            0x500000: 0x4000004,
	            0x600000: 0x4010104,
	            0x700000: 0x4010000,
	            0x800000: 0x4000000,
	            0x900000: 0x4010100,
	            0xa00000: 0x10100,
	            0xb00000: 0x4010004,
	            0xc00000: 0x4000104,
	            0xd00000: 0x10000,
	            0xe00000: 0x4,
	            0xf00000: 0x100,
	            0x80000: 0x4010100,
	            0x180000: 0x4010004,
	            0x280000: 0x0,
	            0x380000: 0x4000100,
	            0x480000: 0x4000004,
	            0x580000: 0x10000,
	            0x680000: 0x10004,
	            0x780000: 0x104,
	            0x880000: 0x4,
	            0x980000: 0x100,
	            0xa80000: 0x4010000,
	            0xb80000: 0x10104,
	            0xc80000: 0x10100,
	            0xd80000: 0x4000104,
	            0xe80000: 0x4010104,
	            0xf80000: 0x4000000,
	            0x1000000: 0x4010100,
	            0x1100000: 0x10004,
	            0x1200000: 0x10000,
	            0x1300000: 0x4000100,
	            0x1400000: 0x100,
	            0x1500000: 0x4010104,
	            0x1600000: 0x4000004,
	            0x1700000: 0x0,
	            0x1800000: 0x4000104,
	            0x1900000: 0x4000000,
	            0x1a00000: 0x4,
	            0x1b00000: 0x10100,
	            0x1c00000: 0x4010000,
	            0x1d00000: 0x104,
	            0x1e00000: 0x10104,
	            0x1f00000: 0x4010004,
	            0x1080000: 0x4000000,
	            0x1180000: 0x104,
	            0x1280000: 0x4010100,
	            0x1380000: 0x0,
	            0x1480000: 0x10004,
	            0x1580000: 0x4000100,
	            0x1680000: 0x100,
	            0x1780000: 0x4010004,
	            0x1880000: 0x10000,
	            0x1980000: 0x4010104,
	            0x1a80000: 0x10104,
	            0x1b80000: 0x4000004,
	            0x1c80000: 0x4000104,
	            0x1d80000: 0x4010000,
	            0x1e80000: 0x4,
	            0x1f80000: 0x10100
	        },
	        {
	            0x0: 0x80401000,
	            0x10000: 0x80001040,
	            0x20000: 0x401040,
	            0x30000: 0x80400000,
	            0x40000: 0x0,
	            0x50000: 0x401000,
	            0x60000: 0x80000040,
	            0x70000: 0x400040,
	            0x80000: 0x80000000,
	            0x90000: 0x400000,
	            0xa0000: 0x40,
	            0xb0000: 0x80001000,
	            0xc0000: 0x80400040,
	            0xd0000: 0x1040,
	            0xe0000: 0x1000,
	            0xf0000: 0x80401040,
	            0x8000: 0x80001040,
	            0x18000: 0x40,
	            0x28000: 0x80400040,
	            0x38000: 0x80001000,
	            0x48000: 0x401000,
	            0x58000: 0x80401040,
	            0x68000: 0x0,
	            0x78000: 0x80400000,
	            0x88000: 0x1000,
	            0x98000: 0x80401000,
	            0xa8000: 0x400000,
	            0xb8000: 0x1040,
	            0xc8000: 0x80000000,
	            0xd8000: 0x400040,
	            0xe8000: 0x401040,
	            0xf8000: 0x80000040,
	            0x100000: 0x400040,
	            0x110000: 0x401000,
	            0x120000: 0x80000040,
	            0x130000: 0x0,
	            0x140000: 0x1040,
	            0x150000: 0x80400040,
	            0x160000: 0x80401000,
	            0x170000: 0x80001040,
	            0x180000: 0x80401040,
	            0x190000: 0x80000000,
	            0x1a0000: 0x80400000,
	            0x1b0000: 0x401040,
	            0x1c0000: 0x80001000,
	            0x1d0000: 0x400000,
	            0x1e0000: 0x40,
	            0x1f0000: 0x1000,
	            0x108000: 0x80400000,
	            0x118000: 0x80401040,
	            0x128000: 0x0,
	            0x138000: 0x401000,
	            0x148000: 0x400040,
	            0x158000: 0x80000000,
	            0x168000: 0x80001040,
	            0x178000: 0x40,
	            0x188000: 0x80000040,
	            0x198000: 0x1000,
	            0x1a8000: 0x80001000,
	            0x1b8000: 0x80400040,
	            0x1c8000: 0x1040,
	            0x1d8000: 0x80401000,
	            0x1e8000: 0x400000,
	            0x1f8000: 0x401040
	        },
	        {
	            0x0: 0x80,
	            0x1000: 0x1040000,
	            0x2000: 0x40000,
	            0x3000: 0x20000000,
	            0x4000: 0x20040080,
	            0x5000: 0x1000080,
	            0x6000: 0x21000080,
	            0x7000: 0x40080,
	            0x8000: 0x1000000,
	            0x9000: 0x20040000,
	            0xa000: 0x20000080,
	            0xb000: 0x21040080,
	            0xc000: 0x21040000,
	            0xd000: 0x0,
	            0xe000: 0x1040080,
	            0xf000: 0x21000000,
	            0x800: 0x1040080,
	            0x1800: 0x21000080,
	            0x2800: 0x80,
	            0x3800: 0x1040000,
	            0x4800: 0x40000,
	            0x5800: 0x20040080,
	            0x6800: 0x21040000,
	            0x7800: 0x20000000,
	            0x8800: 0x20040000,
	            0x9800: 0x0,
	            0xa800: 0x21040080,
	            0xb800: 0x1000080,
	            0xc800: 0x20000080,
	            0xd800: 0x21000000,
	            0xe800: 0x1000000,
	            0xf800: 0x40080,
	            0x10000: 0x40000,
	            0x11000: 0x80,
	            0x12000: 0x20000000,
	            0x13000: 0x21000080,
	            0x14000: 0x1000080,
	            0x15000: 0x21040000,
	            0x16000: 0x20040080,
	            0x17000: 0x1000000,
	            0x18000: 0x21040080,
	            0x19000: 0x21000000,
	            0x1a000: 0x1040000,
	            0x1b000: 0x20040000,
	            0x1c000: 0x40080,
	            0x1d000: 0x20000080,
	            0x1e000: 0x0,
	            0x1f000: 0x1040080,
	            0x10800: 0x21000080,
	            0x11800: 0x1000000,
	            0x12800: 0x1040000,
	            0x13800: 0x20040080,
	            0x14800: 0x20000000,
	            0x15800: 0x1040080,
	            0x16800: 0x80,
	            0x17800: 0x21040000,
	            0x18800: 0x40080,
	            0x19800: 0x21040080,
	            0x1a800: 0x0,
	            0x1b800: 0x21000000,
	            0x1c800: 0x1000080,
	            0x1d800: 0x40000,
	            0x1e800: 0x20040000,
	            0x1f800: 0x20000080
	        },
	        {
	            0x0: 0x10000008,
	            0x100: 0x2000,
	            0x200: 0x10200000,
	            0x300: 0x10202008,
	            0x400: 0x10002000,
	            0x500: 0x200000,
	            0x600: 0x200008,
	            0x700: 0x10000000,
	            0x800: 0x0,
	            0x900: 0x10002008,
	            0xa00: 0x202000,
	            0xb00: 0x8,
	            0xc00: 0x10200008,
	            0xd00: 0x202008,
	            0xe00: 0x2008,
	            0xf00: 0x10202000,
	            0x80: 0x10200000,
	            0x180: 0x10202008,
	            0x280: 0x8,
	            0x380: 0x200000,
	            0x480: 0x202008,
	            0x580: 0x10000008,
	            0x680: 0x10002000,
	            0x780: 0x2008,
	            0x880: 0x200008,
	            0x980: 0x2000,
	            0xa80: 0x10002008,
	            0xb80: 0x10200008,
	            0xc80: 0x0,
	            0xd80: 0x10202000,
	            0xe80: 0x202000,
	            0xf80: 0x10000000,
	            0x1000: 0x10002000,
	            0x1100: 0x10200008,
	            0x1200: 0x10202008,
	            0x1300: 0x2008,
	            0x1400: 0x200000,
	            0x1500: 0x10000000,
	            0x1600: 0x10000008,
	            0x1700: 0x202000,
	            0x1800: 0x202008,
	            0x1900: 0x0,
	            0x1a00: 0x8,
	            0x1b00: 0x10200000,
	            0x1c00: 0x2000,
	            0x1d00: 0x10002008,
	            0x1e00: 0x10202000,
	            0x1f00: 0x200008,
	            0x1080: 0x8,
	            0x1180: 0x202000,
	            0x1280: 0x200000,
	            0x1380: 0x10000008,
	            0x1480: 0x10002000,
	            0x1580: 0x2008,
	            0x1680: 0x10202008,
	            0x1780: 0x10200000,
	            0x1880: 0x10202000,
	            0x1980: 0x10200008,
	            0x1a80: 0x2000,
	            0x1b80: 0x202008,
	            0x1c80: 0x200008,
	            0x1d80: 0x0,
	            0x1e80: 0x10000000,
	            0x1f80: 0x10002008
	        },
	        {
	            0x0: 0x100000,
	            0x10: 0x2000401,
	            0x20: 0x400,
	            0x30: 0x100401,
	            0x40: 0x2100401,
	            0x50: 0x0,
	            0x60: 0x1,
	            0x70: 0x2100001,
	            0x80: 0x2000400,
	            0x90: 0x100001,
	            0xa0: 0x2000001,
	            0xb0: 0x2100400,
	            0xc0: 0x2100000,
	            0xd0: 0x401,
	            0xe0: 0x100400,
	            0xf0: 0x2000000,
	            0x8: 0x2100001,
	            0x18: 0x0,
	            0x28: 0x2000401,
	            0x38: 0x2100400,
	            0x48: 0x100000,
	            0x58: 0x2000001,
	            0x68: 0x2000000,
	            0x78: 0x401,
	            0x88: 0x100401,
	            0x98: 0x2000400,
	            0xa8: 0x2100000,
	            0xb8: 0x100001,
	            0xc8: 0x400,
	            0xd8: 0x2100401,
	            0xe8: 0x1,
	            0xf8: 0x100400,
	            0x100: 0x2000000,
	            0x110: 0x100000,
	            0x120: 0x2000401,
	            0x130: 0x2100001,
	            0x140: 0x100001,
	            0x150: 0x2000400,
	            0x160: 0x2100400,
	            0x170: 0x100401,
	            0x180: 0x401,
	            0x190: 0x2100401,
	            0x1a0: 0x100400,
	            0x1b0: 0x1,
	            0x1c0: 0x0,
	            0x1d0: 0x2100000,
	            0x1e0: 0x2000001,
	            0x1f0: 0x400,
	            0x108: 0x100400,
	            0x118: 0x2000401,
	            0x128: 0x2100001,
	            0x138: 0x1,
	            0x148: 0x2000000,
	            0x158: 0x100000,
	            0x168: 0x401,
	            0x178: 0x2100400,
	            0x188: 0x2000001,
	            0x198: 0x2100000,
	            0x1a8: 0x0,
	            0x1b8: 0x2100401,
	            0x1c8: 0x100401,
	            0x1d8: 0x400,
	            0x1e8: 0x2000400,
	            0x1f8: 0x100001
	        },
	        {
	            0x0: 0x8000820,
	            0x1: 0x20000,
	            0x2: 0x8000000,
	            0x3: 0x20,
	            0x4: 0x20020,
	            0x5: 0x8020820,
	            0x6: 0x8020800,
	            0x7: 0x800,
	            0x8: 0x8020000,
	            0x9: 0x8000800,
	            0xa: 0x20800,
	            0xb: 0x8020020,
	            0xc: 0x820,
	            0xd: 0x0,
	            0xe: 0x8000020,
	            0xf: 0x20820,
	            0x80000000: 0x800,
	            0x80000001: 0x8020820,
	            0x80000002: 0x8000820,
	            0x80000003: 0x8000000,
	            0x80000004: 0x8020000,
	            0x80000005: 0x20800,
	            0x80000006: 0x20820,
	            0x80000007: 0x20,
	            0x80000008: 0x8000020,
	            0x80000009: 0x820,
	            0x8000000a: 0x20020,
	            0x8000000b: 0x8020800,
	            0x8000000c: 0x0,
	            0x8000000d: 0x8020020,
	            0x8000000e: 0x8000800,
	            0x8000000f: 0x20000,
	            0x10: 0x20820,
	            0x11: 0x8020800,
	            0x12: 0x20,
	            0x13: 0x800,
	            0x14: 0x8000800,
	            0x15: 0x8000020,
	            0x16: 0x8020020,
	            0x17: 0x20000,
	            0x18: 0x0,
	            0x19: 0x20020,
	            0x1a: 0x8020000,
	            0x1b: 0x8000820,
	            0x1c: 0x8020820,
	            0x1d: 0x20800,
	            0x1e: 0x820,
	            0x1f: 0x8000000,
	            0x80000010: 0x20000,
	            0x80000011: 0x800,
	            0x80000012: 0x8020020,
	            0x80000013: 0x20820,
	            0x80000014: 0x20,
	            0x80000015: 0x8020000,
	            0x80000016: 0x8000000,
	            0x80000017: 0x8000820,
	            0x80000018: 0x8020820,
	            0x80000019: 0x8000020,
	            0x8000001a: 0x8000800,
	            0x8000001b: 0x0,
	            0x8000001c: 0x20800,
	            0x8000001d: 0x820,
	            0x8000001e: 0x20020,
	            0x8000001f: 0x8020800
	        }
	    ];

	    // Masks that select the SBOX input
	    var SBOX_MASK = [
	        0xf8000001, 0x1f800000, 0x01f80000, 0x001f8000,
	        0x0001f800, 0x00001f80, 0x000001f8, 0x8000001f
	    ];

	    /**
	     * DES block cipher algorithm.
	     */
	    var DES = C_algo.DES = BlockCipher.extend({
	        _doReset: function () {
	            // Shortcuts
	            var key = this._key;
	            var keyWords = key.words;

	            // Select 56 bits according to PC1
	            var keyBits = [];
	            for (var i = 0; i < 56; i++) {
	                var keyBitPos = PC1[i] - 1;
	                keyBits[i] = (keyWords[keyBitPos >>> 5] >>> (31 - keyBitPos % 32)) & 1;
	            }

	            // Assemble 16 subkeys
	            var subKeys = this._subKeys = [];
	            for (var nSubKey = 0; nSubKey < 16; nSubKey++) {
	                // Create subkey
	                var subKey = subKeys[nSubKey] = [];

	                // Shortcut
	                var bitShift = BIT_SHIFTS[nSubKey];

	                // Select 48 bits according to PC2
	                for (var i = 0; i < 24; i++) {
	                    // Select from the left 28 key bits
	                    subKey[(i / 6) | 0] |= keyBits[((PC2[i] - 1) + bitShift) % 28] << (31 - i % 6);

	                    // Select from the right 28 key bits
	                    subKey[4 + ((i / 6) | 0)] |= keyBits[28 + (((PC2[i + 24] - 1) + bitShift) % 28)] << (31 - i % 6);
	                }

	                // Since each subkey is applied to an expanded 32-bit input,
	                // the subkey can be broken into 8 values scaled to 32-bits,
	                // which allows the key to be used without expansion
	                subKey[0] = (subKey[0] << 1) | (subKey[0] >>> 31);
	                for (var i = 1; i < 7; i++) {
	                    subKey[i] = subKey[i] >>> ((i - 1) * 4 + 3);
	                }
	                subKey[7] = (subKey[7] << 5) | (subKey[7] >>> 27);
	            }

	            // Compute inverse subkeys
	            var invSubKeys = this._invSubKeys = [];
	            for (var i = 0; i < 16; i++) {
	                invSubKeys[i] = subKeys[15 - i];
	            }
	        },

	        encryptBlock: function (M, offset) {
	            this._doCryptBlock(M, offset, this._subKeys);
	        },

	        decryptBlock: function (M, offset) {
	            this._doCryptBlock(M, offset, this._invSubKeys);
	        },

	        _doCryptBlock: function (M, offset, subKeys) {
	            // Get input
	            this._lBlock = M[offset];
	            this._rBlock = M[offset + 1];

	            // Initial permutation
	            exchangeLR.call(this, 4,  0x0f0f0f0f);
	            exchangeLR.call(this, 16, 0x0000ffff);
	            exchangeRL.call(this, 2,  0x33333333);
	            exchangeRL.call(this, 8,  0x00ff00ff);
	            exchangeLR.call(this, 1,  0x55555555);

	            // Rounds
	            for (var round = 0; round < 16; round++) {
	                // Shortcuts
	                var subKey = subKeys[round];
	                var lBlock = this._lBlock;
	                var rBlock = this._rBlock;

	                // Feistel function
	                var f = 0;
	                for (var i = 0; i < 8; i++) {
	                    f |= SBOX_P[i][((rBlock ^ subKey[i]) & SBOX_MASK[i]) >>> 0];
	                }
	                this._lBlock = rBlock;
	                this._rBlock = lBlock ^ f;
	            }

	            // Undo swap from last round
	            var t = this._lBlock;
	            this._lBlock = this._rBlock;
	            this._rBlock = t;

	            // Final permutation
	            exchangeLR.call(this, 1,  0x55555555);
	            exchangeRL.call(this, 8,  0x00ff00ff);
	            exchangeRL.call(this, 2,  0x33333333);
	            exchangeLR.call(this, 16, 0x0000ffff);
	            exchangeLR.call(this, 4,  0x0f0f0f0f);

	            // Set output
	            M[offset] = this._lBlock;
	            M[offset + 1] = this._rBlock;
	        },

	        keySize: 64/32,

	        ivSize: 64/32,

	        blockSize: 64/32
	    });

	    // Swap bits across the left and right words
	    function exchangeLR(offset, mask) {
	        var t = ((this._lBlock >>> offset) ^ this._rBlock) & mask;
	        this._rBlock ^= t;
	        this._lBlock ^= t << offset;
	    }

	    function exchangeRL(offset, mask) {
	        var t = ((this._rBlock >>> offset) ^ this._lBlock) & mask;
	        this._lBlock ^= t;
	        this._rBlock ^= t << offset;
	    }

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.DES.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.DES.decrypt(ciphertext, key, cfg);
	     */
	    C.DES = BlockCipher._createHelper(DES);

	    /**
	     * Triple-DES block cipher algorithm.
	     */
	    var TripleDES = C_algo.TripleDES = BlockCipher.extend({
	        _doReset: function () {
	            // Shortcuts
	            var key = this._key;
	            var keyWords = key.words;

	            // Create DES instances
	            this._des1 = DES.createEncryptor(WordArray.create(keyWords.slice(0, 2)));
	            this._des2 = DES.createEncryptor(WordArray.create(keyWords.slice(2, 4)));
	            this._des3 = DES.createEncryptor(WordArray.create(keyWords.slice(4, 6)));
	        },

	        encryptBlock: function (M, offset) {
	            this._des1.encryptBlock(M, offset);
	            this._des2.decryptBlock(M, offset);
	            this._des3.encryptBlock(M, offset);
	        },

	        decryptBlock: function (M, offset) {
	            this._des3.decryptBlock(M, offset);
	            this._des2.encryptBlock(M, offset);
	            this._des1.decryptBlock(M, offset);
	        },

	        keySize: 192/32,

	        ivSize: 64/32,

	        blockSize: 64/32
	    });

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.TripleDES.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.TripleDES.decrypt(ciphertext, key, cfg);
	     */
	    C.TripleDES = BlockCipher._createHelper(TripleDES);
	}());


	return CryptoJS.TripleDES;

}));
},{"./cipher-core":2,"./core":3,"./enc-base64":4,"./evpkdf":6,"./md5":11}],34:[function(require,module,exports){
;(function (root, factory) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory(require("./core"));
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	(function (undefined) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var X32WordArray = C_lib.WordArray;

	    /**
	     * x64 namespace.
	     */
	    var C_x64 = C.x64 = {};

	    /**
	     * A 64-bit word.
	     */
	    var X64Word = C_x64.Word = Base.extend({
	        /**
	         * Initializes a newly created 64-bit word.
	         *
	         * @param {number} high The high 32 bits.
	         * @param {number} low The low 32 bits.
	         *
	         * @example
	         *
	         *     var x64Word = CryptoJS.x64.Word.create(0x00010203, 0x04050607);
	         */
	        init: function (high, low) {
	            this.high = high;
	            this.low = low;
	        }

	        /**
	         * Bitwise NOTs this word.
	         *
	         * @return {X64Word} A new x64-Word object after negating.
	         *
	         * @example
	         *
	         *     var negated = x64Word.not();
	         */
	        // not: function () {
	            // var high = ~this.high;
	            // var low = ~this.low;

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Bitwise ANDs this word with the passed word.
	         *
	         * @param {X64Word} word The x64-Word to AND with this word.
	         *
	         * @return {X64Word} A new x64-Word object after ANDing.
	         *
	         * @example
	         *
	         *     var anded = x64Word.and(anotherX64Word);
	         */
	        // and: function (word) {
	            // var high = this.high & word.high;
	            // var low = this.low & word.low;

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Bitwise ORs this word with the passed word.
	         *
	         * @param {X64Word} word The x64-Word to OR with this word.
	         *
	         * @return {X64Word} A new x64-Word object after ORing.
	         *
	         * @example
	         *
	         *     var ored = x64Word.or(anotherX64Word);
	         */
	        // or: function (word) {
	            // var high = this.high | word.high;
	            // var low = this.low | word.low;

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Bitwise XORs this word with the passed word.
	         *
	         * @param {X64Word} word The x64-Word to XOR with this word.
	         *
	         * @return {X64Word} A new x64-Word object after XORing.
	         *
	         * @example
	         *
	         *     var xored = x64Word.xor(anotherX64Word);
	         */
	        // xor: function (word) {
	            // var high = this.high ^ word.high;
	            // var low = this.low ^ word.low;

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Shifts this word n bits to the left.
	         *
	         * @param {number} n The number of bits to shift.
	         *
	         * @return {X64Word} A new x64-Word object after shifting.
	         *
	         * @example
	         *
	         *     var shifted = x64Word.shiftL(25);
	         */
	        // shiftL: function (n) {
	            // if (n < 32) {
	                // var high = (this.high << n) | (this.low >>> (32 - n));
	                // var low = this.low << n;
	            // } else {
	                // var high = this.low << (n - 32);
	                // var low = 0;
	            // }

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Shifts this word n bits to the right.
	         *
	         * @param {number} n The number of bits to shift.
	         *
	         * @return {X64Word} A new x64-Word object after shifting.
	         *
	         * @example
	         *
	         *     var shifted = x64Word.shiftR(7);
	         */
	        // shiftR: function (n) {
	            // if (n < 32) {
	                // var low = (this.low >>> n) | (this.high << (32 - n));
	                // var high = this.high >>> n;
	            // } else {
	                // var low = this.high >>> (n - 32);
	                // var high = 0;
	            // }

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Rotates this word n bits to the left.
	         *
	         * @param {number} n The number of bits to rotate.
	         *
	         * @return {X64Word} A new x64-Word object after rotating.
	         *
	         * @example
	         *
	         *     var rotated = x64Word.rotL(25);
	         */
	        // rotL: function (n) {
	            // return this.shiftL(n).or(this.shiftR(64 - n));
	        // },

	        /**
	         * Rotates this word n bits to the right.
	         *
	         * @param {number} n The number of bits to rotate.
	         *
	         * @return {X64Word} A new x64-Word object after rotating.
	         *
	         * @example
	         *
	         *     var rotated = x64Word.rotR(7);
	         */
	        // rotR: function (n) {
	            // return this.shiftR(n).or(this.shiftL(64 - n));
	        // },

	        /**
	         * Adds this word with the passed word.
	         *
	         * @param {X64Word} word The x64-Word to add with this word.
	         *
	         * @return {X64Word} A new x64-Word object after adding.
	         *
	         * @example
	         *
	         *     var added = x64Word.add(anotherX64Word);
	         */
	        // add: function (word) {
	            // var low = (this.low + word.low) | 0;
	            // var carry = (low >>> 0) < (this.low >>> 0) ? 1 : 0;
	            // var high = (this.high + word.high + carry) | 0;

	            // return X64Word.create(high, low);
	        // }
	    });

	    /**
	     * An array of 64-bit words.
	     *
	     * @property {Array} words The array of CryptoJS.x64.Word objects.
	     * @property {number} sigBytes The number of significant bytes in this word array.
	     */
	    var X64WordArray = C_x64.WordArray = Base.extend({
	        /**
	         * Initializes a newly created word array.
	         *
	         * @param {Array} words (Optional) An array of CryptoJS.x64.Word objects.
	         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.x64.WordArray.create();
	         *
	         *     var wordArray = CryptoJS.x64.WordArray.create([
	         *         CryptoJS.x64.Word.create(0x00010203, 0x04050607),
	         *         CryptoJS.x64.Word.create(0x18191a1b, 0x1c1d1e1f)
	         *     ]);
	         *
	         *     var wordArray = CryptoJS.x64.WordArray.create([
	         *         CryptoJS.x64.Word.create(0x00010203, 0x04050607),
	         *         CryptoJS.x64.Word.create(0x18191a1b, 0x1c1d1e1f)
	         *     ], 10);
	         */
	        init: function (words, sigBytes) {
	            words = this.words = words || [];

	            if (sigBytes != undefined) {
	                this.sigBytes = sigBytes;
	            } else {
	                this.sigBytes = words.length * 8;
	            }
	        },

	        /**
	         * Converts this 64-bit word array to a 32-bit word array.
	         *
	         * @return {CryptoJS.lib.WordArray} This word array's data as a 32-bit word array.
	         *
	         * @example
	         *
	         *     var x32WordArray = x64WordArray.toX32();
	         */
	        toX32: function () {
	            // Shortcuts
	            var x64Words = this.words;
	            var x64WordsLength = x64Words.length;

	            // Convert
	            var x32Words = [];
	            for (var i = 0; i < x64WordsLength; i++) {
	                var x64Word = x64Words[i];
	                x32Words.push(x64Word.high);
	                x32Words.push(x64Word.low);
	            }

	            return X32WordArray.create(x32Words, this.sigBytes);
	        },

	        /**
	         * Creates a copy of this word array.
	         *
	         * @return {X64WordArray} The clone.
	         *
	         * @example
	         *
	         *     var clone = x64WordArray.clone();
	         */
	        clone: function () {
	            var clone = Base.clone.call(this);

	            // Clone "words" array
	            var words = clone.words = this.words.slice(0);

	            // Clone each X64Word object
	            var wordsLength = words.length;
	            for (var i = 0; i < wordsLength; i++) {
	                words[i] = words[i].clone();
	            }

	            return clone;
	        }
	    });
	}());


	return CryptoJS;

}));
},{"./core":3}],35:[function(require,module,exports){
/**
 * flash的应用信息
 */
module.exports = {
   	// domain: 'g-assets.daily.taobao.net',
    domain: 'g.alicdn.com',
    flashVersion: '1.3.2',
    h5Version: '1.7.4',
    logReportTo: '//videocloud.cn-hangzhou.log.aliyuncs.com/logstores/newplayer/track'

};					

},{}],36:[function(require,module,exports){
/** 
 * @fileoverview prismplayer的入口模块
 */

var Player = require('./player/player');
var FlashPlayer = require('./player/flashplayer');
var Dom = require('./lib/dom');
var UA = require('./lib/ua');
var _ = require('./lib/object');
var cfg = require('./config');

var prism = function  (opt) {
	var id = opt.id,
		tag;
	
	//如果是一个字符串，我们就认为是元素的id
	if('string' === typeof id){
		
		// id为#string的情况
		if (id.indexOf('#') === 0) {
			id = id.slice(1);
		}

		// 如果在此id上创建过prismplayer实例，返回该实例
		if (prism.players[id]) {
			return prism.players[id];
		} else {
			tag = Dom.el(id);
		}

	} else {
		//否则就认为是dom 元素
		tag = id;
	}

	if(!tag || !tag.nodeName){
		 throw new TypeError('没有为播放器指定容器');
	}

	var option = _.merge(_.copy(prism.defaultOpt), opt);
	console.log(option);

	//isLive 判断
	if (UA.IS_H5&&opt.isLive) {
		option.skinLayout=[
			{name:"bigPlayButton", align:"blabs", x:30, y:80},
			{
				name:"controlBar", align:"blabs", x:0, y:0,
				children: [
					{name:"liveDisplay", align:"tlabs", x: 15, y:25},
					{name:"fullScreenButton", align:"tr", x:20, y:25},
					{name:"volume", align:"tr", x:20, y:25}
				]
			}
		]
	};

	if (UA.IS_IOS) {
		for(var i=0;i<option.skinLayout.length;i++){
			if(option.skinLayout[i].name=="controlBar"){
				var children=option.skinLayout[i];
				for(var c=0;c<children.children.length;c++){
					if(children.children[c].name=="volume"){
						children.children.splice(c,1);
						break;
					}
				}
			}
		}
	};

	if (option.width) {
		tag.style.width = option.width;
	}
    if (option.height) {
        var per_idx = option.height.indexOf("%");
        if (per_idx > 0)
        {
            var screen_height = window.screen.height;
            var per_value = option.height.replace("%", "");
            if(!isNaN(per_value))
            {
                var scale_value = screen_height * 9 * parseInt(per_value) / 1000;
                tag.style.height = String(scale_value % 2 ? scale_value + 1: scale_value) + "px";
            }
            else
            {
                tag.style.height = option.height;
            }
        }
        else
        {
            tag.style.height = option.height;
        }
    }

	//如果tag已指向一个存在的player，则返回这个player实例
	//否则初始化播放器
	if(tag['player']) {
		console.log(tag['player']);
	}

	return tag['player'] || (UA.IS_H5 ? new Player(tag, option) : new FlashPlayer(tag, option));
	//return new FlashPlayer(tag, option);
			//new Player(tag, option);
}

var prismplayer = window['prismplayer'] = prism;

//全局变量，记录所有的播放器
prism.players = {};

/**
 * 默认的配置项
 */
prism.defaultOpt = {
	preload: false,                     // 是否预加载
	autoplay: true,                    // 是否自动播放
	useNativeControls: false,           // 是否使用默认的控制面板
	width: '100%',                      // 播放器宽度
	height: '300px',                    // 播放器高度
	cover: '',                          // 默认封面图
	from: '',               // 渠道来源
	trackLog: true,                     // 是否需要打点
	waterMark:"",					// swf水印配置 http://taobao.com/wm.swf||BR||11123 以||分割url||对齐方式||参数
	isLive:false,						//是否为直播状态(直播暂时只有flash版本支持)
	/* vid 淘宝视频的视频id，必填 */    // 视频id
    showBarTime:5000,
    rePlay:false,
	skinRes: '//' + cfg.domain + '/de/prismplayer-flash/' + cfg.flashVersion + '/atlas/defaultSkin',  // String, ui皮肤图片地址，非必填，不填使用默认，纯h5播放器可以不考虑这个字段
	skinLayout: [                            // false | Array, 播放器使用的ui组件，非必填，不传使用默认，传false或[]整体隐藏
		{name:"bigPlayButton", align:"blabs", x:30, y:80},
    {name: "H5Loading", align: "cc"},
		{
			name:"controlBar", align:"blabs", x:0, y:0,
			children: [
				{name:"progress", align:"tlabs", x: 0, y:0},
				{name:"playButton", align:"tl", x:15, y:26},
				{name:"nextButton", align:"tl", x:10, y:26},
				{name:"timeDisplay", align:"tl", x:10, y:24},
				{name:"fullScreenButton", align:"tr", x:10, y:25},
				//{name:"setButton", align:"tr", x:0, y:25},
				{name:"streamButton", align:"tr", x:10, y:23},
				{name:"volume", align:"tr", x:10, y:25}
			]
		},
		{
			name:"fullControlBar", align:"tlabs", x:0, y:0,
			children: [
				{name:"fullTitle", align:"tl", x:25, y:6},
				{name:"fullNormalScreenButton", align:"tr", x:24, y:13},
				{name:"fullTimeDisplay", align:"tr", x:10, y:12},
				{name:"fullZoom", align:"cc"}
			]
		}
	]
}

// AMD
if (typeof define === 'function' && define['amd']) {
	  define([], function(){ return prismplayer; });
// commonjs, 支持browserify
} else if (typeof exports === 'object' && typeof module === 'object') {
	  module['exports'] = prismplayer;
}

},{"./config":35,"./lib/dom":39,"./lib/object":44,"./lib/ua":46,"./player/flashplayer":50,"./player/player":51}],37:[function(require,module,exports){
module.exports.get = function(cname) {
	var name = cname + '';
	var ca = document.cookie.split(';');
	for(var i = 0; i < ca.length; i++) {
		var c = ca[i].trim();
		if(c.indexOf(name) == 0) {
			return unescape(c.substring(name.length + 1,c.length));
		}
	}
	return '';
};

module.exports.set = function(cname, cvalue, exdays) {
	var d = new Date();
	d.setTime(d.getTime() + (exdays * 24 * 60 * 60 * 1000));
	var expires = 'expires=' + d.toGMTString();
	document.cookie = cname + '=' + escape(cvalue) + '; ' + expires;
};

},{}],38:[function(require,module,exports){
var _ = require('./object');

/**
 * Element Data Store. Allows for binding data to an element without putting it directly on the element.
 * Ex. Event listneres are stored here.
 * (also from jsninja.com, slightly modified and updated for closure compiler)
 * @type {Object}
 * @private
 */
module.exports.cache = {};

/**
 * Unique ID for an element or function
 * @type {Number}
 * @private
 */
module.exports.guid = function(len, radix) {
	var chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.split('');
	var uuid = [], i;
	radix = radix || chars.length;

	if (len) {
		for (i = 0; i < len; i++) uuid[i] = chars[0 | Math.random()*radix];
	} else {
		var r;
		uuid[8] = uuid[13] = uuid[18] = uuid[23] = '-';
		uuid[14] = '4';
		for (i = 0; i < 36; i++) {
			if (!uuid[i]) {
				r = 0 | Math.random()*16;
				uuid[i] = chars[(i == 19) ? (r & 0x3) | 0x8 : r];
			}
		}
	}

	return uuid.join('');
};

/**
 * Unique attribute name to store an element's guid in
 * @type {String}
 * @constant
 * @private
 */
module.exports.expando = 'vdata' + (new Date()).getTime();

/**
 * Returns the cache object where data for an element is stored
 * @param  {Element} el Element to store data for.
 * @return {Object}
 * @private
 */
module.exports.getData = function(el){
  var id = el[module.exports.expando];
  if (!id) {
    id = el[module.exports.expando] = module.exports.guid();
    module.exports.cache[id] = {};
  }
  return module.exports.cache[id];
};

/**
 * Returns the cache object where data for an element is stored
 * @param  {Element} el Element to store data for.
 * @return {Object}
 * @private
 */
module.exports.hasData = function(el){
  var id = el[module.exports.expando];
  return !(!id || _.isEmpty(module.exports.cache[id]));
};

/**
 * Delete data for the element from the cache and the guid attr from getElementById
 * @param  {Element} el Remove data for an element
 * @private
 */
module.exports.removeData = function(el){
  var id = el[module.exports.expando];
  if (!id) { return; }
  // Remove all stored data
  // Changed to = null
  // http://coding.smashingmagazine.com/2012/11/05/writing-fast-memory-efficient-javascript/
  // module.exports.cache[id] = null;
  delete module.exports.cache[id];

  // Remove the expando property from the DOM node
  try {
    delete el[module.exports.expando];
  } catch(e) {
    if (el.removeAttribute) {
      el.removeAttribute(module.exports.expando);
    } else {
      // IE doesn't appear to support removeAttribute on the document element
      el[module.exports.expando] = null;
    }
  }
};

},{"./object":44}],39:[function(require,module,exports){
/**
 * @fileoverview 封装对dom元素的基本操作
 */

var _ = require('./object');

/**
 * 根据id获取dom
 */
module.exports.el = function(id){
  return document.getElementById(id);
}

/**
 * Creates an element and applies properties.
 * @param  {String=} tagName    Name of tag to be created.
 * @param  {Object=} properties Element properties to be applied.
 * @return {Element}
 * @private
 */
module.exports.createEl = function(tagName, properties){
  var el;

  tagName = tagName || 'div';
  properties = properties || {};

  el = document.createElement(tagName);

  _.each(properties, function(propName, val){
    // Not remembering why we were checking for dash
    // but using setAttribute means you have to use getAttribute

    // The check for dash checks for the aria-* attributes, like aria-label, aria-valuemin.
    // The additional check for "role" is because the default method for adding attributes does not
    // add the attribute "role". My guess is because it's not a valid attribute in some namespaces, although
    // browsers handle the attribute just fine. The W3C allows for aria-* attributes to be used in pre-HTML5 docs.
    // http://www.w3.org/TR/wai-aria-primer/#ariahtml. Using setAttribute gets around this problem.
    if (propName.indexOf('aria-') !== -1 || propName == 'role') {
     el.setAttribute(propName, val);
    } else {
     el[propName] = val;
    }
  });

  return el;
};

/**
 * Add a CSS class name to an element
 * @param {Element} element    Element to add class name to
 * @param {String} classToAdd Classname to add
 * @private
 */
module.exports.addClass = function(element, classToAdd){
  if ((' '+element.className+' ').indexOf(' '+classToAdd+' ') == -1) {
    element.className = element.className === '' ? classToAdd : element.className + ' ' + classToAdd;
  }
};

/**
 * Remove a CSS class name from an element
 * @param {Element} element    Element to remove from class name
 * @param {String} classToAdd Classname to remove
 * @private
 */
module.exports.removeClass = function(element, classToRemove){
  var classNames, i;

  if (element.className.indexOf(classToRemove) == -1) { return; }

  classNames = element.className.split(' ');

  // no arr.indexOf in ie8, and we don't want to add a big shim
  for (i = classNames.length - 1; i >= 0; i--) {
    if (classNames[i] === classToRemove) {
      classNames.splice(i,1);
    }
  }

  element.className = classNames.join(' ');
};

/**
 *
 */
module.exports.getElementAttributes = function(tag){
  var obj, knownBooleans, attrs, attrName, attrVal;

  obj = {};

  // known boolean attributes
  // we can check for matching boolean properties, but older browsers
  // won't know about HTML5 boolean attributes that we still read from
  knownBooleans = ','+'autoplay,controls,loop,muted,default'+',';

  if (tag && tag.attributes && tag.attributes.length > 0) {
    attrs = tag.attributes;

    for (var i = attrs.length - 1; i >= 0; i--) {
      attrName = attrs[i].name;
      attrVal = attrs[i].value;

      // check for known booleans
      // the matching element property will return a value for typeof
      if (typeof tag[attrName] === 'boolean' || knownBooleans.indexOf(','+attrName+',') !== -1) {
        // the value of an included boolean attribute is typically an empty
        // string ('') which would equal false if we just check for a false value.
        // we also don't want support bad code like autoplay='false'
        attrVal = (attrVal !== null) ? true : false;
      }

      obj[attrName] = attrVal;
    }
  }

  return obj;
};
/*

*/
module.exports.insertFirst = function(child, parent){
  if (parent.firstChild) {
    parent.insertBefore(child, parent.firstChild);
  } else {
    parent.appendChild(child);
  }
};

// Attempt to block the ability to select text while dragging controls
module.exports.blockTextSelection = function(){
  document.body.focus();
  document.onselectstart = function () { return false; };
};
// Turn off text selection blocking
module.exports.unblockTextSelection = function(){ document.onselectstart = function () { return true; }; };

/**
 * 设置或获取css属性
 */
module.exports.css = function(el, cssName, cssVal) {
	if (!el.style) return false;
	
	if (cssName && cssVal) {
		el.style[cssName] = cssVal;
		return true;
	
	} else if (!cssVal && typeof cssName === 'string') {
		return el.style[cssName];
	
	} else if (!cssVal && typeof cssName === 'object') {
		_.each(cssName, function(k, v) {
			el.style[k] = v;
		});
		return true;
	}

	return false;
};



},{"./object":44}],40:[function(require,module,exports){
var _ = require('./object');
var Data = require('./data');

/**
 * @fileoverview Event System (John Resig - Secrets of a JS Ninja http://jsninja.com/)
 * (Original book version wasn't completely usable, so fixed some things and made Closure Compiler compatible)
 * This should work very similarly to jQuery's events, however it's based off the book version which isn't as
 * robust as jquery's, so there's probably some differences.
 */

/**
 * Add an event listener to element
 * It stores the handler function in a separate cache object
 * and adds a generic handler to the element's event,
 * along with a unique id (guid) to the element.
 * @param  {Element|Object}   elem Element or object to bind listeners to
 * @param  {String|Array}   type Type of event to bind to.
 * @param  {Function} fn   Event listener.
 * @private
 */
module.exports.on = function(elem, type, fn){
  if (_.isArray(type)) {
    return _handleMultipleEvents(module.exports.on, elem, type, fn);
  }

  var data = Data.getData(elem);

  // We need a place to store all our handler data
  if (!data.handlers) data.handlers = {};

  if (!data.handlers[type]) data.handlers[type] = [];

  if (!fn.guid) fn.guid = Data.guid();

  data.handlers[type].push(fn);

  if (!data.dispatcher) {
    data.disabled = false;

    data.dispatcher = function (event){

      if (data.disabled) return;
      event = module.exports.fixEvent(event);

      var handlers = data.handlers[event.type];

      if (handlers) {
        // Copy handlers so if handlers are added/removed during the process it doesn't throw everything off.
        var handlersCopy = handlers.slice(0);

        for (var m = 0, n = handlersCopy.length; m < n; m++) {
          if (event.isImmediatePropagationStopped()) {
            break;
          } else {
            handlersCopy[m].call(elem, event);
          }
        }
      }
    };
  }

  if (data.handlers[type].length == 1) {
    if (elem.addEventListener) {
      elem.addEventListener(type, data.dispatcher, false);
    } else if (elem.attachEvent) {
      elem.attachEvent('on' + type, data.dispatcher);
    }
  }
};

/**
 * Removes event listeners from an element
 * @param  {Element|Object}   elem Object to remove listeners from
 * @param  {String|Array=}   type Type of listener to remove. Don't include to remove all events from element.
 * @param  {Function} fn   Specific listener to remove. Don't incldue to remove listeners for an event type.
 * @private
 */
module.exports.off = function(elem, type, fn) {
  // Don't want to add a cache object through getData if not needed
  if (!Data.hasData(elem)) return;

  var data = Data.getData(elem);

  // If no events exist, nothing to unbind
  if (!data.handlers) { return; }

  if (_.isArray(type)) {
    return _handleMultipleEvents(module.exports.off, elem, type, fn);
  }

  // Utility function
  var removeType = function(t){
     data.handlers[t] = [];
     module.exports.cleanUpEvents(elem,t);
  };

  // Are we removing all bound events?
  if (!type) {
    for (var t in data.handlers) removeType(t);
    return;
  }

  var handlers = data.handlers[type];

  // If no handlers exist, nothing to unbind
  if (!handlers) return;

  // If no listener was provided, remove all listeners for type
  if (!fn) {
    removeType(type);
    return;
  }

  // We're only removing a single handler
  if (fn.guid) {
    for (var n = 0; n < handlers.length; n++) {
      if (handlers[n].guid === fn.guid) {
        handlers.splice(n--, 1);
      }
    }
  }

  module.exports.cleanUpEvents(elem, type);
};

/**
 * Clean up the listener cache and dispatchers
 * @param  {Element|Object} elem Element to clean up
 * @param  {String} type Type of event to clean up
 * @private
 */
module.exports.cleanUpEvents = function(elem, type) {
  var data = Data.getData(elem);

  // Remove the events of a particular type if there are none left
  if (data.handlers[type].length === 0) {
    delete data.handlers[type];
    // data.handlers[type] = null;
    // Setting to null was causing an error with data.handlers

    // Remove the meta-handler from the element
    if (elem.removeEventListener) {
      elem.removeEventListener(type, data.dispatcher, false);
    } else if (elem.detachEvent) {
      elem.detachEvent('on' + type, data.dispatcher);
    }
  }

  // Remove the events object if there are no types left
  if (_.isEmpty(data.handlers)) {
    delete data.handlers;
    delete data.dispatcher;
    delete data.disabled;

    // data.handlers = null;
    // data.dispatcher = null;
    // data.disabled = null;
  }

  // Finally remove the expando if there is no data left
  if (_.isEmpty(data)) {
    Data.removeData(elem);
  }
};

/**
 * Fix a native event to have standard property values
 * @param  {Object} event Event object to fix
 * @return {Object}
 * @private
 */
module.exports.fixEvent = function(event) {

  function returnTrue() { return true; }
  function returnFalse() { return false; }

  // Test if fixing up is needed
  // Used to check if !event.stopPropagation instead of isPropagationStopped
  // But native events return true for stopPropagation, but don't have
  // other expected methods like isPropagationStopped. Seems to be a problem
  // with the Javascript Ninja code. So we're just overriding all events now.
  if (!event || !event.isPropagationStopped) {
    var old = event || window.event;

    event = {};
    // Clone the old object so that we can modify the values event = {};
    // IE8 Doesn't like when you mess with native event properties
    // Firefox returns false for event.hasOwnProperty('type') and other props
    //  which makes copying more difficult.
    // TODO: Probably best to create a whitelist of event props
    for (var key in old) {
      // Safari 6.0.3 warns you if you try to copy deprecated layerX/Y
      // Chrome warns you if you try to copy deprecated keyboardEvent.keyLocation
      if (key !== 'layerX' && key !== 'layerY' && key !== 'keyboardEvent.keyLocation') {
        // Chrome 32+ warns if you try to copy deprecated returnValue, but
        // we still want to if preventDefault isn't supported (IE8).
        if (!(key == 'returnValue' && old.preventDefault)) {
          event[key] = old[key];
        }
      }
    }

    // The event occurred on this element
    if (!event.target) {
      event.target = event.srcElement || document;
    }

    // Handle which other element the event is related to
    event.relatedTarget = event.fromElement === event.target ?
      event.toElement :
      event.fromElement;

    // Stop the default browser action
    event.preventDefault = function () {
      if (old.preventDefault) {
        old.preventDefault();
      }
      event.returnValue = false;
      event.isDefaultPrevented = returnTrue;
      event.defaultPrevented = true;
    };

    event.isDefaultPrevented = returnFalse;
    event.defaultPrevented = false;

    // Stop the event from bubbling
    event.stopPropagation = function () {
      if (old.stopPropagation) {
        old.stopPropagation();
      }
      event.cancelBubble = true;
      event.isPropagationStopped = returnTrue;
    };

    event.isPropagationStopped = returnFalse;

    // Stop the event from bubbling and executing other handlers
    event.stopImmediatePropagation = function () {
      if (old.stopImmediatePropagation) {
        old.stopImmediatePropagation();
      }
      event.isImmediatePropagationStopped = returnTrue;
      event.stopPropagation();
    };

    event.isImmediatePropagationStopped = returnFalse;

    // Handle mouse position
    if (event.clientX != null) {
      var doc = document.documentElement, body = document.body;

      event.pageX = event.clientX +
        (doc && doc.scrollLeft || body && body.scrollLeft || 0) -
        (doc && doc.clientLeft || body && body.clientLeft || 0);
      event.pageY = event.clientY +
        (doc && doc.scrollTop || body && body.scrollTop || 0) -
        (doc && doc.clientTop || body && body.clientTop || 0);
    }

    // Handle key presses
    event.which = event.charCode || event.keyCode;

    // Fix button for mouse clicks:
    // 0 == left; 1 == middle; 2 == right
    if (event.button != null) {
      event.button = (event.button & 1 ? 0 :
        (event.button & 4 ? 1 :
          (event.button & 2 ? 2 : 0)));
    }
  }

  // Returns fixed-up instance
  return event;
};

/**
 * Trigger an event for an element
 * @param  {Element|Object}      elem  Element to trigger an event on
 * @param  {Event|Object|String} event A string (the type) or an event object with a type attribute
 * @private
 */
module.exports.trigger = function(elem, event) {
  // Fetches element data and a reference to the parent (for bubbling).
  // Don't want to add a data object to cache for every parent,
  // so checking hasData first.

  var elemData = (Data.hasData(elem)) ? Data.getData(elem) : {};
  var parent = elem.parentNode || elem.ownerDocument;
      // type = event.type || event,
      // handler;

  // If an event name was passed as a string, creates an event out of it
  if (typeof event === 'string') {
    var paramData = null;
    if(elem.paramData){
      paramData = elem.paramData;
      elem.paramData = null;
      elem.removeAttribute(paramData);
    }
    event = { type:event, target:elem, paramData:paramData };
  }
  // Normalizes the event properties.
  event = module.exports.fixEvent(event);

  // If the passed element has a dispatcher, executes the established handlers.
  if (elemData.dispatcher) {
    elemData.dispatcher.call(elem, event);
  }

  // Unless explicitly stopped or the event does not bubble (e.g. media events)
    // recursively calls this function to bubble the event up the DOM.
  if (parent && !event.isPropagationStopped() && event.bubbles !== false) {
    module.exports.trigger(parent, event);

  // If at the top of the DOM, triggers the default action unless disabled.
  } else if (!parent && !event.defaultPrevented) {
    var targetData = Data.getData(event.target);

    // Checks if the target has a default action for this event.
    if (event.target[event.type]) {
      // Temporarily disables event dispatching on the target as we have already executed the handler.
      targetData.disabled = true;
      // Executes the default action.
      if (typeof event.target[event.type] === 'function') {
        event.target[event.type]();
      }
      // Re-enables event dispatching.
      targetData.disabled = false;
    }
  }

  // Inform the triggerer if the default was prevented by returning false
  return !event.defaultPrevented;
};

/**
 * Trigger a listener only once for an event
 * @param  {Element|Object}   elem Element or object to
 * @param  {String|Array}   type
 * @param  {Function} fn
 * @private
 */
module.exports.one = function(elem, type, fn) {
  if (_.isArray(type)) {
    return _handleMultipleEvents(module.exports.one, elem, type, fn);
  }
  var func = function(){
    module.exports.off(elem, type, func);
    fn.apply(this, arguments);
  };
  // copy the guid to the new function so it can removed using the original function's ID
  func.guid = fn.guid = fn.guid || Data.guid();
  module.exports.on(elem, type, func);
};

/**
 * Loops through an array of event types and calls the requested method for each type.
 * @param  {Function} fn   The event method we want to use.
 * @param  {Element|Object} elem Element or object to bind listeners to
 * @param  {String}   type Type of event to bind to.
 * @param  {Function} callback   Event listener.
 * @private
 */
function _handleMultipleEvents(fn, elem, type, callback) {
  _.each(type, function(type) {
    fn(elem, type, callback); //Call the event method for each one of the types
  });
}

},{"./data":38,"./object":44}],41:[function(require,module,exports){
var Data = require('./data');

module.exports.bind = function(context, fn, uid) {
  // Make sure the function has a unique ID
  if (!fn.guid) { fn.guid = Data.guid(); }

  // Create the new function that changes the context
  var ret = function() {
    return fn.apply(context, arguments);
  };

  // Allow for the ability to individualize this function
  // Needed in the case where multiple objects might share the same prototype
  // IF both items add an event listener with the same function, then you try to remove just one
  // it will remove both because they both have the same guid.
  // when using this, you need to use the bind method when you remove the listener as well.
  // currently used in text tracks
  ret.guid = (uid) ? uid + '_' + fn.guid : fn.guid;

  return ret;
};

},{"./data":38}],42:[function(require,module,exports){
var Url = require('./url');

/**
 * Simple http request for retrieving external files (e.g. text tracks)
 * @param  {String}    url             URL of resource
 * @param  {Function} onSuccess       Success callback
 * @param  {Function=} onError         Error callback
 * @param  {Boolean=}   withCredentials Flag which allow credentials
 * @private
 */
module.exports.get = function(url, onSuccess, onError, withCredentials){
  var fileUrl, request, urlInfo, winLoc, crossOrigin;

  onError = onError || function(){};

  if (typeof XMLHttpRequest === 'undefined') {
    // Shim XMLHttpRequest for older IEs
    window.XMLHttpRequest = function () {
      try { return new window.ActiveXObject('Msxml2.XMLHTTP.6.0'); } catch (e) {}
      try { return new window.ActiveXObject('Msxml2.XMLHTTP.3.0'); } catch (f) {}
      try { return new window.ActiveXObject('Msxml2.XMLHTTP'); } catch (g) {}
      throw new Error('This browser does not support XMLHttpRequest.');
    };
  }

  request = new XMLHttpRequest();

  urlInfo = Url.parseUrl(url);
  winLoc = window.location;
  // check if url is for another domain/origin
  // ie8 doesn't know location.origin, so we won't rely on it here
  crossOrigin = (urlInfo.protocol + urlInfo.host) !== (winLoc.protocol + winLoc.host);

  // Use XDomainRequest for IE if XMLHTTPRequest2 isn't available
  // 'withCredentials' is only available in XMLHTTPRequest2
  // Also XDomainRequest has a lot of gotchas, so only use if cross domain
  if(crossOrigin && window.XDomainRequest && !('withCredentials' in request)) {
    request = new window.XDomainRequest();
    request.onload = function() {
      onSuccess(request.responseText);
    };
    request.onerror = onError;
    // these blank handlers need to be set to fix ie9 http://cypressnorth.com/programming/internet-explorer-aborting-ajax-requests-fixed/
    request.onprogress = function() {};
    request.ontimeout = onError;

  // XMLHTTPRequest
  } else {
    fileUrl = (urlInfo.protocol == 'file:' || winLoc.protocol == 'file:');

    request.onreadystatechange = function() {
      if (request.readyState === 4) {
        if (request.status === 200 || fileUrl && request.status === 0) {
          onSuccess(request.responseText);
        } else {
          onError(request.responseText);
        }
      }
    };
  }

  // open the connection
  try {
    // Third arg is async, or ignored by XDomainRequest
    request.open('GET', url, true);
    // withCredentials only supported by XMLHttpRequest2
    if(withCredentials) {
      request.withCredentials = true;
    }
  } catch(e) {
    onError(e);
    return;
  }

  // send the request
  try {
    request.send();
  } catch(e) {
    onError(e);
  }
};

/**
 * jsonp请求
 */
module.exports.jsonp = function(url, onSuccess, onError) {
	var callbackName = 'jsonp_callback_' + Math.round(100000 * Math.random());
	var script = document.createElement('script');
	
	script.src = url + (url.indexOf('?') >= 0 ? '&' : '?') + 'callback=' + callbackName;
	script.onerror = function() {
		delete window[callbackName];
		document.body.removeChild(script);
		onError();
	};
	// 防止接口返回不支持jsonp时的script标签堆积
	script.onload = function() {
		setTimeout(function() {
			if (window[callbackName]) {
				delete window[callbackName];
				document.body.removeChild(script);
			}
		}, 0);
	};
	
	window[callbackName] = function(data) {
		delete window[callbackName];
		document.body.removeChild(script);
		onSuccess(data);
	};
	
	document.body.appendChild(script);
}

},{"./url":47}],43:[function(require,module,exports){
/**
 * @fileoverview 根据配置渲染ui组件在父级组件中的layout
 * @author 首作<aloysious.ld@taobao.com>
 * @date 2015-01-12
 *
 * ui组件与layout相关的配置项
 * align {String}   'cc'  绝对居中
 *                | 'tl'  左上对齐，组件向左浮动，并以左上角作为偏移原点
 *                | 'tr'  右上对齐，组件向右浮动，并以右上角作为偏移原点
 *                | 'tlabs' 以左上角偏移，相对于父级组件绝对定位，不受同级组件的占位影响
 *                | 'trabs' 以右上角偏移，相对于父级组件绝对定位，不受同级组件的占位影响
 *                | 'blabs' 以左下角偏移，相对于父级组件绝对定位，不受同级组件的占位影响
 *                | 'brabs' 以右下角偏移，相对于父级组件绝对定位，不受同级组件的占位影响
 * x     {Number} x轴的偏移量，align为'cc'时无效
 * y     {Number} y轴的偏移量，align为'cc'时无效
 */

var Dom = require('./dom');

/**
 * 根据配置渲染dom元素的layout
 * @param el  {HTMLElement} dom元素
 * @param opt {Object}      layout配置对象
 */
module.exports.render = function(el, opt) {
	var align = opt.align ? opt.align : 'tl',
		x = opt.x ? opt.x : 0,
		y = opt.y ? opt.y : 0;

	if (align === 'tl') {
		Dom.css(el, {
			'float': 'left',
			'margin-left': x + 'px',
			'margin-top': y+ 'px'
		});
	
	} else if (align === 'tr') {
		Dom.css(el, {
			'float': 'right',
			'margin-right': x + 'px',
			'margin-top': y+ 'px'
		});
	
	} else if (align === 'tlabs') {
		Dom.css(el, {
			'position': 'absolute',
			'left': x + 'px',
			'top': y + 'px'
		});
	
	} else if (align === 'trabs') {
		Dom.css(el, {
			'position': 'absolute',
			'right': x + 'px',
			'top': y + 'px'
		});
	
	} else if (align === 'blabs') {
		Dom.css(el, {
			'position': 'absolute',
			'left': x + 'px',
			'bottom': y + 'px'
		});
	
	} else if (align === 'brabs') {
		Dom.css(el, {
			'position': 'absolute',
			'right': x + 'px',
			'bottom': y + 'px'
		});

	} else if (align === 'cc') {
		Dom.css(el, {
			'position': 'absolute',
			'left': '50%',
			'top': '50%',
			'margin-top': ( el.offsetHeight / -2 ) + 'px',
			'margin-left': ( el.offsetWidth / -2 ) + 'px'
		});
	}
};

},{"./dom":39}],44:[function(require,module,exports){
var hasOwnProp = Object.prototype.hasOwnProperty;
/**
 * Object.create shim for prototypal inheritance
 *
 * https://developer.mozilla.org/en-US/docs/JavaScript/Reference/Global_Objects/Object/create
 *
 * @function
 * @param  {Object}   obj Object to use as prototype
 * @private
 */
module.exports.create = Object.create || function(obj){
  //Create a new function called 'F' which is just an empty object.
  function F() {}

  //the prototype of the 'F' function should point to the
  //parameter of the anonymous function.
  F.prototype = obj;

  //create a new constructor function based off of the 'F' function.
  return new F();
};

/**
 * Loop through each property in an object and call a function
 * whose arguments are (key,value)
 * @param  {Object}   obj Object of properties
 * @param  {Function} fn  Function to be called on each property.
 * @this {*}
 * @private
 */

module.exports.isArray = function(arr){
  return Object.prototype.toString.call(arg) === '[object Array]';
}

module.exports.isEmpty = function(obj) {
  for (var prop in obj) {
    // Inlude null properties as empty.
    if (obj[prop] !== null) {
      return false;
    }
  }
  return true;
};


module.exports.each = function(obj, fn, context){
  //
  if(module.exports.isArray(obj)){
    for (var i = 0, len = obj.length; i < len; ++i) {
      if (fn.call(context || this, obj[i], i) === false) {
	  	break;
	  }
    }
  }else{
     for (var key in obj) {
      if (hasOwnProp.call(obj, key)) {
        // if (key=="code") {
        //   console.log(obj);
        // };
        // console.log(key);
        // console.log(obj[key]);
        if (fn.call(context || this, key, obj[key]) === false) {
			break;
		}
      }
     }   
  }

  return obj;
};

/**
 * Merge two objects together and return the original.
 * @param  {Object} obj1
 * @param  {Object} obj2
 * @return {Object}
 * @private
 */
module.exports.merge = function(obj1, obj2){
  if (!obj2) { return obj1; }
  for (var key in obj2){
    if (hasOwnProp.call(obj2, key)) {
      obj1[key] = obj2[key];
    }
  }
  return obj1;
};

/**
 * Merge two objects, and merge any properties that are objects
 * instead of just overwriting one. Uses to merge options hashes
 * where deeper default settings are important.
 * @param  {Object} obj1 Object to override
 * @param  {Object} obj2 Overriding object
 * @return {Object}      New object. Obj1 and Obj2 will be untouched.
 * @private
 */
module.exports.deepMerge = function(obj1, obj2){
  var key, val1, val2;

  // make a copy of obj1 so we're not ovewriting original values.
  // like prototype.options_ and all sub options objects
  obj1 = module.exports.copy(obj1);

  for (key in obj2){
    if (hasOwnProp.call(obj2, key)) {
      val1 = obj1[key];
      val2 = obj2[key];

      // Check if both properties are pure objects and do a deep merge if so
      if (module.exports.isPlain(val1) && module.exports.isPlain(val2)) {
        obj1[key] = module.exports.deepMerge(val1, val2);
      } else {
        obj1[key] = obj2[key];
      }
    }
  }
  return obj1;
};

/**
 * Make a copy of the supplied object
 * @param  {Object} obj Object to copy
 * @return {Object}     Copy of object
 * @private
 */
module.exports.copy = function(obj){
  return module.exports.merge({}, obj);
};

/**
 * Check if an object is plain, and not a dom node or any object sub-instance
 * @param  {Object} obj Object to check
 * @return {Boolean}     True if plain, false otherwise
 * @private
 */
module.exports.isPlain = function(obj){
  return !!obj
    && typeof obj === 'object'
    && obj.toString() === '[object Object]'
    && obj.constructor === Object;
};

/**
 * Check if an object is Array
*  Since instanceof Array will not work on arrays created in another frame we need to use Array.isArray, but since IE8 does not support Array.isArray we need this shim
 * @param  {Object} obj Object to check
 * @return {Boolean}     True if plain, false otherwise
 * @private
 */
module.exports.isArray = Array.isArray || function(arr) {
  return Object.prototype.toString.call(arr) === '[object Array]';
};

module.exports.unescape = function(str) {
	return str.replace(/&([^;]+);/g, function(m,$1) {
		return {
			'amp': '&',
			'lt': '<',
		   	'gt': '>',
		   	'quot': '"',
		   	'#x27': "'",
		   	'#x60': '`'
		}[$1.toLowerCase()] || m;
	});
};

},{}],45:[function(require,module,exports){
var _ = require('./object');

var oo = function(){};
// Manually exporting module.exports['oo'] here for Closure Compiler
// because of the use of the extend/create class methods
// If we didn't do this, those functions would get flattend to something like
// `a = ...` and `this.prototype` would refer to the global object instead of
// oo

var oo = function() {};
/**
 * Create a new object that inherits from this Object
 *
 *     var Animal = oo.extend();
 *     var Horse = Animal.extend();
 *
 * @param {Object} props Functions and properties to be applied to the
 *                       new object's prototype
 * @return {module.exports.oo} An object that inherits from oo
 * @this {*}
 */
oo.extend = function(props){
  var init, subObj;

  props = props || {};
  // Set up the constructor using the supplied init method
  // or using the init of the parent object
  // Make sure to check the unobfuscated version for external libs
  init = props['init'] || props.init || this.prototype['init'] || this.prototype.init || function(){};
  // In Resig's simple class inheritance (previously used) the constructor
  //  is a function that calls `this.init.apply(arguments)`
  // However that would prevent us from using `ParentObject.call(this);`
  //  in a Child constuctor because the `this` in `this.init`
  //  would still refer to the Child and cause an inifinite loop.
  // We would instead have to do
  //    `ParentObject.prototype.init.apply(this, argumnents);`
  //  Bleh. We're not creating a _super() function, so it's good to keep
  //  the parent constructor reference simple.
  subObj = function(){
    init.apply(this, arguments);
  };

  // Inherit from this object's prototype
  subObj.prototype = _.create(this.prototype);
  // Reset the constructor property for subObj otherwise
  // instances of subObj would have the constructor of the parent Object
  subObj.prototype.constructor = subObj;

  // Make the class extendable
  subObj.extend = oo.extend;
  // Make a function for creating instances
  subObj.create = oo.create;

  // Extend subObj's prototype with functions and other properties from props
  for (var name in props) {
    if (props.hasOwnProperty(name)) {
      subObj.prototype[name] = props[name];
    }
  }

  return subObj;
};

/**
 * Create a new instace of this Object class
 *
 *     var myAnimal = Animal.create();
 *
 * @return {module.exports.oo} An instance of a oo subclass
 * @this {*}
 */
oo.create = function(){
  // Create a new object that inherits from this object's prototype
  var inst = _.create(this.prototype);

  // Apply this constructor function to the new object
  this.apply(inst, arguments);

  // Return the new object
  return inst;
};

module.exports = oo;

},{"./object":44}],46:[function(require,module,exports){
module.exports.USER_AGENT = navigator.userAgent;

/**
 * Device is an iPhone
 * @type {Boolean}
 * @constant
 * @private
 */
module.exports.IS_IPHONE = (/iPhone/i).test(module.exports.USER_AGENT);
module.exports.IS_IPAD = (/iPad/i).test(module.exports.USER_AGENT);
module.exports.IS_IPOD = (/iPod/i).test(module.exports.USER_AGENT);
module.exports.IS_MAC = (/mac/i).test(module.exports.USER_AGENT);
module.exports.IS_SAFARI = (/Safari/i).test(module.exports.USER_AGENT);
module.exports.IS_CHROME = (/Chrome/i).test(module.exports.USER_AGENT);
module.exports.IS_FIREFOX = (/Firefox/i).test(module.exports.USER_AGENT);


if(document.all){  // IE
    var swf = new ActiveXObject('ShockwaveFlash.ShockwaveFlash');  
    if (swf){
        module.exports.HAS_FLASH = true;
    } else {
        module.exports.HAS_FLASH = false;
    }
} else {  // others
    if (navigator.plugins && navigator.plugins.length > 0) {
        var swf = navigator.plugins["Shockwave Flash"];
        if (swf) {
            module.exports.HAS_FLASH = true;
        } else {
            module.exports.HAS_FLASH = false;
        }
    } else {
         module.exports.HAS_FLASH = false;
    }
}

module.exports.IS_MAC_SAFARI = module.exports.IS_MAC && module.exports.IS_SAFARI && (!module.exports.IS_CHROME) && (!module.exports.HAS_FLASH);
module.exports.IS_IOS = module.exports.IS_IPHONE || module.exports.IS_IPAD || module.exports.IS_IPOD || module.exports.IS_MAC_SAFARI;

module.exports.IOS_VERSION = (function(){
  var match = module.exports.USER_AGENT.match(/OS (\d+)_/i);
  if (match && match[1]) { return match[1]; }
})();

module.exports.IS_ANDROID = (/Android/i).test(module.exports.USER_AGENT);
module.exports.ANDROID_VERSION = (function() {
  // This matches Android Major.Minor.Patch versions
  // ANDROID_VERSION is Major.Minor as a Number, if Minor isn't available, then only Major is returned
  var match = module.exports.USER_AGENT.match(/Android (\d+)(?:\.(\d+))?(?:\.(\d+))*/i),
    major,
    minor;

  if (!match) {
    return null;
  }

  major = match[1] && parseFloat(match[1]);
  minor = match[2] && parseFloat(match[2]);

  if (major && minor) {
    return parseFloat(match[1] + '.' + match[2]);
  } else if (major) {
    return major;
  } else {
    return null;
  }
})();
// Old Android is defined as Version older than 2.3, and requiring a webkit version of the android browser
module.exports.IS_OLD_ANDROID = module.exports.IS_ANDROID && (/webkit/i).test(module.exports.USER_AGENT) && module.exports.ANDROID_VERSION < 2.3;

module.exports.TOUCH_ENABLED = !!(('ontouchstart' in window) || window.DocumentTouch && document instanceof window.DocumentTouch);

module.exports.IS_MOBILE = module.exports.IS_IOS || module.exports.IS_ANDROID;
module.exports.IS_H5 = module.exports.IS_MOBILE || !module.exports.HAS_FLASH;
module.exports.IS_PC = !module.exports.IS_H5;




},{}],47:[function(require,module,exports){
var Dom = require('./dom');

/**
 * Get abosolute version of relative URL. Used to tell flash correct URL.
 * http://stackoverflow.com/questions/470832/getting-an-absolute-url-from-a-relative-one-ie6-issue
 * @param  {String} url URL to make absolute
 * @return {String}     Absolute URL
 * @private
 */
module.exports.getAbsoluteURL = function(url){

  // Check if absolute URL
  if (!url.match(/^https?:\/\//)) {
    // Convert to absolute URL. Flash hosted off-site needs an absolute URL.
    url = Dom.createEl('div', {
      innerHTML: '<a href="'+url+'">x</a>'
    }).firstChild.href;
  }

  return url;
};


/**
 * Resolve and parse the elements of a URL
 * @param  {String} url The url to parse
 * @return {Object}     An object of url details
 */
module.exports.parseUrl = function(url) {
  var div, a, addToBody, props, details;

  props = ['protocol', 'hostname', 'port', 'pathname', 'search', 'hash', 'host'];

  // add the url to an anchor and let the browser parse the URL
  a = Dom.createEl('a', { href: url });

  // IE8 (and 9?) Fix
  // ie8 doesn't parse the URL correctly until the anchor is actually
  // added to the body, and an innerHTML is needed to trigger the parsing
  addToBody = (a.host === '' && a.protocol !== 'file:');
  if (addToBody) {
    div = Dom.createEl('div');
    div.innerHTML = '<a href="'+url+'"></a>';
    a = div.firstChild;
    // prevent the div from affecting layout
    div.setAttribute('style', 'display:none; position:absolute;');
    document.body.appendChild(div);
  }

  // Copy the specific URL properties to a new object
  // This is also needed for IE8 because the anchor loses its
  // properties when it's removed from the dom
  details = {};
  for (var i = 0; i < props.length; i++) {
    details[props[i]] = a[props[i]];
  }

  if (addToBody) {
    document.body.removeChild(div);
  }

  return details;
};

},{"./dom":39}],48:[function(require,module,exports){
// 将秒格式化为00:00:00格式
module.exports.formatTime = function(seconds) {
	var raw = Math.round(seconds),
	hour,
	min,
	sec;

	hour = Math.floor(raw / 3600);
	raw = raw % 3600;
	min = Math.floor(raw / 60);
	sec = raw % 60;

	if (hour === Infinity || isNaN(hour)
		|| min === Infinity || isNaN(min)
		|| sec === Infinity || isNaN(sec)) {
		return false;
	}

	hour = hour >= 10 ? hour: '0' + hour;
	min = min >= 10 ? min: '0' + min;
	sec = sec >= 10 ? sec: '0' + sec;

	return (hour === '00' ? '': (hour + ':')) + min + ':' + sec;
},

// 将00:00:00格式解析为秒
module.exports.parseTime = function(timeStr) {
	var timeArr = timeStr.split(':'),
	h = 0,
	m = 0,
	s = 0;

	if (timeArr.length === 3) {
		h = timeArr[0];
		m = timeArr[1];
		s = timeArr[2];
	} else if (timeArr.length === 2) {
		m = timeArr[0];
		s = timeArr[1];
	} else if (timeArr.length === 1) {
		s = timeArr[0];
	}

	h = parseInt(h, 10);
	m = parseInt(m, 10);
	// 秒可能有小数位，需要向上取整
	s = Math.ceil(parseFloat(s));

	return h * 3600 + m * 60 + s;
}

},{}],49:[function(require,module,exports){
var oo = require('../lib/oo');
var _ = require('../lib/object');
var Cookie = require('../lib/cookie');
var Data = require('../lib/data');
var IO = require('../lib/io');
var UA = require('../lib/ua');
var CONF = require('../config');

var updateTime = 0;

var EVENT = {
    'INIT':             1001,  // 初始化
    'CLOSE':            1002,  // 关闭播放器
    'PLAY':             2001,  // 开始播放
    'STOP':             2002,  // 停止，h5下指播放完毕
    'PAUSE':            2003,  // 暂停
    'RECOVER':          2010,  // 暂停恢复
    'SEEK':             2004,  // 拖动
    'SEEK_END':         2011,  // 拖动结束，h5暂时不实现
    'FULLSREEM':        2005,  // 全屏
    'QUITFULLSCREEM':   2006,  // 退出全屏
    'UNDERLOAD':        3002,  // 卡顿
    'LOADED':           3001,  // 卡顿恢复
    'RESOLUTION':       2007,  // 切换清晰度，h5暂时不实现
    'RESOLUTION_DONE':  2009,  // 切换清晰度完成，h5暂时不实现
    'HEARTBEAT':        9001,  // 心跳，5秒间隔。  20170425 -- 30秒
    'ERROR':            4001   // 发生错误
};

//实时监测id
var checkIntervalInt;

var Monitor = oo.extend({
    /**
     * @param player  {Player} 播放器实例
     * @param options {Object} 监控的配置参数
     *     - lv      (log_version)     日志版本，初始版本为1
     *     - b       (bussiness_id)    业务方id, 初始为prism_aliyun, 输入参数from
     *     - lm      (live_mode)       直播点播区分：prism_live,prism_vod
     *     - t       (terminal_type)   终端类型
     *     - pv      (player_version)  播放器版本号，1
     *     - uuid    (uuid)            设备或机器id，h5保存在cookie中
     *     - v       (video_id)        视频id
     *     - u       (user_id)         用户id
     *     - s       (session_id)      播放行为id，一个视频正常播放后需要重置（动态生成）
     *     - e       (event_id)        事件id（动态生成）
     *     - args    (args)            事件携带参数
     *     - d       (definition)      清晰度
     *     - cdn_ip  (cdn_ip)          下载数据的cdn地址，h5无法设置host，这个字段无用，写死为0.0.0.0
     *     - ct      (client_timestamp) 客户端事件戳
     */

     /**
     * 2017-04-18 日志改版
     * @param player  {Player} 播放器实例
     * @param options {Object} 监控的配置参数
     *     - t       (time)             时间戳，毫秒级
     *     - ll      (log_level)        日志级别
     *     - lv      (log_version)      日志版本，初始版本为1
     *     - pd      (product)          player,pusher,mixer
     *     - md      (module)           saas,paas,mixer,publisher
     *     - hn      (hostname)         ip地址
     *     - bi      (business_id)      阿里云账号
     *     - ri      (session_id)       uuid
     *     - e       (event_id)         事件id（动态生成）
     *     - args    (args)             事件携带参数
     *     - vt      (video_type)       直播点播区分：prism_live,prism_vod
     *     - tt      (terminal_type)    终端类型
     *     - dm      (device_model)     设备型号
     *     - av      (app_version)      播放器版本号
     *     - uuid    (uuid)             设备或机器id，h5保存在cookie中
     *     - vu      (video_url)        推流或播放url，为避免url中有&等特殊字符，编码前要做urlencode
     *     - ua       (user_id)         用户id
     *     - dn       (definition)      清晰度
     *     - cdn_ip  (cdn_ip)           下载数据的cdn地址，h5无法设置host，这个字段无用，写死为0.0.0.0
     *     - r  (referer)               来源网站和链接信息
     */




    init: function(player, options) {
        this.player = player;
        var po=this.player.getOptions();

        var h5_log_version = "1";
        var h5_bussiness_id = options.from ? options.from : "";
        var h5_live_mode = po.isLive?"prism_live":"prism_vod";

        var h5_product = po.isLive?"pusher":"player";
        var h5_video_type = po.isLive?"live" : "vod";

        // default: pcweb
        var h5_terminal_type = "pc";
        if (UA.IS_IPAD) {
            h5_terminal_type = "pad";
        } else if (UA.IS_IPHONE) {
            h5_terminal_type = "iphone";
        } else if (UA.IS_ANDROID) {
            h5_terminal_type = "andorid";
        }

        var h5_device_model = UA.IS_PC?'pc_h5':'h5';
        var h5_player_version = CONF.h5Version;
        var h5_uuid = this._getUuid();
        var h5_video_id = po.source ? encodeURIComponent(po.source) : options.video_id;
        var h5_user_id = "0";
        var h5_session_id = this.sessionId;
        var h5_event_id = "0";
        var h5_args = "0";
        var h5_definition = "custom";
        var h5_cdn_ip = "0.0.0.0";
        var h5_client_timestamp = new Date().getTime();


        this.opt = {
            APIVersion: '0.6.0',
            t : h5_client_timestamp,
            ll : 'info',
            lv : '1.0',
            pd : h5_product,
            md : 'saas_player',
            hn : '0.0.0.0',
            bi : h5_bussiness_id,
            ri : h5_session_id,
            e : h5_event_id,
            args : h5_args,
            vt : h5_video_type,
            tt : h5_terminal_type,
            dm : h5_device_model,
            av : 'player',
            uuid :h5_uuid,
            vu : h5_video_id,
            ua : h5_user_id,
            dn : h5_definition,
            cdn_ip: h5_cdn_ip,
            r : '',

        };

        // this.opt = {
        //     APIVersion: '0.6.0',
        //     lv: h5_log_version,           //log_version
        //     b: h5_bussiness_id,           //business_id
        //     lm: h5_live_mode,             //live_mode
        //     t: h5_terminal_type,          //terminal_type
        //     m: h5_device_model,           //device_model
        //     pv: h5_player_version,        //player_version
        //     uuid: h5_uuid,                //uuid
        //     v: h5_video_id,               //video_id
        //     u: h5_user_id,                //user_id
        //     s: h5_session_id,             //session_id
        //     e: h5_event_id,               //event_id
        //     args: h5_args,                //args
        //     d: h5_definition,             //definition
        //     cdn_ip: h5_cdn_ip,            //cdn_ip
        //     ct: h5_client_timestamp,      //client_timestamp
        // };

        this.bindEvent();
    },

    //更新视频信息,当播放器实例不变,播放内容更换时使用
    updateVideoInfo:function(options){
        var po=this.player.getOptions();

        var h5_log_version = "1";
        var h5_bussiness_id = options.from ? options.from : "";
        var h5_live_mode = po.isLive?"prism_live":"prism_vod";

        var h5_product = po.isLive?"pusher":"player";
        var h5_video_type = po.isLive?"live" : "vod";

        // default: pcweb
        var h5_terminal_type = "pc";
        if (UA.IS_IPAD) {
            h5_terminal_type = "pad";
        } else if (UA.IS_IPHONE) {
            h5_terminal_type = "iphone";
        } else if (UA.IS_ANDROID) {
            h5_terminal_type = "andorid";
        }

        var h5_device_model = UA.IS_PC?'pc_h5':'h5';
        var h5_player_version = CONF.h5Version;
        var h5_uuid = this._getUuid();
        var h5_video_id = po.source ? encodeURIComponent(po.source) : options.video_id;
        var h5_user_id = "0";
        var h5_session_id = this.sessionId;
        var h5_event_id = "0";
        var h5_args = "0";
        var h5_definition = "custom";
        var h5_cdn_ip = "0.0.0.0";
        var h5_client_timestamp = new Date().getTime();

        this.opt = {
            APIVersion: '0.6.0',
            t : h5_client_timestamp,
            ll : 'info',
            lv : '1.0',
            pd : h5_product,
            md : 'saas_player',
            hn : '0.0.0.0',
            bi : '',
            ri : h5_session_id,
            e : h5_event_id,
            args : h5_args,
            vt : h5_video_type,
            tt : h5_terminal_type,
            dm : h5_device_model,
            av : 'player',
            uuid :h5_uuid,
            vu : h5_video_id,
            ua : h5_user_id,
            dn : h5_definition,
            cdn_ip: h5_cdn_ip,
            r : '',

        };
    },

    

    //event
    bindEvent: function() {
        var that = this;
        this.player.on('init',           function() {that._onPlayerInit();});
        window.addEventListener('beforeunload', function() {that._onPlayerClose();});
        this.player.on('ready',          function() {that._onPlayerReady();});
        this.player.on('ended',          function() {that._onPlayerFinish();});
        this.player.on('play',           function() {that._onPlayerPlay();});
        this.player.on('pause',          function() {that._onPlayerPause();});
        //this.player.on('seeking',      function(e){that._onPlayerSeekStart(e);});
        //this.player.on('seeked',       function(e){that._onPlayerSeekEnd(e);});
        this.player.on('seekStart',      function(e){that._onPlayerSeekStart(e);});
        this.player.on('seekEnd',        function(e){that._onPlayerSeekEnd(e);});
        this.player.on('waiting',        function() {that._onPlayerLoaded();});
        this.player.on('canplaythrough', function() {that._onPlayerUnderload();});
        //this.player.on('canplay',        function() {that._onPlayerUnderload();});
        //this.player.on('timeupdate',     function() {that._onPlayerHeartBeat();});
        this.player.on('error',          function() {that._onPlayerError();});
        //this.player.on('fullscreenchange', function() {that._onFullscreenChange);});
        //this.player.on('qualitychange', function() {that._onPlayerSwitchResolution);});

        checkIntervalInt=setInterval(function() {
            // 卡顿开始
            if (that.player.readyState() === 2 || that.player.readyState() === 3) {
                that._onPlayerLoaded();
            //alert("state_buffer");
            // 卡顿恢复
            } else if (that.player.readyState() === 4) {
                that._onPlayerUnderload();
            }
        }, 100);


        checkTimeUpdate=setInterval(function() {
            var currTime = Math.floor(that.player.getCurrentTime() * 1000);
            if (that.player.paused()) {
                return;
            };
            updateTime++;
            if (updateTime>=30) {
                that._log('HEARTBEAT', {vt: currTime,interval:updateTime*1000});
                updateTime = 0;
            };

        }, 1000);


    },

    removeEvent:function(){
        var that = this;
        this.player.off('init');
        this.player.off('ready');
        this.player.off('ended');
        this.player.off('play');
        this.player.off('pause');
        this.player.off('seekStart');
        this.player.off('seekEnd');
        this.player.off('canplaythrough');
        //this.player.off('timeupdate', function() {that._onPlayerHeartBeat();});
        this.player.off('error');
        //this.player.off('fullscreenchange');
        //this.player.off('qualitychange');

        clearInterval(checkIntervalInt);
    },

    //init
    _onPlayerInit: function() {
        // 重置sessionId
        this.sessionId = Data.guid();
        this._log('INIT', {});
        this.buffer_flag = 0;    //after first play, set 1
        this.pause_flag = 0;     //pause status
    },

    //beforeunload
    _onPlayerClose: function() {
        this._log('CLOSE', {vt: Math.floor(this.player.getCurrentTime() * 1000)});
    },

    //ready
    _onPlayerReady: function() {
        //保存开始播放时间戳
        this.startTimePlay = new Date().getTime();
    },

    //end
    _onPlayerFinish: function() {
        // 重置sessionId
        this.sessionId = Data.guid();
        this._log('STOP', {vt: Math.floor(this.player.getCurrentTime() * 1000)});
    },

    //play
    _onPlayerPlay: function() {
        //若为autoplay,点击开始才上报2001
        if (!this.buffer_flag && this.player._options.autoplay) {
            this.first_play_time = new Date().getTime();
            this._log('PLAY', {dsm: 'fix', vt: 0, start_cost: this.first_play_time - this.player.getReadyTime()});
            this.buffer_flag = 1;
            return;
        }

        //忽略播放前的暂停
        if (!this.buffer_flag) return;
        //若非暂停则返回
        if (!this.pause_flag) return;
        this.pause_flag = 0;
        this.pauseEndTime = new Date().getTime();
        this._log('RECOVER', {vt: Math.floor(this.player.getCurrentTime() * 1000), cost: this.pauseEndTime - this.pauseTime});
    },

    //pause
    _onPlayerPause: function() {
        //忽略播放前的暂停
        if (!this.buffer_flag) return;
        //未赋值不记录暂停
        if (!this.startTimePlay) return;
        //忽略seek时的暂停
        if (this.seeking) return;
        this.pause_flag = 1;
        this.pauseTime = new Date().getTime();
        this._log('PAUSE', {vt: Math.floor(this.player.getCurrentTime() * 1000)});
    },

    //seekstart
    _onPlayerSeekStart: function(e) {
        this.seekStartTime = e.paramData.fromTime;
        this.seeking = true;
        this.seekStartStamp = new Date().getTime();
    },

    //seekend
    _onPlayerSeekEnd: function(e) {
        this.seekEndStamp = new Date().getTime();
        this._log('SEEK', {drag_from_timestamp: Math.floor(this.seekStartTime * 1000), drag_to_timestamp: Math.floor(e.paramData.toTime * 1000)});
        this._log('SEEK_END', {vt: Math.floor(this.player.getCurrentTime() * 1000), cost: this.seekEndStamp - this.seekStartStamp });
        this.seeking = false;
    },

    //waiting
    _onPlayerLoaded: function() {
        // 第一次播放前不记录卡顿，卡顿不置位，不产生卡顿恢复
        if (!this.buffer_flag) return;
        //未赋值不记录卡顿
        if (!this.startTimePlay) return;
        // 已经处于卡顿或者拖拽过程中不去记录卡顿
        if (this.stucking || this.seeking) return;

        // 如果卡顿在开始播放1s以内发生则忽略
        this.stuckStartTime = new Date().getTime();
        //console.log(this.stuckStartTime);
        //console.log(this.startTimePlay);
        if ( this.stuckStartTime - this.startTimePlay <= 1000 )
            return;

        //alert("load_buffer");
        this.stucking = true;
        this._log('UNDERLOAD', {vt: Math.floor(this.player.getCurrentTime() * 1000)});
        this.stuckStartTime = new Date().getTime();
    },

     //canplaythrough, canplay:有些浏览器没有
    _onPlayerUnderload: function() { //卡顿恢复
        //第一次恢复,并且非自动播放，认为开始播放,(自动播放会提起load数据，导致上报过早)
        if (!this.buffer_flag && !this.player._options.autoplay) {
            this.first_play_time = new Date().getTime();
            this._log('PLAY', {play_mode: 'fix', vt: 0, start_cost: this.first_play_time - this.player.getReadyTime()});
            this.buffer_flag = 1;
            return;
        }

        //若未开播，且autoplay,则返回
        if(!this.buffer_flag && this.player._options.autoplay ) return;

        // 如果当前不在卡顿中，或者在拖拽过程中，不应该记录卡顿恢复
        if (!this.stucking || this.seeking) return;

        var currTime = Math.floor(this.player.getCurrentTime() * 1000),
            startTime = this.stuckStartTime || new Date().getTime(),
            cost = Math.floor(new Date().getTime() - startTime);

        if (cost < 0) cost = 0;
        this._log('LOADED', {vt: currTime, cost: cost});  
        this.stucking = false;
    },

    _onPlayerHeartBeat: function() {
        // 拖拽过程中不去记录心跳
        if (this.seeking) return;

        var currTime = Math.floor(this.player.getCurrentTime() * 1000),
            that = this;

        if (!this.timer) {
            this.timer = setTimeout(function() {
                !that.seeking && that._log('HEARTBEAT', {progress: currTime});
                clearTimeout(that.timer);
                that.timer = null;
            }, 60000);
        }

        console.log('timeupdate');
    },

    //error
    _onPlayerError: function() {
        var trackerError = {
                'MEDIA_ERR_NETWORK': -1,
                'MEDIA_ERR_SRC_NOT_SUPPORTED': -2,
                'MEDIA_ERR_DECODE': -3
            },
            errorObj = this.player.getError(),
            errorCode = errorObj.code,
            tMsg;

        _.each(errorObj.__proto__, function(k, v) {
            if (v === errorCode) {
                tMsg = k;
                return false;
            }
        });

        if (trackerError[tMsg]) {
            this._log('ERROR', {vt: Math.floor(this.player.getCurrentTime() * 1000), error_code: trackerError[tMsg], error_msg: tMsg});
        }
    },

    _log: function(eventType, extCfg) {
        var cfg = _.copy(this.opt);



        //var url='//log.video.taobao.com/stat/';
        //var url='//videocloud.cn-hangzhou.log.aliyuncs.com/logstores/player/track';
        var url= CONF.logReportTo;

        cfg.e = EVENT[eventType];
        // cfg.s = this.sessionId;
        // cfg.ct = new Date().getTime();

        //2017-04-18 新版日志
        cfg.ri = this.sessionId;
        cfg.t = new Date().getTime();

        var args_params = [];
        _.each(extCfg, function(k, v) {
            args_params.push(k + '=' + v);
        });
        args_params = args_params.join('&');

        if (args_params == "") {
            args_params = "0";
        }
        cfg.args = encodeURIComponent(args_params);

        /*
        if (extCfg.vt) {
            extCfg.vt = Math.round(extCfg.vt);
        }
        if (extCfg.cost) {
            extCfg.cost = Math.round(extCfg.cost);
        }

        extCfg.systs = new Date().getTime();

        cfg = _.merge(cfg, extCfg);
        */

        var params = [];
        _.each(cfg, function(k, v) {
            params.push(k + '=' + v);
        });
        params = params.join('&');

        IO.jsonp(url + '?' + params, function() {}, function() {});

    },

    /**
     * 唯一表示播放器的id缓存在cookie中
     */
    _getUuid: function() {
        // p_h5_u表示prism_h5_uuid
        var uuid = Cookie.get('p_h5_u');

        if (!uuid) {
            uuid = Data.guid();
            Cookie.set('p_h5_u', uuid, 7);
        }

        return uuid;
    }
});

module.exports = Monitor;

},{"../config":35,"../lib/cookie":37,"../lib/data":38,"../lib/io":42,"../lib/object":44,"../lib/oo":45,"../lib/ua":46}],50:[function(require,module,exports){
/*
* flash播放器核心类
*/
var Component = require('../ui/component');
var Data = require('../lib/data');
var _ = require('../lib/object');
var cfg = require('../config');
//var swfobj=require('../lib/swfobject');

var FlashPlayer = Component.extend({

	init: function(tag, options) {
		Component.call(this, this, options);
		
		// 在window下挂载变量,便于flash调用
		this._id = this.id = 'prism-player-' + Data.guid();
        this.tag = tag;
        this._el = this.tag;
		window[this.id] = this;
		
		var width = '100%';
		var height = '100%';
		// TODO 临时先用日常的
		var swfUrl = '//' + cfg.domain + '/de/prismplayer-flash/' + cfg.flashVersion + '/PrismPlayer.swf';
		var flashVar = this._comboFlashVars();
		var wmode=this._options.wmode?this._options.wmode:"opaque";

		tag.innerHTML = '<object classid="clsid:D27CDB6E-AE6D-11cf-96B8-444553540000" codebase="//download.macromedia.com/pub/shockwave/cabs/flash/swflash.cab#version=5,0,0,0" width="' + width + '" height="' + height + '" id="' + this.id + '">' +
			'<param name=movie value="' + swfUrl + '">'+
			'<param name=quality value=High>'+
			'<param name="FlashVars" value="' + flashVar + '">' +
			'<param name="WMode" value="'+wmode+'">' +
			'<param name="AllowScriptAccess" value="always">' +
			'<param name="AllowFullScreen" value="true">' +
			'<param name="AllowFullScreenInteractive" value="true">' +
			'<embed name="' + this.id + '" src="' + swfUrl + '" quality=high pluginspage="//www.macromedia.com/shockwave/download/index.cgi?P1_Prod_Version=ShockwaveFlash" type="application/x-shockwave-flash" width="' + width + '" height="' + height + '" AllowScriptAccess="always" AllowFullScreen="true" AllowFullScreenInteractive="true" WMode="'+wmode+'" FlashVars="' + flashVar + '">' +
			'</embed>'+
		'</object>';

		//swfobj.registerObject(this._id, "10.1.0");
	},
		
	_getPlayer: function(id) {
		if (navigator.appName.indexOf("Microsoft") != -1) { 
			return document.getElementById(id);
		}else{
		   return document[id];
		}
	},

	//增加对 domain,statisticService,videoInfoService,vurl(调整为 source) 的设置支持
	_comboFlashVars: function(){
		var opt = this._options,
			flashVarArr = {
				autoPlay: opt.autoplay ? 1 : 0,

				//20170419 日志改版，不在让用户传from >=1.6.8
				// from: opt.from,
				
				isInner: 0,
				actRequest: 1,
				//ref: 'share',
				vid: opt.vid,
				domain: opt.domain ? opt.domain : '//tv.taobao.com',
				//statisticService: opt.statisticService ? opt.statisticService : '//log.video.taobao.com/stat/', 
				//statisticService: opt.statisticService ? opt.statisticService : '//videocloud.cn-hangzhou.log.aliyuncs.com/logstores/player/track', 
				statisticService: opt.statisticService ? opt.statisticService : cfg.logReportTo,
				videoInfoService: opt.videoInfoService?opt.videoInfoService:'/player/json/getBaseVideoInfo.do',
				disablePing: opt.trackLog ? 0 : 1,
				namespace: this.id,
				barMode:opt.barMode != 0 ? 1 : 0,
				//直播状态
				isLive:opt.isLive?1:0,
				//水印
				waterMark:opt.waterMark,
				//直接播放的地址
				vurl:opt.source ? encodeURIComponent(opt.source):"",
				//插件
				plugins:opt.plugins?opt.plugins:"",
                snapShotShow:opt.snapshot ? 1 : 0,

                accessId:opt.accId ? opt.accId : "",
                accessKey:opt.accSecret ? opt.accSecret : "",
                apiKey:opt.apiKey ? opt.apiKey : "",
                
                flashApiKey:opt.flashApiKey?opt.flashApiKey : "",
                fromAdress_taoTV : opt.fromAdress_taoTV ? opt.fromAdress_taoTV : "",

            
                stsToken:opt.stsToken ? opt.stsToken : "",
                domainRegion:opt.domainRegion ? opt.domainRegion : "",
                authInfo:opt.authInfo ? encodeURIComponent(opt.authInfo) : "",
                playDomain : opt.playDomain?opt.playDomain : "",



                playauth : opt.playauth ? opt.playauth.replace(/\+/g,'%2B') : "",
                prismType : opt.prismType ? opt.prismType : 0,

                formats:opt.formats ? opt.formats : "",
                notShowTips:opt.notShowTips ? 1 : 0,
                showBarTime:opt.showBarTime ? opt.showBarTime : 0,
                showBuffer: opt.showBuffer==0 ? 0 : 1,
                rePlay:opt.rePlay ? 1 : 0,
                encryp:opt.encryp ? opt.encryp : "",
                secret:opt.secret ? opt.secret : ""
			},
			flashVar = [];

		if (opt.cover) {
			flashVarArr.cover = opt.cover;
		}
        if (opt.extraInfo) {
            flashVarArr.extraInfo = encodeURIComponent(JSON.stringify(opt.extraInfo));
        }

		_.each(flashVarArr, function(k, v) {
			flashVar.push(k + '=' + v);
		});

		return flashVar.join('&');
	},
	
	/************************ flash调用js的函数 ***********************/
	
	/**
	 * flashPlayer初始化完毕
	 */
	flashReady: function() {
		this.flashPlayer = this._getPlayer(this.id);
		this._isReady = true;

		// 传递skin相关
		var skinRes = this._options.skinRes,
			skinLayout = this._options.skinLayout,
			skin;

		// 必须是false或者array
		if (skinLayout !== false && !_.isArray(skinLayout)) {
			throw new Error('PrismPlayer Error: skinLayout should be false or type of array!');
		}
		if (typeof skinRes !== 'string') {
			throw new Error('PrismPlayer Error: skinRes should be string!');
		}

		// 如果是false或者[]，隐藏ui组件
		if (skinLayout == false || skinLayout.length === 0) {
			skin = false;
		
		} else {
			skin = {
				skinRes: skinRes,
				skinLayout: skinLayout
			};
		}
		this.flashPlayer.setPlayerSkin(skin);
		
		this.trigger('ready');

		// 告知flash播放器页面关闭
		var that = this;
		window.addEventListener('beforeunload', function() {
			try{
				that.flashPlayer.setPlayerCloseStatus();
			}catch(e){

			}
		});
	},

	/**
	 * flash调用该函数，轮询js的函数声明是否完成
	 */
	jsReady: function() {
		return true;
	},

	uiReady: function() {
		this.trigger('uiReady');
	},

	loadedmetadata: function() {
		this.trigger('loadedmetadata');
	},

	onPlay: function() {
		this.trigger('play');		
	},

	onEnded: function() {
		this.trigger('ended');		
	},

	onPause: function() {
		this.trigger('pause');		
	},
	//flash弹幕插件初始化完成
	onBulletScreenReady:function(){
		this.trigger('bSReady');
	},
	//flash弹幕发送弹幕消息
	onBulletScreenMsgSend:function(msg){
		this.trigger('bSSendMsg',msg);
	},

	//flash视频开始渲染播放器内逻辑做了单个视频的发送滤重,可以作为canplay的依赖
	onVideoRender:function(time){
		this.trigger('videoRender');
		this.trigger('canplay',{loadtime:time});
	},
	//flash播放器捕捉到错误时调用
	onVideoError:function(type){
		this.trigger('error',{errortype:type});
	},
    //flash catch m3u8 request error and retry
    onM3u8Retry:function(){
        this.trigger('m3u8Retry');
    },
    //send hide bar
    hideBar:function(){
        this.trigger('hideBar');
    },
    //send show bar: closed now
    showBar:function(){
        this.trigger('showBar');
    },
    //flash catch live stream stop
    liveStreamStop:function(){
        this.trigger('liveStreamStop');
    },
    //flash catch live stream stop
    stsTokenExpired:function(){
        this.trigger('stsTokenExpired');
    },
	//flash播放器捕捉到缓冲
	onVideoBuffer:function(){
		this.trigger('waiting');
	},

	/**
	 * js调用flash函数的基础方法
	 */
	_invoke: function() {
		var fnName = arguments[0],
			args = arguments;

		Array.prototype.shift.call(args);

		if (!this.flashPlayer) {
			throw new Error('PrismPlayer Error: flash player is not ready!');
		}
		if (typeof this.flashPlayer[fnName] !== 'function') {
			throw new Error('PrismPlayer Error: function ' + fnName + ' is not found!');
		}

		return this.flashPlayer[fnName].apply(this.flashPlayer, args);
	},

	/* ================ 公共接口 ====================== */
	play: function() {
		this._invoke('playVideo'); 
	},
	replay: function() {
		this._invoke('replayVideo'); 
	},

	pause: function() {
		this._invoke('pauseVideo');	   
	},
	stop:function(){
		this._invoke('stopVideo');
	},
	// 秒
	seek: function(time) {
		this._invoke('seekVideo', time);	  
	},

	getCurrentTime: function() {
		return this._invoke('getCurrentTime');				
	},

	getDuration: function() {
		return this._invoke('getDuration');			 
	},

	mute: function() {
        this.setVolume(0);
	},

	unMute: function() {
        this.setVolume(0.5);
	},


	// 0-1
	getVolume: function() {
		return this._invoke('getVolume');		   
	},

	// 0-1
	setVolume: function(vol) {
		this._invoke('setVolume', vol);		   
	},
	//新增接口============================
	//通过id加载视频
	loadByVid: function(vid) {
		this._invoke('loadByVid', vid,false);		   
	},
	//通过url加载视频
	loadByUrl: function(url, seconds) {
		this._invoke('loadByUrl', url, seconds);
	},
	//销毁 暂停视频,其余的由业务逻辑处理
	dispose: function() {
		this._invoke('pauseVideo');		   
	},
	//推送弹幕消息,js获取到消息后推送给flash显示
	showBSMsg:function(msg){
		this._invoke('showBSMsg',msg);
	},
	//设置是否启用toast信息提示
	setToastEnabled:function(enabled){
		this._invoke('setToastEnabled',enabled);
	},
	//设置是否显示loading
	setLoadingInvisible:function(){
		this._invoke('setLoadingInvisible');
	},
    //set player size
    setPlayerSize:function(input_w, input_h){
        var that = this;
        this._el.style.width = input_w

        var per_idx = input_h.indexOf("%");
        if (per_idx > 0)
        {
            var screen_height = window.screen.height;
            var per_value = input_h.replace("%", "");
            if(!isNaN(per_value))
            {
                var scale_value = screen_height * 9 * parseInt(per_value) / 1000;
                this._el.style.height = String(scale_value % 2 ? scale_value + 1: scale_value) + "px";
            }
            else
            {
                this._el.style.height = input_h;
            }
        }
        else
        {
            this._el.style.height = input_h;
        }
        console.log(input_w + input_h);
    },
});

module.exports = FlashPlayer;

},{"../config":35,"../lib/data":38,"../lib/object":44,"../ui/component":52}],51:[function(require,module,exports){
/*
* 播放器核心类
*
*/
var Component = require('../ui/component');
var _ = require('../lib/object');
var Dom = require('../lib/dom');
var Event = require('../lib/event');
var io = require('../lib/io');
var UI = require('../ui/exports');
var Monitor = require('../monitor/monitor');
var UA = require('../lib/ua');


var CryptoJS = require("crypto-js"); 


var debug_flag = 1;

var Player = Component.extend({
    init: function (tag, options) {
        this.tag = tag;
        this.loaded = false;
        this.played = false;

        //调用父类的构造函数
        Component.call(this, this, options);

        //初始化所有插件
        if (options['plugins']) {
            _.each(options['plugins'], function(key, val){
                this[key](val);
            }, this);
        }

        // 如果不使用默认的controls，并且不是iphone，才初始化ui组件
        if (!options['useNativeControls'] /*&& !UA.IS_IPHONE*/) {
            // 将所有可用的ui组件挂载在player下，供初始化组件时索引
            this.UI = UI;
            this.initChildren();
        // 否则设置controls即可
    } else {
        this.tag.setAttribute('controls','controls');
    }

        //监听视频播放器的事件
        this.bindVideoEvent();

        

        // 如果采用直接传入视频源的方式，则直接播放
        if (this._options.source) {
            // 开始监控
            if (this._options['trackLog']) {
                // 直接传视频源，没有vid和aid，用默认0代替
                this._monitor=new Monitor(this, {video_id: 0, album_id: 0, from: this._options.from});
            }

            // 可以认为此时player init
            this.trigger('init');
            if (debug_flag) {
                console.log('init');
            }

            if (this._options.autoplay || this._options.preload) {
                this.getMetaData();
                this.tag.setAttribute('src', this._options.source);
                this.readyTime = new Date().getTime();
                this.loaded = true;
            }

        // 否则，调用接口加载视频资源
    } else if (this._options.vid) {
            
            //增加参数 来确定用户使用 版本和逻辑   默认 vid + playauth 播放
        var vid =   this._options.vid;
        var playAuth =  this._options.playauth;
        
        
        var accessId = this._options.accId;
        var accessSecret = this._options.accSecret;
        var apiSecretKey = this._options.apiKey;
        var user_stsToken = this._options.stsToken;
        var user_domainRegion = this._options.domainRegion;
        var user_authInfo = this._options.authInfo;


            switch(this._options.prismType){ // 默认初始 0
                case 1 : //taotv
                    //兼容 taotv和youku
                this.loadVideoInfo(); 
                    break;
                case 2: 
                    //兼容 ak apikey 控制台播放 (vid,accessId,accessSecret,apiSecretKey,user_stsToken,user_authInfo,user_domainRegion)
                    this.loadNewVideoInfo(vid,accessId,accessSecret,apiSecretKey,user_stsToken,user_authInfo,user_domainRegion);
                    break;
                default :
                //20170419 vid playauth 播放功能

                this.userPlayInfoAndVidRequestMts(vid,playAuth);

            }


            
        } else {
            // 开始监控
            if (this._options['trackLog']) {
                // 直接传视频源，没有vid和aid，用默认0代替
                this._monitor=new Monitor(this, {video_id: 0, album_id: 0, from: this._options.from});
            }

            // 可以认为此时player init
            this.trigger('init');
            if (debug_flag) {
                console.log('init');
            }
        }

        if (this._options.extraInfo) {
            var dict = eval(this._options.extraInfo);
            if (dict.liveRetry)
                this._options.liveRetry = dict.liveRetry;
        }

        //要想拿到video的元数据，必须等到readyState > 0
        this.on('readyState',function(){
            //是否出现控制面板
            //this.setControls();
            this.trigger('ready');
            if (debug_flag) {
                console.log('ready');
            }
        });

    }
});

/**
 * 重写component的initChildren，
 * player的children通过options.skin传入
 */
 Player.prototype.initChildren = function() {
    var opt = this.options(),
    skin = opt.skinLayout;

    // 必须是false或者array
    if (skin !== false && !_.isArray(skin)) {
        throw new Error('PrismPlayer Error: skinLayout should be false or type of array!');
    }

    // 如果是false或者[]，隐藏ui组件
    if (skin !== false && skin.length !== 0) {
        this.options({
            children: skin
        });
        Component.prototype.initChildren.call(this);
    }

    // 所有ui组件被正式添加到dom树后触发
    this.trigger('uiH5Ready');
    if (debug_flag) {
        console.log('uiH5ready');
    }
},

Player.prototype.createEl = function() {
    if(this.tag.tagName !== 'VIDEO'){
        this._el = this.tag;
        this.tag = Component.prototype.createEl.call(this, 'video');
        //如果设置了 inline 播放
        if (this._options.playsinline) {
            this.tag.setAttribute('webkit-playsinline','');
            this.tag.setAttribute('playsinline','');
            this.tag.setAttribute('x-webkit-airplay','');
        };
    }

    var el = this._el,
    tag = this.tag,
    that = this;

    //该video已经被初始化为播放器
    tag['player'] = this;



    //把video标签上的属性转移到外围容器上
    var attrs = Dom.getElementAttributes(tag);
    
    _.each(attrs,function(attr){
        el.setAttribute(attr,attrs[attr]);
    });

    //设置video标签属性
    this.setVideoAttrs();

    // 把video标签包裹在el这个容器中
    if (tag.parentNode) {
        tag.parentNode.insertBefore(el, tag);
    }
    Dom.insertFirst(tag, el); // Breaks iPhone, fixed in HTML5 setup.*''

    // 为了屏蔽各个浏览器下video标签的默认样式，需要在其上加一层遮罩
    this.cover = Dom.createEl('div');
    Dom.addClass(this.cover, 'prism-cover');
    el.appendChild(this.cover);

    if (this.options().cover) {
        this.cover.style.backgroundImage = 'url(' + this.options().cover + ')';
    }
    if (!UA.IS_IOS) {
        /*
        this.cover = Dom.createEl('div');
        Dom.addClass(this.cover, 'prism-cover');
        el.appendChild(this.cover);

        if (this.options().cover) {
            this.cover.style.backgroundImage = 'url(' + this.options().cover + ')';
        }
        */

    // ios下用遮罩的方式触发播放有问题，只能使用display:none的方式
} else {
    Dom.css(tag, 'display', 'none');
}

return el;
};

Player.prototype.setVideoAttrs = function(){
    var preload = this._options.preload,
    autoplay = this._options.autoplay;

    this.tag.style.width = '100%';
    this.tag.style.height = '100%';

    if (preload) {
        this.tag.setAttribute('preload','preload');
    }

    if (autoplay) {
        this.tag.setAttribute('autoplay','autoplay');
    }
}

/**
 * sleep function
 */
 function sleep(d){
    for(var t = Date.now();Date.now() - t <= d;);
}

/**
 * player的id直接返回组件的id
 */
 Player.prototype.id = function() {
    return this.el().id;
};

Player.prototype.renderUI = function() {};

Player.prototype.bindVideoEvent = function(){
    var tag = this.tag,
    that = this;

    //(1)开始load数据
    Event.on(tag, 'loadstart', function(e){
        that.trigger('loadstart');
        if (debug_flag) {
            console.log('loadstart');
        }
    });

    //(2)加载视频时长
    Event.on(tag, 'durationchange', function(e){
        that.trigger('durationchange');
        if (debug_flag) {
            console.log('durationchange');
        }
    });


    //(3)成功获取资源长度
    Event.on(tag, 'loadedmetadata', function(e){
        that.trigger('loadedmetadata');
        if (debug_flag) {
            console.log('loadedmetadata');
        }
    });

    //(4)已加载当前帧,但无足够数据播放
    Event.on(tag, 'loadeddata', function(e){
        that.trigger('loadeddata');
        if (debug_flag) {
            console.log('loadeddata');
        }
    });

    //(5)客户端正在请求数据 
    Event.on(tag, 'progress', function(e){
        that.trigger('progress');
        if (debug_flag) {
            console.log('progress');
        }
    });

    //(6)可以播放数据
    Event.on(tag, 'canplay', function(e){
        var time=(new Date().getTime())-that.readyTime;
        that.trigger('canplay',{loadtime:time});
        if (debug_flag) {
            console.log('canplay');
        }
    });

    //(7)可以无缓冲播放数据
    Event.on(tag, 'canplaythrough', function(e){
        //if (that.cover/* && !UA.IS_IOS*/) {
        //if autoplay, canplaythrough delete cover; else play delete cover
        if (that.cover && that._options.autoplay) {
            Dom.css(that.cover, 'display', 'none');
            delete that.cover;
        }
        /* else */
        if (tag.style.display === 'none' && UA.IS_IOS) {
            setTimeout(function() {
                Dom.css(tag, 'display', 'block');
            }, 100);
        }

        that.trigger('canplaythrough');

        if (debug_flag) {
            console.log('canplaythrough');
        }
    });

    //开始播放触发事件 
    Event.on(tag, 'play', function(e){
        that.trigger('play');
        if (debug_flag) {
            console.log('play');
        }
    });

    //none
    Event.on(tag,'play',function(e){
        that.trigger('videoRender');
        if (debug_flag) {
            console.log('videoRender');
        }
    });

    //暂停触发事件 
    Event.on(tag, 'pause', function(e){
        that.trigger('pause');
        if (debug_flag) {
            console.log('pause');
        }
    });

    //结束
    Event.on(tag, 'ended', function(e){
        if(that._options.rePlay)
        {
            that.seek(0);
            that.tag.play();
        }
        that.trigger('ended');
        if (debug_flag) {
            console.log('ended');
        }
    }); 

    //客户端尝试获取数据 none
    Event.on(tag, 'stalled', function(e){
        that.trigger('stalled');
        if (debug_flag) {
            console.log('stalled');
        }
    });

    //缓冲等待数据
    Event.on(tag, 'waiting', function(e){
        that.trigger('waiting');
        that.trigger('h5_loading_show');
        if (debug_flag) {
            console.log('waiting');
        }
    });

    //播放中
    Event.on(tag, 'playing', function(e){
        that.trigger('playing');
        that.trigger('h5_loading_hide');
        if (debug_flag) {
            console.log('playing');
        }
    });

    Event.on(tag, 'error', function(e){
        console.log('error');
        //console.log(e);

        if (that._options.isLive)
        {
            if(that._options.liveRetry)
            {
                sleep(2000);
                that.tag.load(that._options.source);
                that.tag.play();
            }
            else
            {
                that.trigger('error');
            }

            that.trigger('liveStreamStop');
        }
        else
        {
            var errorFlag = 0;
            if(that._options.source&&that._options.source.indexOf("flv") > 0 )
            {
                errorFlag = 1;
            }
            else
            {
                if(that._options.source&&that._options.source.indexOf("m3u8") > 0 && !UA.IS_MOBILE)
                {
                    errorFlag = 1;
                }
            }

            errmsg = document.querySelector('#' + that.id());
            errmsg.style.lineHeight = errmsg.clientHeight + "px";
            Dom.css(errmsg, 'text-align', 'center');
            Dom.css(errmsg, 'color', '#FFFFFF');

            if(errorFlag)
            {
                errmsg.innerText = "播放失败: h5不支持此格式，请安装flashplayer";
            }
            else
            {
                errmsg.innerText = "播放失败: 请确认播放源";
            }
            that.trigger('error');
        }
    });

    //not exist now
    Event.on(tag, 'onM3u8Retry', function(e){
        that.trigger('m3u8Retry');
        if (debug_flag) {
            console.log('m3u8Retry');
        }
    });

    //not exist now
    Event.on(tag, 'liveStreamStop', function(e){
        that.trigger('liveStreamStop');
        if (debug_flag) {
            console.log('liveStreamStop');
        }
    });

    //寻找中
    Event.on(tag, 'seeking', function(e){
        that.trigger('seeking');
        if (debug_flag) {
            console.log('seeking');
        }
    });

    //寻找完毕
    Event.on(tag, 'seeked', function(e){
        that.trigger('seeked');
        if (debug_flag) {
            console.log('seeked');
        }
    });

    //播放速率改变
    Event.on(tag, 'ratechange', function(e){
        that.trigger('ratechange');
        if (debug_flag) {
            console.log('ratechange');
        }
    });

    //播放过程触发的事件
    Event.on(tag,'timeupdate',function(e){
        //var currentTime = e.target.currentTime;
        //that.currentTime(currentTime);
        that.trigger('timeupdate');
        if (debug_flag) {
            console.log('timeupdate');
        }
    });

    //全屏修改
    Event.on(tag, 'webkitfullscreenchange', function(e){
        that.trigger('fullscreenchange');
        if (debug_flag) {
            console.log('fullscreenchange');
        }
    });
    


    this.on('requestFullScreen', function() {
        Dom.addClass(that.el(), 'prism-fullscreen');
        if (debug_flag) {
            console.log('request-fullscreen');
        }
    });
    this.on('cancelFullScreen', function() {
        Dom.removeClass(that.el(), 'prism-fullscreen');
        if (debug_flag) {
            console.log('cancel-fullscreen');
        }
    });

    //may not used
    Event.on(tag,'suspend',function(e){
        that.trigger('suspend');
        if (debug_flag) {
            console.log('sudpend');
        }
    });

    Event.on(tag,'abort',function(e){
        that.trigger('abort');
        if (debug_flag) {
            console.log('abort');
        }
    });

    Event.on(tag,'volumechange',function(e){
        that.trigger('volumechange');
        if (debug_flag) {
            console.log('volumechange');
        }
    });

    Event.on(tag,'drag',function(e){
        that.trigger('drag');
        if (debug_flag) {
            console.log('drag');
        }
    });

    Event.on(tag,'dragstart',function(e){
        that.trigger('dragstart');
        if (debug_flag) {
            console.log('dragstart');
        }
    });

    Event.on(tag,'dragover',function(e){
        that.trigger('dragover');
        if (debug_flag) {
            console.log('dragover');
        }
    });


    Event.on(tag,'dragenter',function(e){
        that.trigger('dragenter');
        if (debug_flag) {
            console.log('dragenter');
        }
    });

    Event.on(tag,'dragleave',function(e){
        that.trigger('dragleave');
        if (debug_flag) {
            console.log('dragleave');
        }
    });

    Event.on(tag,'ondrag',function(e){
        that.trigger('ondrag');
        if (debug_flag) {
            console.log('ondrag');
        }
    });

    Event.on(tag,'ondragstart',function(e){
        that.trigger('ondragstart');
        if (debug_flag) {
            console.log('ondragstart');
        }
    });

    Event.on(tag,'ondragover',function(e){
        that.trigger('ondragover');
        if (debug_flag) {
            console.log('ondragover');
        }
    });

    Event.on(tag,'ondragenter',function(e){
        that.trigger('ondragenter');
        if (debug_flag) {
            console.log('ondragenter');
        }
    });

    Event.on(tag,'ondragleave',function(e){
        that.trigger('ondragleave');
        if (debug_flag) {
            console.log('ondragleave');
        }
    });

    Event.on(tag,'drop',function(e){
        that.trigger('drop');
        if (debug_flag) {
            console.log('drop');
        }
    });

    Event.on(tag,'dragend',function(e){
        that.trigger('dragend');
        if (debug_flag) {
            console.log('dragend');
        }
    });

    Event.on(tag,'onscroll',function(e){
        that.trigger('onscroll');
        if (debug_flag) {
            console.log('onscroll');
        }
    });

}

//utf8
function AliyunEncodeURI(input)
{
   var  output = encodeURIComponent(input);
            //(+)  --> %2B
            //(*)  --> %2A
            //%7E --> ~
            output = output.replace("+", "%2B");
            output = output.replace("*", "%2A");
            output = output.replace("%7E", "~");
            
            return output;
        }

//公共方法 拼接字符串的
function makesort (ary,str1,str2) {
    if (!ary) {   
       throw new Error('PrismPlayer Error: vid should not be null!');
   };
        var pbugramsdic=Object.keys(ary).sort(); //key
        var outputPub = "";
        for (var key in pbugramsdic) {
          if (outputPub == "") {
              outputPub = pbugramsdic[key]+str1+ary[pbugramsdic[key]];
          }
          else {
              outputPub += str2+pbugramsdic[key]+str1+ary[pbugramsdic[key]];
          }
      }
      return outputPub;
  }

//拼接字符串 做utf8
function makeUTF8sort (ary,str1,str2) {
    if (!ary) {   
       throw new Error('PrismPlayer Error: vid should not be null!');
   };
        var pbugramsdic=Object.keys(ary).sort(); //key

        var outputPub = "";
        for (var key in pbugramsdic) {

            var a3 = AliyunEncodeURI(pbugramsdic[key]);
            var b3 = AliyunEncodeURI(ary[pbugramsdic[key]]);

            if (outputPub == "") {

              outputPub = a3 + str1 + b3;
          }
          else {
              outputPub += str2+a3 + str1 + b3;
          }
      }
      return outputPub;
  }

//signature
function makeChangeSiga (obj,secStr) {
    if (!obj) {   
       throw new Error('PrismPlayer Error: vid should not be null!');
   };
   return  CryptoJS.HmacSHA1('GET&'+AliyunEncodeURI('/')+'&' + AliyunEncodeURI(makeUTF8sort(obj,'=','&')), secStr+'&').toString(CryptoJS.enc.Base64);
}

function ISODateString(d) {  
    function pad(n){  
        return n<10 ? '0'+n : n  
    }  
    return d.getUTCFullYear()+'-'  
    + pad(d.getUTCMonth()+1)+'-'  
    + pad(d.getUTCDate())+'T'  
    + pad(d.getUTCHours())+':'  
    + pad(d.getUTCMinutes())+':'  
    + pad(d.getUTCSeconds())+'Z'  
}  

function randomUUID() {
    var s = [];
    var hexDigits = "0123456789abcdef";
    for (var i = 0; i < 36; i++) {
        s[i] = hexDigits.substr(Math.floor(Math.random() * 0x10), 1);
    }
    s[14] = "4";  // bits 12-15 of the time_hi_and_version field to 0010
    s[19] = hexDigits.substr((s[19] & 0x3) | 0x8, 1);  // bits 6-7 of the clock_seq_hi_and_reserved to 01
    s[8] = s[13] = s[18] = s[23] = "-";
 
    var uuid = s.join("");
    return uuid;
}

Player.prototype.loadNewVideoInfo = function  (vid,accessId,accessSecret,apiSecretKey,user_stsToken,user_authInfo,user_domainRegion) {   

    this._options.vid = vid;
    this._options.accId = accessId;
    this._options.accSecret = accessSecret;
    this._options.apiKey = apiSecretKey;
    this._options.stsToken = user_stsToken;
    this._options.domainRegion = user_domainRegion;
    this._options.authInfo = user_authInfo;

    var that = this;
    
    if (!vid) {
        throw new Error('PrismPlayer Error: vid should not be null!');
    }
    if (!accessId) {
        throw new Error('PrismPlayer Error: accessId should not be null!');
    }
    if (!accessSecret) {
        throw new Error('PrismPlayer Error: accessSecret should not be null!');
    }
    if (!apiSecretKey) {

        if (user_stsToken&&user_domainRegion&&user_authInfo) {
        
            this.userPramaRequestMts();

        return;
        }


        throw new Error('PrismPlayer Error: apiSecretKey should not be null!');
    }

    

    var timeTS =  new Date().getTime();
    var randomNum = randomUUID();

    var baseObj = {
        'ClientVersion' : '0.0.1',
        'SignVersion' : '0.0.1',
        'Channel' : 'HTML5',
        'ClientTS' : timeTS,
        'VideoId' : vid,
    };
    
    var base64a = CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse('{'+ makesort(baseObj,'=',',') + '}'));
    base64a = base64a.replace(/\s+/g,'')
    base64a = base64a.replace(/\n+/g, '');
    base64a = base64a.replace(/\r+/g, '');

    var baseUrlMd5 = CryptoJS.MD5(base64a + apiSecretKey).toString(CryptoJS.enc.Hex);
    var Timestamptest = ISODateString(new Date());
    var versionID = '2017-03-21';
    var SignatureMethodT = 'HMAC-SHA1';

    var pubgrams = {
        'ClientVersion' : '0.0.1',
        'SignVersion' : '0.0.1',
        'Channel' : 'HTML5',
        'ClientTS' : timeTS,
        'VideoId' : vid,
        'PlaySign' : baseUrlMd5,
        'Format' : 'JSON',
        'Version' : versionID,
        'AccessKeyId' : accessId,
        'SignatureMethod' : SignatureMethodT,
        'Timestamp' : Timestamptest,
        'SignatureVersion' : '1.0',
        'SignatureNonce' : randomNum,
        'Action' : 'GetVideoPlayInfo',
    };

    var outputPub1 = makeUTF8sort(pubgrams,'=','&');

    var pbugramsdic =  outputPub1+'&Signature='+AliyunEncodeURI(makeChangeSiga(pubgrams,accessSecret));

    io.get('//vod.cn-shanghai.aliyuncs.com/?'+pbugramsdic, function(data) {
        if (!data) {
            throw new Error('json data nil!');
        };

        var dataObj = JSON.parse(data);
        if (!dataObj) {
            throw new Error('json dataObj nil!');
        }





        //buisness_id
        that._options.from = dataObj.VideoInfo.CustomerId;

        var rid = dataObj.RequestId;

        var videoId = dataObj.VideoInfo.VideoId;
        var playIn =  JSON.parse(data);
        var atI = dataObj.PlayInfo.AuthInfo;
        var acckid = dataObj.PlayInfo.AccessKeyId;
        var videoSec = dataObj.PlayInfo.AccessKeySecret;
        var ston = dataObj.PlayInfo.SecurityToken;
        var mReg = dataObj.PlayInfo.Region;
        var timemts =  new Date().getTime();
        var ranNum = randomUUID();;
        var playDomain = dataObj.PlayInfo.PlayDomain;
        var Timestampmts = ISODateString(new Date());

        //test1
        if (debug_flag) {
         var testObject = {
            'SecurityToken' : ston,
            'AuthInfo' : atI,
            'AccessKeyId' : acckid,
            'PlayDomain' : playDomain,
            'AccessKeySecret' : videoSec,
            'Region' : mReg,
            'CustomerId': dataObj.VideoInfo.CustomerId,
            'VideoMeta': dataObj.VideoInfo,
         };
        var testStr = JSON.stringify(testObject);
        var str64= CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(testStr));
        console.log(str64);
            
        }

        


        var newAry = {
            'AccessKeyId' : acckid,
            'Action' : 'PlayInfo',
            'MediaId' : videoId,
            'Formats' : 'mp4|m3u8|flv',
            'AuthInfo' : atI,
            'AuthTimeout':'1800',
            'Rand' : ranNum,
            'SecurityToken' : ston,
            'PlayDomain' : playDomain,
            'Format' : 'JSON',
            'Version' : '2014-06-18',
            'SignatureMethod' : SignatureMethodT,
            'Timestamp' : Timestampmts,
            'SignatureVersion' : '1.0',
            'SignatureNonce' : randomNum,
        }
        
        var pbugramsdic =  makeUTF8sort(newAry,'=','&')+'&Signature='+AliyunEncodeURI(makeChangeSiga(newAry,videoSec));

        var httpUrlend = 'https://mts.' + mReg + '.aliyuncs.com/?'+pbugramsdic;

        io.get(httpUrlend,function  (data)  {

            var h5_device_model = UA.IS_PC?'pc_h5':'h5';//判定用户端
            
            if (!dataObj) {
            throw new Error('json data nil!');
            }
            if (data) {

             try{

                var playInfoAry = JSON.parse(data).PlayInfoList.PlayInfo;
                var testurl = '';
                for (var i = playInfoAry.length - 1; i >= 0; i--) {
                    var b =  playInfoAry[i];
                    if (b.format=='mp4') {
                         testurl = b.Url;
                         break;
                    }else{
                      if (b.format == 'm3u8'){;
                         testurl = b.Url;
                        }else{
                         testurl = '';
                        };
                    }
                }

                 var src = testurl;
                 that._options.vid=0;
                 that._options.source=src;

                                 // 开始监控
                if (that._options['trackLog']) {
                    that._monitor=new Monitor(that, {video_id: vid, album_id: 0, from: that._options.from});
                }
                
                // 可以认为此时player init
                that.trigger('init');
                if (debug_flag) {
                    console.log('init');
                }

                if (that._options.autoplay || that._options.preload) {
                    that.getMetaData();
                    that.tag.setAttribute('src', that._options.source);
                    that.readyTime = new Date().getTime();
                    that.loaded = true;
                }
                    
             } catch(e){
              throw new Error('json data nil!');
             } 
         }

    },function  () {
        throw new Error('PrismPlayer Error: network error!');
    })

}, function() {

 throw new Error('PrismPlayer Error: network error!');
}); 

}


//用与重新加载播放
Player.prototype.reloadNewVideoInfo = function  (vid,accessId,accessSecret,apiSecretKey,user_stsToken,user_authInfo,user_domainRegion) {   

    this._options.vid = vid;
    this._options.accId = accessId;
    this._options.accSecret = accessSecret;
    this._options.apiKey = apiSecretKey;
    this._options.stsToken = user_stsToken;
    this._options.domainRegion = user_domainRegion;
    this._options.authInfo = user_authInfo;

    var that = this;
    
    if (!vid) {
        throw new Error('PrismPlayer Error: vid should not be null!');
    }
    if (!accessId) {
        throw new Error('PrismPlayer Error: accessId should not be null!');
    }
    if (!accessSecret) {
        throw new Error('PrismPlayer Error: accessSecret should not be null!');
    }
    if (!apiSecretKey) {

        if (user_stsToken&&user_domainRegion&&user_authInfo) {
        
            this.userPramaRequestMts();

        return;
        }


        throw new Error('PrismPlayer Error: apiSecretKey should not be null!');
    }

    

    var timeTS =  new Date().getTime();
    var randomNum = randomUUID();

    var baseObj = {
        'ClientVersion' : '0.0.1',
        'SignVersion' : '0.0.1',
        'Channel' : 'HTML5',
        'ClientTS' : timeTS,
        'VideoId' : vid,
    };
    
    var base64a = CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse('{'+ makesort(baseObj,'=',',') + '}'));
    base64a = base64a.replace(/\s+/g,'')
    base64a = base64a.replace(/\n+/g, '');
    base64a = base64a.replace(/\r+/g, '');

    var baseUrlMd5 = CryptoJS.MD5(base64a + apiSecretKey).toString(CryptoJS.enc.Hex);
    var Timestamptest = ISODateString(new Date());
    var versionID = '2017-03-21';
    var SignatureMethodT = 'HMAC-SHA1';

    var pubgrams = {
        'ClientVersion' : '0.0.1',
        'SignVersion' : '0.0.1',
        'Channel' : 'HTML5',
        'ClientTS' : timeTS,
        'VideoId' : vid,
        'PlaySign' : baseUrlMd5,
        'Format' : 'JSON',
        'Version' : versionID,
        'AccessKeyId' : accessId,
        'SignatureMethod' : SignatureMethodT,
        'Timestamp' : Timestamptest,
        'SignatureVersion' : '1.0',
        'SignatureNonce' : randomNum,
        'Action' : 'GetVideoPlayInfo',
    };

    var outputPub1 = makeUTF8sort(pubgrams,'=','&');

    var pbugramsdic =  outputPub1+'&Signature='+AliyunEncodeURI(makeChangeSiga(pubgrams,accessSecret));

    io.get('//vod.cn-shanghai.aliyuncs.com/?'+pbugramsdic, function(data) {
        if (!data) {
            throw new Error('json data nil!');
        };

        var dataObj = JSON.parse(data);
        if (!dataObj) {
            throw new Error('json dataObj nil!');
        }





        //buisness_id
        that._options.from = dataObj.VideoInfo.CustomerId;

        var rid = dataObj.RequestId;

        var videoId = dataObj.VideoInfo.VideoId;
        var playIn =  JSON.parse(data);
        var atI = dataObj.PlayInfo.AuthInfo;
        var acckid = dataObj.PlayInfo.AccessKeyId;
        var videoSec = dataObj.PlayInfo.AccessKeySecret;
        var ston = dataObj.PlayInfo.SecurityToken;
        var mReg = dataObj.PlayInfo.Region;
        var timemts =  new Date().getTime();
        var ranNum = randomUUID();;
        var playDomain = dataObj.PlayInfo.PlayDomain;
        var Timestampmts = ISODateString(new Date());

        var newAry = {
            'AccessKeyId' : acckid,
            'Action' : 'PlayInfo',
            'MediaId' : videoId,
            'Formats' : 'mp4|m3u8|flv',
            'AuthInfo' : atI,
            'AuthTimeout':'1800',
            'Rand' : ranNum,
            'SecurityToken' : ston,
            'PlayDomain' : playDomain,
            'Format' : 'JSON',
            'Version' : '2014-06-18',
            'SignatureMethod' : SignatureMethodT,
            'Timestamp' : Timestampmts,
            'SignatureVersion' : '1.0',
            'SignatureNonce' : randomNum,
        }
        
        var pbugramsdic =  makeUTF8sort(newAry,'=','&')+'&Signature='+AliyunEncodeURI(makeChangeSiga(newAry,videoSec));

        var httpUrlend = 'https://mts.' + mReg + '.aliyuncs.com/?'+pbugramsdic;

        io.get(httpUrlend,function  (data)  {

            var h5_device_model = UA.IS_PC?'pc_h5':'h5';//判定用户端
            
            if (!dataObj) {
            throw new Error('json data nil!');
            }
            if (data) {

             try{

                var playInfoAry = JSON.parse(data).PlayInfoList.PlayInfo;
                var testurl = '';
                for (var i = playInfoAry.length - 1; i >= 0; i--) {
                    var b =  playInfoAry[i];
                    if (b.format=='mp4') {
                         testurl = b.Url;
                         break;
                    }else{
                      if (b.format == 'm3u8'){;
                         testurl = b.Url;
                        }else{
                         testurl = '';
                        };
                    }
                }

                 var src = testurl;
                 that._options.vid=0;
                 that._options.source=src;

                // 开始监控
                if (that._options['trackLog']) {
                    if (that._monitor) {
                        that._monitor.updateVideoInfo({video_id: vid, album_id: 0, from: that._options.from});
                    }else{
                        that._monitor=new Monitor(this,{video_id: vid, album_id: 0, from: that._options.from});
                    };
                }

                // 可以认为此时player init
                if (!that.loaded) {
                    that.trigger('init'); 
                    if (debug_flag) {
                        console.log('init');
                    }
                };
                
                that.getMetaData();
                that.tag.setAttribute('src', that._options.source);
                that.readyTime = new Date().getTime();
                that.loaded = true;

                //if not preload/autoplay, canplaythrough delete cover; else play delete cover
                if (that.cover && (that._options.preload || that._options.autoplay)) {
                    Dom.css(that.cover, 'display', 'none');
                    delete that.cover;
                }

                that.tag.play();
             } catch(e){
              throw new Error('json data nil!');
             } 
         }

    },function  () {
        throw new Error('PrismPlayer Error: network error!');
    })

}, function() {

 throw new Error('PrismPlayer Error: network error!');
}); 

}

/**
 * 异步获取 控制台 获取url，
 */

Player.prototype.userPramaRequestMts = function () {

    
    var vid = this._options.vid;
    var accessId = this._options.accId;
    var accessSecret = this._options.accSecret;
    var user_stsToken = this._options.stsToken;
    var user_domainRegion = this._options.domainRegion;
    var user_authInfo = this._options.authInfo;
    var user_playDomain = this._options.playDomain;

    var that = this;    
    
    var timemts =  new Date().getTime();
    var randNum = randomUUID();
    var SignatureNonceNum = randomUUID();
    var Timestampmts = ISODateString(new Date());
    var SignatureMethodT = 'HMAC-SHA1';

    if (!vid) {
        throw new Error('PrismPlayer Error: vid should not be null!');
    }
    if (!accessId) {
        throw new Error('PrismPlayer Error: accessId should not be null!');
    }
    if (!accessSecret) {
        throw new Error('PrismPlayer Error: accessSecret should not be null!');
    }
    if (!user_stsToken) {

        throw new Error('PrismPlayer Error: stsToken should not be null!');
    }
    if (!user_domainRegion) {

        throw new Error('PrismPlayer Error: domainRegion should not be null!');
    }
    if (!user_authInfo) {

        throw new Error('PrismPlayer Error: authInfo should not be null!');
    }
    if (!user_playDomain) {

        throw new Error('PrismPlayer Error: playDomain should not be null!');
    }


    var newAry = {
            'AccessKeyId' : accessId,
            'Action' : 'PlayInfo',
            'MediaId' : vid,
            'Formats' : 'mp4|m3u8|flv',
            'AuthInfo' : user_authInfo,
            'AuthTimeout':'1800',
            'Rand' : randNum,
            'SecurityToken' : user_stsToken,
            'PlayDomain' : user_playDomain,
            'Format' : 'JSON',
            'Version' : '2014-06-18',
            'SignatureMethod' : SignatureMethodT,
            'Timestamp' : Timestampmts,
            'SignatureVersion' : '1.0',
            'SignatureNonce' : SignatureNonceNum,
        }
        
        var pbugramsdic =  makeUTF8sort(newAry,'=','&')+'&Signature='+AliyunEncodeURI(makeChangeSiga(newAry,accessSecret));

        var httpUrlend = 'https://mts.' + user_domainRegion + '.aliyuncs.com/?'+pbugramsdic;

        io.get(httpUrlend,function  (data)  {

            var h5_device_model = UA.IS_PC?'pc_h5':'h5';//判定用户端
            
            if (data) {

             try{

                var playInfoAry = JSON.parse(data).PlayInfoList.PlayInfo;
                var testurl = '';
                for (var i = playInfoAry.length - 1; i >= 0; i--) {
                    var b =  playInfoAry[i];
                    if (b.format=='mp4') {
                         testurl = b.Url;
                         break;
                    }else{
                      if (b.format == 'm3u8'){;
                         testurl = b.Url;
                        }else{
                         testurl = '';
                        };
                    }
                }
            
             } catch(e){
              throw new Error('json data nil!');

             }

             that.firstNewUrlloadByUrl(testurl);
              
         }

    },function  () {
        throw new Error('PrismPlayer Error: network error!');
    })
}




//vid playInfo -> mts 2017-04-19
Player.prototype.userPlayInfoAndVidRequestMts = function (vid ,playAuth) {

    this._options.vid = vid;
    this._options.playauth = playAuth;


    var that = this; 
    var vid = that._options.vid;
    var playauth = CryptoJS.enc.Utf8.stringify(CryptoJS.enc.Base64.parse(that._options.playauth));


    var timemts =  new Date().getTime();
    var randNum = randomUUID();
    var SignatureNonceNum = randomUUID();
    var Timestampmts = ISODateString(new Date());
    var SignatureMethodT = 'HMAC-SHA1';

    if (!vid) {
        throw new Error('PrismPlayer Error: vid should not be null!');
    }

    if (!playauth) {
        throw new Error('PrismPlayer Error: playauth should not be null!');
    }

    var playAuthJson = JSON.parse(playauth);

    //buisness_id
        that._options.from = playAuthJson.CustomerId?playAuthJson.CustomerId : '';

    var playAuthAccessId = playAuthJson.AccessKeyId;
    var playAuthAccessSecret = playAuthJson.AccessKeySecret;
    var playAuthStsToken =  playAuthJson.SecurityToken;
    var playAuthJsonDomainRegion = playAuthJson.Region;
    var playauthAuthInfo = playAuthJson.AuthInfo;
    var playauthPlayDomain = playAuthJson.PlayDomain;

    var newAry = {
            'AccessKeyId' : playAuthAccessId,
            'Action' : 'PlayInfo',
            'MediaId' : vid,
            'Formats' : 'mp4|m3u8|flv',
            'AuthInfo' : playauthAuthInfo,
            'AuthTimeout':'1800',
            'Rand' : randNum,
            'SecurityToken' : playAuthStsToken,
            'PlayDomain' : playauthPlayDomain,
            'Format' : 'JSON',
            'Version' : '2014-06-18',
            'SignatureMethod' : SignatureMethodT,
            'Timestamp' : Timestampmts,
            'SignatureVersion' : '1.0',
            'SignatureNonce' : SignatureNonceNum,
        }
        
        var pbugramsdic =  makeUTF8sort(newAry,'=','&')+'&Signature='+AliyunEncodeURI(makeChangeSiga(newAry,playAuthAccessSecret));

        var httpUrlend = 'https://mts.' + playAuthJsonDomainRegion + '.aliyuncs.com/?'+pbugramsdic;

        io.get(httpUrlend,function  (data)  {

            var h5_device_model = UA.IS_PC?'pc_h5':'h5';//判定用户端
            
            if (data) {

             try{

                var playInfoAry = JSON.parse(data).PlayInfoList.PlayInfo;
                var testurl = '';
                for (var i = playInfoAry.length - 1; i >= 0; i--) {
                    var b =  playInfoAry[i];
                    if (b.format=='mp4') {
                         testurl = b.Url;
                         break;
                    }else{
                      if (b.format == 'm3u8'){;
                         testurl = b.Url;
                        }else{
                         testurl = '';
                        };
                    }
                }

                var src = testurl;
                 that._options.vid=0;
                 that._options.source=src;

                                 // 开始监控
                if (that._options['trackLog']) {
                    that._monitor=new Monitor(that, {video_id: vid, album_id: 0, from: that._options.from});
                }
                
                // 可以认为此时player init
                that.trigger('init');
                if (debug_flag) {
                    console.log('init');
                }

                if (that._options.autoplay || that._options.preload) {
                    that.getMetaData();
                    that.tag.setAttribute('src', that._options.source);
                    that.readyTime = new Date().getTime();
                    that.loaded = true;
                }
            
             } catch(e){
              throw new Error('json data nil!');

             }

             // that.firstNewUrlloadByUrl(testurl);
              
         }

    },function  () {
        throw new Error('PrismPlayer Error: network error!');
    })
}

//用于对外接口 ，重新播放
Player.prototype.reloaduserPlayInfoAndVidRequestMts = function (vid ,playAuth) {

    this._options.vid = vid;
    this._options.playauth = playAuth;


    var that = this; 
    var vid = that._options.vid;
    var playauth = CryptoJS.enc.Utf8.stringify(CryptoJS.enc.Base64.parse(that._options.playauth));


    var timemts =  new Date().getTime();
    var randNum = randomUUID();
    var SignatureNonceNum = randomUUID();
    var Timestampmts = ISODateString(new Date());
    var SignatureMethodT = 'HMAC-SHA1';

    if (!vid) {
        throw new Error('PrismPlayer Error: vid should not be null!');
    }

    if (!playauth) {
        throw new Error('PrismPlayer Error: playauth should not be null!');
    }

    var playAuthJson = JSON.parse(playauth);

    //buisness_id
        that._options.from = playAuthJson.CustomerId?playAuthJson.CustomerId : '';

    var playAuthAccessId = playAuthJson.AccessKeyId;
    var playAuthAccessSecret = playAuthJson.AccessKeySecret;
    var playAuthStsToken =  playAuthJson.SecurityToken;
    var playAuthJsonDomainRegion = playAuthJson.Region;
    var playauthAuthInfo = playAuthJson.AuthInfo;
    var playauthPlayDomain = playAuthJson.PlayDomain;

    var newAry = {
            'AccessKeyId' : playAuthAccessId,
            'Action' : 'PlayInfo',
            'MediaId' : vid,
            'Formats' : 'mp4|m3u8|flv',
            'AuthInfo' : playauthAuthInfo,
            'AuthTimeout':'1800',
            'Rand' : randNum,
            'SecurityToken' : playAuthStsToken,
            'PlayDomain' : playauthPlayDomain,
            'Format' : 'JSON',
            'Version' : '2014-06-18',
            'SignatureMethod' : SignatureMethodT,
            'Timestamp' : Timestampmts,
            'SignatureVersion' : '1.0',
            'SignatureNonce' : SignatureNonceNum,
        }
        
        var pbugramsdic =  makeUTF8sort(newAry,'=','&')+'&Signature='+AliyunEncodeURI(makeChangeSiga(newAry,playAuthAccessSecret));

        var httpUrlend = 'https://mts.' + playAuthJsonDomainRegion + '.aliyuncs.com/?'+pbugramsdic;

        io.get(httpUrlend,function  (data)  {

            var h5_device_model = UA.IS_PC?'pc_h5':'h5';//判定用户端
            
            if (data) {

             try{

                var playInfoAry = JSON.parse(data).PlayInfoList.PlayInfo;
                var testurl = '';
                for (var i = playInfoAry.length - 1; i >= 0; i--) {
                    var b =  playInfoAry[i];
                    if (b.format=='mp4') {
                         testurl = b.Url;
                         break;
                    }else{
                      if (b.format == 'm3u8'){;
                         testurl = b.Url;
                        }else{
                         testurl = '';
                        };
                    }
                }

                var src = testurl;
                 that._options.vid=0;
                 that._options.source=src;

                // 开始监控
                if (that._options['trackLog']) {
                    if (that._monitor) {
                        that._monitor.updateVideoInfo({video_id: vid, album_id: 0, from: that._options.from});
                    }else{
                        that._monitor=new Monitor(this,{video_id: vid, album_id: 0, from: that._options.from});
                    };
                }

                // 可以认为此时player init
                if (!that.loaded) {
                    that.trigger('init'); 
                    if (debug_flag) {
                        console.log('init');
                    }
                };
                
                that.getMetaData();
                that.tag.setAttribute('src', that._options.source);
                that.readyTime = new Date().getTime();
                that.loaded = true;

                //if not preload/autoplay, canplaythrough delete cover; else play delete cover
                if (that.cover && (that._options.preload || that._options.autoplay)) {
                    Dom.css(that.cover, 'display', 'none');
                    delete that.cover;
                }

                that.tag.play();
            
             } catch(e){
              throw new Error('json data nil!');

             }

             // that.firstNewUrlloadByUrl(testurl);
              
         }

    },function  () {
        throw new Error('PrismPlayer Error: network error!');
    })
}
/**
 * 异步获取videoinfo，成功后触发readyState的检测hack，
 * 因为有很多ui组件的ui更新需要依赖于metadata（时长、buffered等）
 */
 
 Player.prototype.loadVideoInfo = function() {
    var vid = this._options.vid,
    that = this;

    if (!vid) {
        throw new Error('PrismPlayer Error: vid should not be null!');
    }

    // tv.taobao.com
    io.jsonp('//tv.taobao.com/player/json/getBaseVideoInfo.do?vid=' + vid + '&playerType=3', function(data) {

    // applewatch 和 new iphone的临时修改，由于这个活动访问量较大，接口请求临时走cdn
    //io.jsonp('//www.taobao.com/go/rgn/tv/ajax/applewatch-media.php?vid=' + vid + '&playerType=3', function(data) {

        if (data.status === 1 && data.data.source) {
            var src,
            maxDef = -1;
            _.each(data.data.source, function(k, v) {
                var def = +k.substring(1);
                if (def > maxDef) maxDef = def;
            });
            src = data.data.source['v' + maxDef];
            src = _.unescape(src)/*.replace(/n\.videotest\.alikunlun\.com/g, 'd.tv.taobao.com')*/;
            that._options.source = src;

            // 开始监控
            if (that._options['trackLog']) {
                that._monitor=new Monitor(that, {video_id: vid, album_id: data.data.baseInfo.aid, from: that._options.from});
            }
            
            // 可以认为此时player init
            that.trigger('init');
            if (debug_flag) {
                console.log('init');
            }

            if (that._options.autoplay || that._options.preload) {
                that.getMetaData();
                that.tag.setAttribute('src', that._options.source);
                that.readyTime = new Date().getTime();
                that.loaded = true;
            }

        } else {
            throw new Error('PrismPlayer Error: #vid:' + vid + ' cannot find video resource!');
        }
        
    }, function() {
        throw new Error('PrismPlayer Error: network error!');
    }); 

};


Player.prototype.setControls = function(){
    var options = this.options();
  //如果指定使用系统默认的控制面板
  if(options.useNativeControls){
    this.tag.setAttribute('controls','controls');
}else{
    //否则使用我们自定义的控制面板
    // TODO
    if(typeof options.controls === 'object'){
      //options.controls为controbar的配置项
      var controlBar = this._initControlBar(options.controls);
      this.addChild(controlBar);
  }
}
}
//
Player.prototype._initControlBar = function(options){
    var controlBar = new ControlBar(this,options);
    return controlBar;
}

/** 
 * 获取视频元数据信息
 */
 Player.prototype.getMetaData = function(){
    var that = this, 
    timer = null,
    video = this.tag;

    timer = window.setInterval(function(t){
        if (video.readyState > 0) {
            var vid_duration = Math.round(video.duration);
            that.tag.duration = vid_duration;
            //that.readyTime = new Date().getTime() - that.readyTime;
            that.trigger('readyState');
            if (debug_flag) {
                console.log('readystate');
            }
            clearInterval(timer);
        }
    }, 100);
};

Player.prototype.getReadyTime = function() {
    return this.readyTime;
};

Player.prototype.readyState = function() {
    return this.tag.readyState;
};

Player.prototype.getError = function() {
    return this.tag.error;
};

/* 标准化播放器api
============================================================================= */
//开始播放视频
Player.prototype.play = function(){
    var that = this;
    if (!this._options.autoplay && !this._options.preload && !this.loaded) {
        this.getMetaData();
        this.tag.setAttribute('src', this._options.source);
        this.readyTime = new Date().getTime();
        this.loaded = true;
    }
    //if autoplay, canplaythrough delete cover; else play delete cover
    if (that.cover && (!that._options.autoplay)) {
        Dom.css(that.cover, 'display', 'none');
        delete that.cover;
    }
    this.tag.play();

    return this;
}
//replay
Player.prototype.replay = function(){
    this.seek(0);
    this.tag.play();
    return this;
}
//暂停视频
Player.prototype.pause = function(){
  this.tag.pause();
  return this;
}
//停止视频
Player.prototype.stop = function(){
  this.tag.setAttribute('src',null);
  return this;
}
Player.prototype.paused = function(){
  // The initial state of paused should be true (in Safari it's actually false)
  return this.tag.paused === false ? false : true;
};
//获取视频总时长
Player.prototype.getDuration = function(){
  var totalDuration = this.tag.duration;
  return totalDuration;
}
//设置或者获取当前播放时间

Player.prototype.getCurrentTime = function(){
  var currentTime = this.tag.currentTime;
  return currentTime;
}

Player.prototype.seek = function(time){
    if (time === this.tag.duration) time--;
    try {
        this.tag.currentTime = time;
    } catch(e) {
        console.log(e);
    }
    return this;
}



//通过id加载视频
Player.prototype.loadByVid=function(vid) {
    this._options.vid=vid;
    var that = this;

    if (!vid) {
        throw new Error('PrismPlayer Error: vid should not be null!');
    }



    // tv.taobao.com
    io.jsonp('//tv.taobao.com/player/json/getBaseVideoInfo.do?vid=' + vid + '&playerType=3', function(data) {

    // applewatch 和 new iphone的临时修改，由于这个活动访问量较大，接口请求临时走cdn
    //io.jsonp('//www.taobao.com/go/rgn/tv/ajax/applewatch-media.php?vid=' + vid + '&playerType=3', function(data) {

        if (data.status === 1 && data.data.source) {
            var src,
            maxDef = -1;
            _.each(data.data.source, function(k, v) {
                var def = +k.substring(1);
                if (def > maxDef) maxDef = def;
            });
            src = data.data.source['v' + maxDef];
            src = _.unescape(src)/*.replace(/n\.videotest\.alikunlun\.com/g, 'd.tv.taobao.com')*/;
            that._options.source = src;

            // 开始监控
            if (that._options['trackLog']) {
                if (that._monitor) {
                    that._monitor.updateVideoInfo({video_id: vid, album_id: data.data.baseInfo.aid, from: that._options.from});
                }else{
                    that._monitor=new Monitor(that, {video_id: vid, album_id: data.data.baseInfo.aid, from: that._options.from});
                };
            }

            that._options.autoplay=true;

            
            // 可以认为此时player init
            if (!that.loaded) {
                that.trigger('init'); 
                if (debug_flag) {
                    console.log('init');
                }
            };
            
            that.getMetaData();
            that.tag.setAttribute('src', that._options.source);
            that.readyTime = new Date().getTime();
            that.loaded = true;
            
            //if preload/autoplay, canplaythrough delete cover; else play delete cover
            if (that.cover && that._options.autoplay) {
                Dom.css(that.cover, 'display', 'none');
                delete that.cover;
            }
            that.tag.play();

        } else {
            throw new Error('PrismPlayer Error: #vid:' + vid + ' cannot find video resource!');
        }
        
    }, function() {
        throw new Error('PrismPlayer Error: network error!');
    });        
}


//通过url加载视频,第一次请求视频url，不直接播放。播放由用户手动操作。  2017-04-18
Player.prototype.firstNewUrlloadByUrl=function(url, seconds) {
    this._options.vid=0;
    this._options.source=url;
    // this._options.autoplay=true;
    // var test = this._options.autoplay;
    // 开始监控
    if (this._options['trackLog']) {
        if (this._monitor) {
            this._monitor.updateVideoInfo({video_id: 0, album_id: 0, from: this._options.from});
        }else{
            this._monitor=new Monitor(this,{video_id: 0, album_id: 0, from: this._options.from});
        };
    }

    // 可以认为此时player init
    if (!this.loaded) {
        this.trigger('init'); 
        if (debug_flag) {
            console.log('init');
        }
    };
    
    this.getMetaData();
    this.tag.setAttribute('src', this._options.source);
    this.readyTime = new Date().getTime();
    this.loaded = true;

    //if not preload/autoplay, canplaythrough delete cover; else play delete cover
    if (this.cover && (this._options.preload || this._options.autoplay)) {
        Dom.css(this.cover, 'display', 'none');
        delete this.cover;
    }

    //增加播放时 
    if (this._options.autoplay) {
        this.trigger('play');
    }else{
        this.trigger('pause');
    };

    // this.tag.play();
    if (seconds && !isNaN(seconds)) {
        this.seek(seconds);
    }
}

Player.prototype.loadByUrl=function(url, seconds) {
    this._options.vid=0;
    this._options.source=url;
    this._options.autoplay=true;
    // 开始监控
    if (this._options['trackLog']) {
        if (this._monitor) {
            this._monitor.updateVideoInfo({video_id: 0, album_id: 0, from: this._options.from});
        }else{
            this._monitor=new Monitor(this,{video_id: 0, album_id: 0, from: this._options.from});
        };
    }

    // 可以认为此时player init
    if (!this.loaded) {
        this.trigger('init'); 
        if (debug_flag) {
            console.log('init');
        }
    };
    
    this.getMetaData();
    this.tag.setAttribute('src', this._options.source);
    this.readyTime = new Date().getTime();
    this.loaded = true;

    //if not preload/autoplay, canplaythrough delete cover; else play delete cover
    if (this.cover && (this._options.preload || this._options.autoplay)) {
        Dom.css(this.cover, 'display', 'none');
        delete this.cover;
    }

    this.tag.play();
    if (seconds && !isNaN(seconds)) {
        this.seek(seconds);
    }
}

//播放器销毁方法在清除节点前调用
Player.prototype.dispose=function(){
    this.tag.pause();
    //remove events

    var tag = this.tag,
    that = this;

  //播放过程触发的事件
  Event.off(tag,'timeupdate');
  //开始播放触发事件 
  Event.off(tag, 'play');
  //暂停触发事件 
  Event.off(tag, 'pause');
  Event.off(tag, 'canplay'); 
  Event.off(tag, 'waiting');

  Event.off(tag, 'playing');

  Event.off(tag, 'ended'); 

  Event.off(tag, 'error'); 

  Event.off(tag, 'durationchange');
  Event.off(tag, 'loadedmetadata');
  Event.off(tag, 'loadeddata');
  Event.off(tag, 'progress');
  Event.off(tag, 'canplaythrough');

  Event.off(tag, 'webkitfullscreenchange');
  this.tag=null;
  this._options=null;

  if (this._monitor) {
    this._monitor.removeEvent();
    this._monitor=null;
};
}

//设置静音或者获取是否静音

Player.prototype.mute = function(){
  this.tag.muted = true;
  return this;
}

Player.prototype.unMute = function(){
  this.tag.muted = false;
  return this;
}

Player.prototype.muted = function() {
    return this.tag.muted;
};

//设置或者获取音量
Player.prototype.getVolume = function(){
    return this.tag.volume;
}
//获取配置
Player.prototype.getOptions=function(){
    return this._options;
}
/*
0-1区间
*/
Player.prototype.setVolume = function(volume){
    this.tag.volume = volume;
}
//隐藏进度条控制
Player.prototype.hideProgress = function(){
    var that = this;
    that.trigger('hideProgress');
}
//取消隐藏进度条控制
Player.prototype.cancelHideProgress = function(){
    var that = this;
    that.trigger('cancelHideProgress');
}

//set player size when play
Player.prototype.setPlayerSize = function(input_w, input_h){
    var that = this;
    this._el.style.width = input_w

    if (input_h)
    {
        var per_idx = input_h.indexOf("%");
        if (per_idx > 0)
        {
            var screen_height = window.screen.height;
            var per_value = input_h.replace("%", "");
            if(!isNaN(per_value))
            {
                var scale_value = screen_height * 9 * parseInt(per_value) / 1000;
                this._el.style.height = String(scale_value % 2 ? scale_value + 1: scale_value) + "px";
            }
            else
            {
                this._el.style.height = input_h;
            }
        }
        else
        {
            this._el.style.height = input_h;
        }
    }
}



/*
//no full sreen function call
var fullScreenNoSupportCall = (function() {
    var docHtml  = document.documentElement;
    var docBody  = document.body;
    var videobox  = document.getElementById('videobox');
    var cssText = 'width:100%;height:100%;overflow:hidden;';

    docHtml.style.cssText = cssText;
//    docBody.style.cssText = cssText;
    videobox.style.cssText = cssText+';'+'margin:0px;padding:0px;';
    document.IsFullScreen = true;

})()

//no full sreen function exit
var fullScreenNoSupportExit = (function() {
    var docHtml  = document.documentElement;
    var docBody  = document.body;
    var videobox  = document.getElementById('videobox');

    docHtml.style.cssText = "";
//    docBody.style.cssText = "";
    videobox.style.cssText = "";
    document.IsFullScreen = false;
})()
*/

// 检测fullscreen的支持情况，即时函数
var __supportFullscreen = (function() {
    var prefix, requestFS, div;

    div = Dom.createEl('div');
    requestFS = {};

    var apiMap = [
      // Spec: https://dvcs.w3.org/hg/fullscreen/raw-file/tip/Overview.html
      [
      'requestFullscreen',
      'exitFullscreen',
      'fullscreenElement',
      'fullscreenEnabled',
      'fullscreenchange',
      'fullscreenerror',
      'fullScreen'
      ],
      // WebKit
      [
      'webkitRequestFullscreen',
      'webkitExitFullscreen',
      'webkitFullscreenElement',
      'webkitFullscreenEnabled',
      'webkitfullscreenchange',
      'webkitfullscreenerror',
      'webkitfullScreen'
      ],
      // Old WebKit(Safari 5.1)
      [
      'webkitRequestFullScreen',
      'webkitCancelFullScreen',
      'webkitCurrentFullScreenElement',
      'webkitFullscreenEnabled',
      'webkitfullscreenchange',
      'webkitfullscreenerror',
      'webkitIsFullScreen'
      ],
      // // safari iOS
      // [
      //   'webkitEnterFullscreen',
      //   'webkitExitFullscreen',
      //   'webkitCurrentFullScreenElement',
      //   'webkitCancelFullScreen',
      //   'webkitfullscreenchange',
      //   'webkitfullscreenerror',
      //   'webkitDisplayingFullscreen'
      // ],
      // Mozilla
      [
      'mozRequestFullScreen',
      'mozCancelFullScreen',
      'mozFullScreenElement',
      'mozFullScreenEnabled',
      'mozfullscreenchange',
      'mozfullscreenerror',
      'mozfullScreen'
      ],
      // Microsoft
      [
      'msRequestFullscreen',
      'msExitFullscreen',
      'msFullscreenElement',
      'msFullscreenEnabled',
      'MSFullscreenChange',
      'MSFullscreenError',
      'MSFullScreen'
      ]
      ];

      if (UA.IS_IOS) {
        //IOS 特殊处理
        requestFS.requestFn="webkitEnterFullscreen";
        requestFS.cancelFn="webkitExitFullscreen";
        requestFS.eventName="webkitfullscreenchange";
        requestFS.isFullScreen ="webkitDisplayingFullscreen";
    }else{
        var l=5;
        for (var i = 0; i < l; i++) {
          // check for exitFullscreen function
          if (apiMap[i][1] in document) {
            requestFS.requestFn=apiMap[i][0];
            requestFS.cancelFn=apiMap[i][1];
            requestFS.eventName=apiMap[i][4];
            requestFS.isFullScreen =apiMap[i][6];
            break;
        }
    }

        //modify if has write fun
        //full screen
        if ( 'requestFullscreen' in document) {
            requestFS.requestFn='requestFullscreen';
        } else if ( 'webkitRequestFullscreen' in document ) {
            requestFS.requestFn='webkitRequestFullscreen';
        } else if ( 'webkitRequestFullScreen' in document ) {
            requestFS.requestFn='webkitRequestFullScreen';
        } else if ( 'webkitEnterFullscreen' in document ) {
            requestFS.requestFn='webkitEnterFullscreen';
        } else if ( 'mozRequestFullScreen' in document ) {
            requestFS.requestFn='mozRequestFullScreen';
        } else if ( 'msRequestFullscreen' in document ) {
            requestFS.requestFn='msRequestFullscreen';
        }

        //full screen change
        if ( 'fullscreenchange' in document) {
            requestFS.eventName='fullscreenchange';
        } else if ( 'webkitfullscreenchange' in document ) {
            requestFS.eventName='webkitfullscreenchange';
        } else if ( 'webkitfullscreenchange' in document ) {
            requestFS.eventName='webkitfullscreenchange';
        } else if ( 'webkitfullscreenchange' in document ) {
            requestFS.eventName='webkitfullscreenchange';
        } else if ( 'mozfullscreenchange' in document ) {
            requestFS.eventName='mozfullscreenchange';
        } else if ( 'MSFullscreenChange' in document ) {
            requestFS.eventName='MSFullscreenChange';
        }

        //full screen status
        if ( 'fullScreen' in document) {
            requestFS.isFullScreen='fullScreen';
        } else if ( 'webkitfullScreen' in document ) {
            requestFS.isFullScreen='webkitfullScreen';
        } else if ( 'webkitIsFullScreen' in document ) {
            requestFS.isFullScreen='webkitIsFullScreen';
        } else if ( 'webkitDisplayingFullscreen' in document ) {
            requestFS.isFullScreen='webkitDisplayingFullscreen';
        } else if ( 'mozfullScreen' in document ) {
            requestFS.isFullScreen='mozfullScreen';
        } else if ( 'MSFullScreen' in document ) {
            requestFS.isFullScreen='MSFullScreen';
        }

    };


    // 如果浏览器实现了W3C标准的定义
    /*if (div.cancelFullscreen !== undefined) {
        requestFS.requestFn = 'requestFullscreen';
        requestFS.cancelFn = 'cancelFullscreen';
        requestFS.eventName = 'fullscreenchange';
        requestFS.isFullScreen = 'fullScreen';

        // 如果是webkit和mozilla内核，调用全屏接口时需要带前缀
    } else {
        if (document.mozCancelFullScreen) {
            prefix = 'moz';
            requestFS.isFullScreen = prefix + 'FullScreen';
        } else {
            prefix = 'webkit';
            requestFS.isFullScreen = prefix + 'IsFullScreen';
        }

        if (div[prefix + 'RequestFullScreen']) {
            requestFS.requestFn = prefix + 'RequestFullScreen';
            requestFS.cancelFn = prefix + 'CancelFullScreen';
        }else if( div[prefix + 'EnterFullScreen']){
            requestFS.requestFn=prefix + 'EnterFullScreen';
            if(div[prefix + 'CancelFullScreen']){
                requestFS.cancelFn = prefix + 'CancelFullScreen';
            }else if(div[prefix + 'ExitFullscreen']){
                requestFS.cancelFn = prefix + 'ExitFullscreen';
            }
        }
        requestFS.eventName = prefix + 'fullscreenchange';
    }*/

    if (requestFS.requestFn) {
        return requestFS;
    }
    // 如果浏览器不支持全屏接口，返回null
    return null;
})();
// 注意，即时函数

/**
 * 不支持fullscreenAPI时的全屏模拟
 *
 * @method _enterFullWindow
 * @private
 */
 Player.prototype._enterFullWindow = function() {
    var that = this;

    this.isFullWindow = true;
    this.docOrigOverflow = document.documentElement.style.overflow;

    document.documentElement.style.overflow = 'hidden';
    Dom.addClass(document.getElementsByTagName('body')[0], 'prism-full-window');
    //this.trigger('enterfullwindow');
};

/**
 * 不支持fullscreenAPI时的取消全屏模拟
 *
 * @method _exitFullWindow
 * @private
 */
 Player.prototype._exitFullWindow = function() {
    this.isFullWindow = false;

    document.documentElement.style.overflow = this.docOrigOverflow;
    Dom.removeClass(document.getElementsByTagName('body')[0], 'prism-full-window');
    //this.trigger('exitfullwindow');
};

/**
 * 设置全屏
 *
 * @method requestFullScreen
 */
 Player.prototype.requestFullScreen = function() {
    var requestFullScreen = __supportFullscreen,
    conTag = this.el(),
    that = this;

    if (UA.IS_IOS) {
        conTag=this.tag;
        conTag[requestFullScreen.requestFn]();

        return this;
    };

    this.isFullScreen = true;

    // 如果浏览器支持全屏接口
    if (requestFullScreen) {
        Event.on(document, requestFullScreen.eventName, function(e) {
            that.isFullScreen = document[requestFullScreen.isFullScreen];
            if (that.isFullScreen === true) {
                Event.off(document, requestFullScreen.eventName);
            }
            that.trigger('requestFullScreen');
        });
        conTag[requestFullScreen.requestFn]();

        // 如果不支持全屏接口，则模拟实现
    } else {
        this._enterFullWindow();
        this.trigger('requestFullScreen');
    }

    return this;
};

/**
 * 取消全屏
 *
 * @method cancelFullScreen
 */
 Player.prototype.cancelFullScreen = function() {
    var requestFullScreen = __supportFullscreen,
    that = this;

    this.isFullScreen = false;

    if (requestFullScreen) {
        Event.on(document, requestFullScreen.eventName, function(e) {
            that.isFullScreen = document[requestFullScreen.isFullScreen];

            if (that.isFullScreen === false) {
                Event.off(document, requestFullScreen.eventName);
            }

            that.trigger('cancelFullScreen');
        });
        
        document[requestFullScreen.cancelFn]();

        this.trigger('play');
    } else {
        this._exitFullWindow();
        this.trigger('cancelFullScreen');
        this.trigger('play');
    }

    return this;
};

/**
 * 是否处于全屏
 *
 * @method getIsFullScreen
 * @return {Boolean} 是否为全屏
 */
 Player.prototype.getIsFullScreen = function() {
    return this.isFullScreen;
};

/**
 * 获取已经缓存的时间区间
 *
 * @method getBuffered
 * @return {Array} 时间区间数组timeRanges
 */
 Player.prototype.getBuffered = function() {
    return this.tag.buffered;
};

//设置是否启用toast信息提示
Player.prototype.setToastEnabled=function(enabled){
    //for flash
    //this._invoke('setToastEnabled');
};

//设置是否显示loading
Player.prototype.setLoadingInvisible=function(){
    //for flash
    //this_invoke('setLoadingInvisible');
}

module.exports = Player;

},{"../lib/dom":39,"../lib/event":40,"../lib/io":42,"../lib/object":44,"../lib/ua":46,"../monitor/monitor":49,"../ui/component":52,"../ui/exports":62,"crypto-js":9}],52:[function(require,module,exports){
var oo = require('../lib/oo');
var Data = require('../lib/data');
var _ = require('../lib/object');
var Dom = require('../lib/dom');
var Event = require('../lib/event'); 
var Fn = require('../lib/function');
var Layout = require('../lib/layout');

var Component = oo.extend({
	init: function (player, options) {
		var that = this;

		this._player = player;

		// Make a copy of prototype.options_ to protect against overriding global defaults
		this._options = _.copy(options);
		this._el = this.createEl();
		this._id = player.id() + '_component_' + Data.guid();

		this._children = [];
		this._childIndex = {};

		// 只有组件真正被添加到dom树中后再同步ui、绑定事件
		// 从而避免获取不到dom元素
		this._player.on('uiH5Ready', function() {
			that.renderUI();
			that.syncUI();
			that.bindEvent();
		});
	}
});

/**
 * 渲染ui 
 */
Component.prototype.renderUI = function() {
	// 根据ui组件的配置渲染layout
	Layout.render(this.el(), this.options());
	// 设置id
	this.el().id = this.id();
};

/**
 * 同步ui状态，子类中实现
 */
Component.prototype.syncUI = function() {};

/**
 * 绑定事件，子类中实现
 */
Component.prototype.bindEvent = function() {};

/**
 * 生成compoent的dom元素
 *
 */
Component.prototype.createEl = function(tagName, attributes){
  return Dom.createEl(tagName, attributes);
};

/**
 * 获取component的所有配置项
 *
 */

Component.prototype.options = function(obj){
  if (obj === undefined) return this._options;

  return this._options = _.merge(this._options, obj);
};

/**
 * 获取componet的dom元素
 *
 */
Component.prototype.el = function(){
  return this._el;
};


Component.prototype._contentEl;


Component.prototype.player = function(){
  return this._player;
}

/**
 * Return the component's DOM element for embedding content.
 * Will either be el_ or a new element defined in createEl.
 *
 * @return {Element}
 */
Component.prototype.contentEl = function(){
  return this._contentEl || this._el;
};

/**
 * 设置元素id
 *
 */

Component.prototype._id;

/**
 * 获取元素id
 *
 */
Component.prototype.id = function(){
  return this._id;
};

/* 子元素相关操作
============================================================================= */

/**
 * 添加所有子元素
 *
 */
Component.prototype.addChild = function(child, options){
    var component, componentClass, componentName, componentId;

    // 如果child是一个字符串
    if(typeof child === 'string'){
      if(!this._player.UI[child]) return;
      component = new this._player.UI[child](this._player,options);
    }else{
    // child是一个compnent对象
      component = child;
    }

    //
    this._children.push(component);

    if (typeof component.id === 'function') {
      this._childIndex[component.id()] = component;
    }

    // 把子元素的dom元素插入父元素中
    if (typeof component['el'] === 'function' && component['el']()) {
      this.contentEl().appendChild(component['el']());
    }

    // 返回添加的子元素
    return component;
};
/**
 * 删除指定的子元素
 *
 */
Component.prototype.removeChild = function(component){

    if (!component || !this._children) return;

    var childFound = false;
    for (var i = this._children.length - 1; i >= 0; i--) {
      if (this._children[i] === component) {
        childFound = true;
        this._children.splice(i,1);
        break;
      }
    }

    if (!childFound) return;

    this._childIndex[component.id] = null;

    var compEl = component.el();
    if (compEl && compEl.parentNode === this.contentEl()) {
      this.contentEl().removeChild(component.el());
    }
};
/**
 * 初始化所有子元素
 *
 */
Component.prototype.initChildren = function(){
  var parent, children, child, name, opts;

  parent = this;
  children = this.options()['children'];

  if (children) {
    // 如果多个子元素是一个数组
    if (_.isArray(children)) {
      for (var i = 0; i < children.length; i++) {
        child = children[i];

        if (typeof child == 'string') {
          name = child;
          opts = {};
        } else {
          name = child.name;
          opts = child;
        }

        parent.addChild(name, opts);
      }
    } else {
      _.each(children, function(name, opts){
        // Allow for disabling default components
        // e.g. vjs.options['children']['posterImage'] = false
        if (opts === false) return;

        parent.addChild(name, opts);
      });
    }
  }
};


/* 事件操作
============================================================================= */

/**
 * 在component上的的dom元素上添加一个事件监听器
 *
 *     var myFunc = function(){
 *       var myPlayer = this;
 *       // Do something when the event is fired
 *     };
 *
 *     myPlayer.on("eventName", myFunc);
 *
 * The context will be the component.
 *
 * @param  {String}   type The event type e.g. 'click'
 * @param  {Function} fn   The event listener
 * @return {Component} self
 */
Component.prototype.on = function(type, fn){

  Event.on(this._el, type, Fn.bind(this, fn));
  return this;
};

/**
 * 从component上删除指定事件的监听器
 *
 *     myComponent.off("eventName", myFunc);
 *
 * @param  {String=}   type Event type. Without type it will remove all listeners.
 * @param  {Function=} fn   Event listener. Without fn it will remove all listeners for a type.
 * @return {Component}
 */
Component.prototype.off = function(type, fn){
  Event.off(this._el, type, fn);
  return this;
};

/**
 * 在组件的元素上添加一个只执行一次的事件监听器
 *
 * @param  {String}   type Event type
 * @param  {Function} fn   Event listener
 * @return {Component}
 */
Component.prototype.one = function(type, fn) {
  Event.one(this._el, type, Fn.bind(this, fn));
  return this;
};

/**
 * 在组件的元素上触发一个事件
 */
Component.prototype.trigger = function(event,paramData){
  //
  if(paramData){
    this._el.paramData = paramData;
  }
  Event.trigger(this._el, event);
  return this;
};

/* 组件展现
============================================================================= */

/**
 * 在component上添加指定的className
 *
 * @param {String} classToAdd Classname to add
 * @return {Component}
 */
Component.prototype.addClass = function(classToAdd){
  Dom.addClass(this._el, classToAdd);
  return this;
};

/**
 * 从component删除指定的className
 *
 * @param {String} classToRemove Classname to remove
 * @return {Component}
 */
Component.prototype.removeClass = function(classToRemove){
  Dom.removeClass(this._el, classToRemove);
  return this;
};

/**
 * 显示组件
 *
 * @return {Component}
 */
Component.prototype.show = function(){
  this._el.style.display = 'block';
  return this;
};

/**
 * 隐藏组件
 *
 * @return {Component}
 */
Component.prototype.hide = function(){
  this._el.style.display = 'none';
  return this;
};

/**
 * 销毁component
 *
 * @return 
 */

Component.prototype.destroy = function(){
    this.trigger({ type: 'destroy', 'bubbles': false });

    // 销毁所有子元素
    if (this._children) {
      for (var i = this._children.length - 1; i >= 0; i--) {
        if (this._children[i].destroy) {
          this._children[i].destroy();
        }
      }
    }

    // 删除所有children引用
    this.children_ = null;
    this.childIndex_ = null;

    // 删除所有事件监听器.
    this.off();

    // 从dom中删除所有元素
    if (this._el.parentNode) {
      this._el.parentNode.removeChild(this._el);
    }
    // 删除所有data引用
    Data.removeData(this._el);
    this._el = null;
};

module.exports = Component;

},{"../lib/data":38,"../lib/dom":39,"../lib/event":40,"../lib/function":41,"../lib/layout":43,"../lib/object":44,"../lib/oo":45}],53:[function(require,module,exports){
/**
 * @fileoverview 大播放按钮
 */
var Component = require('../component');
var Dom = require('../../lib/dom');

var BigPlayButton = Component.extend({
	init: function  (player, options) {
		var that = this;
		Component.call(this, player, options);
		this.addClass(options.className || 'prism-big-play-btn');
	},
	
	bindEvent: function() {
		var that = this;

		this._player.on('play', function(){
			that.addClass('playing');
			Dom.css(that.el(), 'display', 'none');
		});

		this._player.on('pause', function(){
			that.removeClass('playing');
			Dom.css(that.el(), 'display', 'block');
		});

		this.on('click', function() {
			if (that._player.paused()) {
				that._player.play();
				Dom.css(that.el(), 'display', 'none');
			}
		});
	}
});

module.exports = BigPlayButton;

},{"../../lib/dom":39,"../component":52}],54:[function(require,module,exports){
/**
 * @fileoverview 控制条组件
*/
var Component = require('../component');

var ControlBar = Component.extend({
	init: function(player,options) {
		Component.call(this, player, options);
		this.addClass(options.className || 'prism-controlbar');
		this.initChildren();
		this.onEvent();
	},
	createEl: function() {
		var el = Component.prototype.createEl.call(this);
		el.innerHTML = '<div class="prism-controlbar-bg"></div>'
		return el;
	},
	onEvent: function(){
		var player = this.player();
		var that = this;
		
		this.timer = null;

		player.on('click',function(e){
			e.preventDefault();
			e.stopPropagation();
			that._show();
			that._hide();
		});
		player.on('ready',function(){
			that._hide();
		});
		this.on('touchstart', function() {
			that._show();
		});
		this.on('touchmove', function() {
			that._show();
		});
		this.on('touchend', function() {
			that._hide();
		});
	},
	_show: function() {
		this.show();
        this._player.trigger('showBar');
		if (this.timer) {
			clearTimeout(this.timer);
			this.timer = null;
		}
	},
	_hide: function(){
		var that = this;
		var player = this.player();
        var curOptions = player.options();
        var hideTime = curOptions.showBarTime;
		this.timer = setTimeout(function(){
			that.hide();
            that._player.trigger('hideBar');
		}, hideTime);
	}
});

module.exports = ControlBar;

},{"../component":52}],55:[function(require,module,exports){
/**
 * @fileoverview 全屏按钮
 */
var Component = require('../component');

var FullScreenButton = Component.extend({
	init: function  (player,options) {
		var that = this;
		Component.call(this, player, options);
		this.addClass(options.className || 'prism-fullscreen-btn');
	},

	bindEvent: function() {
		var that = this;

		this._player.on('requestFullScreen', function() {
			that.addClass('fullscreen');
		});

		this._player.on('cancelFullScreen', function() {
			that.removeClass('fullscreen');
		});

		this.on('click', function() {
            //alert("click_full_status:" + this._player.getIsFullScreen());
			if (!this._player.getIsFullScreen()) {
				this._player.requestFullScreen();	
			} else {
				this._player.cancelFullScreen();
			}
		});
	}
});

module.exports = FullScreenButton;

},{"../component":52}],56:[function(require,module,exports){
/**
 * Created by yuyingjie on 2017/3/24.
 */
"use strict";
/**
 * @fileoverview 大播放按钮
 */
var Component = require('../component');
var Dom = require('../../lib/dom');

var H5_Loading = Component.extend({
  init: function (player, options) {
    var that = this;
    Component.call(this, player, options);
    this.addClass(options.className || 'prism-hide');
  },

  createEl: function () {
    var el = Component.prototype.createEl.call(this, 'div');
    el.innerHTML = '<div class="circle"></div> <div class="circle1"></div>';
    return el;
  },
  _loading_hide: function (e) {
    var that = this,
      loadingNode = document.querySelector('#' + that.id() + ' .prism-loading');
    if (loadingNode) {
      loadingNode.className = "prism-hide";
    }
  },
  _loading_show: function (e) {
    var that = this,
      loadingNode = document.querySelector('#' + that.id() + ' .prism-hide');
    if (loadingNode) {
      loadingNode.className = "prism-loading";
    }
  },
  bindEvent: function () {
    var that = this;
    that._player.on('h5_loading_show', that._loading_show);
    that._player.on('h5_loading_hide', that._loading_hide);
  }
});

module.exports = H5_Loading;

},{"../../lib/dom":39,"../component":52}],57:[function(require,module,exports){
/**
 * @fileoverview 直播状态 icon
 */
var Component = require('../component');
var Util = require('../../lib/util');

var LiveDisplay = Component.extend({
	init: function  (player,options) {
		var that = this;
		Component.call(this, player, options);

		this.className = options.className ? options.className : 'prism-live-display';
		this.addClass(this.className);
	}
});

module.exports = LiveDisplay;
},{"../../lib/util":48,"../component":52}],58:[function(require,module,exports){
/**
 * @fileoverview 播放按钮
 */
var Component = require('../component');

var PlayButton = Component.extend({
	init: function  (player, options) {
		var that = this;
		Component.call(this, player, options);
		this.addClass(options.className || 'prism-play-btn');
	},
	
	bindEvent: function() {
		var that = this;

		this._player.on('play', function(){
			that.addClass('playing');
		});
		
		this._player.on('pause', function(){
			that.removeClass('playing');
		});

		this.on('click', function() {
            //alert("click_play:" + that._player.paused())
			if (that._player.paused()) {
				that._player.play();
				that.addClass('playing');
			} else {
				that._player.pause();
				that.removeClass('playing');
			}
		});
	}
});

module.exports = PlayButton;

},{"../component":52}],59:[function(require,module,exports){
/**
 * @fileoverview 进度条
 */
var Component = require('../component');
var Dom = require('../../lib/dom');
var Event = require('../../lib/event');
var UA = require('../../lib/ua');
var Fn = require('../../lib/function');

var Progress = Component.extend({
	init: function (player, options) {
		var that = this;
		Component.call(this, player, options);

		this.className = options.className ? options.className : 'prism-progress';
		this.addClass(this.className);
	},

	createEl: function() {
		var el = Component.prototype.createEl.call(this);
		el.innerHTML = '<div class="prism-progress-loaded"></div>'
				     + '<div class="prism-progress-played"></div>'
				   	 + '<div class="prism-progress-cursor"></div>';
		return el;
	},

	bindEvent: function() {
		var that = this;
		
		this.loadedNode = document.querySelector('#' + this.id() + ' .prism-progress-loaded');
		this.playedNode = document.querySelector('#' + this.id() + ' .prism-progress-played');
		this.cursorNode = document.querySelector('#' + this.id() + ' .prism-progress-cursor');
        this.controlNode = document.getElementsByClassName("prism-controlbar")[0];

		Event.on(this.cursorNode, 'mousedown', function(e) {that._onMouseDown(e);});
		Event.on(this.cursorNode, 'touchstart', function(e) {that._onMouseDown(e);});
		Event.on(this._el, 'click', function(e) {that._onMouseClick(e);});
		this._player.on('hideProgress', function(e) {that._hideProgress(e);});
		this._player.on('cancelHideProgress', function(e) {that._cancelHideProgress(e);});
		
		this.bindTimeupdate = Fn.bind(this, this._onTimeupdate);
		this._player.on('timeupdate', this.bindTimeupdate);
			
		// ipad下播放无法触发progress事件，原因待查
		if (UA.IS_IPAD) {
			this.interval = setInterval(function() {
				that._onProgress();
			}, 500);
		} else {
			this._player.on('progress', function() {that._onProgress();});
		}
	},

    //取消控制进度条
	_hideProgress: function(e) {
		var that = this;
		Event.off(this.cursorNode, 'mousedown');
		Event.off(this.cursorNode, 'touchstart');
     },

    //打开控制进度条
    _cancelHideProgress: function(e) {
		var that = this;
		Event.on(this.cursorNode, 'mousedown', function(e) {that._onMouseDown(e);});
		Event.on(this.cursorNode, 'touchstart', function(e) {that._onMouseDown(e);});
     },


    

    //handle click
    _onMouseClick: function(e) {
        var that = this;
        //解决鼠标 和 进度条 不统一bug
		var x = this.el().offsetLeft;
    	var b = this.el();

    	while(b = b.offsetParent)
    	{
        	x += b.offsetLeft;
    	}
        var pageX = e.touches? e.touches[0].pageX: e.pageX,
			distance = pageX - x,//,this.el().offsetLeft,
			width = this.el().offsetWidth,
			sec = (this._player.getDuration()) ? distance / width * this._player.getDuration(): 0;

		if (sec < 0) sec = 0;
		if (sec > this._player.getDuration()) sec = this._player.getDuration();

		this._player.trigger('seekStart', {fromTime: this._player.getCurrentTime()});
		this._player.seek(sec);
        
		this._player.play();
		this._player.trigger('seekEnd', {toTime: this._player.getCurrentTime()});
    },

	_onMouseDown: function(e) {
		var that = this;

		e.preventDefault();
		//e.stopPropagation();

		this._player.pause();
		this._player.trigger('seekStart', {fromTime: this._player.getCurrentTime()});

		Event.on(this.controlNode, 'mousemove', function(e) {that._onMouseMove(e);});
		//Event.on(this.cursorNode, 'mouseup', function(e) {that._onMouseUp(e);});
		Event.on(this.controlNode, 'touchmove', function(e) {that._onMouseMove(e);});
		//Event.on(this.cursorNode, 'touchend', function(e) {that._onMouseUp(e);});

		Event.on(this._player.tag, 'mouseup', function(e) {that._onPlayerMouseUp(e);});
		Event.on(this._player.tag, 'touchend', function(e) {that._onPlayerMouseUp(e);});
		Event.on(this.controlNode, 'mouseup', function(e) {that._onControlBarMouseUp(e);});
		Event.on(this.controlNode, 'touchend', function(e) {that._onControlBarMouseUp(e);});
	},

	_onMouseUp: function(e) {
		var that = this;
		e.preventDefault();

		Event.off(this.controlNode, 'mousemove');
		//Event.off(this.cursorNode, 'mouseup');
		Event.off(this.controlNode, 'touchmove');
		//Event.off(this.cursorNode, 'touchend');
		Event.off(this._player.tag, 'mouseup');
		Event.off(this._player.tag, 'touchend');
		Event.off(this.controlNode, 'mouseup');
		Event.off(this.controlNode, 'touchend');
		
		// 设置当前时间，播放视频
		var sec = this.playedNode.offsetWidth / this.el().offsetWidth * this._player.getDuration();
        var sec_now = this._player.getDuration();
		this._player.seek(sec);
		this._player.play();
		this._player.trigger('seekEnd', {toTime: this._player.getCurrentTime()});
	},

	_onControlBarMouseUp: function(e) {
		var that = this;
		e.preventDefault();

		Event.off(this.controlNode, 'mousemove');
		//Event.off(this.cursorNode, 'mouseup');
		Event.off(this.controlNode, 'touchmove');
		//Event.off(this.cursorNode, 'touchend');
		Event.off(this._player.tag, 'mouseup');
		Event.off(this._player.tag, 'touchend');
		Event.off(this.controlNode, 'mouseup');
		Event.off(this.controlNode, 'touchend');
		
		// 设置当前时间，播放视频
		var sec = this.playedNode.offsetWidth / this.el().offsetWidth * this._player.getDuration();
        var sec_now = this._player.getDuration();
		this._player.seek(sec);
		
		this._player.play();
		this._player.trigger('seekEnd', {toTime: this._player.getCurrentTime()});
	},


	_onPlayerMouseUp: function(e) {
		var that = this;
		e.preventDefault();

		Event.off(this.controlNode, 'mousemove');
		//Event.off(this.cursorNode, 'mouseup');
		Event.off(this.controlNode, 'touchmove');
		//Event.off(this.cursorNode, 'touchend');
		Event.off(this._player.tag, 'mouseup');
		Event.off(this._player.tag, 'touchend');
		Event.off(this.controlNode, 'mouseup');
		Event.off(this.controlNode, 'touchend');
		
		// 设置当前时间，播放视频
		var sec = this.playedNode.offsetWidth / this.el().offsetWidth * this._player.getDuration();
        var sec_now = this._player.getDuration();
        if(!isNaN(sec))
        {
		    this._player.seek(sec);
		    this._player.play();
        }

		this._player.trigger('seekEnd', {toTime: this._player.getCurrentTime()});
	},

	_onMouseMove: function(e) {
		e.preventDefault();
		//e.stopPropagation();

		
		//解决鼠标 和 进度条 不统一bug
		var x = this.el().offsetLeft;
    	var b = this.el();

    	while(b = b.offsetParent)
    	{
        	x += b.offsetLeft;
    	}

		var pageX = e.touches? e.touches[0].pageX: e.pageX,
		distance = pageX - x,//this.el().offsetLeft,
		width = this.el().offsetWidth,
		sec = (this._player.getDuration()) ? distance / width * this._player.getDuration(): 0;

		if (sec < 0) sec = 0;
		if (sec > this._player.getDuration()) sec = this._player.getDuration();

		this._player.seek(sec);
        
		this._player.play();
		this._updateProgressBar(this.playedNode, sec);
		this._updateCursorPosition(sec);
	},

	_onTimeupdate: function(e) {
		// ios下
		// 为了解决seek会跳转到原来的位置，需要进入lock的机制。。。丑陋的代码
		// 只有当前时刻与seekto的时刻间隔小于1秒，并且连续三次，才放开lock
		/*
		if (S.UA.ios) {
			var thre = Math.abs(this._player.getCurrentTime() - this._player.getLastSeekTime());
			if (this._player.getSeekLock()) {
				if (thre < 1 && this.lockCount > 3) {
					this._player.setSeekLock(false);
					this.lockCount = 1;
				} else if (thre < 1){
					this.lockCount++;
				}
			}

			if (!this._player.getSeekLock() ) {
				this._updateProgressBar(this.playedNode, this._player.getCurrentTime());
				this._updateCursorPosition(this._player.getCurrentTime());
				this._updateTip(this._player.getCurrentTime());
				
				this._player.fire('updateProgressBar', {
					time: this._player.getCurrentTime()
				});
			}
		
		} else {
		*/
		this._updateProgressBar(this.playedNode, this._player.getCurrentTime());
		this._updateCursorPosition(this._player.getCurrentTime());
		
		this._player.trigger('updateProgressBar', {
			time: this._player.getCurrentTime()
		});
		//}
	},

	_onProgress: function(e) {
		// 此时buffer可能还没有准备好
		if (this._player.getDuration()) {
            if(this._player.getBuffered().length>=1)
            {
                this._updateProgressBar(this.loadedNode, this._player.getBuffered().end(this._player.getBuffered().length - 1));
            }
		}
	},

	_updateProgressBar: function(node, sec) {
		var percent = (this._player.getDuration()) ? sec / this._player.getDuration(): 0;
		if (node) {
			Dom.css(node, 'width', (percent * 100) + '%');
		};		
	},

	_updateCursorPosition: function(sec) {
		var percent = (this._player.getDuration()) ? sec / this._player.getDuration(): 0;
		if (this.cursorNode) {
			Dom.css(this.cursorNode, 'left', (percent * 100) + '%');
		};
	}
});

module.exports = Progress;

},{"../../lib/dom":39,"../../lib/event":40,"../../lib/function":41,"../../lib/ua":46,"../component":52}],60:[function(require,module,exports){
/**
 * @fileoverview 播放时间
 */
var Component = require('../component');
var Util = require('../../lib/util');

var TimeDisplay = Component.extend({
	init: function  (player,options) {
		var that = this;
		Component.call(this, player, options);

		this.className = options.className ? options.className : 'prism-time-display';
		this.addClass(this.className);
	},

	createEl: function() {
		var el = Component.prototype.createEl.call(this,'div');
		el.innerHTML = '<span class="current-time">00:00</span> <span class="time-bound">/</span> <span class="duration">00:00</span>';
		return el;
	},

	bindEvent: function() {
		var that = this;

		this._player.on('durationchange', function() {
			var dur = Util.formatTime(that._player.getDuration());
			if (dur) {
				document.querySelector('#' + that.id() + ' .time-bound').style.display = 'inline';
				document.querySelector('#' + that.id() + ' .duration').style.display = 'inline';
				document.querySelector('#' + that.id() + ' .duration').innerText = dur;
			} else {
				document.querySelector('#' + that.id() + ' .duration').style.display = 'none';
				document.querySelector('#' + that.id() + ' .time-bound').style.display = 'none';
			}
		});

		this._player.on('timeupdate', function() {
            //var curr_time = that._player.getCurrentTime();
			var curr = Util.formatTime(that._player.getCurrentTime());

            /*
            if (!this._player.last_curT) {
                this._player.last_curT = curr_time;
            }
            else {
                var diff = curr - this._player.last_curT;
                console.log("diff_time" + diff);
                this._player.last_curT = curr_time;
            }
            */
            var curTime = document.querySelector('#' + that.id() + ' .current-time');
            if (!curTime) {return };
			if (curr) {

				document.querySelector('#' + that.id() + ' .current-time').style.display = 'inline';
				document.querySelector('#' + that.id() + ' .current-time').innerText = curr;
			} else {
				document.querySelector('#' + that.id() + ' .current-time').style.display = 'none';
			}
		});
	}
});

module.exports = TimeDisplay;

},{"../../lib/util":48,"../component":52}],61:[function(require,module,exports){
/**
 * @fileoverview 音量按钮，h5下只做静音非静音的控制
 */
var Component = require('../component');

var Volume = Component.extend({
	init: function  (player, options) {
		var that = this;
		Component.call(this, player, options);
		this.addClass(options.className || 'prism-volume');
	},
	
	bindEvent: function() {
		var that = this;
		
		this.on('click', function() {
			if (that._player.muted()) {
				that._player.unMute();
				that.removeClass('mute');
			} else {
				that._player.mute();
				that.addClass('mute');
			}
		});
	}
});

module.exports = Volume;

},{"../component":52}],62:[function(require,module,exports){
/**
 * @fileoverview ui组件列表，fullversion会将定义的所有ui组件列于此做统一加载
 *               后期补上根据实际需求配置组件列表，从而一定程度上减少体积
 * @author 首作<aloysious.ld@taobao.com>
 * @date 2015-01-05
 */
module.exports = {
  'H5Loading': require('./component/h5-loading'),
  'bigPlayButton': require('./component/big-play-button'),
  'controlBar': require('./component/controlbar'),
  'progress': require('./component/progress'),
  'playButton': require('./component/play-button'),
  'liveDisplay': require('./component/live-display'),
  'timeDisplay': require('./component/time-display'),
  'fullScreenButton': require('./component/fullscreen-button'),
  'volume': require('./component/volume')
};

},{"./component/big-play-button":53,"./component/controlbar":54,"./component/fullscreen-button":55,"./component/h5-loading":56,"./component/live-display":57,"./component/play-button":58,"./component/progress":59,"./component/time-display":60,"./component/volume":61}]},{},[36]);
