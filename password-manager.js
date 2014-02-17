"use strict";


/********* External Imports ********/

var lib = require("./lib");

var KDF = lib.KDF,
    HMAC = lib.HMAC,
    SHA256 = lib.SHA256,
    setup_cipher = lib.setup_cipher,
    enc_gcm = lib.enc_gcm,
    dec_gcm = lib.dec_gcm,
    bitarray_slice = lib.bitarray_slice,
    bitarray_to_string = lib.bitarray_to_string,
    string_to_bitarray = lib.string_to_bitarray,
    bitarray_to_hex = lib.bitarray_to_hex,
    hex_to_bitarray = lib.hex_to_bitarray,
    bitarray_to_base64 = lib.bitarray_to_base64,
    base64_to_bitarray = lib.base64_to_bitarray,
    byte_array_to_hex = lib.byte_array_to_hex,
    hex_to_byte_array = lib.hex_to_byte_array,
    string_to_padded_byte_array = lib.string_to_padded_byte_array,
    string_to_padded_bitarray = lib.string_to_padded_bitarray,
    string_from_padded_byte_array = lib.string_from_padded_byte_array,
    string_from_padded_bitarray = lib.string_from_padded_bitarray,
    random_bitarray = lib.random_bitarray,
    bitarray_equal = lib.bitarray_equal,
    bitarray_len = lib.bitarray_len,
    bitarray_concat = lib.bitarray_concat,
    dict_num_keys = lib.dict_num_keys;


/********* Implementation ********/


var keychain = function() {
		// Class-private instance variables.
		var priv = {
				secrets: { /* Your secrets here */ },
				data: { /* Non-secret data here */ }
		};

		// Maximum length of each record in bytes
		var MAX_PW_LEN_BYTES = 64;
		
		// Flag to indicate whether password manager is "ready" or not
		var ready = false;;

		var keychain = {};


		keychain.encrypt = function (plaintext) {
				return enc_gcm(priv.secrets.cipher, plaintext);
		};

		keychain.decrypt = function (ciphertext) {
				return dec_gcm(priv.secrets.cipher, ciphertext);
		};

		/** 
     * Creates an empty keychain with the given password. Once init is called,
     * the password manager should be in a ready state.
     *
     * Arguments:
     *   password: string
     * Return Type: void
     */
		keychain.init = function(password) {
				priv.data.version = "CS 255 Password Manager v1.0";
				var salt = "" // FIXME make this random
				priv.secrets.salt = salt;
				priv.secrets.key = KDF(password, salt);
				priv.secrets.cipher = setup_cipher(priv.secrets.key);
        ready = true;
		};

		/**
     * Loads the keychain state from the provided representation (repr). The
     * repr variable will contain a JSON encoded serialization of the contents
     * of the KVS (as returned by the save function). The trusted_data_check
     * is an *optional* SHA-256 checksum that can be used to validate the 
     * integrity of the contents of the KVS. If the checksum is provided and the
     * integrity check fails, an exception should be thrown. You can assume that
     * the representation passed to load is well-formed (e.g., the result of a 
     * call to the save function). Returns true if the data is successfully loaded
     * and the provided password is correct. Returns false; otherwise.
     *
     * Arguments:
     *   password:           string
     *   repr:               string
k     *   trusted_data_check: string
     * Return Type: boolean
     */
		keychain.load = function(password, repr, trusted_data_check) {
				throw "Not implemented!";
		};

		/**
     * Returns a JSON serialization of the contents of the keychain that can be 
     * loaded back using the load function. The return value should consist of
     * an array of two strings:
     *   arr[0] = JSON encoding of password manager
     *   arr[1] = SHA-256 checksum
     * As discussed in the handout, the first element of the array should contain
     * all of the data in the password manager. The second element is a SHA-256
     * checksum computed over the password manager to preserve integrity. If the
     * password manager is not in a ready-state, return null.
     *
     * Return Type: array
     */ 
		keychain.dump = function() {
				throw "Not implemented!";
		}

		/**
     * Fetches the data (as a string) corresponding to the given domain from the KVS.
     * If there is no entry in the KVS that matches the given domain, then return
     * null. If the password manager is not in a ready state, throw an exception. If
     * tampering has been detected with the records, throw an exception.
     *
     * Arguments:
     *   name: string
     * Return Type: string
     */
		keychain.get = function(name) {
				if (!ready) { throw "Not yet initialized."; }

				var key = HMAC(priv.secrets.key, name);
				var result = priv.data[key];

				if (!result) {
						return null;
				}

				// console.log("Attempting to use: ", result, " for ", name);
				var padded_password = keychain.decrypt(result.password);
				var length = parseInt(bitarray_to_string(keychain.decrypt(result.length)), 10);

				// console.log(padded_password, length)

				// Note: string_From_padded_bitarray seems to want the total length of the string
				return string_from_padded_bitarray(padded_password, 64); // FIXME bytearray?
		}

		/** 
		 * Inserts the domain and associated data into the KVS. If the domain is
		 * already in the password manager, this method should update its value. If
		 * not, create a new entry in the password manager. If the password manager is
		 * not in a ready state, throw an exception.
		 *
		 * Arguments:
		 *   name: string
		 *   value: string
		 * Return Type: void
		 */
		keychain.set = function(name, value) {
				if (!ready) { throw "Not yet initialized."; }
				if(value.length > 64) { throw "Password is too long"; }
				

				var key = HMAC(priv.secrets.key, name);
				//console.log("Attempting to store ", name, " with key ", key, ". The password is: ", value);
				var padded_password = string_to_padded_bitarray(value, 64);
				var encrypted_password = keychain.encrypt(padded_password);
				
				var encrypted_length = keychain.encrypt(string_to_bitarray("" + value.length)); // FIXME: make sure that we don't leak length information'
				//console.log("Encrypted length is: ", encrypted_length)
				
				var entry = {
						length: encrypted_length,
						password: encrypted_password,
						authenticity_token: HMAC(priv.secrets.key, key + encrypted_length + encrypted_password)
				};

				priv.data[key] = entry;
				// console.log("Storing ", entry, " for ", name);
		}

		/**
     * Removes the record with name from the password manager. Returns true
     * if the record with the specified name is removed, false; otherwise. If
     * the password manager is not in a ready state, throws an exception.
     *
     * Arguments:
     *   name: string
     * Return Type: boolean
		 */
		keychain.remove = function(name) {
				if (!ready) { throw "Not yet initialized."; }
				
				var key = HMAC(priv.secrets.key, name);
				if (priv.data[key]) {
						delete priv.data[key];
            return true;
				} else {
						return false;
				}
		}

		return keychain;
}

module.exports.keychain = keychain;
