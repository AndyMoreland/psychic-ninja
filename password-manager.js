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
		var ready = false;

		var keychain = {};


		keychain.encrypt = function (plaintext) {
				return enc_gcm(priv.secrets.cipher, plaintext);
		};

		keychain.decrypt = function (ciphertext) {
				return dec_gcm(priv.secrets.cipher, ciphertext);
		};

		keychain.HMAC_message = function (plaintext) {
				return HMAC(priv.secrets.HMAC_key,string_to_bitarray(plaintext));
		};


		keychain.key_from_bitarray = function(bitarray) {
				return bitarray_slice(bitarray, 0, 128);
		};

		// Here we derive four keys from the initial password
		keychain.generate_four_keys_from_password = function (salt, password) {
				var password_bitarray = string_to_bitarray(password);

				var root_key = KDF(password_bitarray, salt);

				var second_derived_mac_1 = HMAC(root_key, string_to_bitarray("" + 0));
				var second_derived_mac_2 = HMAC(root_key, string_to_bitarray("" + 1));

				var final_keys = [];

				final_keys.push(bitarray_slice(second_derived_mac_1, 0, 128));
				final_keys.push(bitarray_slice(second_derived_mac_1, 128, 256));
				final_keys.push(bitarray_slice(second_derived_mac_2, 0, 128));
				final_keys.push(bitarray_slice(second_derived_mac_2, 128, 256));

				return final_keys;
		};

		// serializes a single domain's entry deterministically
		keychain.deterministic_serialize_entry = function (key) {
				return bitarray_to_base64(key) +
						bitarray_to_base64(priv.data.storage[key].password) + 
						bitarray_to_base64(priv.data.storage[key].authenticity_token);
		};

		// This is deterministic and injective: any two unique keychains will always produce the same output
		// 
		// It is injective because everything we serialize has a fixed length, so we never have inconvenient
		// collisions in output between unique keychains.
		//	
		// It is deterministic because we impose an ordering on the data before it is serialized
		keychain.deterministic_serialize_data = function (data) {
				var serialized_data = bitarray_to_base64(data.verification_key);

				var keys = []
				for (var k in data.storage) { keys.push(k); }

				// sorts in place
				keys.sort( function (key1, key2) { return bitarray_to_base64(key1) <  bitarray_to_base64(key2) } );

				for (var k in keys) {
						if (data.storage.hasOwnProperty(k)) {
								serialized_data += keychain.deterministic_serialize_entry(k);
						}
				}

				return serialized_data;
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
				priv.data.salt = random_bitarray(128);

				var keys = keychain.generate_four_keys_from_password(priv.data.salt, password);

        ready = true;
				priv.data.storage = {};
				priv.data.verification_key = keys[0];
				priv.secrets.HMAC_key = keys[1];
				priv.secrets.password_key = keys[2];
				priv.secrets.authentication_key = keys[3];
				priv.secrets.cipher = setup_cipher(priv.secrets.password_key);
				priv.secrets.counter = 0;
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
     *   trusted_data_check: string
     * Return Type: boolean
     */
		keychain.load = function(password, repr, trusted_data_check) {
				priv.secrets.counter = trusted_data_check;
				
				var disk_representation = JSON.parse(repr);
				priv.data = disk_representation.data; 

				var keys = keychain.generate_four_keys_from_password(priv.data.salt, password);
 
				if (!bitarray_equal(keys[0], priv.data.verification_key)) {
						throw "Incorrect password!";
				}

				priv.secrets.HMAC_key = keys[1];
				priv.secrets.password_key = keys[2];
				priv.secrets.authentication_key = keys[3];
				priv.secrets.cipher = setup_cipher(priv.secrets.password_key);
				ready = true;

				if (trusted_data_check !== undefined) {
						if (!bitarray_equal(
								HMAC(priv.secrets.authentication_key, 
										 string_to_bitarray(keychain.deterministic_serialize_data(priv.data) + "," + priv.secrets.counter)), 
								disk_representation.authenticity_token)) {

								ready = false;
								throw "Tampering detected: rollback attack?";

								return false; // this line shouldn't happen'
						}
				}

				return true;
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
				if (!ready) { throw "Not yet initialized."; }

				priv.secrets.counter++;
				
				var return_value = [];
				
				var disk_representation = {
						data: priv.data,
						authenticity_token: HMAC(priv.secrets.authentication_key, 
																		 string_to_bitarray(keychain.deterministic_serialize_data(priv.data) + "," + priv.secrets.counter))
				}

				return_value[0] = JSON.stringify(disk_representation);
				return_value[1] = priv.secrets.counter;

				return return_value;
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

				var key = keychain.HMAC_message(name);
				var result = priv.data.storage[key];

				if (!result) {
						return null;
				}

				var password = string_from_padded_bitarray(keychain.decrypt(result.password), 64);

				if (!bitarray_equal(result.authenticity_token, 
														keychain.HMAC_message(bitarray_concat(key, result.password)))) { throw "Suspected tampering."; }

				return password;
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
				

				var key = keychain.HMAC_message(name);
				var padded_password = string_to_padded_bitarray(value, 64);
				var encrypted_password = keychain.encrypt(padded_password);
				
				// 16 chosen to exceed maximum possible size of the string representation of an integer
				// realistically this should never be more than 2 digits, though
				
				var entry = {
						password: encrypted_password,
						authenticity_token: keychain.HMAC_message(bitarray_concat(key, encrypted_password))
				};

				priv.data.storage[key] = entry;
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
				
				var key = keychain.HMAC_message(name);
				if (priv.data.storage[key]) {
						delete priv.data.storage[key];
            return true;
				} else {
						return false;
				}
		}

		return keychain;
}

module.exports.keychain = keychain;
