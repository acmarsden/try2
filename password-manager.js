"use strict";


/********* External Imports ********/

var lib = require("./lib");
var sjcl = require("./sjcl");

var KDF = lib.KDF,
    HMAC = lib.HMAC,
    SHA256 = lib.SHA256,
    setupCipher = lib.setupCipher,
    encryptwithGCM = lib.encryptwithGCM,
    decryptWithGCM = lib.decryptWithGCM,
    bitarraySlice = lib.bitarraySlice,
    bitarrayToString = lib.bitarrayToString,
    stringToBitarray = lib.stringToBitarray,
    bitarrayToBase64 = lib.bitarrayToBase64,
    base64ToBitarray = lib.base64ToBitarray,
    stringToPaddedBitarray = lib.stringToPaddedBitarray,
    paddedBitarrayToString = lib.paddedBitarrayToString,
    randomBitarray = lib.randomBitarray,
    bitarrayEqual = lib.bitarrayEqual,
    bitarrayLen = lib.bitarrayLen,
    bitarrayConcat = lib.bitarrayConcat,
    objectHasKey = lib.objectHasKey;

// Functions from sjcl
var bitarrayToHex = function(bitarray) {
  return sjcl.codec.hex.fromBits(bitarray);
};

var hexToBitarray = function(hexStr) {
  return sjcl.codec.hex.toBits(hexStr);
};

/********* Implementation ********/


var keychainClass = function() {

  // Private instance variables.
    
  // Use this variable to store everything you need to.
  var priv = {
    secrets: { /* Your secrets here */ },
    data: { /* Non-secret data here */ }
  };

  // Maximum length of each record in bytes
  var MAX_PW_LEN_BYTES = 64;
  
  // Flag to indicate whether password manager is "ready" or not
  var ready = false;

  var keychain = {};

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

    // Generates a random salt
    priv.data.salt = randomBitarray(128);
    // Creates master key by KDFing the password with the salt
    priv.secrets.master_key = KDF(password,priv.data.salt);

    // Generates mac key from HMACing master key with arbitrary string 
    priv.secrets.mac_key = HMAC(priv.secrets.master_key,"mac key generator");

    // Generates aes key from HMACing master key with another arbitrary string
    priv.secrets.aes_key = HMAC(priv.secrets.master_key,"aes key generator").slice(0,4);

    // The password authentication. Password is checked against the HMAC of the mac_key with "another arbitrary string"
    priv.data.password_authentication = HMAC(priv.secrets.mac_key,"another arbitrary string");

    // Setup cipher
    priv.secrets.cipher = setupCipher(priv.secrets.aes_key);

    // Initializes keychain
    priv.data.kvs = {};

    // Ready after successfully initialized
    ready = true;
  };

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the save function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object). Returns true if the data is successfully loaded
    * and the provided password is correct. Returns false otherwise.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: boolean
    */
  keychain.load = function(password, repr, trustedDataCheck) {
      // Make sure keychain has not been tampered with
      if ( !(trustedDataCheck==undefined) ) {
        var sha_check = SHA256(repr);
        if ( !bitarrayEqual(sha_check,trustedDataCheck) ) {
          throw "Tampering detected!!";
        }
      }

      // Password authentication
      var data = JSON.parse(repr);
      var master_key = KDF(password,data.salt);
      var mac_key = HMAC(master_key,"mac key generator");
      var pass_hmac = HMAC(mac_key,"another arbitrary string");
      if ( !bitarrayEqual(pass_hmac,data.password_authentication) ) {
        return false;
      }

      // If everything passed, loads the keychain
      priv.data = data;
      priv.secrets.master_key = master_key;
      priv.secrets.mac_key = mac_key;
      priv.secrets.aes_key = HMAC(master_key,"aes key generator").slice(0,4);
      priv.secrets.cipher = setupCipher(priv.secrets.aes_key);    

      // Password was authenticated so we're in the ready state
      ready = true;
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
      // If init/load wasn't successfully called, don't do anything
      if (! ready) {
        return null;
      }
      // Return the JSON representation and its SHA256
      var repr = JSON.stringify(priv.data);
      return [repr,SHA256(repr)];
  };

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
      // If init/load not successful, throw exception
      if (!ready) {
        throw "Keychain not initialized.";
      }

      // Searches for the HMAC of the domain name in the kvs. If in the kvs, decrypts and returns password
      var hmac_domain = HMAC(priv.secrets.mac_key,name);
      var domain_string = bitarrayToHex(hmac_domain);
      if (domain_string in priv.data.kvs) {
        var value_store = decryptWithGCM(priv.secrets.cipher,hexToBitarray(priv.data.kvs[domain_string]),hmac_domain);
        return paddedBitarrayToString(value_store,MAX_PW_LEN_BYTES);
      }
      return null;
  };

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
      // If not successfully init/load, throw an exception
      if (!ready) {
        throw "Keychain not initialized.";
      }
      // key is the HMAC of the domain, value is gcm encrypted password with the HMAC of the domain as the associated data (to fight swap attacks)
      var hmac_domain = HMAC(priv.secrets.mac_key,name);
      var padded_value = stringToPaddedBitarray(value,MAX_PW_LEN_BYTES);
      var value_store = bitarrayToHex(encryptwithGCM(priv.secrets.cipher, padded_value, hmac_domain));
      priv.data.kvs[bitarrayToHex(hmac_domain)] = value_store;
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise. If
    * the password manager is not in a ready state, throws an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: boolean
  */
  keychain.remove = function(name) {
      if (!ready) {
        throw "Keychain not initialized."
      }
      // Delete the entry if it's in the kvs
      var hmac_domain = bitarrayToHex(HMAC(priv.secrets.mac_key,name));
      if (hmac_domain in priv.data.kvs) {
        delete priv.data.kvs[hmac_domain];
        return true;
      }
      return false;

  };

  return keychain;
};

module.exports.keychain = keychainClass;

let chain = new keychainClass('password');
console.log(chain);
