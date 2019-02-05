"use strict";


/********* External Imports ********/

var lib = require("./lib");

var KDF = lib.KDF,
    HMAC = lib.HMAC,
    SHA256 = lib.SHA256,
    setupCipher = lib.setupCipher,
    bitarrayToHex = lib.bitarrayToHex,
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
    priv.secrets.master_key = KDF(password,priv.data.salt);

    // Generates mac key from HMACing master key with arbitrary string 
    priv.secrets.mac_key = HMAC(priv.secrets.master_key,"mac key generator");

    // Generates aes key from HMACing master key with another arbitrary string
    priv.secrets.aes_key = HMAC(priv.secrets.master_key,"aes key generator");

    // The password authentication 
    priv.data.password_authentication = HMAC(priv.secrets.mac_key,"another arbitrary string");

    // Setup cipher
    priv.secrets.cipher = setupCipher(priv.secrets.aes_key);

    priv.data.KVS = {};

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
      // throw "Not implemented!";

      // Make sure keychain has not been tampered with
      if ( !(trustedDataCheck==undefined) ) {
        var sha_check = SHA256(repr);
        if ( !bitArrayEqual(sha_check,trustedDataCheck) ) {
          throw "Tampering detected!!";
        }
      }

      // Password authentication
      var data = JSON.parse(repr);
      var master_key = KDF(password,priv.data.salt);
      var mac_key = HMAC(master_key,"mac key generator");
      var pass_hmac = HMAC(mac_key,"another arbitrary string");
      if ( !bitArrayEqual(pass_hmac,data.password_authentication) ) {
        return false;
      }

      // If everything passed, loads the keychain
      priv.secrets.master_key = master_key;
      priv.secrets.mac_key = mac_key;
      priv.secrets.aes_key = HMAC(master_key,"aes key generator");
      priv.secrets.cipher = setupCipher(priv.secrets.aes_key);    
      priv.data=data;
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
      if (! ready) {
        return null;
      }
      var repr = JSON.stringify(priv.data);
      return [repr,SHA256(repr)];
      // throw "Not implemented!";
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
      //throw "Not implemented!";
      if (!ready) {
        throw "Keychain not initialized.";
      }

      var hmac_domain = HMAC(priv.secrets.mac_key,name);
      if (hmac_domain in priv.data.KVS) {
        /* do stuff */
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
      //throw "Not implemented!";
      if (!ready) {
        throw "Keychain not initialized.";
      }
      var hmac_domain = bitarrayToHex(HMAC(priv.secrets.mac_key,name));
      var value_store = encryptWithGCM(priv.secrets.cipher, value, name);
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
      throw "Not implemented!";
  };

  return keychain;
};

module.exports.keychain = keychainClass;
