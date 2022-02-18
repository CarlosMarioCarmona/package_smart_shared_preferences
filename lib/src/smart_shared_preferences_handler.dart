import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/export.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:smart_shared_preferences/src/rsa_helper.dart';


class RSAEncryptedSharedPreferences
{
  final String rsaPublicKeyPem;
  final String rsaPrivateKeyPem;
  late SharedPreferences _prefs;
  late Encrypter _encrypter;

  RSAEncryptedSharedPreferences({required this.rsaPublicKeyPem, required this.rsaPrivateKeyPem});

  Future<bool> initSharePreferenceInstance() async
  {
    try
    {
      _prefs = await SharedPreferences.getInstance();
      RSAPrivateKey privateKey = RSAHelper.parsePrivateKeyFromPem(rsaPrivateKeyPem);
      RSAPublicKey publicKey = RSAHelper.parsePublicKeyFromPem(rsaPublicKeyPem);
      _encrypter = Encrypter(RSA(privateKey: privateKey, publicKey: publicKey));
      return Future<bool>.value(true);
    }catch(e){
      //TODO: log error
      return Future<bool>.value(false);
    }
  }

  Future<bool> setString({required String key, required String value})
  async {
    try
    {
      Encrypted valueEncrypted = _encrypter.encrypt(value);
      await _prefs.setString(key, valueEncrypted.base64);
      return Future<bool>.value(true);
    }catch(e)
    {
      //TODO: log error
      return Future<bool>.value(false);
    }
  }


  String? getString({required String key})
  {
    try{
      bool containsKey = _prefs.containsKey(key);
      if(containsKey)
      {
        String encryptedStringValue = _prefs.getString(key)!;
        Encrypted encryptedValue = Encrypted.fromBase64(encryptedStringValue);
        String value = _encrypter.decrypt(encryptedValue);
        return value;
      }else{
        return null;
      }
    }catch(e){
      //TODO: log error
      return null;
    }

  }


}