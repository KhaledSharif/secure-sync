using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace secure_sync.Encryption_Functions
{
    class RsaFunctions
    {
        private RSACryptoServiceProvider _rsaServiceProvider;
        private RSAParameters _publicRsaKey, _privateRsaKey;
        private Encryption _encryptionsClass;

        public Boolean OpenRsaKeys(string pathToPublicKey, string pathToPrivateKey)
        {
            if (File.Exists(pathToPrivateKey))
            {
                try
                {
                    _rsaServiceProvider = new RSACryptoServiceProvider();
                    _rsaServiceProvider.ImportCspBlob(File.ReadAllBytes(pathToPrivateKey));
                    if (!File.Exists(pathToPublicKey))
                        File.WriteAllBytes(pathToPublicKey, _rsaServiceProvider.ExportCspBlob(false));
                }
                catch (Exception e)
                {
                    return ThrowExceptions.ThrowExceptionError("Failed to open already existing RSA keys.", e);
                }
            }
            else
            {
                try
                {
                    _rsaServiceProvider = new RSACryptoServiceProvider(4096);
                    File.WriteAllBytes(pathToPrivateKey, _rsaServiceProvider.ExportCspBlob(true));
                    File.WriteAllBytes(pathToPublicKey, _rsaServiceProvider.ExportCspBlob(false));
                }
                catch (Exception e)
                {
                    return ThrowExceptions.ThrowExceptionError("Failed to create new RSA keys due to absence of saved keys.", e);
                }
            }
            try
            {
                _publicRsaKey = _rsaServiceProvider.ExportParameters(false);
                _privateRsaKey = _rsaServiceProvider.ExportParameters(true);
                return true;
            }
            catch (Exception e)
            {
                return ThrowExceptions.ThrowExceptionError("Failed to set public and private RSA keys in memory.", e);
            }
        }

        public Boolean SaveRandomPassword(string pathToPassword, int lengthOfPassword)
        {
            var randomPassword = new RNGCryptoServiceProvider();
            var randomPasswordBytes = new byte[lengthOfPassword];
            try
            {
                using (var streamWriter = new StreamWriter(@"C:\Users\home\Documents\password.txt", false))
                {
                    try
                    {
                        randomPassword.GetBytes(randomPasswordBytes);
                        streamWriter.Write(Convert.ToBase64String(randomPasswordBytes, 0, randomPasswordBytes.Length));
                        return true;
                    }
                    catch (NotSupportedException e)
                    {
                        return ThrowExceptions.ThrowExceptionError("Failed to write password to an invalid format or path-name.", e);
                    }
                    catch (Exception e)
                    {
                        return ThrowExceptions.ThrowExceptionError("Failed to generate and/or save a random password.", e);
                    }
                    finally
                    {
                        randomPassword.Dispose();
                        randomPasswordBytes = null;
                    }
                }
            }
            catch (UnauthorizedAccessException e)
            {
                return ThrowExceptions.ThrowExceptionError("You do not have authorization to save a password in the specified path.", e);
            }
            catch (ArgumentNullException e)
            {
                return ThrowExceptions.ThrowExceptionError("Trying to generate and/or save a password resulting in an Argument Null exception.", e);
            }
            catch (DirectoryNotFoundException e)
            {
                return ThrowExceptions.ThrowExceptionError("The specified path to save the password is invalid.", e);
            }
            catch (Exception e)
            {
                return ThrowExceptions.ThrowExceptionError("Failed to generate and/or save a random password for an unknown reason.", e);
            }
        }

        public Boolean EncryptAndSavePassword(string pathToPassword, string pathToEncryption, int sizeOfBuffer)
        {
            try
            {
                _encryptionsClass = new Encryption();
                var streamReader = new StreamReader(pathToPassword, true);
                var buffer = new byte[sizeOfBuffer];
                var encryptedFileList = new List<byte>();

                while (streamReader.BaseStream.Read(buffer, 0, buffer.Length) > 0)
                {
                    var encryptedBuffer = _encryptionsClass.EncryptFile(_publicRsaKey, buffer);
                    encryptedFileList.AddRange(encryptedBuffer);
                }
                streamReader.Close();
                File.WriteAllBytes(pathToEncryption, encryptedFileList.ToArray());
                return true;
            }
            catch (Exception e)
            {
                return ThrowExceptions.ThrowExceptionError("Failed to encrypt and save the already existing password file.", e);
            }
        }

        public Boolean DecryptPasswordFile(string pathToEncryption, string pathToPassword, int sizeOfBuffer)
        {
            try
            {
                List<byte> decryptedFileList;
                using (var streamReader = new StreamReader(pathToEncryption))
                {
                    var buffer = new byte[sizeOfBuffer];
                    decryptedFileList = new List<byte>();

                    while (streamReader.BaseStream.Read(buffer, 0, buffer.Length) > 0)
                    {
                        var decryptedBuffer = _encryptionsClass.DecryptFile(_privateRsaKey, buffer);
                        if (decryptedBuffer == null) throw new Exception("The decryptedBuffer variable was found to be null.");
                        decryptedFileList.AddRange(decryptedBuffer);
                    }
                    streamReader.Close();
                }
                File.WriteAllBytes(pathToPassword, decryptedFileList.ToArray());
                return true;
            }
            catch (ArgumentNullException e)
            {
                return ThrowExceptions.ThrowExceptionError("Reading the password file resulted in an Argument Null Exception.", e);
            }
            catch (Exception e)
            {
                return ThrowExceptions.ThrowExceptionError("Cannot decrypt the encrypted password file.", e);
            }
        }
    }
}
