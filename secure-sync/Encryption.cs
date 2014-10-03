using System;
using System.Security.Cryptography;

namespace secure_sync
{
    class Encryption
    {
        private static byte[] RsaEncrypt(byte[] dataToEncrypt, RSAParameters rsaKeyInfo, bool doOaepPadding)
        {
            try
            {
                var rsAalg = new RSACryptoServiceProvider();
                rsAalg.ImportParameters(rsaKeyInfo);
                return rsAalg.Encrypt(dataToEncrypt, doOaepPadding);
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }

        private static byte[] RsaDecrypt(byte[] dataToDecrypt, RSAParameters rsaKeyInfo, bool doOaepPadding)
        {
            try
            {
                var rsAalg = new RSACryptoServiceProvider();
                rsAalg.ImportParameters(rsaKeyInfo);
                return rsAalg.Decrypt(dataToDecrypt, doOaepPadding);
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());
                return null;
            }
        }

        public byte[] EncryptFile(RSAParameters rsaPublicKey, byte[] fileToBeEncrypted)
        {
            try
            {
                var encryptedFile = RsaEncrypt(fileToBeEncrypted, rsaPublicKey, false);
                return encryptedFile;
            }
            catch
            {
                Console.WriteLine("Can't open files and/or write to files.");
                return null;
            }
        }

        public byte[] DecryptFile(RSAParameters rsaPrivateKey, byte[] fileToBeDecrypted)
        {
            try
            {
                var decryptedFile = RsaDecrypt(fileToBeDecrypted, rsaPrivateKey, false);
                return decryptedFile;
            }
            catch
            {
                Console.WriteLine("Can't open files and/or write to files.");
                return null;
            }
        }
    }
}
