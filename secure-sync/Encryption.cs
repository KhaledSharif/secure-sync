using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;


namespace SecureSync
{
    class Encryption
    {
        private byte[] RSAEncrypt(
            byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();
                RSAalg.ImportParameters(RSAKeyInfo);
                return RSAalg.Encrypt(DataToEncrypt, DoOAEPPadding);
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }

        private byte[] RSADecrypt(
            byte[] DataToDecrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();
                RSAalg.ImportParameters(RSAKeyInfo);
                return RSAalg.Decrypt(DataToDecrypt, DoOAEPPadding);
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());
                return null;
            }
        }

        public byte[] EncryptFile(
            RSAParameters rsa_public_key, byte[] file_to_be_encrypted)
        {
            byte[] encrypted_file;
            try
            {
                encrypted_file = RSAEncrypt(file_to_be_encrypted, rsa_public_key, false);
                return encrypted_file;
            }
            catch
            {
                Console.WriteLine("Can't open files and/or write to files.");
                return null;
            }
        }

        public byte[] DecryptFile(
            RSAParameters rsa_private_key, byte[] file_to_be_decrypted)
        {
            byte[] decrypted_file;
            try
            {
                decrypted_file = RSADecrypt(file_to_be_decrypted, rsa_private_key, false);
                return decrypted_file;
            }
            catch
            {
                Console.WriteLine("Can't open files and/or write to files.");
                return null;
            }
        }
    }
}
