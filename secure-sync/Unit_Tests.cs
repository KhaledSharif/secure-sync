using System.Diagnostics;
using SecureSync;
using secure_sync.Encryption_Functions;

namespace secure_sync
{
    class UnitTests
    {

        public UnitTests()
        {
            Test_File_Encryption();
        }

        private void Test_HTTP_Server()
        {

        }

        private static void Test_File_Encryption()
        {
            var rsaClass = new RsaFunctions();
            var aesClass = new AES_Functions();

            Debug.Assert(rsaClass.OpenRsaKeys(@"C:\Users\home\Documents\rsa_public_key.blob",@"C:\Users\home\Documents\rsa_private_key.blob"));
            Debug.Assert(rsaClass.SaveRandomPassword(@"C:\Users\home\Documents\password.txt", 256));
            Debug.Assert(rsaClass.EncryptAndSavePassword(@"C:\Users\home\Documents\password.txt",@"C:\Users\home\Documents\password_encrypted.txt", 256));
            Debug.Assert(rsaClass.DecryptPasswordFile(@"C:\Users\home\Documents\password_encrypted.txt",@"C:\Users\home\Documents\password_decrypted.txt", 512));
            Debug.Assert(aesClass.Get_Security(@"C:\Users\home\Documents\password_decrypted.txt"));
            Debug.Assert(aesClass.Encrypt_With_Security(@"C:\Users\home\Documents\color.jpg",@"C:\Users\home\Documents\color_encrypted.jpg"));
            Debug.Assert(aesClass.Decrypt_Using_Security(@"C:\Users\home\Documents\color_encrypted.jpg",@"C:\Users\home\Documents\color_decrypted.jpg"));
      
        }

    }
}
