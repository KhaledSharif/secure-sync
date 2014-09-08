using System;

using SecureSync;

using System.Diagnostics;

namespace SecureSync
{
    class Unit_Tests
    {

        private void Test_File_Encryption()
        {
            RSA_Functions rsa_class = new RSA_Functions();
            AES_Functions aes_class = new AES_Functions();

            Debug.Assert(
                rsa_class.Open_RSA_Keys(@"C:\Users\home\Documents\rsa_public_key.blob",
                                        @"C:\Users\home\Documents\rsa_private_key.blob"));

            Debug.Assert(
                rsa_class.Save_Random_Password(@"C:\Users\home\Documents\password.txt", 256));

            Debug.Assert(
                rsa_class.Encrypt_And_Save_Password(@"C:\Users\home\Documents\password.txt",
                                                    @"C:\Users\home\Documents\password_encrypted.txt", 256));

            Debug.Assert(
                rsa_class.Decrypt_Password_File(@"C:\Users\home\Documents\password_encrypted.txt", 
                                                @"C:\Users\home\Documents\password_decrypted.txt", 512));

            Debug.Assert(
                aes_class.Get_Security(@"C:\Users\home\Documents\password_decrypted.txt"));

            Debug.Assert(
                aes_class.Encrypt_With_Security(@"C:\Users\home\Documents\color.jpg", 
                                                @"C:\Users\home\Documents\color_encrypted.jpg"));

            Debug.Assert(
                aes_class.Decrypt_Using_Security(@"C:\Users\home\Documents\color_encrypted.jpg",
                                                 @"C:\Users\home\Documents\color_decrypted.jpg"));
      
        }

    }
}
