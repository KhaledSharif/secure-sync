using System;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Text;
using System.Collections.Generic;

using SecureSync;

namespace Program
{
    class Program
    {
        static void Main()
        {
            RSA_Functions rsa_class = new RSA_Functions();
            AES_Functions aes_class = new AES_Functions();

            if (!rsa_class.Open_RSA_Keys(@"C:\Users\home\Documents\rsa_public_key.blob",
                                         @"C:\Users\home\Documents\rsa_private_key.blob"))
                return;

            if (!rsa_class.Save_Random_Password(@"C:\Users\home\Documents\password.txt", 256))
                return;

            if (!rsa_class.Encrypt_And_Save_Password(@"C:\Users\home\Documents\password.txt",
                                                     @"C:\Users\home\Documents\password_encrypted.txt", 256))
                return;

            if (!rsa_class.Decrypt_Password_File(@"C:\Users\home\Documents\password_encrypted.txt",
                                                 @"C:\Users\home\Documents\password_decrypted.txt", 512))
                return;

            if (!aes_class.Get_Security(@"C:\Users\home\Documents\password_decrypted.txt"))
                return;

            if (!aes_class.Encrypt_With_Security(@"C:\Users\home\Documents\color.jpg",
                                                 @"C:\Users\home\Documents\color_encrypted.jpg"))
                return;

            if (!aes_class.Decrypt_Using_Security(@"C:\Users\home\Documents\color_encrypted.jpg",
                                                  @"C:\Users\home\Documents\color_decrypted.jpg"))
                return;
        }
    }
}