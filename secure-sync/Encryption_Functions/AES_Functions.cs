﻿using System;
using System.IO;
using secure_sync;

namespace SecureSync
{
    class AES_Functions
    {
        private Secure security;

        public Boolean Get_Security(string path_to_password)
        {
            try
            {
                var read_key = File.ReadAllBytes(path_to_password);
                var read_key_sub_array = new byte[32];
                Buffer.BlockCopy(read_key, 0, read_key_sub_array, 0, 32);
                security = new Secure(read_key_sub_array);
                return true;
            }
            catch (FileNotFoundException e)
            {
                return ThrowExceptions.ThrowExceptionError("You provided an invalid path to the password file.", e);
            }
            catch (Exception e)
            {
                return ThrowExceptions.ThrowExceptionError("Failed to fetch some or all of the securities.", e);
            }
        }

        public Boolean Encrypt_With_Security(string path_to_file, string path_to_encryption)
        {
            try
            {
                File.WriteAllBytes(path_to_encryption, security.Encrypt(File.ReadAllBytes(path_to_file)));
                return true;
            }
            catch (DirectoryNotFoundException e)
            {
                return ThrowExceptions.ThrowExceptionError("The path for the file to be encrypted and/or saved was incorrect.", e);
            }
            catch (Exception e)
            {
                return ThrowExceptions.ThrowExceptionError("Failed to encrypt the file with securities.", e);
            }
        }

        public Boolean Decrypt_Using_Security(string path_to_encrypted_file, string path_to_decrypted_file)
        {
            try
            {
                File.WriteAllBytes(path_to_decrypted_file, security.Decrypt(File.ReadAllBytes(path_to_encrypted_file)));
                return true;
            }
            catch (DirectoryNotFoundException e)
            {
                return ThrowExceptions.ThrowExceptionError("The path for the file to be decrypted and/or saved was incorrect.", e);
            }
            catch (Exception e)
            {
                return ThrowExceptions.ThrowExceptionError("Failed to decrypt or to write the decrypted file to disk.", e);
            }
        }

    }
}
