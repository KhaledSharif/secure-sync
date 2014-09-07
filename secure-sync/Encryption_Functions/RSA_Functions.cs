using System;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Text;
using System.Collections.Generic;

using SecureSync;

namespace SecureSync
{
    class RSA_Functions
    {
        private RSACryptoServiceProvider rsa_service_provider;
        private RSAParameters public_rsa_key, private_rsa_key;
        private Encryption encryptions_class;

        public Boolean Open_RSA_Keys(string path_to_public_key, string path_to_private_key)
        {
            if (File.Exists(path_to_private_key))
            {
                try
                {
                    rsa_service_provider = new RSACryptoServiceProvider();
                    rsa_service_provider.ImportCspBlob(File.ReadAllBytes(path_to_private_key));
                    if (!File.Exists(path_to_public_key))
                        File.WriteAllBytes(path_to_public_key, rsa_service_provider.ExportCspBlob(false));
                }
                catch (Exception e)
                {
                    return Throw_Exceptions.Throw_Exception_Error("Failed to open already existing RSA keys.", e);
                }
            }
            else
            {
                try
                {
                    rsa_service_provider = new RSACryptoServiceProvider(4096);
                    File.WriteAllBytes(path_to_private_key, rsa_service_provider.ExportCspBlob(true));
                    File.WriteAllBytes(path_to_public_key, rsa_service_provider.ExportCspBlob(false));
                }
                catch (Exception e)
                {
                    return Throw_Exceptions.Throw_Exception_Error("Failed to create new RSA keys due to absence of saved keys.", e);
                }
            }
            try
            {
                public_rsa_key = rsa_service_provider.ExportParameters(false);
                private_rsa_key = rsa_service_provider.ExportParameters(true);
                return true;
            }
            catch (Exception e)
            {
                return Throw_Exceptions.Throw_Exception_Error("Failed to set public and private RSA keys in memory.", e);
            }
        }

        public Boolean Save_Random_Password(string path_to_password, int length_of_password)
        {
            RNGCryptoServiceProvider random_password = new RNGCryptoServiceProvider();
            byte[] random_password_bytes = new byte[length_of_password];
            try
            {
                using (StreamWriter stream_writer = new StreamWriter(@"C:\Users\home\Documents\password.txt", false))
                {
                    try
                    {
                        random_password.GetBytes(random_password_bytes);
                        stream_writer.Write(Convert.ToBase64String(random_password_bytes, 0, random_password_bytes.Length));
                        return true;
                    }
                    catch (NotSupportedException e)
                    {
                        return Throw_Exceptions.Throw_Exception_Error("Failed to write password to an invalid format or path-name.", e);
                    }
                    catch (Exception e)
                    {
                        return Throw_Exceptions.Throw_Exception_Error("Failed to generate and/or save a random password.", e);
                    }
                    finally
                    {
                        random_password.Dispose();
                        random_password_bytes = null;
                    }
                }
            }
            catch (UnauthorizedAccessException e)
            {
                return Throw_Exceptions.Throw_Exception_Error("You do not have authorization to save a password in the specified path.", e);
            }
            catch (ArgumentNullException e)
            {
                return Throw_Exceptions.Throw_Exception_Error("Trying to generate and/or save a password resulting in an Argument Null exception.", e);
            }
            catch (DirectoryNotFoundException e)
            {
                return Throw_Exceptions.Throw_Exception_Error("The specified path to save the password is invalid.", e);
            }
            catch (Exception e)
            {
                return Throw_Exceptions.Throw_Exception_Error("Failed to generate and/or save a random password for an unknown reason.", e);
            }
        }

        public Boolean Encrypt_And_Save_Password(string path_to_password, string path_to_encryption, int size_of_buffer)
        {
            try
            {
                encryptions_class = new Encryption();
                StreamReader stream_reader = new StreamReader(path_to_password, true);
                byte[] buffer = new byte[size_of_buffer];
                byte[] encrypted_buffer;
                List<byte> encrypted_file_list = new List<byte>();

                while (stream_reader.BaseStream.Read(buffer, 0, buffer.Length) > 0)
                {
                    if (buffer != null)
                    {
                        encrypted_buffer = encryptions_class.EncryptFile(public_rsa_key, buffer);
                        for (int i = 0; i < encrypted_buffer.Length; i++) encrypted_file_list.Add(encrypted_buffer[i]);
                    }
                    else { throw new IOException("Buffer was null!"); }
                }
                stream_reader.Close();
                File.WriteAllBytes(path_to_encryption, encrypted_file_list.ToArray());
                return true;
            }
            catch (Exception e)
            {
                return Throw_Exceptions.Throw_Exception_Error("Failed to encrypt and save the already existing password file.", e);
            }
        }

        public Boolean Decrypt_Password_File(string path_to_encryption, string path_to_password, int size_of_buffer)
        {
            try
            {
                StreamReader stream_reader = new StreamReader(path_to_encryption);

                byte[] buffer = new byte[size_of_buffer], decrypted_buffer;
                List<byte> decrypted_file_list = new List<byte>();

                while (stream_reader.BaseStream.Read(buffer, 0, buffer.Length) > 0)
                {
                    if (buffer != null)
                    {
                        decrypted_buffer = encryptions_class.DecryptFile(private_rsa_key, buffer);
                        for (int i = 0; i < decrypted_buffer.Length; i++) decrypted_file_list.Add(decrypted_buffer[i]);
                    }
                    else { throw new IOException("Buffer was null!"); }
                }
                stream_reader.Close();
                File.WriteAllBytes(path_to_password, decrypted_file_list.ToArray());

                return true;
            }
            catch (ArgumentNullException e)
            {
                return Throw_Exceptions.Throw_Exception_Error("Reading the password file resulted in an Argument Null Exception.", e);
            }
            catch (Exception e)
            {
                return Throw_Exceptions.Throw_Exception_Error("Cannot decrypt the encrypted password file.", e);
            }
        }
    }
}
