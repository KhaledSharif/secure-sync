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
    class Hello
    {
        static private RSACryptoServiceProvider rsa_service_provider;
        static private RSAParameters public_rsa_key, private_rsa_key;
        static private Encryption encryptions_class;
        static private List<Secure> list_of_securities;

        static private Boolean Throw_Exception_Error(String error_message, Exception e)
        {
            Console.WriteLine("A fatal error has just occured: \n\t{0}\n\n" +
                              "The program will now terminate. " +
                              "The exception is printed out below:\n\n{1}\n\n",
                              error_message, e.ToString());
            return false;
        }

        static private Boolean Open_RSA_Keys(string path_to_public_key, string path_to_private_key)
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
                    return Throw_Exception_Error("Failed to open already existing RSA keys.", e);
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
                    return Throw_Exception_Error("Failed to create new RSA keys due to absence of saved keys.", e);
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
                return Throw_Exception_Error("Failed to set public and private RSA keys in memory.", e);
            }
        }

        static private Boolean Save_Random_Password(string path_to_password, int length_of_password)
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
                        return Throw_Exception_Error("Failed to write password to an invalid format or path-name.", e);
                    }
                    catch (Exception e)
                    {
                        return Throw_Exception_Error("Failed to generate and/or save a random password.", e);
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
                return Throw_Exception_Error("You do not have authorization to save a password in the specified path.", e);
            }
            catch (ArgumentNullException e)
            {
                return Throw_Exception_Error("Trying to generate and/or save a password resulting in an Argument Null exception.", e);
            }
            catch (DirectoryNotFoundException e)
            {
                return Throw_Exception_Error("The specified path to save the password is invalid.", e);
            }
            catch (Exception e)
            {
                return Throw_Exception_Error("Failed to generate and/or save a random password for an unknown reason.", e);
            }
        }

        static private Boolean Encrypt_And_Save_Password(string path_to_password, string path_to_encryption, int size_of_buffer)
        {
            try
            {
                encryptions_class = new Encryption();
                StreamReader stream_reader = new StreamReader(path_to_password, true);
                byte[] buffer = new byte[size_of_buffer];
                byte[] encrypted_buffer;
                List<byte> encrypted_file_list = new List<byte>();
                int bytes_read = 0;
                while ((bytes_read = stream_reader.BaseStream.Read(buffer, 0, buffer.Length)) > 0)
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
                return Throw_Exception_Error("Failed to encrypt and save the already existing password file.", e);
            }
        }

        static private Boolean Decrypt_Password_File(string path_to_encryption, string path_to_password, int size_of_buffer)
        {
            try
            {
                StreamReader stream_reader = new StreamReader(path_to_encryption);
                byte[] new_buffer = new byte[size_of_buffer];
                byte[] decrypted_buffer;
                List<byte> decrypted_file_list = new List<byte>();
                int bytes_read = 0;
                while ((bytes_read = stream_reader.BaseStream.Read(new_buffer, 0, new_buffer.Length)) > 0)
                {
                    if (new_buffer != null)
                    {
                        decrypted_buffer = encryptions_class.DecryptFile(private_rsa_key, new_buffer);
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
                return Throw_Exception_Error("Reading the password file resulted in an Argument Null Exception.", e);
            }
            catch (Exception e)
            {
                return Throw_Exception_Error("Cannot decrypt the encrypted password file.", e);
            }
        }

        static private Boolean Get_All_Securities(string path_to_password)
        {
            try
            {
                byte[] read_key = File.ReadAllBytes(path_to_password);
                list_of_securities = new List<Secure>();
                for (int i = 0; i < read_key.Length; i += 32)
                    list_of_securities.Add(new Secure(new List<byte>(read_key).GetRange(i, 32).ToArray()));
                return true;
            }
            catch (FileNotFoundException e)
            {
                return Throw_Exception_Error("You provided an invalid path to the password file.", e);
            }
            catch (Exception e)
            {
                return Throw_Exception_Error("Failed to fetch some or all of the securities.", e);
            }
        }

        static private Boolean Encrypt_With_Securities(string path_to_file, string path_to_encryption)
        {
            byte[] insecure_file, secure_file;
            try
            {
                insecure_file = File.ReadAllBytes(path_to_file);
                secure_file = new byte[insecure_file.Length];
                Buffer.BlockCopy(insecure_file, 0, secure_file, 0, insecure_file.Length);
                for (int i = 0; i < list_of_securities.Count; i++)
                    secure_file = list_of_securities[i].Encrypt(secure_file);
                File.WriteAllBytes(path_to_encryption, secure_file);
                return true;
            }
            catch (DirectoryNotFoundException e)
            {
                return Throw_Exception_Error("The path for the file to be encrypted and/or saved was incorrect.", e);
            }
            catch (Exception e)
            {
                return Throw_Exception_Error("Failed to encrypt the file with securities.", e);
            }
        }

        static private Boolean Decrypt_Using_Securities(string path_to_encrypted_file, string path_to_decrypted_file)
        {
            byte[] new_secure_file, new_insecure_file;
            try
            {
                new_secure_file = File.ReadAllBytes(path_to_encrypted_file);
                new_insecure_file = new byte[new_secure_file.Length];
                Buffer.BlockCopy(new_secure_file, 0, new_insecure_file, 0, new_secure_file.Length);
                for (int i = list_of_securities.Count - 1; i >= 0; i--)
                    new_insecure_file = list_of_securities[i].Decrypt(new_insecure_file);
                File.WriteAllBytes(path_to_decrypted_file, new_insecure_file);
            }
            catch (DirectoryNotFoundException e)
            {
                return Throw_Exception_Error("The path for the file to be decrypted and/or saved was incorrect.", e);
            }
            catch (Exception e)
            {
                return Throw_Exception_Error("Failed to decrypt or to write the decrypted file to disk.", e);
            }
            return true;
        }

        static void Main()
        {
            if (!Open_RSA_Keys(@"C:\Users\home\Documents\rsa_public_key.blob",
                               @"C:\Users\home\Documents\rsa_private_key.blob"))
                return;

            if (!Save_Random_Password(@"C:\Users\home\Documents\password.txt", 512))
                return;

            if (!Encrypt_And_Save_Password(@"C:\Users\home\Documents\password.txt",
                                           @"C:\Users\home\Documents\password_encrypted.txt", 256))
                return;

            if (!Decrypt_Password_File(@"C:\Users\home\Documents\password_encrypted.txt",
                                       @"C:\Users\home\Documents\password_decrypted.txt", 512))
                return;

            if (!Get_All_Securities(@"C:\Users\home\Documents\password_decrypted.txt"))
                return;

            if (!Encrypt_With_Securities(@"C:\Users\home\Documents\color.jpg",
                                         @"C:\Users\home\Documents\color_encrypted.jpg"))
                return;

            if (!Decrypt_Using_Securities(@"C:\Users\home\Documents\color_encrypted.jpg",
                                          @"C:\Users\home\Documents\color_decrypted.jpg"))
                return;
        }
    }
}