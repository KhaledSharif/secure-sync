using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace SecureSync
{
    class Secure
    {
        private AesCryptoServiceProvider m_des = new AesCryptoServiceProvider();

        private byte[] m_key;
        private byte[] m_iv;

        private Random random_seed;

        public Secure(byte[] key)
        {
            this.m_key = key;
            this.random_seed = new Random(BitConverter.ToInt32(this.m_key, 0));
            this.m_iv = new byte[16];
            this.random_seed.NextBytes(this.m_iv);
        }

        public byte[] Encrypt(byte[] input)
        {
            return Transform(input, m_des.CreateEncryptor(m_key, m_iv));
        }

        public byte[] Decrypt(byte[] input)
        {
            return Transform(input, m_des.CreateDecryptor(m_key, m_iv));
        }

        private byte[] Transform(byte[] input, ICryptoTransform CryptoTransform)
        {
            MemoryStream memStream = new MemoryStream();
            CryptoStream cryptStream = new CryptoStream(memStream, CryptoTransform, CryptoStreamMode.Write);
            cryptStream.Write(input, 0, input.Length);
            cryptStream.FlushFinalBlock();
            memStream.Position = 0;
            byte[] result = memStream.ToArray();
            memStream.Close();
            cryptStream.Close();
            return result;
        }
    }
}
