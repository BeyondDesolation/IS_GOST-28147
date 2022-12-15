using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace D.ISlab2
{
    internal class GOST28147
    {
        private readonly byte[,] _sBoxes = new byte[,]
        {
            {4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3 },
            {14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9 },
            {5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11 },
            {7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3},
            {6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2},
            {4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14},
            {13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12},
            {1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12}
        };

        private uint[] _subKeys;

        private byte[]? _key;
        public byte[] Key
        {
            get => _key ?? throw new ArgumentException("Key isn't initialized");
            set
            {
                if (value.Length != 32)
                    throw new ArgumentException("Key lenght must be 256 bit");
               
                _key = value;
            }
        }
        private byte[]? _IV;
        public byte[] IV
        {
            get => _IV ?? throw new ArgumentException("IV isn't initialized");
            set
            {
                if (value.Length != 8)
                    throw new ArgumentException("IV lenght must be 64 bit");

                _IV = value;
            }
        }

        public byte[] PlainText { get; set; } = new byte[0];

        public GOST28147(byte[] key, byte[] iv)
        {
            Key = key;
            IV = iv;
        }

        public byte[] Encrypt(byte[] plainText)
        {
            return EncryptInner(plainText, true);
        }

        public byte[] Decrypt(byte[] cipherText) 
        {
            return EncryptInner(cipherText, false);
        }

        private byte[] EncryptInner(byte[] text, bool encrypt)
        {
            _subKeys = SplitKey(Key);

            var gamma = EncryptinCycle32_3(IV);

            var result = new byte[text.Length];

            for (int i = 0; i < text.Length; i+= 8)
            {

                var remaining = text.Length - i;
                var blockSize = remaining > 8 ? 8 : remaining;

                var block = new byte[blockSize];

                for (int j = 0; j < 8 && i + j < text.Length; j++)
                {
                    block[j] = text[i + j];
                }

                var encryptedBlock = ApplyGamma(block, gamma);

                if (remaining > 8)
                {
                    if (encrypt)
                    {
                        gamma = EncryptinCycle32_3(encryptedBlock);
                    }
                    else
                    {
                        gamma = EncryptinCycle32_3(block);
                    }
                }

                for (int j = 0; j < encryptedBlock.Length; j++)
                {
                    result[i + j] = encryptedBlock[j];
                }
            }

            return result;
        }

        private byte[] ApplyGamma(byte[] data, byte[] gamma)
        {
            byte[] res = new byte[data.Length];

            for (int i = 0; i < data.Length; i++)
            {
                res[i] = (byte)(data[i] ^ gamma[i]);
            }

            return res;
        }

        private byte[] EncryptinCycle32_3(byte[] block)
        {
            var left = BitConverter.ToUInt32(block, 0);
            var right = BitConverter.ToUInt32(block, 4);

            var result = new byte[8];


            for (int i = 0; i < 32; i++)
            {
                var keyIndex = GetKeyIndexFor32_3Cycle(i, true);
                var subKey = _subKeys[keyIndex];

                var fValue = F(right, subKey);
                var round = left ^ fValue;

                if (i < 31)
                {
                    left = right;
                    right = round;
                }
                else
                {
                    left = round;
                }
            }

            Array.Copy(BitConverter.GetBytes(left), 0, result, 0, 4);
            Array.Copy(BitConverter.GetBytes(right), 0, result, 4, 4);

            return result;
        }

    private int GetKeyIndexFor32_3Cycle(int i, bool encrypt)
        {
            return encrypt ? (i < 24) ? i % 8 : 7 - (i % 8)
                           : (i < 8) ? i % 8 : 7 - (i % 8);
        }

        private uint F(uint block, uint subKey)
        {
            block = (block + subKey) % uint.MaxValue;
            block = Substitute(block);
            block = (block << 11) | (block >> 21);
            return block;
        }

        private uint Substitute(uint value)
        {
            byte index, sBlock;
            uint result = 0;

            for (int i = 0; i < 8; i++)
            {
                index = (byte)(value >> (4 * i) & 0x0f);
                sBlock = _sBoxes[i, index];
                result |= (uint)sBlock << (4 * i);
            }

            return result;
        }

        private uint[] SplitKey(byte[] key)
        {
            // Да, можно было просто использовать BitConverter, но так неинтересно
            uint[] sybKeys = new uint[8];
            int index = 0;
            for (int i = 0; i < 32; i+= 4)
            {
                uint sybKey = 0;
                for (int j = 0; j < 4; j++)
                {
                    sybKey <<= 8;
                    sybKey |= key[i + j];
                }
                sybKeys[index] = sybKey;
                index++;
            }
            return sybKeys;
        }

    }
}
