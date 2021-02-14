using System;
using System.Collections.Generic;
using System.Text;

namespace NtlmHttp
{
    /// <summary>
    /// Based on https://www.sevecek.com/EnglishPages/Lists/Posts/Post.aspx?ID=90
    /// </summary>
    internal class MD4
    {
        private class Bitwise
        {
            /// <summary>
            /// Added missing function: 
            /// </summary>
            public static UInt32 LoadUInt32(byte[] message, int i)
            {
                return BitConverter.ToUInt32(message, i);
            }
        }

        // Note: this implements RFC1320

        private static UInt32 AuxF(UInt32 x, UInt32 y, UInt32 z)
        {
            // Note: ... "We first define three auxiliary functions" ...
            return ((x & y) | ((~x) & z));
        }

        private static UInt32 AuxG(UInt32 x, UInt32 y, UInt32 z)
        {
            // Note: ... "We first define three auxiliary functions" ...
            return ((x & y) | (x & z) | (y & z));
        }

        private static UInt32 AuxH(UInt32 x, UInt32 y, UInt32 z)
        {
            // Note: ... "We first define three auxiliary functions" ...
            return (x ^ y ^ z);
        }

        private static UInt32 LeftRotate(UInt32 x, int s)
        {
            // Note: ... "32-bit value obtained by circularly shifting (rotating) X left by s bit positions" ...
            return (x << s) | (x >> (32 - s));
        }

        private static void RoundF(ref UInt32 a, ref UInt32 b, ref UInt32 c, ref UInt32 d, UInt32 k, int s, UInt32[] processingBuffer)
        {
            a = LeftRotate((a + AuxF(b, c, d) + processingBuffer[k]), s);
        }

        private static void RoundG(ref UInt32 a, ref UInt32 b, ref UInt32 c, ref UInt32 d, UInt32 k, int s, UInt32[] processingBuffer)
        {
            a = LeftRotate(a + AuxG(b, c, d) + processingBuffer[k] + 0x5A827999, s);
        }

        private static void RoundH(ref UInt32 a, ref UInt32 b, ref UInt32 c, ref UInt32 d, UInt32 k, int s, UInt32[] processingBuffer)
        {
            a = LeftRotate(a + AuxH(b, c, d) + processingBuffer[k] + 0x6ED9EBA1, s);
        }

        public static byte[] Compute(byte[] message)
        {
            // Note: ... "The message is "padded" (extended) so that its length (in bits) is congruent to 448, modulo 512." ...
            int messageLenBit = message.Length * 8;

            int paddedLenBit = (messageLenBit / 512) * 512 + 448;
            if (paddedLenBit <= messageLenBit) { paddedLenBit += 512; }

            // Note: ... "A 64-bit representation of b (the length of the message before the padding bits were added) is appended to the result of the previous step" ...
            byte[] paddedMessage = new byte[(paddedLenBit + 64) / 8];

            Array.Copy(message, 0, paddedMessage, 0, message.Length);
            // Note: ... "a single "1" bit is appended to the message" ...
            // Note: as the RFC defines, a byte is a sequence of bits with the highest order bit going first
            paddedMessage[message.Length] = 0x80;

            byte[] uint64messageLen = BitConverter.GetBytes((UInt64)messageLenBit);
            Array.Copy(uint64messageLen, 0, paddedMessage, paddedMessage.Length - uint64messageLen.Length, uint64messageLen.Length);

            int paddedMessageWords = paddedMessage.Length / 4;
            int paddedMessage16WordBlocks = paddedMessageWords / 16;

            // Note: ... "These registers are initialized to the following values in hexadecimal" ...
            UInt32 regA = 0x67452301;
            UInt32 regB = 0xEFCDAB89;
            UInt32 regC = 0x98BADCFE;
            UInt32 regD = 0x10325476;

            UInt32[] processingBuffer = new UInt32[16];

            // Note: ... "Process each 16-word block" ...
            for (int i = 0; i < paddedMessage16WordBlocks; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    processingBuffer[j] = Bitwise.LoadUInt32(paddedMessage, (i * 16 + j) * 4);
                }

                UInt32 saveA = regA;
                UInt32 saveB = regB;
                UInt32 saveC = regC;
                UInt32 saveD = regD;

                //
                // Note: ... "Round 1" ...

                RoundF(ref regA, ref regB, ref regC, ref regD, 0, 3, processingBuffer);
                RoundF(ref regD, ref regA, ref regB, ref regC, 1, 7, processingBuffer);
                RoundF(ref regC, ref regD, ref regA, ref regB, 2, 11, processingBuffer);
                RoundF(ref regB, ref regC, ref regD, ref regA, 3, 19, processingBuffer);

                RoundF(ref regA, ref regB, ref regC, ref regD, 4, 3, processingBuffer);
                RoundF(ref regD, ref regA, ref regB, ref regC, 5, 7, processingBuffer);
                RoundF(ref regC, ref regD, ref regA, ref regB, 6, 11, processingBuffer);
                RoundF(ref regB, ref regC, ref regD, ref regA, 7, 19, processingBuffer);

                RoundF(ref regA, ref regB, ref regC, ref regD, 8, 3, processingBuffer);
                RoundF(ref regD, ref regA, ref regB, ref regC, 9, 7, processingBuffer);
                RoundF(ref regC, ref regD, ref regA, ref regB, 10, 11, processingBuffer);
                RoundF(ref regB, ref regC, ref regD, ref regA, 11, 19, processingBuffer);

                RoundF(ref regA, ref regB, ref regC, ref regD, 12, 3, processingBuffer);
                RoundF(ref regD, ref regA, ref regB, ref regC, 13, 7, processingBuffer);
                RoundF(ref regC, ref regD, ref regA, ref regB, 14, 11, processingBuffer);
                RoundF(ref regB, ref regC, ref regD, ref regA, 15, 19, processingBuffer);

                //
                // Note: ... "Round 2" ...

                RoundG(ref regA, ref regB, ref regC, ref regD, 0, 3, processingBuffer);
                RoundG(ref regD, ref regA, ref regB, ref regC, 4, 5, processingBuffer);
                RoundG(ref regC, ref regD, ref regA, ref regB, 8, 9, processingBuffer);
                RoundG(ref regB, ref regC, ref regD, ref regA, 12, 13, processingBuffer);

                RoundG(ref regA, ref regB, ref regC, ref regD, 1, 3, processingBuffer);
                RoundG(ref regD, ref regA, ref regB, ref regC, 5, 5, processingBuffer);
                RoundG(ref regC, ref regD, ref regA, ref regB, 9, 9, processingBuffer);
                RoundG(ref regB, ref regC, ref regD, ref regA, 13, 13, processingBuffer);

                RoundG(ref regA, ref regB, ref regC, ref regD, 2, 3, processingBuffer);
                RoundG(ref regD, ref regA, ref regB, ref regC, 6, 5, processingBuffer);
                RoundG(ref regC, ref regD, ref regA, ref regB, 10, 9, processingBuffer);
                RoundG(ref regB, ref regC, ref regD, ref regA, 14, 13, processingBuffer);

                RoundG(ref regA, ref regB, ref regC, ref regD, 3, 3, processingBuffer);
                RoundG(ref regD, ref regA, ref regB, ref regC, 7, 5, processingBuffer);
                RoundG(ref regC, ref regD, ref regA, ref regB, 11, 9, processingBuffer);
                RoundG(ref regB, ref regC, ref regD, ref regA, 15, 13, processingBuffer);

                //
                // Note: ... "Round 3" ...

                RoundH(ref regA, ref regB, ref regC, ref regD, 0, 3, processingBuffer);
                RoundH(ref regD, ref regA, ref regB, ref regC, 8, 9, processingBuffer);
                RoundH(ref regC, ref regD, ref regA, ref regB, 4, 11, processingBuffer);
                RoundH(ref regB, ref regC, ref regD, ref regA, 12, 15, processingBuffer);

                RoundH(ref regA, ref regB, ref regC, ref regD, 2, 3, processingBuffer);
                RoundH(ref regD, ref regA, ref regB, ref regC, 10, 9, processingBuffer);
                RoundH(ref regC, ref regD, ref regA, ref regB, 6, 11, processingBuffer);
                RoundH(ref regB, ref regC, ref regD, ref regA, 14, 15, processingBuffer);

                RoundH(ref regA, ref regB, ref regC, ref regD, 1, 3, processingBuffer);
                RoundH(ref regD, ref regA, ref regB, ref regC, 9, 9, processingBuffer);
                RoundH(ref regC, ref regD, ref regA, ref regB, 5, 11, processingBuffer);
                RoundH(ref regB, ref regC, ref regD, ref regA, 13, 15, processingBuffer);

                RoundH(ref regA, ref regB, ref regC, ref regD, 3, 3, processingBuffer);
                RoundH(ref regD, ref regA, ref regB, ref regC, 11, 9, processingBuffer);
                RoundH(ref regC, ref regD, ref regA, ref regB, 7, 11, processingBuffer);
                RoundH(ref regB, ref regC, ref regD, ref regA, 15, 15, processingBuffer);

                //
                //

                regA += saveA;
                regB += saveB;
                regC += saveC;
                regD += saveD;
            }


            byte[] hash = new byte[16];
            Array.Copy(BitConverter.GetBytes(regA), 0, hash, 0, 4);
            Array.Copy(BitConverter.GetBytes(regB), 0, hash, 4, 4);
            Array.Copy(BitConverter.GetBytes(regC), 0, hash, 8, 4);
            Array.Copy(BitConverter.GetBytes(regD), 0, hash, 12, 4);

            return hash;
        }

        // Added for compatiblity
        public static void Hash(Span<byte> output, Span<byte> input)
        {
            var result = Compute(input.ToArray());
            result.CopyTo(output);
        }
    }
}
