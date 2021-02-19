/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
   rights reserved.

   License to copy and use this software is granted provided that it
   is identified as the "RSA Data Security, Inc. MD4 Message-Digest
   Algorithm" in all material mentioning or referencing this software
   or this function.

   License is also granted to make and use derivative works provided
   that such works are identified as "derived from the RSA Data
   Security, Inc. MD4 Message-Digest Algorithm" in all material
   mentioning or referencing the derived work.

   RSA Data Security, Inc. makes no representations concerning either
   the merchantability of this software or the suitability of this
   software for any particular purpose. It is provided "as is"
   without express or implied warranty of any kind.

   These notices must be retained in any copies of any part of this
   documentation and/or software.
 */

using System;
using System.Collections.Generic;
using System.Text;

namespace NtlmHttp
{
    public class Md4
    {
        private const int S11 = 3;
        private const int S12 = 7;
        private const int S13 = 11;
        private const int S14 = 19;
        private const int S21 = 3;
        private const int S22 = 5;
        private const int S23 = 9;
        private const int S24 = 13;
        private const int S31 = 3;
        private const int S32 = 9;
        private const int S33 = 11;
        private const int S34 = 15;

        private static byte[] Padding = {
          0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };

        private UInt32[] state = new UInt32[4];        // state (ABCD)
        private UInt32[] count = new UInt32[2];        // number of bits, modulo 2^64 (lsb first)
        private byte[] buffer = new byte[64];          //

        // F, G and H are basic MD4 functions.
        static UInt32 F(UInt32 x, UInt32 y, UInt32 z) => (x & y) | (~x & z);
        static UInt32 G(UInt32 x, UInt32 y, UInt32 z) => (x & y) | (x & z) | (y & z);
        static UInt32 H(UInt32 x, UInt32 y, UInt32 z) => x ^ y ^ z;

        // rotates x left n bits.
        static UInt32 RotateLeft(UInt32 x, int n) => (x << n) | (x >> (32 - n));

        // FF, GG and HH are transformations for rounds 1, 2 and 3
        // Rotation is separate from addition to prevent recomputation
        static void FF(ref UInt32 a, UInt32 b, UInt32 c, UInt32 d, UInt32 x, int s)
        {
            a += F(b, c, d) + x;
            a = RotateLeft(a, s);
        }

        static void GG(ref UInt32 a, UInt32 b, UInt32 c, UInt32 d, UInt32 x, int s)
        {
            a += G(b, c, d) + x + (UInt32)0x5a827999;
            a = RotateLeft(a, s);
        }

        static void HH(ref UInt32 a, UInt32 b, UInt32 c, UInt32 d, UInt32 x, int s)
        {
            a += H(b, c, d) + x + (UInt32)0x6ed9eba1;
            a = RotateLeft(a, s);
        }

        // MD4 initialization. Begins an MD4 operation, writing a new context.
        private void Init()
        {
            count[0] = 0;
            count[1] = 0;

            // Load magic initialization constants.
            state[0] = 0x67452301;
            state[1] = 0xefcdab89;
            state[2] = 0x98badcfe;
            state[3] = 0x10325476;
        }

        /// <summary>
        /// MD4 block update operation. Continues an MD4 message-digest
        /// operation, processing another message block, and updating the context.
        /// </summary>
        private void Update(Span<byte> input, int inputLen)
        {
            int i, index, partLen;

            // Compute number of bytes mod 64
            index = (int)((count[0] >> 3) & 0x3F);

            // Update number of bits
            if ((count[0] += ((UInt32)inputLen << 3)) < ((UInt32)inputLen << 3))
            {
                count[1]++;
            }

            count[1] += ((UInt32)inputLen >> 29);

            partLen = 64 - index;

            // Transform as many times as possible.
            if (inputLen >= partLen)
            {
                Copy(buffer.AsSpan(index), input, partLen);
                Transform(state, buffer);

                for (i = partLen; i + 63 < inputLen; i += 64)
                {
                    Transform(state, input.Slice(i));
                }

                index = 0;
            }
            else
            {
                i = 0;
            }

            // Buffer remaining input
            Copy(buffer.AsSpan(index), input.Slice(i), inputLen - i);
        }

        /// <summary>
        /// MD4 finalization. Ends an MD4 message-digest operation, writing the
        /// the message digest and zeroizing the context.
        /// </summary>
        /// <param name="digest"></param>
        private void Final(byte[] digest)
        {
            var bits = new byte[8];
            int index, padLen;

            // Save number of bits
            Encode(bits, count);

            // Pad out to 56 mod 64.
            index = (int)((count[0] >> 3) & 0x3f);
            padLen = (index < 56) ? (56 - index) : (120 - index);
            Update(Padding, padLen);

            // Append length (before padding)
            Update(bits, 8);

            // Store state in digest
            Encode(digest, state);

            // Zeroize sensitive information.
            Clear<UInt32>(state);
            Clear<UInt32>(count);
            Clear<byte>(buffer);
        }

        /// <summary>
        /// MD4 basic transformation. Transforms state based on block.
        /// </summary>
        private void Transform(UInt32[] state, Span<byte> block)
        {
            UInt32 a = state[0], b = state[1], c = state[2], d = state[3];
            UInt32[] x = new UInt32[16];

            Decode(x, block, 64);

            // Round 1
            FF(ref a, b, c, d, x[0], S11); // 1
            FF(ref d, a, b, c, x[1], S12); // 2
            FF(ref c, d, a, b, x[2], S13); // 3
            FF(ref b, c, d, a, x[3], S14); // 4
            FF(ref a, b, c, d, x[4], S11); // 5
            FF(ref d, a, b, c, x[5], S12); // 6
            FF(ref c, d, a, b, x[6], S13); // 7
            FF(ref b, c, d, a, x[7], S14); // 8
            FF(ref a, b, c, d, x[8], S11); // 9
            FF(ref d, a, b, c, x[9], S12); // 10
            FF(ref c, d, a, b, x[10], S13); // 11
            FF(ref b, c, d, a, x[11], S14); // 12
            FF(ref a, b, c, d, x[12], S11); // 13
            FF(ref d, a, b, c, x[13], S12); // 14
            FF(ref c, d, a, b, x[14], S13); // 15
            FF(ref b, c, d, a, x[15], S14); // 16

            // Round 2
            GG(ref a, b, c, d, x[0], S21); // 17
            GG(ref d, a, b, c, x[4], S22); // 18
            GG(ref c, d, a, b, x[8], S23); // 19
            GG(ref b, c, d, a, x[12], S24); // 20
            GG(ref a, b, c, d, x[1], S21); // 21
            GG(ref d, a, b, c, x[5], S22); // 22
            GG(ref c, d, a, b, x[9], S23); // 23
            GG(ref b, c, d, a, x[13], S24); // 24
            GG(ref a, b, c, d, x[2], S21); // 25
            GG(ref d, a, b, c, x[6], S22); // 26
            GG(ref c, d, a, b, x[10], S23); // 27
            GG(ref b, c, d, a, x[14], S24); // 28
            GG(ref a, b, c, d, x[3], S21); // 29
            GG(ref d, a, b, c, x[7], S22); // 30
            GG(ref c, d, a, b, x[11], S23); // 31
            GG(ref b, c, d, a, x[15], S24); // 32

            // Round 3
            HH(ref a, b, c, d, x[0], S31); // 33
            HH(ref d, a, b, c, x[8], S32); // 34
            HH(ref c, d, a, b, x[4], S33); // 35
            HH(ref b, c, d, a, x[12], S34); // 36
            HH(ref a, b, c, d, x[2], S31); // 37
            HH(ref d, a, b, c, x[10], S32); // 38
            HH(ref c, d, a, b, x[6], S33); // 39
            HH(ref b, c, d, a, x[14], S34); // 40
            HH(ref a, b, c, d, x[1], S31); // 41
            HH(ref d, a, b, c, x[9], S32); // 42
            HH(ref c, d, a, b, x[5], S33); // 43
            HH(ref b, c, d, a, x[13], S34); // 44
            HH(ref a, b, c, d, x[3], S31); // 45
            HH(ref d, a, b, c, x[11], S32); // 46
            HH(ref c, d, a, b, x[7], S33); // 47
            HH(ref b, c, d, a, x[15], S34); // 48

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;

            // Zeroize sensitive information.
            Clear<UInt32>(x);
        }

        // Encodes input (UINT4) into output (unsigned char). Assumes len is a multiple of 4.
        private static void Encode(byte[] output, Span<UInt32> input)
        {
            int i, j;

            for (i = 0, j = 0; j < output.Length; i++, j += 4)
            {
                BitConverter.GetBytes(input[i]).CopyTo(output, j);
            }
        }

        private static void Decode(Span<UInt32> output, Span<byte> input, int len)
        {
            int i, j;

            for (i = 0, j = 0; j < len; i++, j += 4)
            {
                output[i] = BitConverter.ToUInt32(input.Slice(j));
            }
        }

        private static void Copy(Span<byte> output, Span<byte> input, int len)
        {
            input.Slice(0, len).CopyTo(output);
        }

        // Note: Replace "for loop" with standard memset if possible.
        private static void Clear<T>(Span<T> output)
        {
            output.Clear();
        }

        public byte[] Hash(Span<byte> input)
        {
            var hash = new byte[16];

            Init();
            Update(input, input.Length);
            Final(hash);

            return hash;
        }

    }
}
