using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        // Global matrices
        byte[,] sBox = AESSBoxGenerator.GenerateSBox();

        // First row only, the rest is zeroes
        byte[] roundConst = new byte[] { 1, 2, 4, 8, 16, 32, 64, 128, 27, 54 };

        // Mix columns matrix
        byte[,] mixColumnsMatrix = new byte[4, 4]
            {{2,3,1,1},{1,2,3,1},{ 1,1,2,3}, { 3,1,1,2}
        };

        // Inverse mix columns matrix
        byte[,] invMixColumnsMatrix = new byte[4, 4]
            {{14,11,13,9},{9,14,11,13},{ 13,9,14,11}, { 11,13,9,14}
        };

        public override string Decrypt(string cipherText, string key)
        {
            byte[,] cipherTextBlock = HexaStringToByteMatrix(cipherText);
            byte[,] initialKeyBlock = HexaStringToByteMatrix(key);
            List<byte[,]> expandedKey = ExpandKey(initialKeyBlock);

            // Inverse final round
            byte[,] plainTextBlock = AddRoundKey(cipherTextBlock, expandedKey[10]);
            plainTextBlock = ShiftRows(plainTextBlock, true);
            plainTextBlock = InverseSubBytes(plainTextBlock);

            // 9 Rounds in between
            for (int i = 9; i > 0; i--)
            {
                plainTextBlock = AddRoundKey(plainTextBlock, expandedKey[i]);
                plainTextBlock = mixColumns(invMixColumnsMatrix, plainTextBlock);
                plainTextBlock = ShiftRows(plainTextBlock, true);
                plainTextBlock = InverseSubBytes(plainTextBlock);

            }

            // Initial round, just add round key
            plainTextBlock = AddRoundKey(plainTextBlock, initialKeyBlock);


            return ByteMatrixToHexaString(plainTextBlock);


        }


        public override string Encrypt(string plainText, string key)
        {
            byte[,] plainTextBlock = HexaStringToByteMatrix(plainText);
            byte[,] initialKeyBlock = HexaStringToByteMatrix(key);
            List<byte[,]> expandedKey = ExpandKey(initialKeyBlock);


            // Initial round, just add round key
            byte[,] cipherTextBlock = AddRoundKey(plainTextBlock, initialKeyBlock);

            // 9 Rounds in between
            for (int i = 1; i < 10; i++)
            {
                cipherTextBlock = SubBytes(cipherTextBlock);
                cipherTextBlock = ShiftRows(cipherTextBlock);
                cipherTextBlock = mixColumns(mixColumnsMatrix, cipherTextBlock);
                cipherTextBlock = AddRoundKey(cipherTextBlock, expandedKey[i]);
            }

            // Final round
            cipherTextBlock = SubBytes(cipherTextBlock);
            cipherTextBlock = ShiftRows(cipherTextBlock);
            cipherTextBlock = AddRoundKey(cipherTextBlock, expandedKey[10]);


            return ByteMatrixToHexaString(cipherTextBlock);
        }



        // Takes initial key and generates 10 keys based on that key
        private List<byte[,]> ExpandKey(byte[,] initialKey) {

            List<byte[,]> result = new List<byte[,]>();
            result.Add(initialKey);
            // Iterates over every round key
            for (int k = 1; k <= 10; k++)
            {
                byte[,] currentRoundKey = new byte[4, 4];
                byte[,] previousRoundKey = result[k - 1];

                // First word is a special case (mod 4 == 0) so W[i] = f(W[i-1]) XOR W[i-4]

                // Frst word in current round key is the last in the previous round key
                for (int i = 0; i < 4; i++) {
                    // Get bytes from previous word and rotate
                    currentRoundKey[i, 0] = previousRoundKey[(i + 1) % 4, 3];

                    // Sub Bytes
                    currentRoundKey[i, 0] = SubOneByte(currentRoundKey[i, 0]);
                }

                // XOR with round const
                currentRoundKey[0,0] ^= roundConst[k - 1];

                // XOR with w[i-4]
                for (int i = 0; i < 4; i++)
                {
                    // Get bytes from previous word and rotate
                    currentRoundKey[i, 0] ^= previousRoundKey[i, 0];
                }


                // Iterates over the rest of the words to do  // W[i] = W[i-1] XOR W[i-4]
                for (int i = 1; i< 4; i++)
                {
                    // Iterates over word elements
                    for (int j = 0; j < 4; j++)
                    {
                        currentRoundKey[j, i] = Convert.ToByte(currentRoundKey[j, i - 1] ^ previousRoundKey[j, i]);
                    }
            
                }
                result.Add(currentRoundKey);

            }
            return result;
        }

        // Shifts each row to the left by its index
        private byte[,] ShiftRows(byte[,] toShift, bool isInverse = false)
        {
            byte[,] result = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int shiftAmount = isInverse ? 4 - i : i;
                    // Calculate the new column index based on the direction of the shift and value of i
                    int newColIndex = (j + shiftAmount) % 4;
                    result[i, j] = toShift[i, newColIndex];
                }
            }

            return result;
        }

        // Performs matrix multplication in GF(2^8)
        private byte[,] mixColumns(byte[,] constantMatrix, byte[,] toMix)
        {
            byte[,] result = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result[i, j] = 0;
                    for (int k = 0; k < 4; k++) // combine elements from the constantMatrix and toMix
                    {
                        // Perform GF multiplication and XOR for addition in GF(2^8)
                        result[i, j] ^= AESSBoxGenerator.GFMul(constantMatrix[i, k], toMix[k, j]);
                    }
                }
            }

            return result;
        }

        // XORs respective elements together
        private byte[,] AddRoundKey(byte[,] plainTextBlock, byte[,] keyBlock)
        {
            byte[,] result = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result[i, j] = Convert.ToByte(plainTextBlock[i, j] ^ keyBlock[i, j]);
                }
            }

            return result;
        }


        // Takes a byte and subsitutes for it in the sBox
        private byte SubOneByte(byte toSub)
        {
            // Getting indices for sBox subsitution
            int rowIndex = toSub / 16;
            int colIndex = toSub % 16;

            return sBox[rowIndex, colIndex];

        }

        // Subsitutes all bytes in a block
        private byte[,] SubBytes(byte[,] toSub, bool isInverse = false)
        {
            byte[,] result = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result[i, j] = SubOneByte(toSub[i, j]);
                }
            }
            return result;
        }

        // Performs the inverse of SubBytes (for decryption)
        private byte[,] InverseSubBytes(byte[,] toSub)
        {
            byte[,] result = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    // Getting the rows and columns and then converting them to the original byte format
                    int[] indices = GetIndicesInSBox(toSub[i, j]);
                    result[i, j] = Convert.ToByte(16 * indices[0] + indices[1]);
                }
            }
            return result;

        }

        // Helper function to get indices of a byte
        private int[] GetIndicesInSBox(byte x) {

            for (int i = 0; i < 16; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    if (sBox[i, j] == x)
                    {
                        return new int[] {i,j};
                    }
                }
            }
            return new int[] { -1, -1 };
            
        }

        // Converts string hexa representation to a 4x4 matrix where each cell is a byte
        private byte[,] HexaStringToByteMatrix(string hexaFormat)
        {
            byte[,] result = new byte[4, 4];

            int Index = 2;
            for (int i = 0; i < 4; i++) { 
                for (int j = 0; j < 4; j++)
                {
                    // Hexa to Byte conversion
                    result[j, i] = Convert.ToByte(hexaFormat[Index].ToString() + hexaFormat[Index + 1].ToString(), 16);
                    Index +=2;
                }
            }

            return result;
        }


        // Converts a 4x4 byte matrix to a string of 32 Hexa letters preceeded by 0x
        private string ByteMatrixToHexaString(byte[,] matrix)
        {
            string result = "0x";

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result += matrix[j, i].ToString("X2");
                }
            }
            return result;
        }

    }


    public class AESSBoxGenerator
    {
        // Multiplication in GF(2^8)
        public static byte GFMul(byte a, byte b)
        {
            byte p = 0;
            byte counter;
            byte hi_bit_set;
            for (counter = 0; counter < 8; counter++)
            {
                if ((b & 1) != 0)
                {
                    p ^= a;
                }
                hi_bit_set = (byte)(a & 0x80);
                a <<= 1;
                if (hi_bit_set != 0)
                {
                    a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
                }
                b >>= 1;
            }
            return p;
        }

        // Calculate the multiplicative inverse in GF(2^8)
        private static byte GFMulInverse(byte b)
        {
            if (b == 0)
            {
                return 0;
            }
            byte inv = 1;
            for (int i = 0; i < 254; i++) // Extended Euclidean Algorithm
            {
                inv = GFMul(inv, b);
            }
            return inv;
        }

        // Apply the affine transformation
        private static byte AffineTransform(byte b)
        {
            byte[] matrix = new byte[] {
            0xF1, 0xE3, 0xC7, 0x8F, 0x1F, 0x3E, 0x7C, 0xF8
        };
            byte result = 0;
            for (int i = 0; i < 8; i++)
            {
                byte temp = 0;
                for (int j = 0; j < 8; j++)
                {
                    if ((b & (1 << j)) != 0 && (matrix[i] & (1 << j)) != 0)
                    {
                        temp ^= 1;
                    }
                }
                result |= (byte)(temp << i);
            }
            return (byte)(result ^ 0x63);
        }

        // Generate the S-box
        public static byte[,] GenerateSBox()
        {
            byte[,] sBox = new byte[16, 16];
            for (int i = 0; i < 256; i++)
            {
                byte inverse = GFMulInverse((byte)i);
                byte transformed = AffineTransform(inverse);
                sBox[i / 16, i % 16] = transformed;
            }
            return sBox;
        }
    }
}
