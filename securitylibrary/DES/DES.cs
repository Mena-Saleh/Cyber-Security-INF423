using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        // Key expansion permutation choices:
        List<int> PC1 = new List<int>
        {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 56, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        };

        List<int> PC2 = new List<int>
        {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        };

        // Initial Permutation and its inverse
        List<int> IP = new List<int>
        {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };

        List<int> IPInv = new List<int>
        {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        };

        // Expansion Permutation (32 -> 48)
        List<int> EP = new List<int>
        {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        };

        // Sub Boxes
        List<int[,]> SBoxes = new List<int[,]>
        {
            // S1
            new int[,] {
                {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
            },
            // S2
            new int[,] {
                {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
            },
            // S3
            new int[,] {
                {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
            },
            // S4
            new int[,] {
                {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
            },
            // S5
            new int[,] {
                {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
            },
            // S6
            new int[,] {
                {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
            },
            // S7
            new int[,] {
                {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
            },
            // S8
            new int[,] {
                {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
            }
        };

        // Permutation Box
        List<int> PBox = new List<int>
        {
            16, 7, 20, 21, 29, 12, 28, 17,
            1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9,
            19, 13, 30, 6, 22, 11, 4, 25
        };

        public override string Decrypt(string cipherText, string key)
        {
            // Run the DES algorithm with keys in reverse order
            return PerformDES(cipherText, key, true);
        }

        public override string Encrypt(string plainText, string key)
        {
           // Run the DES algorithm
           return PerformDES(plainText, key);
        }


        // Wrapper to perform DesAlgorithm
        public string PerformDES(string plainText, string key, bool isDecrypt = false)
        {
            // Convert to lists of int
            List<int> plainList = StringHexToIntList(plainText);
            List<int> keyList = StringHexToIntList(key);

            // Generate keys for all 16 rounds
            List<List<int>> keys = GenerateKeys(keyList);

            // Perfrom initial permutation
            List<int> cipherList = PermutateList(plainList, IP);

            // Perform 16 rounds

            // The midpoint of the list
            int mid = cipherList.Count / 2;

            // Split into two lists
            List<int> L = cipherList.GetRange(0, mid);
            List<int> R = cipherList.GetRange(mid, mid);


            // Feed keys in reverse in case of decryption
            if (isDecrypt)
            {
                for (int i = 15; i >= 0; i--)
                {
                    // New left is old right
                    List<int> LNew = new List<int>(R);
                    // New right is the result of the feistel function with the current round key
                    R = new List<int>(PerformFeistelFunction(L, R, keys[i]));
                    L = LNew;
                }
            }
            else {
                for (int i = 0; i < 16; i++)
                {
                    // New left is old right
                    List<int> LNew = new List<int>(R);
                    // New right is the result of the feistel function with the current round key
                    R = new List<int>(PerformFeistelFunction(L, R, keys[i]));
                    L = LNew;
                }
            }
        

            // Concatenate but with reverse order
            cipherList = R.Concat(L).ToList();

            // Perfrom inverse initial permutation
            cipherList = PermutateList(cipherList, IPInv);

            // Return hex string repesentation of cipher text
            return ListOfIntToStringHex(cipherList);
        }
        // Performs feistel function on right half to get new left half
        public List<int> PerformFeistelFunction(List<int> L, List<int> R, List<int> roundKey)
        {
            // Perform expansion permutation to get 48 bits out of 32 bits
            List<int> result = PermutateList(R, EP);

            // XOR with round key
            result = XORLists(result, roundKey);

            // Subsitute bits in S-Boxes to get 32 bits back again from 48 bits
            result = SubBits(result);

            // Apply permutation function of P-Box
            result = PermutateList(result, PBox);

            // XOR with left half
            result = XORLists(result, L);

            return result;
        }

        // Performs S-boxes subsition to get 32 bits from 48 bits.
        public List<int> SubBits(List<int> inputList)
        {
            List<int> result = new List<int>();
            for (int i = 0; i < inputList.Count; i += 6)
            {
                // Get row index from the first and last bit of the 6-bit segment
                string rowBits = inputList[i].ToString() + inputList[i + 5].ToString();
                int rowIndex = Convert.ToInt32(rowBits, 2);

                // Get column index from the middle four bits
                string columnBits = "";
                for (int j = 1; j <= 4; j++)
                {
                    columnBits += inputList[i + j].ToString();
                }
                int columnIndex = Convert.ToInt32(columnBits, 2);

                // Get the S-box value using rowIndex and columnIndex
                int sBoxValue = SBoxes[i / 6][rowIndex, columnIndex];

                // Convert the S-box value into 4-bit binary and add each bit to the result list
                string sBoxValueBinary = Convert.ToString(sBoxValue, 2).PadLeft(4, '0');
                foreach (char bit in sBoxValueBinary)
                {
                    result.Add(int.Parse(bit.ToString()));
                }
            }

            return result;

        }

        // Performs element wise XORing of two lists
        public List<int> XORLists(List<int> L1, List<int> L2)
        {
            List<int> result = new List<int>();

            for (int i = 0; i < L1.Count(); i++)
            {
                result.Add(L1[i] ^ L2[i]);
            }
            return result;
        
        }

        // Shits N elements in a list to the left and puts them back at the right (rotation)
        public void RotateLeft(List<int> list, int shiftCount)
        {
            for (int i = 0; i < shiftCount; i++)
            {
                // Take the first element
                int temp = list[0];
                // Remove it from the list
                list.RemoveAt(0);
                // Add it to the end of the list
                list.Add(temp);
            }
        }

        // Generates 16 keys for all rounds
        public List<List<int>> GenerateKeys(List<int> initialKey) { 
        
            // List to store all 16 keys
            List<List<int>> keys = new List<List<int>>();

            // Apply PC1
            initialKey = PermutateList(initialKey, PC1);

            // The midpoint of the list
            int mid = initialKey.Count / 2;

            // Split into two lists
            List<int> C = initialKey.GetRange(0, mid);
            List<int> D = initialKey.GetRange(mid, mid);

            // Generate all keys by shifting and applying PC2
            for (int i = 1; i <= 16; i++)
            {
                // Shift each half by 2 except in rounds num: 1,2,9,16
                int shiftCount = 2;
                if (i == 1 || i == 2 || i == 9 || i == 16) shiftCount = 1;

                // Shift each half
                RotateLeft(C, shiftCount);
                RotateLeft(D, shiftCount);

                // Concatenate the two halves
                List<int> concatenatedList = C.Concat(D).ToList();

                // Apply PC2
                concatenatedList = PermutateList(concatenatedList, PC2);

                // Add round key to the list of all round keys
                keys.Add(concatenatedList);
            }


            return keys;
        }

        // Rearranges a list by taking a list of permutations' indices and following the new arrangement
        public List<int> PermutateList(List<int> toPermutate, List<int> permutation)
        { 
            List<int> result = new List<int>();

            for (int i = 0; i < permutation.Count(); i++)
            {
                result.Add(toPermutate[permutation[i]-1]);
            }
        
            return result;
        }

        // Converts a hexadecimal string that starts with 0x to a list of bits
        public List<int> StringHexToIntList(string hex) {

            // Remove 0x at the beginning
            hex = hex.Substring(2);

            // Store bits in a list
            List<int> bitArray = new List<int>();

            // Convert each hex character to a 4-bit binary string
            foreach (char hexChar in hex)
            {
                // Convert the hex character to an integer (0 to 15)
                int integerValue = Convert.ToInt32(hexChar.ToString(), 16);

                // Convert the integer to a binary string and pad it to make sure its 4 bits
                string binaryString = Convert.ToString(integerValue, 2).PadLeft(4, '0');

                // Add each bit to the list as an individual entry
                foreach (char bit in binaryString)
                {
                    bitArray.Add(bit - '0');  // Convert char '0' or '1' to int 0 or 1
                }
            }

            return bitArray;

        }

        // Converts a list of integers into a hexadecimal string
        public string ListOfIntToStringHex(List<int> inputList)
        {
            // String for final result
            string hexString = "0x";

            // Convert each 4 bits to one hex digit
            for (int i = 0; i < inputList.Count; i += 4)
            {
                // Take 4 bits at a time and create a string out of them
                string fourBitString = "";
                for (int j = i; j < i + 4 && j < inputList.Count; j++)
                {
                    fourBitString += inputList[j].ToString();
                }

                // Convert the 4 bit binary string to a single hex digit
                int decimalValue = Convert.ToInt32(fourBitString, 2);
                hexString += decimalValue.ToString("X");
            }

            return hexString;
        }
    }
}
