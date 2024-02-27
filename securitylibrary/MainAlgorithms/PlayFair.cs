using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Policy;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            char[,] matrix = BuildMatrix(key);
            string plainText = "";
            for (int i = 0; i < cipherText.Length; i += 2)
            {
                int[] firstIndices = GetIndices(matrix, cipherText[i]);
                int[] secondIndices = GetIndices(matrix, cipherText[i + 1]);

                // Same row
                if (firstIndices[0] == secondIndices[0])
                {
                    plainText += matrix[firstIndices[0], CustomModulus((firstIndices[1] - 1), 5)];
                    plainText += matrix[secondIndices[0], CustomModulus((secondIndices[1] - 1), 5)];
                }
                // Same column
                else if (firstIndices[1] == secondIndices[1])
                {
                    plainText += matrix[CustomModulus((firstIndices[0] - 1), 5), firstIndices[1]];
                    plainText += matrix[CustomModulus((secondIndices[0] - 1), 5), secondIndices[1]];
                }
                // Neither
                else
                {
                    plainText += matrix[firstIndices[0], secondIndices[1]];
                    plainText += matrix[secondIndices[0], firstIndices[1]];

                }

            }

            plainText = RemoveSeperators(plainText);  
            return plainText.ToLower();
        }

        public string Encrypt(string plainText, string key)
        {
            char[,] matrix = BuildMatrix(key);
            string cipherText = "";
            plainText = AddSeperators(plainText);
            for (int i = 0; i < plainText.Length; i += 2)
            {
                int[] firstIndices = GetIndices(matrix, plainText[i]);
                int[] secondIndices = GetIndices(matrix, plainText[i + 1]);

                // Same row
                if (firstIndices[0] == secondIndices[0]) {
                    cipherText += matrix[firstIndices[0], (firstIndices[1] + 1) % 5];
                    cipherText += matrix[secondIndices[0], (secondIndices[1] + 1) % 5];
                }
                // Same column
                else if (firstIndices[1] == secondIndices[1]) {
                    cipherText += matrix[(firstIndices[0] + 1) % 5, firstIndices[1]];
                    cipherText += matrix[(secondIndices[0] + 1) % 5, secondIndices[1]];
                }
                // Neither
                else {
                    cipherText += matrix[firstIndices[0], secondIndices[1]];
                    cipherText += matrix[secondIndices[0], firstIndices[1]];
     
                }

            }


            return cipherText.ToUpper();
        }


        // Builds a playfair cipher matrix using they keyword without repition and fills empty cells with empty alphabet in ascending order, also I and J are in one cell.
        public char[, ] BuildMatrix(string key)
        {
            char[,] matrix = new char[5, 5];
            int keyPointer = 0;
            int i, j;
            for (i = 0; i < matrix.GetLength(0); i++)
            {
                for (j = 0; j < matrix.GetLength(1); j++)
                {
                    if (keyPointer < key.Length)
                    {
                        while (true)
                        {
                            char currentChar = key[keyPointer];
                            if (!(ContainsChar(matrix, currentChar)))
                            {
                                if ((currentChar == 'i' && ContainsChar(matrix, 'j')) || (currentChar == 'j' && ContainsChar(matrix, 'i')))
                                {
                                    keyPointer++;
                                    continue;
                                }
                                matrix[i, j] = currentChar;
                                keyPointer++;
                                break;
                            }
                            keyPointer++;
                        }
                    }
                    else {
                        int k = 0;
                        while (true)
                        {
                            char currentChar = Convert.ToChar('a' + k);
                            if (!(ContainsChar(matrix,currentChar)))
                            {
                                if ((currentChar == 'i' && ContainsChar(matrix, 'j')) || (currentChar == 'j' && ContainsChar(matrix, 'i')))
                                {
                                    k++;
                                    continue;
                                }
                                matrix[i, j] = currentChar;
                                break;
                            }
                            k++;
                        }
                    }
       
                }

            }
            ReplaceJwithI(ref matrix);
            return matrix;
        }
        
        // Checks if a matrix contains a specific character or not.
        public bool ContainsChar(char[,] matrix, char c)
        {
            for (int i = 0; i < matrix.GetLength(0); i++)
            {
                for (int j = 0; j < matrix.GetLength(1); j++)
                {
                    if (matrix[i,j] == c)
                    {
                        return true;
                    }
                }

            }
            return false;
        }

        // Gets indices [i,j] of a char in an array 
        public int[] GetIndices(char[,] matrix, char c)
        {
            if (c == 'j')
            {
                c = 'i';
            }
            for (int i = 0; i < matrix.GetLength(0); i++)
            {
                for (int j = 0; j < matrix.GetLength(1); j++)
                {
                    if (matrix[i, j] == c)
                    {
                        return new int[] {i,j};
                    }
                }
            }
            return new int[] {-1};
        }
       
        // Replace J with I in the matrix to unify code logic later
        public void ReplaceJwithI(ref char[,] matrix)
        {
            for (int i = 0; i < matrix.GetLength(0); i++)
            {
                for (int j = 0; j < matrix.GetLength(1); j++)
                {
                    if (matrix[i, j] == 'j')
                    {
                        matrix[i, j] = 'i';
                    }
                }

            }
        }

        // Add seperators between reapeating characters and also to make string length even.
        public string AddSeperators(string text)
        {
            string result = "";
            result += text[0];
            int countX = 0;
            for (int i = 1; i < text.Length; i++)
            {
                if (text[i] == text[i-1] && (i+countX) % 2 == 1)
                {
                    result += "x";
                    countX++;
                }
                result += text[i];
            }

            if (result.Length % 2 == 1)
            {
                result += "x";
            }


            return result;
        }

        // Remove previously added seperators
        public string RemoveSeperators(string text)
        {
            string result = "";
            result += text[0];
            for (int i = 1; i < text.Length - 1; i++)
            {
                if (text[i] == 'x'  && text[i - 1] == text[i+1] && i % 2 == 1)
                {
                    continue;
                }
                result += text[i];
            }

            if (text[text.Length - 1] != 'x')
            {
                result += text[text.Length -1];
            }


            return result;
        }


        // Handles negative values in modulus operations, it does so by adding the mod untill a positive value is achieved.
        public int CustomModulus(int num, int mod)
        {

            if (num >= 0)
            {
                return num % mod;
            }
            else
            {
                while (num < 0)
                {
                    num += mod;
                }
                return num;
            }
        }

    }

}