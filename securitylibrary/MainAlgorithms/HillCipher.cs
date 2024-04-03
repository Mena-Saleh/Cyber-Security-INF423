using SecurityLibrary.AES;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {

        // Solve two linear equations in two unknowns each by trying all combinations of the two variables (26^6), this is done 2 times, once for each row
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {

            int[] key = new int[4] { 0,0,0,0};

            // Get the first row for the key
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if ((i * plainText[0] + j * plainText[1]) % 26 == cipherText[0] && (i * plainText[2] + j * plainText[3])%26 == cipherText[2])
                    {
                        key[0] = i;
                        key[1] = j;
                        break;
                    }
                }
            }

            // Get the second row for the key
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if ((i * plainText[0] + j * plainText[1]) % 26 == cipherText[1] && (i * plainText[2] + j * plainText[3]) % 26 == cipherText[3])
                    {
                        key[2] = i;
                        key[3] = j;
                        break;
                    }
                }
            }

            // Invalid key (determinant = 0)
            if (key[0] * key[3] - key[2] * key[1] ==0 ) throw new InvalidAnlysisException();

            return key.ToList();

        }
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int m = Convert.ToInt32(Math.Sqrt(key.Count()));
            int n = Convert.ToInt32(Math.Ceiling(cipherText.Count() / Convert.ToDouble(m)));

            int[,] keyMatrix = ListToMatrix(key, m, m);
            int[,] cipherTextMatrix = ListToMatrix(cipherText, m, n, true);

            int[,] inverseKeyMatrix;
            if (m == 2)
            {
                inverseKeyMatrix = InverseMatrix2By2(keyMatrix);
            }
            else
            {
                inverseKeyMatrix = InverseMatrix3By3(keyMatrix);
            }


            int[,] result = MultiplyMatrices(inverseKeyMatrix, cipherTextMatrix);


            return MatrixToList(result);

        }
        public string Decrypt(string cipherText, string key)
        {
            int m = Convert.ToInt32(Math.Sqrt(key.Count()));

            throw new NotImplementedException();
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int m = Convert.ToInt32(Math.Sqrt(key.Count()));
            int n = Convert.ToInt32(Math.Ceiling(plainText.Count() / Convert.ToDouble(m)));

            int[,] keyMatrix = ListToMatrix(key, m, m);
            int[,] plainTextMatrix = ListToMatrix(plainText, m , n, true);

            int[,] result = MultiplyMatrices(keyMatrix, plainTextMatrix);

            return MatrixToList(result);
        }
        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        // Solve three linear equations in three unknowns each by trying all combinations of the three variables (26^3), this is done 3 times, once for each row
        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            int[] key = new int[9];

            // Get the first row for the key
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        if ((i * plain3[0] + j * plain3[1] + k * plain3[2]) % 26 == cipher3[0] && (i * plain3[3] + j * plain3[4] + k * plain3[5]) % 26 == cipher3[3] && (i * plain3[6] + j * plain3[7] + k * plain3[8]) % 26 == cipher3[6])
                        {
                            key[0] = i;
                            key[1] = j;
                            key[2] = k;
                            break;
                        }
                    }
                   
                }
            }

            // Get the second row for the key
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        if ((i * plain3[0] + j * plain3[1] + k * plain3[2]) % 26 == cipher3[1] && (i * plain3[3] + j * plain3[4] + k * plain3[5]) % 26 == cipher3[4] && (i * plain3[6] + j * plain3[7] + k * plain3[8]) % 26 == cipher3[7])
                        {
                            key[3] = i;
                            key[4] = j;
                            key[5] = k;
                            break;
                        }
                    }

                }
            }

            // Get the third row for the key
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        if ((i * plain3[0] + j * plain3[1] + k * plain3[2]) % 26 == cipher3[2] && (i * plain3[3] + j * plain3[4] + k * plain3[5]) % 26 == cipher3[5] && (i * plain3[6] + j * plain3[7] + k * plain3[8]) % 26 == cipher3[8])
                        {
                            key[6] = i;
                            key[7] = j;
                            key[8] = k;
                            break;
                        }
                    }

                }
            }

            return key.ToList();
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }


        // Helper functions
        private void Swap(ref int a,ref int b)
        {
            a = a + b;
            b = a - b;
            a = a - b;

        }


        // Converts a list into a matrix
        private int[,] ListToMatrix(List<int> l, int m, int n, bool columnWise = false) {

            int[,] result = new int[m, n];
            int iterator = 0;

            // Swap m and n, and also i and j later on, to fill column by column instead of row by row
            if (columnWise) Swap(ref n, ref m);
            // Loop over all matrix cells and fill with list items from the list, (row wise or column wise)
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    if (iterator < l.Count())
                    {
                        if (columnWise) result[j, i] = l[iterator];

                        else result[i, j] = l[iterator];

                        iterator++;

                    }
                    // The list is finished, but the matrix has extra space.
                    else return result;
                }

            }

            return result;

        }


        // Converts a matrix to a list
        private List<int> MatrixToList(int[,] matrix) { 
        
            List<int> result = new List<int>();
            for (int i = 0; i < matrix.GetLength(1); i++) 
            {
                for (int j = 0; j < matrix.GetLength(0); j++) 
                {
                    result.Add(Convert.ToInt32(matrix[j,i]));
                }
            }

            return result;
        }

        // Performs naive multiplication of two matrices.
        private int[,] MultiplyMatrices(int[,] matrix1, int[,] matrix2)
        {
            int R1 = matrix1.GetLength(0);
            int R2 = matrix2.GetLength(0);
            int C2 = matrix2.GetLength(1);
            int[,] result = new int[R1, C2];
            int i, j, k;
            for (i = 0; i < R1; i++)
            {
                for (j = 0; j < C2; j++)
                {
                    result[i, j] = 0;
                    for (k = 0; k < R2; k++)
                        result[i, j] += matrix1[i, k] * matrix2[k, j];
                    result[i, j] %= 26;
                }
            }
            return result;
        }

        // Gets the inverse of a 2 by 2 matrix modulo 26
        private int[,] InverseMatrix2By2(int[,] matrix) {

            int determinant = matrix[0, 0] * matrix[1, 1] - (matrix[1, 0] * matrix[0, 1]);
            if (determinant == 0)
            {
                throw new InvalidOperationException("The matrix does not have an inverse because its determinant is 0.");
            }

            determinant = ((determinant % 26) + 26) % 26; // Ensure positive result in mod 26 space
            ExtendedEuclid extendedEucled = new ExtendedEuclid();
            int modInverse = extendedEucled.GetMultiplicativeInverse(determinant, 26);
            Console.WriteLine(modInverse);

            if (modInverse == -1) {
                throw new InvalidOperationException("The determinant does not have an inverse mod 26");
            }
            int[,] inverse = new int[2, 2];

            inverse[0, 0] = (modInverse * matrix[1, 1]) %26;
            inverse[1, 1] = (modInverse * matrix[0, 0]) %26;
            inverse[0, 1] = (modInverse * -matrix[0, 1]) % 26;
            inverse[1, 0] = (modInverse * -matrix[1, 0]) % 26;

            // Ensure all values are positive
            for (int i = 0; i < 2; i++)
                for (int j = 0; j < 2; j++)
                    if (inverse[i, j] < 0) inverse[i, j] += 26;


            return inverse;

        }

        // Gets the inverse of a 3 by 3 matrix modulo 26
        private int[,] InverseMatrix3By3(int[,] matrix)
        {
            int determinant = matrix[0, 0] * (matrix[1, 1] * matrix[2, 2] - matrix[2, 1] * matrix[1, 2]) -
                              matrix[0, 1] * (matrix[1, 0] * matrix[2, 2] - matrix[1, 2] * matrix[2, 0]) +
                              matrix[0, 2] * (matrix[1, 0] * matrix[2, 1] - matrix[1, 1] * matrix[2, 0]);

            determinant = ((determinant % 26) + 26) % 26; // Ensure positive result in mod 26 space

            ExtendedEuclid extendedEuclid = new ExtendedEuclid();
            int modInverse = extendedEuclid.GetMultiplicativeInverse(determinant, 26);

            if (modInverse == -1)
            {
                throw new InvalidOperationException("The determinant does not have an inverse mod 26");
            }

            int[,] inverseMatrix = new int[3, 3];

            // Manual computation of cofactors, adjusted for modular arithmetic
            int[,] cofactors = new int[3, 3]
            {
                {
                    (matrix[1, 1] * matrix[2, 2] - matrix[2, 1] * matrix[1, 2]),
                    -(matrix[0, 1] * matrix[2, 2] - matrix[2, 1] * matrix[0, 2]),
                    (matrix[0, 1] * matrix[1, 2] - matrix[1, 1] * matrix[0, 2])
                },

                {
                    -(matrix[1, 0] * matrix[2, 2] - matrix[2, 0] * matrix[1, 2]),
                    (matrix[0, 0] * matrix[2, 2] - matrix[2, 0] * matrix[0, 2]),
                    -(matrix[0, 0] * matrix[1, 2] - matrix[1, 0] * matrix[0, 2])
                },

                {
                    (matrix[1, 0] * matrix[2, 1] - matrix[2, 0] * matrix[1, 1]),
                    -(matrix[0, 0] * matrix[2, 1] - matrix[2, 0] * matrix[0, 1]),
                    (matrix[0, 0] * matrix[1, 1] - matrix[1, 0] * matrix[0, 1])
                }
             };

            // Apply modInverse and transpose in one step, ensuring all operations are mod 26
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    // Compute each element's modular inverse, adjust for any negative values to ensure positive mod 26 results
                    inverseMatrix[i, j] = modInverse * cofactors[i, j] % 26;
                    inverseMatrix[i, j] = (inverseMatrix[i, j] + 26) % 26;
                }
            }

            return inverseMatrix;
        }





    }
}

