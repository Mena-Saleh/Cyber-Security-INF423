using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            int plainLength = plainText.Length;
            List<KeyValuePair<int, int>> columnars = CalculateColumnars(plainLength);
            List<int> key;

            foreach (KeyValuePair<int, int> columnar in columnars)
            {
                for (int i = 0; i < 2; i++)
                {
                    if (i == 1 && columnar.Key == columnar.Value)
                        break;

                    int colCount, rowCount;
                    if (i == 0)
                    {
                        colCount = columnar.Key;
                        rowCount = columnar.Value;
                    }
                    else
                    {
                        colCount = columnar.Value;
                        rowCount = columnar.Key;
                    }


                    key = new List<int>();
                    string generatedCipherText = new string('x', cipherText.Length);
                    bool validKey = true;

                    for (int keyIndex = 0; keyIndex < colCount; keyIndex++)
                    {
                        string substring = GetSubstring(plainText, colCount, rowCount, keyIndex);

                        int substringIndex = cipherText.IndexOf(substring);

                        if (substringIndex == -1)
                        {
                            validKey = false;
                            break;
                        }

                        key.Add(substringIndex / rowCount + 1);
                        generatedCipherText = UpdateGeneratedCipherText(generatedCipherText, substringIndex, rowCount, substring);
                    }

                    if (validKey) return key;
                }
            }

            return Enumerable.Repeat(0, cipherText.Length).ToList();
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int colCount = key.Count;
            int rowCount = cipherText.Length / colCount;

            char[] plainTextArray = new char[cipherText.Length];

            for (int rowIndex = 0; rowIndex < rowCount; rowIndex++)
            {
                for (int keyIndex = 0; keyIndex < key.Count; keyIndex++)
                {
                    int cipherTextIndex = (key[keyIndex] - 1) * rowCount + rowIndex;
                    int plainTextIndex = rowIndex * colCount + keyIndex;
                    plainTextArray[plainTextIndex] = cipherText[cipherTextIndex];
                }
            }

            return new string(plainTextArray);
        }


        public string Encrypt(string plainText, List<int> key)
        {
            int keyLen = key.Count;
            string cipherText = "";

            for (int i = 1; i < keyLen + 1; i++) {
                int index = key.IndexOf(i);
                for (int j = index; j < plainText.Length; j+= keyLen)
                {
                    cipherText += plainText[j];
                }
            }

            Console.WriteLine(cipherText);
            return cipherText;

        }



        private List<KeyValuePair<int, int>> CalculateColumnars(int number)
        {
            List<KeyValuePair<int, int>> columnars = new List<KeyValuePair<int, int>>();

            for (int num = 2; num < Math.Sqrt(number) + 1; num++)
            {
                if (number % num == 0) columnars.Add(new KeyValuePair<int, int>(num, number / num));
            }

            return columnars;
        }

        private string GetSubstring(string plainText, int colCount, int rowCount, int keyIndex)
        {
            string substring = "";

            for (int rowIndex = 0; rowIndex < rowCount; rowIndex++)
            {
                substring += plainText[rowIndex * colCount + keyIndex];
            }

            return substring;
        }

        private string UpdateGeneratedCipherText(string generatedCipherText, int substringIndex, int rowCount, string substring)
        {
            return generatedCipherText.Remove(substringIndex, rowCount).Insert(substringIndex, substring);
        }
    }
}
