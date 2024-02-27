using System;
using System.Collections.Generic;
using System.Linq;

namespace SecurityLibrary
{

    public class Ceaser : ICryptographicTechnique<string, int>
    {

        // NOTE: Subtracting the char 'a' from any character results in a value that is between 0-25 for the letters a-z, this operation can be reversed as well by adding 'a'

        public string Encrypt(string plainText, int key)
        {
            string cipherText = "";

            foreach (char c in plainText) 
            {
                cipherText += Convert.ToChar(CustomModulus((c - 'a' + key), 26) + 'a');
            }
            return cipherText.ToUpper();
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            string plainText = "";

            foreach (char c in cipherText)
            {
                plainText += Convert.ToChar(CustomModulus((c - 'a' - key), 26) + 'a');
            }

            return plainText;
        }

        public int Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            return CustomModulus((cipherText[0] - plainText[0]), 26);
        }


        // Handles negative values in modulus operations, it does so by adding the mod untill a positive value is achieved.
        public int CustomModulus(int num, int mod) {

            if (num >= 0)
            {
                return num % mod;
            }
            else {
                while (num < 0)
                {
                    num += mod;
                }
                return num;
            }
        }
    }
}