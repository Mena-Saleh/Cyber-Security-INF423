using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int key = 2;
            while (key < 50) {
                if (Encrypt(plainText, key) == cipherText.ToUpper())
                {
                    return key;
                }
                key++;
            }
            return -1;
        }

        public string Decrypt(string cipherText, int key)
        {
            string plainText = "";
            double divRes = cipherText.Length / (1.0 * key);
            int rowLen = Convert.ToInt32(Math.Ceiling(divRes));
            for (int i = 0; i < rowLen; i++)
            {
                for (int j = i; j < cipherText.Length; j += rowLen)
                {
                    plainText += cipherText[j];
                }
            }
            return plainText.ToLower();
        }

        public string Encrypt(string plainText, int key)
        {
            string cipherText = "";
            for (int i = 0; i < key; i++)
            {
                for (int j = i; j < plainText.Length; j += key) { 
                    cipherText += plainText[j];
                }
            }
            return cipherText.ToUpper();
        }
    }
}
