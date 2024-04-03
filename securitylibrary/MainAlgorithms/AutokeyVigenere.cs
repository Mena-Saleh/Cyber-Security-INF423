using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();
            string result = "";
            char[] key = new char[plainText.Length];

            // Construct the key using the autokey method
            for (int i = 0; i < plainText.Length; i++)
            {
                int keyChar = (cipherText[i] - plainText[i] + 26) % 26;
                key[i] = (char)(keyChar + 'A');
            }

            for (int i = 0; i < key.Length; i++)
            {
                if (key[i] == plainText[0] &&
                    key[i + 1] == plainText[1] &&
                    key[i + 2] == plainText[2] &&
                    key[i + 3] == plainText[3])
                {
                    break;
                }

                result += key[i];
            }

            return result;
        }

        public string Decrypt(string cipherText, string key)
        {
            string result = "";
            key = key.ToUpper();
            int keyIndex = 0;

            foreach (char cipherChar in cipherText.ToUpper())
            {
                if (!char.IsLetter(cipherChar))
                {
                    result += cipherChar;
                    continue;
                }

                int cipherCharIndex = cipherChar - 'A';
                int keyCharIndex = key[keyIndex] - 'A';

                int plainCharIndex = (cipherCharIndex - keyCharIndex + 26) % 26;
                char plainChar = (char)(plainCharIndex + 'A');
                result += plainChar;

                if (char.IsLetter(plainChar))
                {
                    key += plainChar;
                }

                keyIndex = (keyIndex + 1) % key.Length;
            }

            return result;
        }

        public string Encrypt(string plainText, string key)
        {
            string result = "";
            key = key.ToUpper();
            int keyIndex = 0;

            foreach (char plainChar in plainText.ToUpper())
            {
                if (!char.IsLetter(plainChar))
                {
                    result += plainChar;
                    continue;
                }

                int plainCharIndex = plainChar - 'A';
                int keyCharIndex = key[keyIndex] - 'A';

                int cipherCharIndex = (plainCharIndex + keyCharIndex) % 26;
                char cipherChar = (char)(cipherCharIndex + 'A');
                result += cipherChar;

                if (char.IsLetter(plainChar))
                {
                    key += plainChar;
                }
                keyIndex = (keyIndex + 1) % key.Length;
            }

            return result;
        }
    }


}
