using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();
            StringBuilder keyBuilder = new StringBuilder();

            for (int i = 0; i < cipherText.Length; i++)
            {
                // Calculate the difference between cipherText and plainText characters
                int diff = (cipherText[i] - plainText[i] + 26) % 26;
                // Append the corresponding key character
                keyBuilder.Append((char)('A' + diff));
            }

            // Attempt to deduce the actual key from the pattern found in keyBuilder
            string deducedKeyPattern = keyBuilder.ToString();

            // This method is to find the shortest cycle in the deduced key pattern
            for (int keyLength = 1; keyLength <= deducedKeyPattern.Length; keyLength++)
            {
                string keyPart = deducedKeyPattern.Substring(0, keyLength);
                StringBuilder repeatedKey = new StringBuilder();
                while (repeatedKey.Length < deducedKeyPattern.Length)
                {
                    repeatedKey.Append(keyPart);
                }

                if (repeatedKey.ToString().StartsWith(deducedKeyPattern))
                {
                    return keyPart; // Return the shortest repeating part of the key
                }
            }

            return deducedKeyPattern; // Fallback, though this should not happen
        }


        public string Decrypt(string cipherText, string key)
        {
            StringBuilder result = new StringBuilder();
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();
            int keyIndex = 0;

            foreach (char cipherChar in cipherText)
            {
                if (!char.IsLetter(cipherChar))
                {
                    result.Append(cipherChar);
                    continue;
                }

                int cipherCharIndex = cipherChar - 'A';
                int keyCharIndex = key[keyIndex % key.Length] - 'A';

                int plainCharIndex = (cipherCharIndex - keyCharIndex + 26) % 26;
                result.Append((char)(plainCharIndex + 'A'));

                keyIndex++;
            }

            return result.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            StringBuilder result = new StringBuilder();
            plainText = plainText.ToUpper();
            key = key.ToUpper();
            int keyIndex = 0;

            foreach (char plainChar in plainText)
            {
                if (!char.IsLetter(plainChar))
                {
                    result.Append(plainChar);
                    continue;
                }

                int plainCharIndex = plainChar - 'A';
                int keyCharIndex = key[keyIndex % key.Length] - 'A';

                int cipherCharIndex = (plainCharIndex + keyCharIndex) % 26;
                result.Append((char)(cipherCharIndex + 'A'));

                keyIndex++;
            }

            return result.ToString();
        }
    }
}

