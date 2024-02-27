using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            String cipher = "";
            for (int i = 0; i < 26; i++)
            {
                char currentChar = Convert.ToChar('a' + i);
                int plaintTextIndex = plainText.IndexOf(currentChar);
                // If a mapping from current char exists in from plain text to cipher text, store it.
                if (plaintTextIndex != -1)
                {
                    cipher += cipherText[plaintTextIndex];
                }
                else {
                    // Otherwise just look for the letter that has not been taken before and it is in the right order.
                    int j = 1;
                    if (i == 0)
                    {
                        char firstChar = Convert.ToChar('a' + j);
                        while (true)
                        {
                            if (!cipherText.Contains(firstChar))
                            {
                                cipher += firstChar;
                                break;
                            }
                            j++;
                        }
                    }
                    else {
                        while (true)
                        {
                            char nextCharInOrder = Convert.ToChar((cipher[i - 1] - 'a' + j) % 26 + 'a');
                            if (!cipherText.Contains(nextCharInOrder) && !cipher.Contains(nextCharInOrder))
                            {
                                cipher += nextCharInOrder;
                                break;
                            }
                            j++;
                        }
                    }
                   
                }
            }
            return cipher;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string plainText = "";
            foreach (char c in cipherText)
            {
                int index = key.IndexOf(c);
                plainText += Convert.ToChar('a' + index);
            }
            return plainText;

        }

        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            foreach(char c in plainText)
            {
                int index = c - 'a';
                cipherText += key[index];
            }
            return cipherText.ToUpper();
        }






        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	=
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        /// 

        public string AnalyseUsingCharFrequency(string cipher)
        {

            cipher = cipher.ToLower();
            string lettersInOrder = "etaoinsrhldcumfpgwybvkxjqz";
            Dictionary<char, int> frequencyTable = new Dictionary<char, int>();
            
            // Build frequency table using cipher text
            foreach (char c in cipher)
            {
                if (!frequencyTable.ContainsKey(c))
                {
                    frequencyTable[c] = GetLetterFrequency(cipher, c);
                }
            }

            // Order by most frequent first to match the lettersInOrder string mapping.
            frequencyTable = frequencyTable.OrderByDescending(pair => pair.Value).ToDictionary(pair => pair.Key, pair => pair.Value);
            string cipherOrdered = "";

            foreach (KeyValuePair<char, int> p in frequencyTable) {
                cipherOrdered += p.Key;
            }

            // Get the key by comparing similar frequencies together.
            string key = "";
            for (int i = 0; i < 26; i++)
            {
                int letterIndex = lettersInOrder.IndexOf(Convert.ToChar('a' + i));
                key += cipherOrdered[letterIndex];
            }
            
            // Decrypt using the extracted key
            return Decrypt(cipher, key);

        }

        // Gets the number of occurences of one letter in a word.
        public int GetLetterFrequency(string word, char letter)
        {
            int count = 0;
            foreach (char c in word)
            {
                if (c == letter)
                {
                    count++;   
                }
            }
            return count;
        
        }
    }
}