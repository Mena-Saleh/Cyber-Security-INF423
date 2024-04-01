using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            // Initialization
            int q = 0;
            int a1 = 1;
            int a2 = 0;
            int a3 = baseN;
            int b1 = 0;
            int b2 = 1;
            int b3 = number;

            int a1n, a2n, a3n,b1n, b2n,b3n;
            // Main algorithm
            while (true)
            {
                q = a3 / b3;
                b3n = a3 % b3;

                a1n = b1;
                a2n = b2;
                a3n = b3;

                b1n = a1 - q * b1;
                b2n = a2 - q * b2;

                a1 = a1n;
                a2 = a2n;
                a3 = a3n;

                b1 = b1n;
                b2 = b2n;
                b3 = b3n;


                if (b3 == 0) return -1;
                else if (b3 == 1)
                {
                    if (b2 < -1) b2 += 26;
                    return b2;
                }

            }

        }
    }
}
