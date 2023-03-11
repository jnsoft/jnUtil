using System.Security.Cryptography;

namespace jnUtil;

public static class SecureRandom
{
    const byte LENGTH_OF_DOUBLE = 8;

    // RNG
    static readonly ThreadLocal<RandomNumberGenerator> rng =
        new ThreadLocal<RandomNumberGenerator>(() => RandomNumberGenerator.Create());

    public static byte[] GetRandomBytes(int bytes = 32)
    {
        byte[] key = new byte[bytes];
        rng.Value.GetBytes(key);
        return key;
    }

    public static double Double
    {
        get
        {
            var bytes = GetRandomBytes(LENGTH_OF_DOUBLE);

            // Step 2: bit-shift 11 and 53 based on double's mantissa bits
            var ul = BitConverter.ToUInt64(bytes, 0) / (1 << 11);
            return ul / (Double)(1UL << 53);
        }
    }

    public static double[] Doubles(int n)
    {
        var bytes = GetRandomBytes(LENGTH_OF_DOUBLE * n);

        // Step 2: bit-shift 11 and 53 based on double's mantissa bits
        double[] res = new double[n];
        for (int i = 0; i < n; i++)
        {
            var ul = BitConverter.ToUInt64(bytes, i) / (1 << 11);
            res[i] = ul / (double)(1UL << 53);
        }

        return res;
    }

    public static int RollDice(byte noOfSides)
    {
        if (noOfSides <= 0)
            throw new ArgumentOutOfRangeException("noOfSides");

        byte[] randomNumber = new byte[1];
        do
        {
            // Fill the array with a random value.
            rng.Value.GetBytes(randomNumber);
        }
        while (!isFairRoll(randomNumber[0], noOfSides));

        return (byte)((randomNumber[0] % noOfSides) + 1); // add one for zerobased values
    }

    private static bool isFairRoll(byte roll, byte numSides)
    {
        // There are MaxValue / numSides full sets of numbers that can come up
        // in a single byte.  For instance, if we have a 6 sided die, there are
        // 42 full sets of 1-6 that come up.  The 43rd set is incomplete.
        int fullSetsOfValues = byte.MaxValue / numSides;

        // If the roll is within this range of fair values, then we let it continue.
        // In the 6 sided die case, a roll between 0 and 251 is allowed.  (We use
        // < rather than <= since the = portion allows through an extra 0 value).
        // 252 through 255 would provide an extra 0, 1, 2, 3 so they are not fair
        // to use.
        return roll < numSides * fullSetsOfValues;
    }

    public static T[] SecureShuffle<T>(T[] ts)
    {
        // read in the data
        int N = ts.Length;

        double[] r = Doubles(N);

        List<KeyValuePair<double, T>> ls = new List<KeyValuePair<double, T>>();

        for (int i = 0; i < r.Length; i++)
            ls.Add(KeyValuePair.Create(r[i], ts[i]));

        // sort and get resulting permutation
        ls.Sort((x, y) => (y.Key.CompareTo(x.Key)));

        return ls.Select(i => i.Value).ToArray();
    }
}
