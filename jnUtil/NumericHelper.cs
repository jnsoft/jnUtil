namespace jnUtil;

public static class NumericHelper
{
    public static bool IsNearlyEqual(this double a, double b, double epsilon = 1e-15) // use larger epsilon if many calculations are made
    {
        const double doubleNormal = (1L << 52) * double.Epsilon; // 2.2250738585072014E-308d;
        double absA = Math.Abs(a);
        double absB = Math.Abs(b);
        double diff = Math.Abs(a - b);

        if (a.Equals(b))
            return true;  // shortcut, handles infinities

        else if (a == 0 || b == 0 || diff < doubleNormal) // doesn't handle values around 0 great, epsilon for 0.0 is araound 4.940656e-324, but for 1.0 it's around 2.220446e-16
        {
            // a or b is zero or both are extremely close to it, relative error is less meaningful here
            // return diff < (epsilon * doubleNormal);
            return diff < epsilon;
        }

        else // use relative error
            return diff / Math.Min((absA + absB), float.MaxValue) < epsilon;
    }

}
