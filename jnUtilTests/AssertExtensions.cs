using System.Collections;

namespace jnUtilTests;

public class DoubleApproxAssertComperator : IComparer
{
    public int Compare(object x, object y)
    {
        bool test = NumericHelper.IsNearlyEqual((double)x, (double)y);
        Assert.IsTrue(test);
        return 0;
    }
}
