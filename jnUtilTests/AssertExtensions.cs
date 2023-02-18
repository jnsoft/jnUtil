using jnUtil;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections;
using System.Text;

namespace jnUtilTests
{
    public class DoubleApproxAssertComperator : IComparer
    {
        public int Compare(object x, object y)
        {
            bool test = NumericHelper.IsNearlyEqual((double)x, (double)y);
            Assert.IsTrue(test);
            return 0;
        }
    }
}
