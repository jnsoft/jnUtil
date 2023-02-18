using System;
using System.Collections.Generic;
using System.Text;

namespace jnUtil
{
    public static class Conversions
    {
        public static HashSet<T> ToHashSet<T>(this IEnumerable<T> source) => new HashSet<T>(source);
    }
}
