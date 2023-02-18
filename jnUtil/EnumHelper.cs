using System;
using System.Collections.Generic;
using System.Text;

namespace jnUtil
{
    public static class EnumHelper
    {
        public static T NumToEnum<T>(int number) => (T)Enum.ToObject(typeof(T), number);

        public static T StringToEnum<T>(string name) => (T)Enum.Parse(typeof(T), name);

        public static int EnumToNum<T>(Object enumerator) => (int)Enum.Parse(typeof(T), enumerator.ToString());

        public static T ToEnumSafe<T>(this string name)
        {
            try
            {
                return (T)Enum.Parse(typeof(T), name);
            }
            catch (Exception)
            {
                return default(T);
            }

        }
    }
}
