using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Text.Json;

namespace jnUtil
{
    public static class GenericCopier<T>
    {
        // use: GenericCopier<T[]>.DeepCopy(arr); 
        public static T DeepCopy(T obj)
        {
            if (obj == null)
                throw new ArgumentNullException(nameof(obj), "Object cannot be null");

            var json = JsonSerializer.Serialize(obj);
            return JsonSerializer.Deserialize<T>(json);
        }
    }
}
