using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace jnUtil
{
    public static class ArrayHelper
    {
		public static void ClearArray<T>(ref T[] arr)
        {
			Array.Clear(arr, 0, arr.Length);
			arr = null;
		}

        public static T[] ConcatArrays<T>(this T[] arr, T[] arr2)
        {
            T[] ret = new T[arr.Length + arr2.Length];
            arr.CopyTo(ret, 0);
            arr2.CopyTo(ret, arr.Length);
            return ret;
        }

		public static void Append<T>(this T[] data, T[] newData, ref int writePos)
		{
			if(writePos < 0 || writePos + newData.Length > data.Length)
				throw new ArgumentOutOfRangeException(nameof(writePos));

			Array.Copy(newData, 0, data, writePos, newData.Length);
			writePos += newData.Length;
		}

		public static void Extract<T>(this T[] source, T[] dest, ref int readPos)
		{
            if (readPos < 0 || readPos + dest.Length > source.Length)
                throw new ArgumentOutOfRangeException(nameof(readPos));

            Array.Copy(source, readPos, dest, 0, dest.Length);
			readPos += dest.Length;
		}

		public static byte[] Extract<T>(this T[] source, int len, ref int readPos)
		{
			byte[] result = new byte[len];
			Buffer.BlockCopy(source, readPos, result, 0, len);
			readPos += len;
			return result;
		}

		// split byte array in chunks, last chunk can be smaller then the rest
		public static IEnumerable<T[]> SplitArray<T>(this T[] arr, int chunkSize, bool pad = false)
        {
            int arrLen = arr.Length;
            T[] ret = null;

            int i = 0;
            for (; arrLen > (i + 1) * chunkSize; i++)
            {
                ret = new T[chunkSize];
                Array.Copy(arr, i * chunkSize, ret, 0, chunkSize);
                yield return ret;
            }
            if (!pad)
            {
                int reminder = arrLen - i * chunkSize;
                if (reminder > 0)
                {
                    ret = new T[reminder];
                    Array.Copy(arr, i * chunkSize, ret, 0, reminder);
                    yield return ret;
                }
            }
            else // pad
            {
                int reminder = arrLen - i * chunkSize;
                if (reminder > 0)
                {
                    ret = new T[chunkSize];
                    Array.Clear(ret, reminder, chunkSize - reminder);
                    Array.Copy(arr, i * chunkSize, ret, 0, reminder);
                    for (int k = 0; k < ret.Length-reminder; k++)
                        ret[reminder + k] = default(T);
                    yield return ret;
                }
            }
        }

		#region Array to/from File (compatible with Octave)

		public static void ToBinaryFile(this double[] vec, string filename)
		{
			// the size of the array
			int[] size = { vec.Length };

			int temp;
			long value;

			// create a stream to the file, overwriting any existing file
			Stream file = File.OpenWrite(filename);

			// write the number of array dimensions to the file
			temp = size.Length;

			for (int i = 0; i < 4; i++)
			{
				file.WriteByte((byte)(temp & 0xff));
				temp >>= 8;
			}

			// write the array dimensions to the file
			for (int i = 0; i < size.Length; i++)
			{
				temp = size[i];
				for (int j = 0; j < 4; j++)
				{
					file.WriteByte((byte)(temp & 0xff));
					temp >>= 8;
				}
			}

			// write the array to the file
			for (int i = 0; i < vec.Length; i++)
			{
				// get the 64-bit long representation of the double
				value = BitConverter.DoubleToInt64Bits(vec[i]);

				// write the 64-bit long to the stream
				for (int n = 0; n < 8; n++)
				{
					file.WriteByte((byte)(value & 0xff));
					value >>= 8;
				}
			}
			file.Close();
		}

		public static void ToBinaryFile(this double[,] mat, string filename)
		{
			if (mat.Rank != 2)
				throw new Exception("Matrix must have two dimensions");

			int m = mat.GetLength(1);
			int n = mat.GetLength(2);
			int rank = mat.Rank;

			int temp;
			long value;

			// create a stream to the file, overwriting any existing file
			Stream file = File.OpenWrite(filename);

			// write the number of array dimensions to the file
			temp = rank;
			temp = 2;

			for (int i = 0; i < 4; i++)
			{
				file.WriteByte((byte)(temp & 0xff));
				temp >>= 8;
			}

			temp = m;
			// write the array dimensions to the file
			for (int j = 0; j < 4; j++)
			{
				file.WriteByte((byte)(temp & 0xff));
				temp >>= 8;
			}
			temp = n;
			for (int j = 0; j < 4; j++)
			{
				file.WriteByte((byte)(temp & 0xff));
				temp >>= 8;
			}

			// write the array to the file
			for (int i = 0; i < m; i++)
			{
				for (int j = 0; j < n; j++)
				{
					// get the 64-bit long representation of the double
					value = BitConverter.DoubleToInt64Bits(mat[i, j]);

					// write the 64-bit long to the stream
					for (int k = 0; k < 8; k++)
					{
						file.WriteByte((byte)(value & 0xff));
						value >>= 8;
					}
				}
			}
			file.Close();
		}

		public static double[] ReadArrayFromBinaryFile(string filename)
		{
			Stream file = File.OpenRead(filename);

			double[] array = null;
			int[] size = new int[1];

			int temp;
			long value;

			// get the number of dimensions of the array in the file
			temp = (file.ReadByte() & 0xff)
						| ((file.ReadByte() & 0xff) << 8)
						| ((file.ReadByte() & 0xff) << 16)
						| ((file.ReadByte() & 0xff) << 24);

			if (temp != size.Length)
				throw new IOException("File doesn't contain a " + size.Length + " dimensional array");

			// get the size of the array along each of the dimensions
			for (int i = 0; i < size.Length; i++)
				size[i] = (file.ReadByte() & 0xff)
						  | ((file.ReadByte() & 0xff) << 8)
						  | ((file.ReadByte() & 0xff) << 16)
						  | ((file.ReadByte() & 0xff) << 24);


			// read the array
			array = new double[size[0]];

			for (int i = 0; i < size[0]; i++)
			{
				value = 0;

				for (int n = 0; n < 8; n++)
					value |= (long)(file.ReadByte() & 0xff) << (8 * n);

				array[i] = BitConverter.Int64BitsToDouble(value);
			} // end for
			file.Close();
			return array;
		}

		public static double[,] ReadMatrixFromBinaryFile(String filename)
		{
			Stream file = File.OpenRead(filename);

			double[,] mat = null;
			int[] size = new int[2];

			int temp;
			long value;

			// get the number of dimensions of the array in the file
			temp = (file.ReadByte() & 0xff)
						| ((file.ReadByte() & 0xff) << 8)
						| ((file.ReadByte() & 0xff) << 16)
						| ((file.ReadByte() & 0xff) << 24);

			if (temp != size.Length)
				throw new IOException("File doesn't contain a " + size.Length + " dimensional array");

			// get the size of the array along each of the dimensions
			for (int i = 0; i < size.Length; i++)
				size[i] = (file.ReadByte() & 0xff)
						  | ((file.ReadByte() & 0xff) << 8)
						  | ((file.ReadByte() & 0xff) << 16)
						  | ((file.ReadByte() & 0xff) << 24);


			// read the array
			mat = new double[size[0], size[1]];

			for (int i = 0; i < mat.GetLength(0); i++)
			{
				for (int j = 0; j < mat.GetLength(1); j++)
				{

					value = 0;

					for (int n = 0; n < 8; n++)
						value |= (long)(file.ReadByte() & 0xff) << (8 * n);

					mat[i, j] = BitConverter.Int64BitsToDouble(value);

				}
			}

			file.Close();

			return mat;
		}

		public static bool CollectionIsEqual<T>(this T[] arr, T[] arr2)
        {
			if (arr == null && arr2 == null)
				return true;
			else if (arr == null || arr2 == null)
				return false;
			else if (arr.Length != arr2.Length)
				return false;
			else
            {
                for (int i = 0; i < arr.Length; i++)
                {
					if (!arr[i].Equals(arr2[i]))
						return false;
                }
				return true;
            }
        }

		#endregion

	}
}
