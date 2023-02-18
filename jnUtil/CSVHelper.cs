using Microsoft.VisualBasic.FileIO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace jnUtil
{
    public static class CSVHelper
    {
        // wrapper for ReadCSV
        public static string[][] ReadCSVFromFile(string filename, string delimeter = ",", bool trim = false, Encoding enc = null) => ReadCSV(File.ReadAllText(filename, enc), delimeter, trim);

        public static string[][] ReadCSV(string csv, string delimeter = ",", bool trim = false) => ReadCSV(csv.StringToStream(), delimeter, trim);

        public static string[][] ReadCSV(Stream s, string delimeter = ",", bool trim = false)
        {
            List<List<string>> parsed = new List<List<string>>();
            TextFieldParser parser = new TextFieldParser(s);
            parser.TextFieldType = FieldType.Delimited;
            parser.SetDelimiters(delimeter);
            while (!parser.EndOfData)
            {
                //Process row
                List<string> row = new List<string>();
                string[] fields = parser.ReadFields();
                foreach (string field in fields)
                {
                    if (trim)
                        row.Add(field.Trim());
                    else
                        row.Add(field);
                }
                parsed.Add(row);
            }
            parser.Close();

            string[][] ret = new string[parsed.Count][];
            for (int i = 0; i < ret.Length; i++)
                ret[i] = parsed[i].ToArray();

            return ret;
        }

        public static void WriteCSVToFile(string[][] arr, string filename, bool appendTofile = false, Encoding enc = null, string delimeter = ",", bool trim = false, bool forceEnclosingDoubleQuotes = false) => StringUtils.ToFile(WriteCSV(arr, delimeter, trim, forceEnclosingDoubleQuotes), filename, appendTofile, enc);

        public static string WriteCSV(string[][] arr, string delimeter = ",", bool trim = false, bool forceEnclosingDoubleQuotes = false)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < arr.Length; i++)
            {
                for (int j = 0; j < arr[i].Length; j++)
                {
                    string field = "";
                    if (trim)
                        field = arr[i][j].Trim();
                    else
                        field = arr[i][j];

                    if (forceEnclosingDoubleQuotes || (field.Contains("\"") || field.Contains(delimeter) || field.Contains(Environment.NewLine)))
                        field = "\"" + field + "\"";

                    sb.Append(field);
                    if (j != arr[i].Length - 1)
                        sb.Append(delimeter);
                }
                if (i != arr.Length - 1)
                    sb.Append(Environment.NewLine);
            }
            return sb.ToString();
        }
    }
}
