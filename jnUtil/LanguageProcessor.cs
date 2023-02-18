using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace jnUtil
{
    public static class LanguageProcessor
    {
        public static string[] GetSentences(string[] ss, bool cleanStrings = false)
        {
            List<string> sentences = new List<string>();
            string pat = @"[;:\.!,?-]"; // split on typical sentence dividers

            Parallel.For(0, ss.Length, x =>
            {
                string[] sens = Regex.Split(ss[x], pat);
                for (int i = 0; i < sens.Length; i++)
                {
                    if (cleanStrings)
                        sens[i] = cleanString(sens[i]);
                    if (sens[i].Length > 0)
                        sentences.Add(sens[i]);
                }
            });

            //foreach (string s in ss)
            //{
            //    string[] sens = Regex.Split(cleanStrings ? cleanString(s) : s, pat);
            //    foreach(string sen in sens)
            //        if(sen.Length > 0)
            //            sentences.Add(sen);
            //}

            return sentences.ToArray();
        }

        public static string[][] BuildNGrams(string[] text, int ngramLen)
        {
            List<string[][]> ngrams = new List<string[][]>();

            Parallel.For(0, text.Length, x =>
            {
                if (text[x] != null)
                {
                    string[] words = text[x].Split(' ');
                    if (words.Length >= ngramLen)
                    {
                        string[][] ngs = GetNgrams(words, ngramLen);
                        if (ngs != null && ngs[0].Length > 0)
                            ngrams.Add(ngs);
                    }
                }
            });

            //for (int i = 0; i < text.Length; i++)
            //{
            //    if (text[i] != null)
            //    {
            //        try
            //        {
            //            string[] words = text[i].Split(' ');
            //            if (words.Length >= ngramLen)
            //            {
            //                string[][] ngs = Ngram.GetNgrams(words, ngramLen);
            //                if (ngs[0].Length > 0) // skip empty
            //                    ngrams.Add(ngs);
            //            }
            //        }
            //        catch (Exception e)
            //        {
            //            throw e;
            //        }
            //    }
            //}


            int len = ngrams.Where(n => n != null).Select(n => n.Length).Sum();
            string[][] result = new string[len][];
            int c = 0;
            for (int i = 0; i < ngrams.Count; i++)
            {
                if (ngrams[i] != null)
                    for (int j = 0; j < ngrams[i].Count(); j++)
                        result[c++] = ngrams[i][j];
            }

            return result;
        }

        public static string[][] BuildNGramsStat(string[][] ngrams)
        {
            TST<int> tst = new TST<int>();
            int n = ngrams[0].Length;

            for (int i = 0; i < ngrams.Length; i++)
            {
                string key = string.Join("_", ngrams[i]);
                if (tst.Contains(key))
                {
                    tst.Put(key, tst.Get(key) + 1);
                }
                else
                {
                    tst.Put(key, 1);
                }
            }

            string[][] res = new string[tst.Size][];
            int c = 0;
            foreach (string s in tst.Keys)
            {
                string[] t = s.Split('_');
                string[] tr = new string[3];
                tr[0] = t[0];
                tr[1] = t[1];
                tr[2] = tst.Get(s).ToString();
                res[c++] = tr;
            }

            SortStringMatrix(res, 2);
            return res.Reverse().ToArray();
        }

        public static string[] GetNgrams(string chars, int n = 2)
        {
            int l = chars.Length;
            if (l <= n)
                return new string[] { chars };

            string[] ngrams = new string[l - n + 1];
            for (int i = 0; i < chars.Length - n + 1; i++)
                ngrams[i] = chars.Substring(i, n);

            return ngrams;
        }

        public static string[][] GetNgrams(string[] words, int n = 2)
        {
            int l = words.Length;
            if (l <= n)
                return new string[1][] { new string[] { } };

            string[][] ngrams = new string[l - n + 1][];
            for (int i = 0; i < l - n + 1; i++)
            {
                ngrams[i] = new string[n];
                Array.Copy(words, i, ngrams[i], 0, n);
            }
            return ngrams;
        }

        private static string cleanString(string s)
        {
            string pat = "[^a-zA-ZåäöÅÄÖ ]";  // remove non char
            s = Regex.Replace(s, pat, "");

            pat = @"\s+";  // remove exessive white space
            s = Regex.Replace(s, pat, " ");

            pat = @"^\s+|\s$";  // remove leading and trailing white space
            s = Regex.Replace(s, pat, "");

            return s.ToLower();
        }

        private static void SortStringMatrix(string[][] A, int col)
        {
            AlphaNumComparator comparer = new AlphaNumComparator();
            Array.Sort<string[]>(A, (x, y) => comparer.Compare(x[col], y[col]));
        }

        // Ternary Search Trie - fast lookup and more space efficiant than R-tries
        private class TST<TValue>
        {
            private int N;       // size
            private Node root;   // root of TST

            internal class Node
            {
                internal char c;                 // character
                internal Node left, mid, right;  // left, middle, and right subtries
                internal Object val;              // value associated with string
            }

            // return number of key-value pairs
            public int Size => N;

            public bool Contains(String key) => contains(root, key, 0); //return Get(key) != null; // doesn't work for non nullable T

            private bool contains(Node x, String key, int d)
            {
                if (key == null)
                    throw new NullReferenceException();
                if (key.Length == 0)
                    throw new ArgumentException("key must have length >= 1");
                if (x == null)
                    return false;
                char c = key[d];
                if (c < x.c)
                    return contains(x.left, key, d);
                else if (c > x.c)
                    return contains(x.right, key, d);
                else if (d < key.Length - 1)
                    return contains(x.mid, key, d + 1);
                else return x.val != null;
            }

            public TValue Get(String key)
            {
                if (key == null)
                    throw new NullReferenceException();
                if (key.Length == 0)
                    throw new ArgumentException("key must have length >= 1");
                Node x = get(root, key, 0);
                if (x == null)
                    return default(TValue);
                try
                {
                    return (TValue)x.val;
                }
                catch
                {
                    throw new KeyNotFoundException();
                }
            }

            // return subtrie corresponding to given key
            private Node get(Node x, String key, int d)
            {
                if (key == null)
                    throw new NullReferenceException();
                if (key.Length == 0)
                    throw new ArgumentException("key must have length >= 1");
                if (x == null)
                    return null;
                char c = key[d];
                if (c < x.c)
                    return get(x.left, key, d);
                else if (c > x.c)
                    return get(x.right, key, d);
                else if (d < key.Length - 1)
                    return get(x.mid, key, d + 1);
                else return x;
            }

            public void Put(String s, TValue val)
            {
                if (!Contains(s))
                    N++;
                root = put(root, s, val, 0);
            }

            private Node put(Node x, String s, TValue val, int d)
            {
                char c = s[d];
                if (x == null)
                {
                    x = new Node();
                    x.c = c;
                }
                if (c < x.c)
                    x.left = put(x.left, s, val, d);
                else if (c > x.c)
                    x.right = put(x.right, s, val, d);
                else if (d < s.Length - 1)
                    x.mid = put(x.mid, s, val, d + 1);
                else
                    x.val = val;
                return x;
            }

            public String LongestPrefixOf(String s)
            {
                if (s == null || s.Length == 0) return null;
                int length = 0;
                Node x = root;
                int i = 0;
                while (x != null && i < s.Length)
                {
                    char c = s[i];
                    if (c < x.c)
                        x = x.left;
                    else if (c > x.c)
                        x = x.right;
                    else
                    {
                        i++;
                        if (x.val != null) length = i;
                        x = x.mid;
                    }
                }
                return s.Substring(0, length);
            }

            // all keys in symbol table
            public IEnumerable<String> Keys
            {
                get
                {
                    Queue<String> queue = new Queue<String>();
                    collect(root, "", queue);
                    return queue;
                }
            }

            // all keys starting with given prefix
            public IEnumerable<String> PrefixMatch(String prefix)
            {
                Queue<String> queue = new Queue<String>();
                Node x = get(root, prefix, 0);
                if (x == null)
                    return queue;
                if (x.val != null)
                    queue.Enqueue(prefix);
                collect(x.mid, prefix, queue);
                return queue;
            }

            // return all keys matching given wildcard pattern
            public IEnumerable<String> WildcardMatch(String pat)
            {
                Queue<String> queue = new Queue<String>();
                collect(root, "", 0, pat, queue);
                return queue;
            }

            // all keys in subtrie rooted at x with given prefix
            private void collect(Node x, String prefix, Queue<String> queue)
            {
                if (x == null)
                    return;
                collect(x.left, prefix, queue);
                if (x.val != null)
                    queue.Enqueue(prefix + x.c);
                collect(x.mid, prefix + x.c, queue);
                collect(x.right, prefix, queue);
            }

            private void collect(Node x, String prefix, int i, String pat, Queue<String> q)
            {
                if (x == null) return;
                char c = pat[i];
                if (c == '.' || c < x.c)
                    collect(x.left, prefix, i, pat, q);
                if (c == '.' || c == x.c)
                {
                    if (i == pat.Length - 1 && x.val != null)
                        q.Enqueue(prefix + x.c);
                    if (i < pat.Length - 1)
                        collect(x.mid, prefix + x.c, i + 1, pat, q);
                }
                if (c == '.' || c > x.c)
                    collect(x.right, prefix, i, pat, q);
            }
        }
    }
}
