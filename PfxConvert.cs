// PFX 変換（MT5 / Wine 用）
//
// PFX（PKCS#12）を、Ubuntu + Wine の MT5 でログインできた形式に変換する単体 EXE。
//   秘密鍵: pbeWithSHAAnd3-KeyTripleDES-CBC / 証明書: 暗号化なし / MAC: HMAC-SHA1 / 反復 2048 回
// OpenSSL などの外部ツールは使わず、Windows 標準の .NET Framework 4.x だけで動く。
//
// ビルド: build.bat（Windows 標準の csc.exe でコンパイル。C# 5 の文法で書いている）

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows.Forms;

[assembly: AssemblyTitle("PFX 変換（MT5 / Wine 用）")]
[assembly: AssemblyDescription("PFX を MT5 (Wine) でログインできる形式に変換します")]
[assembly: AssemblyProduct("PfxConvert")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

namespace PfxConvert
{
    // ================================================================ 例外

    public class PfxFormatException : Exception
    {
        public PfxFormatException(string message) : base(message) { }
    }

    public class PfxPasswordException : Exception
    {
        public PfxPasswordException(string message) : base(message) { }
    }

    // ================================================================ ASN.1 (BER/DER)

    // BER の 1 要素。Java が作る不定長形式や分割された OCTET STRING も読めるようにしている。
    public sealed class Asn1Node
    {
        public int Tag;
        public byte[] Buffer;
        public int Start, Length;
        public int ContentStart, ContentLength;
        public List<Asn1Node> Children;

        public bool Constructed { get { return (Tag & 0x20) != 0; } }
        public int ChildCount { get { return Children == null ? 0 : Children.Count; } }

        public Asn1Node Child(int index)
        {
            if (Children == null || index >= Children.Count)
                throw new PfxFormatException("PFX の構造を読み取れません（必要な要素がありません）。");
            return Children[index];
        }

        public byte[] Content()
        {
            var b = new byte[ContentLength];
            System.Buffer.BlockCopy(Buffer, ContentStart, b, 0, ContentLength);
            return b;
        }

        // OCTET STRING などの値。BER で分割されている場合は連結して返す
        public byte[] Value()
        {
            if (!Constructed) return Content();
            var ms = new MemoryStream();
            foreach (var c in Children)
            {
                var v = c.Value();
                ms.Write(v, 0, v.Length);
            }
            return ms.ToArray();
        }

        public string Oid()
        {
            if (Tag != 0x06) throw new PfxFormatException("PFX の構造を読み取れません（OID がありません）。");
            var sb = new StringBuilder();
            long value = 0;
            bool first = true;
            for (int i = ContentStart; i < ContentStart + ContentLength; i++)
            {
                value = (value << 7) | (uint)(Buffer[i] & 0x7F);
                if ((Buffer[i] & 0x80) != 0) continue;
                if (first)
                {
                    long a = Math.Min(value / 40, 2);
                    sb.Append(a).Append('.').Append(value - a * 40);
                    first = false;
                }
                else
                {
                    sb.Append('.').Append(value);
                }
                value = 0;
            }
            return sb.ToString();
        }

        public long Integer()
        {
            if (Tag != 0x02 || ContentLength == 0 || ContentLength > 8)
                throw new PfxFormatException("PFX の構造を読み取れません（整数の形式が不正です）。");
            long v = (Buffer[ContentStart] & 0x80) != 0 ? -1 : 0;
            for (int i = ContentStart; i < ContentStart + ContentLength; i++) v = (v << 8) | Buffer[i];
            return v;
        }
    }

    public static class Ber
    {
        public static Asn1Node Parse(byte[] data)
        {
            int pos = 0;
            return Read(data, ref pos, data.Length, 0);
        }

        static Asn1Node Read(byte[] d, ref int pos, int end, int depth)
        {
            if (depth > 64 || end - pos < 2) throw Broken();
            int start = pos;
            int tag = d[pos++];
            if ((tag & 0x1F) == 0x1F)
            {
                do { if (pos >= end) throw Broken(); } while ((d[pos++] & 0x80) != 0);
            }
            if (pos >= end) throw Broken();
            int lenByte = d[pos++];
            var node = new Asn1Node { Tag = tag, Buffer = d, Start = start };

            if (lenByte == 0x80)
            {
                // 不定長: 終端（00 00）まで子要素が続く
                if ((tag & 0x20) == 0) throw Broken();
                node.ContentStart = pos;
                node.Children = new List<Asn1Node>();
                while (true)
                {
                    if (end - pos < 2) throw Broken();
                    if (d[pos] == 0 && d[pos + 1] == 0)
                    {
                        node.ContentLength = pos - node.ContentStart;
                        pos += 2;
                        break;
                    }
                    node.Children.Add(Read(d, ref pos, end, depth + 1));
                }
            }
            else
            {
                int len = lenByte;
                if (lenByte > 0x80)
                {
                    int n = lenByte & 0x7F;
                    if (n > 4) throw Broken();
                    len = 0;
                    for (int i = 0; i < n; i++)
                    {
                        if (pos >= end) throw Broken();
                        len = (len << 8) | d[pos++];
                    }
                    if (len < 0) throw Broken();
                }
                if (len > end - pos) throw Broken();
                node.ContentStart = pos;
                node.ContentLength = len;
                if ((tag & 0x20) != 0)
                {
                    node.Children = new List<Asn1Node>();
                    int contentEnd = pos + len;
                    while (pos < contentEnd) node.Children.Add(Read(d, ref pos, contentEnd, depth + 1));
                }
                else
                {
                    pos += len;
                }
            }
            node.Length = pos - start;
            return node;
        }

        static Exception Broken()
        {
            return new PfxFormatException("PFX ファイルの形式が正しくありません（壊れているか、PFX ではありません）。");
        }
    }

    public static class Der
    {
        public static byte[] Tlv(int tag, byte[] content)
        {
            int len = content.Length;
            byte[] lenBytes;
            if (len < 0x80) lenBytes = new byte[] { (byte)len };
            else if (len < 0x100) lenBytes = new byte[] { 0x81, (byte)len };
            else if (len < 0x10000) lenBytes = new byte[] { 0x82, (byte)(len >> 8), (byte)len };
            else if (len < 0x1000000) lenBytes = new byte[] { 0x83, (byte)(len >> 16), (byte)(len >> 8), (byte)len };
            else lenBytes = new byte[] { 0x84, (byte)(len >> 24), (byte)(len >> 16), (byte)(len >> 8), (byte)len };
            var r = new byte[1 + lenBytes.Length + len];
            r[0] = (byte)tag;
            Buffer.BlockCopy(lenBytes, 0, r, 1, lenBytes.Length);
            Buffer.BlockCopy(content, 0, r, 1 + lenBytes.Length, len);
            return r;
        }

        public static byte[] Concat(IEnumerable<byte[]> parts)
        {
            var ms = new MemoryStream();
            foreach (var p in parts) ms.Write(p, 0, p.Length);
            return ms.ToArray();
        }

        public static byte[] Seq(params byte[][] items) { return Tlv(0x30, Concat(items)); }

        // DER の SET OF は要素をエンコード結果の昇順に並べる
        public static byte[] Set(params byte[][] items)
        {
            var sorted = items.ToList();
            sorted.Sort(CompareBytes);
            return Tlv(0x31, Concat(sorted));
        }

        static int CompareBytes(byte[] a, byte[] b)
        {
            for (int i = 0; i < Math.Min(a.Length, b.Length); i++)
                if (a[i] != b[i]) return a[i].CompareTo(b[i]);
            return a.Length.CompareTo(b.Length);
        }

        public static byte[] Ctx0(byte[] inner) { return Tlv(0xA0, inner); }
        public static byte[] Octet(byte[] value) { return Tlv(0x04, value); }
        public static byte[] Null() { return new byte[] { 0x05, 0x00 }; }
        public static byte[] Bmp(string s) { return Tlv(0x1E, Encoding.BigEndianUnicode.GetBytes(s)); }

        public static byte[] Int(long value)
        {
            var bytes = new List<byte>();
            do
            {
                bytes.Insert(0, (byte)(value & 0xFF));
                value >>= 8;
            } while (value > 0);
            if ((bytes[0] & 0x80) != 0) bytes.Insert(0, 0);
            return Tlv(0x02, bytes.ToArray());
        }

        public static byte[] Oid(string oid)
        {
            var parts = oid.Split('.').Select(s => long.Parse(s)).ToArray();
            var body = new List<byte>();
            AppendBase128(body, parts[0] * 40 + parts[1]);
            for (int i = 2; i < parts.Length; i++) AppendBase128(body, parts[i]);
            return Tlv(0x06, body.ToArray());
        }

        static void AppendBase128(List<byte> output, long v)
        {
            var tmp = new List<byte> { (byte)(v & 0x7F) };
            v >>= 7;
            while (v > 0)
            {
                tmp.Insert(0, (byte)(0x80 | (v & 0x7F)));
                v >>= 7;
            }
            output.AddRange(tmp);
        }

        // BER（不定長・分割 OCTET STRING）を DER に直す
        public static byte[] Reencode(Asn1Node n)
        {
            if (!n.Constructed) return Tlv(n.Tag, n.Content());
            if (n.Tag == 0x24) return Tlv(0x04, n.Value());
            return Tlv(n.Tag, Concat(n.Children.Select(c => Reencode(c))));
        }
    }

    // ================================================================ 暗号処理

    public static class Pkcs12Crypto
    {
        // PKCS#12 の PBE と MAC で使うパスワード表現（UTF-16BE + 終端 00 00）
        public static byte[] BmpPassword(string password)
        {
            var b = Encoding.BigEndianUnicode.GetBytes(password);
            var r = new byte[b.Length + 2];
            Buffer.BlockCopy(b, 0, r, 0, b.Length);
            return r;
        }

        public static HashAlgorithm CreateHash(string name)
        {
            // 反復回数が多いので速いマネージド実装を優先し、FIPS モードでは標準実装に切り替える
            try
            {
                switch (name)
                {
                    case "SHA1": return new SHA1Managed();
                    case "SHA256": return new SHA256Managed();
                    case "SHA384": return new SHA384Managed();
                    case "SHA512": return new SHA512Managed();
                }
            }
            catch (InvalidOperationException)
            {
                switch (name)
                {
                    case "SHA1": return SHA1.Create();
                    case "SHA256": return SHA256.Create();
                    case "SHA384": return SHA384.Create();
                    case "SHA512": return SHA512.Create();
                }
            }
            throw new PfxFormatException("対応していないハッシュ方式です: " + name);
        }

        public static HMAC CreateHmac(string name, byte[] key)
        {
            switch (name)
            {
                case "SHA1": return new HMACSHA1(key);
                case "SHA256": return new HMACSHA256(key);
                case "SHA384": return new HMACSHA384(key);
                case "SHA512": return new HMACSHA512(key);
            }
            throw new PfxFormatException("対応していないハッシュ方式です: " + name);
        }

        // RFC 7292 Appendix B の鍵導出（id: 1=鍵, 2=IV, 3=MAC 鍵）
        public static byte[] Kdf(string hashName, byte[] password, byte[] salt, int iterations, byte id, int length)
        {
            CheckIterations(iterations);
            using (var hash = CreateHash(hashName))
            {
                int u = hash.HashSize / 8;
                int v = hashName == "SHA384" || hashName == "SHA512" ? 128 : 64;
                byte[] s = Stretch(salt, v), p = Stretch(password, v);
                var input = new byte[v + s.Length + p.Length];
                for (int i = 0; i < v; i++) input[i] = id;
                Buffer.BlockCopy(s, 0, input, v, s.Length);
                Buffer.BlockCopy(p, 0, input, v + s.Length, p.Length);

                var result = new byte[length];
                int offset = 0;
                while (true)
                {
                    byte[] a = hash.ComputeHash(input);
                    for (int i = 1; i < iterations; i++) a = hash.ComputeHash(a);
                    int n = Math.Min(u, length - offset);
                    Buffer.BlockCopy(a, 0, result, offset, n);
                    offset += n;
                    if (offset >= length) return result;

                    // I の各ブロックに (A を v バイトに伸ばしたもの + 1) を加える
                    for (int j = v; j < input.Length; j += v)
                    {
                        int carry = 1;
                        for (int k = v - 1; k >= 0; k--)
                        {
                            carry += input[j + k] + a[k % u];
                            input[j + k] = (byte)carry;
                            carry >>= 8;
                        }
                    }
                }
            }
        }

        static byte[] Stretch(byte[] data, int v)
        {
            if (data.Length == 0) return new byte[0];
            var r = new byte[v * ((data.Length + v - 1) / v)];
            for (int i = 0; i < r.Length; i++) r[i] = data[i % data.Length];
            return r;
        }

        public static byte[] Pbkdf2(string prf, byte[] password, byte[] salt, int iterations, int length)
        {
            CheckIterations(iterations);
            using (var hmac = CreateHmac(prf, password))
            {
                int hLen = hmac.HashSize / 8;
                var result = new byte[length];
                int offset = 0;
                for (int block = 1; offset < length; block++)
                {
                    var input = new byte[salt.Length + 4];
                    Buffer.BlockCopy(salt, 0, input, 0, salt.Length);
                    input[salt.Length] = (byte)(block >> 24);
                    input[salt.Length + 1] = (byte)(block >> 16);
                    input[salt.Length + 2] = (byte)(block >> 8);
                    input[salt.Length + 3] = (byte)block;
                    byte[] u = hmac.ComputeHash(input);
                    var t = (byte[])u.Clone();
                    for (int i = 1; i < iterations; i++)
                    {
                        u = hmac.ComputeHash(u);
                        for (int k = 0; k < t.Length; k++) t[k] ^= u[k];
                    }
                    int n = Math.Min(hLen, length - offset);
                    Buffer.BlockCopy(t, 0, result, offset, n);
                    offset += n;
                }
                return result;
            }
        }

        static void CheckIterations(int iterations)
        {
            if (iterations < 1 || iterations > 10000000)
                throw new PfxFormatException("反復回数が不正です: " + iterations);
        }

        public static byte[] Transform(SymmetricAlgorithm cipher, byte[] key, byte[] iv, byte[] data, bool encrypt)
        {
            using (cipher)
            {
                cipher.Mode = CipherMode.CBC;
                cipher.Padding = PaddingMode.PKCS7;
                using (var t = encrypt ? cipher.CreateEncryptor(key, iv) : cipher.CreateDecryptor(key, iv))
                    return t.TransformFinalBlock(data, 0, data.Length);
            }
        }

        public static byte[] RandomBytes(int length)
        {
            var b = new byte[length];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(b);
            return b;
        }
    }

    // ================================================================ PKCS#12 の読み書き

    public sealed class CertEntry
    {
        public byte[] Der;
        public byte[] LocalKeyId;
        public string FriendlyName;
    }

    public sealed class PfxContents
    {
        public byte[] PrivateKey;          // PKCS#8 PrivateKeyInfo（DER）
        public byte[] KeyLocalId;
        public string KeyFriendlyName;
        public bool KeyIsRsa;
        public List<CertEntry> Certs = new List<CertEntry>();
        public bool IsBer;
        public string MacDescription = "なし";
        public List<string> Protection = new List<string>();   // 「証明書: RC2-40（反復 2048 回）」など
    }

    public static class Pkcs12
    {
        public const int Iterations = 2048;

        const string OidData = "1.2.840.113549.1.7.1";
        const string OidEncryptedData = "1.2.840.113549.1.7.6";
        const string OidKeyBag = "1.2.840.113549.1.12.10.1.1";
        const string OidShroudedKeyBag = "1.2.840.113549.1.12.10.1.2";
        const string OidCertBag = "1.2.840.113549.1.12.10.1.3";
        const string OidSafeContentsBag = "1.2.840.113549.1.12.10.1.6";
        const string OidX509Cert = "1.2.840.113549.1.9.22.1";
        const string OidFriendlyName = "1.2.840.113549.1.9.20";
        const string OidLocalKeyId = "1.2.840.113549.1.9.21";
        const string OidPbeSha1_3Des = "1.2.840.113549.1.12.1.3";
        const string OidSha1 = "1.3.14.3.2.26";
        const string OidRsa = "1.2.840.113549.1.1.1";

        // ------------------------------------------------------------ 読み込み

        public static PfxContents Read(byte[] pfx, string password, bool verifyMac = true)
        {
            if (pfx.Length == 0) throw new PfxFormatException("ファイルが空（0 バイト）です。ダウンロードに失敗した可能性があります。");
            if (pfx[0] != 0x30) throw new PfxFormatException("PFX（PKCS#12）ファイルではありません。");

            var result = new PfxContents { IsBer = pfx.Length > 1 && pfx[1] == 0x80 };
            var root = Ber.Parse(pfx);
            long version = root.Child(0).Integer();
            if (version != 3) throw new PfxFormatException("対応していない PFX のバージョンです: " + version);

            var authSafeInfo = root.Child(1);
            if (authSafeInfo.Child(0).Oid() != OidData)
                throw new PfxFormatException("公開鍵で保護された PFX には対応していません。");
            byte[] authSafeBytes = authSafeInfo.Child(1).Child(0).Value();

            byte[] bmp = Pkcs12Crypto.BmpPassword(password);
            if (root.ChildCount > 2 && verifyMac) bmp = VerifyMac(root.Child(2), authSafeBytes, password, result);

            foreach (var info in Ber.Parse(authSafeBytes).Children ?? new List<Asn1Node>())
            {
                string type = info.Child(0).Oid();
                if (type == OidData)
                {
                    ReadSafeContents(info.Child(1).Child(0).Value(), password, bmp, result, "暗号化なし");
                }
                else if (type == OidEncryptedData)
                {
                    var encryptedContentInfo = info.Child(1).Child(0).Child(1);
                    if (encryptedContentInfo.ChildCount < 3) continue;
                    string description;
                    byte[] plain = Decrypt(encryptedContentInfo.Child(1), encryptedContentInfo.Child(2).Value(), password, bmp, out description);
                    ReadSafeContents(plain, password, bmp, result, description);
                }
                else
                {
                    throw new PfxFormatException("対応していない保護方式の PFX です（" + type + "）。");
                }
            }

            if (result.PrivateKey == null) throw new PfxFormatException("秘密鍵が含まれていません。ログインには秘密鍵付きの PFX が必要です。");
            if (result.Certs.Count == 0) throw new PfxFormatException("証明書が含まれていません。");
            return result;
        }

        static byte[] VerifyMac(Asn1Node macData, byte[] content, string password, PfxContents result)
        {
            var digestInfo = macData.Child(0);
            string algOid = digestInfo.Child(0).Child(0).Oid();
            string hashName = HashNameFromOid(algOid);
            if (hashName == null) throw new PfxFormatException("対応していない MAC 方式です（" + algOid + "）。");
            byte[] expected = digestInfo.Child(1).Value();
            byte[] salt = macData.Child(1).Value();
            int iterations = macData.ChildCount > 2 ? (int)macData.Child(2).Integer() : 1;
            result.MacDescription = hashName + "（反復 " + iterations + " 回）";

            // 空パスワードは作成ツールによって表現が異なるので両方試す
            var candidates = new List<byte[]> { Pkcs12Crypto.BmpPassword(password) };
            if (password.Length == 0) candidates.Add(new byte[0]);
            int macLength;
            using (var h = Pkcs12Crypto.CreateHash(hashName)) macLength = h.HashSize / 8;
            foreach (var pw in candidates)
            {
                byte[] key = Pkcs12Crypto.Kdf(hashName, pw, salt, iterations, 3, macLength);
                using (var hmac = Pkcs12Crypto.CreateHmac(hashName, key))
                    if (hmac.ComputeHash(content).SequenceEqual(expected)) return pw;
            }
            throw new PfxPasswordException("パスワードが違います。");
        }

        static string HashNameFromOid(string oid)
        {
            switch (oid)
            {
                case OidSha1: return "SHA1";
                case "2.16.840.1.101.3.4.2.1": return "SHA256";
                case "2.16.840.1.101.3.4.2.2": return "SHA384";
                case "2.16.840.1.101.3.4.2.3": return "SHA512";
            }
            return null;
        }

        static void ReadSafeContents(byte[] der, string password, byte[] bmp, PfxContents result, string protection)
        {
            Asn1Node safeContents;
            try { safeContents = Ber.Parse(der); }
            catch (PfxFormatException) { throw DecryptFailed(); }

            foreach (var bag in safeContents.Children ?? new List<Asn1Node>())
            {
                string bagId = bag.Child(0).Oid();
                var value = bag.Child(1).Child(0);
                string friendlyName;
                byte[] localKeyId;
                ReadAttributes(bag.ChildCount > 2 ? bag.Child(2) : null, out friendlyName, out localKeyId);

                if (bagId == OidCertBag)
                {
                    if (value.Child(0).Oid() != OidX509Cert) continue;
                    result.Certs.Add(new CertEntry { Der = value.Child(1).Child(0).Value(), FriendlyName = friendlyName, LocalKeyId = localKeyId });
                    AddProtection(result, "証明書: " + protection);
                }
                else if (bagId == OidShroudedKeyBag || bagId == OidKeyBag)
                {
                    if (result.PrivateKey != null) continue;
                    string description = "暗号化なし";
                    byte[] pkcs8 = bagId == OidShroudedKeyBag
                        ? Decrypt(value.Child(0), value.Child(1).Value(), password, bmp, out description)
                        : Der.Reencode(value);
                    bool isRsa;
                    result.PrivateKey = NormalizePrivateKey(pkcs8, out isRsa);
                    result.KeyIsRsa = isRsa;
                    result.KeyFriendlyName = friendlyName;
                    result.KeyLocalId = localKeyId;
                    AddProtection(result, "秘密鍵: " + description);
                }
                else if (bagId == OidSafeContentsBag)
                {
                    ReadSafeContents(Der.Reencode(value), password, bmp, result, protection);
                }
            }
        }

        static void AddProtection(PfxContents result, string text)
        {
            if (!result.Protection.Contains(text)) result.Protection.Add(text);
        }

        static void ReadAttributes(Asn1Node attributes, out string friendlyName, out byte[] localKeyId)
        {
            friendlyName = null;
            localKeyId = null;
            if (attributes == null || attributes.Children == null) return;
            foreach (var attr in attributes.Children)
            {
                if (attr.ChildCount < 2 || attr.Child(1).ChildCount < 1) continue;
                string oid = attr.Child(0).Oid();
                var v = attr.Child(1).Child(0);
                if (oid == OidFriendlyName && v.Tag == 0x1E) friendlyName = Encoding.BigEndianUnicode.GetString(v.Value()).TrimEnd('\0');
                else if (oid == OidLocalKeyId) localKeyId = v.Value();
            }
        }

        static byte[] Decrypt(Asn1Node algorithm, byte[] data, string password, byte[] bmp, out string description)
        {
            string oid = algorithm.Child(0).Oid();
            try
            {
                switch (oid)
                {
                    case "1.2.840.113549.1.12.1.3": return Pkcs12Pbe(algorithm, data, bmp, new TripleDESCryptoServiceProvider(), 24, "3DES", out description);
                    case "1.2.840.113549.1.12.1.4": return Pkcs12Pbe(algorithm, data, bmp, new TripleDESCryptoServiceProvider(), 16, "2-key 3DES", out description);
                    case "1.2.840.113549.1.12.1.5": return Pkcs12Pbe(algorithm, data, bmp, new RC2CryptoServiceProvider(), 16, "RC2-128", out description);
                    case "1.2.840.113549.1.12.1.6": return Pkcs12Pbe(algorithm, data, bmp, new RC2CryptoServiceProvider(), 5, "RC2-40", out description);
                    case "1.2.840.113549.1.5.13": return Pbes2(algorithm.Child(1), data, password, out description);
                }
            }
            catch (CryptographicException)
            {
                throw DecryptFailed();
            }
            throw new PfxFormatException("対応していない暗号方式です（" + oid + "）。");
        }

        static byte[] Pkcs12Pbe(Asn1Node algorithm, byte[] data, byte[] bmp, SymmetricAlgorithm cipher, int keyLength, string name, out string description)
        {
            var param = algorithm.Child(1);
            byte[] salt = param.Child(0).Value();
            int iterations = (int)param.Child(1).Integer();
            description = name + "（反復 " + iterations + " 回）";
            byte[] key = Pkcs12Crypto.Kdf("SHA1", bmp, salt, iterations, 1, keyLength);
            byte[] iv = Pkcs12Crypto.Kdf("SHA1", bmp, salt, iterations, 2, 8);
            return Pkcs12Crypto.Transform(cipher, key, iv, data, false);
        }

        static byte[] Pbes2(Asn1Node param, byte[] data, string password, out string description)
        {
            var kdf = param.Child(0);
            var scheme = param.Child(1);
            if (kdf.Child(0).Oid() != "1.2.840.113549.1.5.12")
                throw new PfxFormatException("対応していない鍵導出方式です（" + kdf.Child(0).Oid() + "）。");
            var kp = kdf.Child(1);
            byte[] salt = kp.Child(0).Value();
            int iterations = (int)kp.Child(1).Integer();
            int index = 2, keyLength = -1;
            if (kp.ChildCount > index && kp.Child(index).Tag == 0x02) keyLength = (int)kp.Child(index++).Integer();
            string prf = "SHA1";
            if (kp.ChildCount > index)
            {
                string prfOid = kp.Child(index).Child(0).Oid();
                switch (prfOid)
                {
                    case "1.2.840.113549.2.7": prf = "SHA1"; break;
                    case "1.2.840.113549.2.9": prf = "SHA256"; break;
                    case "1.2.840.113549.2.10": prf = "SHA384"; break;
                    case "1.2.840.113549.2.11": prf = "SHA512"; break;
                    default: throw new PfxFormatException("対応していない PRF です（" + prfOid + "）。");
                }
            }

            string encOid = scheme.Child(0).Oid();
            byte[] iv = scheme.Child(1).Value();
            SymmetricAlgorithm cipher;
            int length;
            string name;
            switch (encOid)
            {
                case "2.16.840.1.101.3.4.1.2": cipher = new AesCryptoServiceProvider(); length = 16; name = "AES-128"; break;
                case "2.16.840.1.101.3.4.1.22": cipher = new AesCryptoServiceProvider(); length = 24; name = "AES-192"; break;
                case "2.16.840.1.101.3.4.1.42": cipher = new AesCryptoServiceProvider(); length = 32; name = "AES-256"; break;
                case "1.2.840.113549.3.7": cipher = new TripleDESCryptoServiceProvider(); length = 24; name = "3DES"; break;
                default: throw new PfxFormatException("対応していない暗号方式です（" + encOid + "）。");
            }
            if (keyLength > 0) length = keyLength;
            description = name + "（PBES2・" + prf + "・反復 " + iterations + " 回）";
            byte[] key = Pkcs12Crypto.Pbkdf2(prf, Encoding.UTF8.GetBytes(password), salt, iterations, length);
            return Pkcs12Crypto.Transform(cipher, key, iv, data, false);
        }

        // 余計な属性などを落とした標準的な PKCS#8 に整える
        static byte[] NormalizePrivateKey(byte[] pkcs8, out bool isRsa)
        {
            Asn1Node node;
            try { node = Ber.Parse(pkcs8); }
            catch (PfxFormatException) { throw DecryptFailed(); }
            if (node.Tag != 0x30 || node.ChildCount < 3) throw DecryptFailed();

            var algorithm = node.Child(1);
            isRsa = algorithm.Child(0).Oid() == OidRsa;
            byte[] algorithmDer = isRsa ? Der.Seq(Der.Oid(OidRsa), Der.Null()) : Der.Reencode(algorithm);
            byte[] inner = node.Child(2).Value();
            try { inner = Der.Reencode(Ber.Parse(inner)); }
            catch (PfxFormatException) { }
            return Der.Seq(Der.Int(0), algorithmDer, Der.Octet(inner));
        }

        static Exception DecryptFailed()
        {
            return new PfxPasswordException("復号できませんでした。パスワードが違うか、ファイルが壊れています。");
        }

        // ------------------------------------------------------------ 書き出し

        // 秘密鍵に対応する証明書（クライアント証明書）の位置
        public static int FindClientCert(PfxContents c)
        {
            if (c.KeyLocalId != null)
            {
                for (int i = 0; i < c.Certs.Count; i++)
                    if (c.Certs[i].LocalKeyId != null && c.Certs[i].LocalKeyId.SequenceEqual(c.KeyLocalId)) return i;
            }
            byte[] keyModulus = RsaModulusOfPrivateKey(c.PrivateKey);
            if (keyModulus != null)
            {
                for (int i = 0; i < c.Certs.Count; i++)
                {
                    byte[] m = RsaModulusOfCert(c.Certs[i].Der);
                    if (m != null && m.SequenceEqual(keyModulus)) return i;
                }
            }
            return c.Certs.Count == 1 ? 0 : -1;
        }

        static byte[] RsaModulusOfPrivateKey(byte[] pkcs8)
        {
            try
            {
                var rsaKey = Ber.Parse(Ber.Parse(pkcs8).Child(2).Value());
                return TrimZeros(rsaKey.Child(1).Content());
            }
            catch (Exception) { return null; }
        }

        static byte[] RsaModulusOfCert(byte[] certDer)
        {
            try
            {
                using (var cert = new X509Certificate2(certDer))
                {
                    if (cert.PublicKey.Oid.Value != OidRsa) return null;
                    return TrimZeros(Ber.Parse(cert.PublicKey.EncodedKeyValue.RawData).Child(0).Content());
                }
            }
            catch (Exception) { return null; }
        }

        static byte[] TrimZeros(byte[] b)
        {
            int i = 0;
            while (i < b.Length - 1 && b[i] == 0) i++;
            return b.Skip(i).ToArray();
        }

        // MT5（Wine）でログインできた形式で書き出す
        public static byte[] Write(PfxContents c, string password)
        {
            int client = FindClientCert(c);
            if (client < 0) throw new PfxFormatException("秘密鍵に対応する証明書が見つかりません。");
            var clientCert = c.Certs[client];
            string friendlyName = c.KeyFriendlyName ?? clientCert.FriendlyName;
            byte[] localKeyId;
            using (var sha1 = SHA1.Create()) localKeyId = sha1.ComputeHash(clientCert.Der);

            var attributes = new List<byte[]>();
            if (!string.IsNullOrEmpty(friendlyName)) attributes.Add(Der.Seq(Der.Oid(OidFriendlyName), Der.Set(Der.Bmp(friendlyName))));
            attributes.Add(Der.Seq(Der.Oid(OidLocalKeyId), Der.Set(Der.Octet(localKeyId))));
            byte[] attributeSet = Der.Set(attributes.ToArray());

            // 証明書: クライアント証明書を先頭に、暗号化しない
            var certBags = new List<byte[]>();
            var ordered = new List<CertEntry> { clientCert };
            ordered.AddRange(c.Certs.Where((x, i) => i != client));
            foreach (var cert in ordered)
            {
                byte[] certBag = Der.Seq(Der.Oid(OidX509Cert), Der.Ctx0(Der.Octet(cert.Der)));
                certBags.Add(cert == clientCert
                    ? Der.Seq(Der.Oid(OidCertBag), Der.Ctx0(certBag), attributeSet)
                    : Der.Seq(Der.Oid(OidCertBag), Der.Ctx0(certBag)));
            }

            // 秘密鍵: pbeWithSHAAnd3-KeyTripleDES-CBC
            byte[] bmp = Pkcs12Crypto.BmpPassword(password);
            byte[] keySalt = Pkcs12Crypto.RandomBytes(8);
            byte[] key = Pkcs12Crypto.Kdf("SHA1", bmp, keySalt, Iterations, 1, 24);
            byte[] iv = Pkcs12Crypto.Kdf("SHA1", bmp, keySalt, Iterations, 2, 8);
            byte[] encryptedKey = Pkcs12Crypto.Transform(new TripleDESCryptoServiceProvider(), key, iv, c.PrivateKey, true);
            byte[] keyAlgorithm = Der.Seq(Der.Oid(OidPbeSha1_3Des), Der.Seq(Der.Octet(keySalt), Der.Int(Iterations)));
            byte[] keyBag = Der.Seq(Der.Oid(OidShroudedKeyBag), Der.Ctx0(Der.Seq(keyAlgorithm, Der.Octet(encryptedKey))), attributeSet);

            byte[] authSafe = Der.Seq(DataContentInfo(Der.Seq(certBags.ToArray())), DataContentInfo(Der.Seq(keyBag)));

            // MAC: HMAC-SHA1
            byte[] macSalt = Pkcs12Crypto.RandomBytes(8);
            byte[] macKey = Pkcs12Crypto.Kdf("SHA1", bmp, macSalt, Iterations, 3, 20);
            byte[] mac;
            using (var hmac = new HMACSHA1(macKey)) mac = hmac.ComputeHash(authSafe);
            byte[] macData = Der.Seq(Der.Seq(Der.Seq(Der.Oid(OidSha1), Der.Null()), Der.Octet(mac)), Der.Octet(macSalt), Der.Int(Iterations));

            return Der.Seq(Der.Int(3), DataContentInfo(authSafe), macData);
        }

        static byte[] DataContentInfo(byte[] content)
        {
            return Der.Seq(Der.Oid(OidData), Der.Ctx0(Der.Octet(content)));
        }
    }

    // ================================================================ 画面

    static class Ui
    {
        public static Icon AppIcon()
        {
            try
            {
                using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("PfxConvert.app.ico"))
                    if (s != null) return new Icon(s);
            }
            catch (Exception) { }
            try { return Icon.ExtractAssociatedIcon(Application.ExecutablePath); }
            catch (Exception) { return null; }
        }

        public static void AddRow(TableLayoutPanel table, Control control, SizeType sizeType, float size)
        {
            table.RowCount++;
            table.RowStyles.Add(sizeType == SizeType.AutoSize ? new RowStyle(SizeType.AutoSize) : new RowStyle(sizeType, size));
            table.Controls.Add(control, 0, table.RowCount - 1);
            if (table.ColumnCount > 1) table.SetColumnSpan(control, table.ColumnCount);
        }

        public static void AddField(TableLayoutPanel table, string label, Control control)
        {
            table.RowCount++;
            table.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            if (label.Length > 0) table.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left }, 0, table.RowCount - 1);
            table.Controls.Add(control, 1, table.RowCount - 1);
        }

        public static bool Confirm(IWin32Window owner, string message)
        {
            return MessageBox.Show(owner, message, "PFX 変換", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes;
        }

        public static void ShowError(IWin32Window owner, string message)
        {
            MessageBox.Show(owner, message, "PFX 変換", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    // ファイルをドロップしたときに出るパスワード入力画面
    public sealed class PasswordDialog : Form
    {
        readonly TextBox txtPass, txtNew, txtNew2;
        readonly CheckBox chkChange, chkShow;
        readonly Label lblError;

        public string OriginalPassword { get { return txtPass.Text; } }
        public string NewPassword { get { return chkChange.Checked ? txtNew.Text : txtPass.Text; } }
        public bool PasswordChanged { get { return chkChange.Checked; } }

        public PasswordDialog(string inputPath, string outputPath)
        {
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
            Text = "パスワードの入力 - PFX 変換";
            Font = new Font("Yu Gothic UI", 9F);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(480, 300);

            var table = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, Padding = new Padding(12, 10, 12, 8) };
            table.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            table.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            Controls.Add(table);

            Ui.AddField(table, "ファイル", new Label { Text = Path.GetFileName(inputPath), AutoSize = true, Anchor = AnchorStyles.Left, Font = new Font(Font, FontStyle.Bold) });
            txtPass = new TextBox { Anchor = AnchorStyles.Left | AnchorStyles.Right, UseSystemPasswordChar = true };
            Ui.AddField(table, "元のパスワード", txtPass);
            chkChange = new CheckBox { Text = "新しいパスワードを設定する", AutoSize = true, Anchor = AnchorStyles.Left };
            Ui.AddField(table, "", chkChange);
            txtNew = new TextBox { Anchor = AnchorStyles.Left | AnchorStyles.Right, UseSystemPasswordChar = true, Enabled = false };
            Ui.AddField(table, "新しいパスワード", txtNew);
            txtNew2 = new TextBox { Anchor = AnchorStyles.Left | AnchorStyles.Right, UseSystemPasswordChar = true, Enabled = false };
            Ui.AddField(table, "新しいパスワード（確認）", txtNew2);
            chkShow = new CheckBox { Text = "パスワードを表示", AutoSize = true, Anchor = AnchorStyles.Left };
            Ui.AddField(table, "", chkShow);
            Ui.AddField(table, "保存先", new Label
            {
                Text = outputPath,
                AutoSize = false,
                AutoEllipsis = true,
                Dock = DockStyle.Fill,
                Height = 36,
                ForeColor = Color.DimGray
            });

            lblError = new Label { AutoSize = true, MaximumSize = new Size(450, 0), ForeColor = Color.Firebrick, Margin = new Padding(3, 4, 3, 4) };
            Ui.AddRow(table, lblError, SizeType.AutoSize, 0);
            table.RowCount++;
            table.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0) };
            var btnCancel = new Button { Text = "キャンセル", AutoSize = true, DialogResult = DialogResult.Cancel };
            var btnOk = new Button { Text = "変換する", AutoSize = true, Padding = new Padding(10, 0, 10, 0) };
            btnOk.Font = new Font(Font, FontStyle.Bold);
            buttons.Controls.Add(btnCancel);
            buttons.Controls.Add(btnOk);
            Ui.AddRow(table, buttons, SizeType.AutoSize, 0);

            AcceptButton = btnOk;
            CancelButton = btnCancel;
            btnOk.Click += delegate { OnOk(); };
            chkChange.CheckedChanged += delegate
            {
                txtNew.Enabled = txtNew2.Enabled = chkChange.Checked;
                if (chkChange.Checked) txtNew.Focus();
            };
            chkShow.CheckedChanged += delegate
            {
                foreach (var t in new[] { txtPass, txtNew, txtNew2 }) t.UseSystemPasswordChar = !chkShow.Checked;
            };
            Shown += delegate { txtPass.Focus(); };
        }

        // 元のパスワードが違ったときに、入力内容を残したまま再表示する
        public void SetError(string message)
        {
            lblError.Text = message;
            txtPass.SelectAll();
            ActiveControl = txtPass;
        }

        void OnOk()
        {
            if (chkChange.Checked && txtNew.Text != txtNew2.Text)
            {
                lblError.Text = "新しいパスワードと確認用の入力が一致しません。";
                txtNew2.SelectAll();
                txtNew2.Focus();
                return;
            }
            string pw = NewPassword;
            if (pw.Length == 0 &&
                !Ui.Confirm(this, "保存するパスワードが空です。\r\n空のパスワードは読み込めない原因になりやすいです。続行しますか？")) return;
            if (pw.Any(ch => ch < 0x20 || ch > 0x7E) &&
                !Ui.Confirm(this, "パスワードに半角英数字・記号以外の文字が含まれています。\r\nWine はパスワードを ASCII として扱うため、MT5 で読み込めない可能性が高いです。続行しますか？")) return;
            lblError.Text = "";
            DialogResult = DialogResult.OK;
        }
    }

    public sealed class MainForm : Form
    {
        const string OutputSuffix = "_3DES-SHA1-certNONE";
        const string OutputFolderName = "PFX変換済み";

        readonly Panel dropPanel;
        readonly Label dropLabel, lblStatus;
        readonly TextBox txtLog;
        readonly Button btnOpen;
        readonly string[] startupFiles;
        string lastOutputPath;

        public MainForm(string[] files)
        {
            startupFiles = files ?? new string[0];
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
            Text = "PFX 変換（MT5 / Wine 用）";
            Font = new Font("Yu Gothic UI", 9F);
            ClientSize = new Size(560, 460);
            MinimumSize = new Size(440, 380);
            StartPosition = FormStartPosition.CenterScreen;
            Icon = Ui.AppIcon();

            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(10) };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            Controls.Add(root);

            Ui.AddRow(root, new Label
            {
                AutoSize = true,
                Margin = new Padding(3, 0, 3, 8),
                Text = "PFX ファイルをドロップするとパスワードの入力画面が開き、MT5（Wine）で\r\n" +
                       "ログインできる形式（秘密鍵 3DES・証明書は暗号化なし・MAC SHA1）に変換します。\r\n" +
                       "変換したファイルは元のファイルと同じ場所の「" + OutputFolderName + "」フォルダに保存されます。"
            }, SizeType.AutoSize, 0);

            dropPanel = new Panel { Dock = DockStyle.Fill, BackColor = Color.AliceBlue, Cursor = Cursors.Hand, Padding = new Padding(3) };
            dropLabel = new Label
            {
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter,
                Font = new Font(Font.FontFamily, 12F),
                ForeColor = Color.SteelBlue,
                Text = "ここに PFX ファイルをドラッグ＆ドロップ\r\n（クリックしてファイルを選ぶこともできます）"
            };
            dropPanel.Controls.Add(dropLabel);
            dropPanel.Paint += delegate(object s, PaintEventArgs e)
            {
                var r = dropPanel.ClientRectangle;
                r.Width -= 1;
                r.Height -= 1;
                using (var pen = new Pen(Color.SteelBlue, 2) { DashStyle = DashStyle.Dash }) e.Graphics.DrawRectangle(pen, r);
            };
            Ui.AddRow(root, dropPanel, SizeType.Absolute, 150);

            txtLog = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, BackColor = SystemColors.Window, Margin = new Padding(3, 8, 3, 3) };
            Ui.AddRow(root, txtLog, SizeType.Percent, 100);

            var bottom = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 2, Margin = new Padding(0) };
            bottom.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            bottom.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            lblStatus = new Label { AutoSize = true, Anchor = AnchorStyles.Left, Text = "PFX ファイルをドロップしてください。" };
            btnOpen = new Button { Text = "出力フォルダを開く", AutoSize = true, Enabled = false };
            bottom.Controls.Add(lblStatus, 0, 0);
            bottom.Controls.Add(btnOpen, 1, 0);
            Ui.AddRow(root, bottom, SizeType.AutoSize, 0);

            btnOpen.Click += delegate { OpenOutputFolder(); };
            dropPanel.Click += delegate { BrowseInput(); };
            dropLabel.Click += delegate { BrowseInput(); };
            foreach (var c in new Control[] { this, dropPanel, dropLabel, txtLog })
            {
                c.AllowDrop = true;
                c.DragEnter += OnDragEnter;
                c.DragLeave += delegate { dropPanel.BackColor = Color.AliceBlue; };
                c.DragDrop += OnDragDrop;
            }

            // EXE のアイコンにファイルをドロップして起動した場合
            Shown += delegate { if (startupFiles.Length > 0) BeginInvoke(new MethodInvoker(delegate { HandleFiles(startupFiles); })); };
        }

        void OnDragEnter(object sender, DragEventArgs e)
        {
            if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;
            e.Effect = DragDropEffects.Copy;
            dropPanel.BackColor = Color.LightSkyBlue;
        }

        void OnDragDrop(object sender, DragEventArgs e)
        {
            dropPanel.BackColor = Color.AliceBlue;
            var files = e.Data.GetData(DataFormats.FileDrop) as string[];
            if (files == null || files.Length == 0) return;
            Activate();
            // ドロップ元（エクスプローラー）を待たせないよう、ドロップ処理を終えてから画面を出す
            BeginInvoke(new MethodInvoker(delegate { HandleFiles(files); }));
        }

        void BrowseInput()
        {
            using (var dlg = new OpenFileDialog())
            {
                dlg.Filter = "PFX / P12 (*.pfx;*.p12)|*.pfx;*.p12|すべてのファイル (*.*)|*.*";
                dlg.Multiselect = true;
                dlg.InitialDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
                if (dlg.ShowDialog(this) == DialogResult.OK) HandleFiles(dlg.FileNames);
            }
        }

        void HandleFiles(string[] files)
        {
            foreach (var file in files)
            {
                if (Directory.Exists(file))
                {
                    Log("× フォルダは変換できません: " + file);
                    continue;
                }
                if (!ProcessFile(file)) break;
            }
        }

        // 1 ファイル分: パスワード入力 → 変換 → 保存先フォルダを開く。キャンセルされたら false
        bool ProcessFile(string inputPath)
        {
            string outputPath = OutputPathFor(inputPath);
            using (var dialog = new PasswordDialog(inputPath, outputPath))
            {
                dialog.Icon = Icon;
                while (true)
                {
                    if (dialog.ShowDialog(this) != DialogResult.OK)
                    {
                        lblStatus.Text = "キャンセルしました。";
                        return false;
                    }
                    if (File.Exists(outputPath) &&
                        !Ui.Confirm(this, "次のファイルは既にあります。上書きしますか？\r\n\r\n" + outputPath)) return false;

                    try
                    {
                        ConvertFile(inputPath, outputPath, dialog.OriginalPassword, dialog.NewPassword, dialog.PasswordChanged);
                        OpenOutputFolder();
                        return true;
                    }
                    catch (PfxPasswordException ex)
                    {
                        Log("  × " + ex.Message);
                        dialog.SetError(ex.Message + "もう一度入力してください。");
                    }
                    catch (Exception ex)
                    {
                        Log("  × " + ex.Message);
                        lblStatus.Text = "変換できませんでした。";
                        Ui.ShowError(this, ex.Message);
                        return false;
                    }
                }
            }
        }

        static string OutputPathFor(string inputPath)
        {
            string dir = Path.GetDirectoryName(Path.GetFullPath(inputPath));
            // 変換済みフォルダ内のファイルを再変換するときは、同じフォルダに出す
            if (!string.Equals(Path.GetFileName(dir), OutputFolderName, StringComparison.OrdinalIgnoreCase))
                dir = Path.Combine(dir, OutputFolderName);
            return Path.Combine(dir, BaseName(inputPath) + OutputSuffix + ".pfx");
        }

        void ConvertFile(string inputPath, string outputPath, string originalPassword, string newPassword, bool passwordChanged)
        {
            Cursor = Cursors.WaitCursor;
            try
            {
                Log("");
                Log("■ " + Path.GetFileName(inputPath));
                byte[] input = File.ReadAllBytes(inputPath);
                var contents = Pkcs12.Read(input, originalPassword);
                LogInput(contents);

                byte[] output = Pkcs12.Write(contents, newPassword);
                var check = Pkcs12.Read(output, newPassword);
                if (!check.PrivateKey.SequenceEqual(contents.PrivateKey) || check.Certs.Count != contents.Certs.Count)
                    throw new PfxFormatException("変換結果の検証に失敗しました。");
                Directory.CreateDirectory(Path.GetDirectoryName(outputPath));
                File.WriteAllBytes(outputPath, output);
                lastOutputPath = outputPath;
                btnOpen.Enabled = true;

                Log("  変換後: 秘密鍵 3DES / 証明書 暗号化なし / MAC SHA1（反復 " + Pkcs12.Iterations + " 回）");
                Log("  ○ " + (passwordChanged ? "新しい" : "元と同じ") + "パスワードで読み直して確認しました");
                string windowsError = CheckWithWindows(output, newPassword);
                Log(windowsError == null ? "  ○ Windows の証明書機能でも読み込めました" : "  △ Windows での読み込みテストに失敗: " + windowsError);
                Log("  保存先: " + outputPath);
                lblStatus.Text = "完了: " + Path.GetFileName(outputPath);
            }
            finally
            {
                Cursor = Cursors.Default;
            }
        }

        void LogInput(PfxContents c)
        {
            Log("  元の形式: " + (c.IsBer ? "BER（Java などで作成）" : "DER") + " / MAC " + c.MacDescription);
            foreach (var p in c.Protection) Log("  " + p);
            int client = Pkcs12.FindClientCert(c);
            if (client >= 0)
            {
                try
                {
                    using (var cert = new X509Certificate2(c.Certs[client].Der))
                    {
                        Log("  有効期限: " + cert.NotAfter.ToString("yyyy/MM/dd HH:mm") + (cert.NotAfter < DateTime.Now ? "  ※期限切れです" : ""));
                    }
                }
                catch (CryptographicException) { }
            }
            if (!c.KeyIsRsa) Log("  ※ RSA 以外の鍵です。Wine では読み込めない可能性があります。");
        }

        static string CheckWithWindows(byte[] pfx, string password)
        {
            X509Certificate2 cert = null;
            try
            {
                // EphemeralKeySet: 鍵を Windows の鍵ストアに保存せずに読み込む
                cert = new X509Certificate2(pfx, password, (X509KeyStorageFlags)32);
                return cert.HasPrivateKey ? null : "秘密鍵が読み込まれませんでした";
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
            finally
            {
                if (cert != null) cert.Reset();
            }
        }

        static string BaseName(string path)
        {
            // ブラウザが付ける「 (1)」を外し、空白は Ubuntu で扱いやすいよう _ にする
            string name = Path.GetFileNameWithoutExtension(path);
            name = System.Text.RegularExpressions.Regex.Replace(name, @"\s*\(\d+\)$", "");
            return System.Text.RegularExpressions.Regex.Replace(name, @"\s+", "_");
        }

        void OpenOutputFolder()
        {
            if (lastOutputPath == null || !File.Exists(lastOutputPath)) return;
            Process.Start("explorer.exe", "/select,\"" + lastOutputPath + "\"");
        }

        void Log(string message)
        {
            txtLog.AppendText(message + "\r\n");
        }
    }

    static class Program
    {
        [DllImport("user32.dll")]
        static extern bool SetProcessDPIAware();

        [STAThread]
        static void Main(string[] args)
        {
            try { SetProcessDPIAware(); } catch (Exception) { }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm(args));
        }
    }
}
