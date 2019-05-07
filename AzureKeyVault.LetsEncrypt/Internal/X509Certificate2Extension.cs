using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace AzureKeyVault.LetsEncrypt.Internal
{
    internal static class X509Certificate2Extension
    {
        private static ReadOnlySpan<byte> Separator => new byte[] { 0x0A, 0x0A };

        public static void ImportFromPem(this X509Certificate2Collection collection, byte[] rawData)
        {
            var rawDataSpan = rawData.AsSpan();

            var separator = rawDataSpan.IndexOf(Separator);

            collection.Add(new X509Certificate2(rawDataSpan.Slice(0, separator).ToArray()));
            collection.Add(new X509Certificate2(rawDataSpan.Slice(separator + 2).ToArray()));
        }
    public static byte[] ExportToPem(this X509Certificate2Collection collection)
    {
      var b1 = collection[0].Export(X509ContentType.Cert);
      var b2 = collection[1].Export(X509ContentType.Cert);
      return b1.Concat(Separator.ToArray()).Concat(b2).ToArray();
    }
    }
}