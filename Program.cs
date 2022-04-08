
using Org.BouncyCastle.Security;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

var tasks = new List<Task>();

for (int i = 0; i < 0x1000; i++)
{
    tasks.Add(Task.Run(DoWork));
}

await Task.WhenAll(tasks);

static void DoWork()
{
    using (var certificate = new X509Certificate2("certificate.pfx", "quamotion", X509KeyStorageFlags.Exportable))
    {
        var bouncyCert = DotNetUtilities.FromX509Certificate(certificate);

        using (var cng = (RSACng)certificate.PrivateKey)
        {
            var exportPolicy = cng.Key.GetProperty("Export Policy", CngPropertyOptions.None);
            var exportPolicyValue = (CngExportPolicies)BinaryPrimitives.ReadInt32LittleEndian(exportPolicy.GetValue());

            Console.WriteLine($"Export policy: {exportPolicyValue}");

            var parameters = cng.ExportParameters(includePrivateParameters: true);
        }
    }
}