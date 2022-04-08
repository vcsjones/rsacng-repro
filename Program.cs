
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

for (int i = 0; i < 1024; i++)
{
    var certificate = new X509Certificate2("certificate.pfx", "quamotion", X509KeyStorageFlags.Exportable);

    var cng = (RSACng)certificate.PrivateKey;
    var exportPolicy = cng.Key.GetProperty("Export Policy", CngPropertyOptions.None);
    var exportPolicyValue = (CngExportPolicies)BinaryPrimitives.ReadInt32LittleEndian(exportPolicy.GetValue());

    Console.WriteLine($"{i:X4}: Export policy: {exportPolicyValue}");
}