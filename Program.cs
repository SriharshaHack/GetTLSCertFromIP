// See https://aka.ms/new-console-template for more information
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


string IP = "51.116.208.221";//args[0];
IPAddress.Parse(IP);
string url = "https://" + IP;

X509Certificate2? certificate = null;
var httpClientHandler = new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = (_, cert, __, ___) =>
    {
        certificate = new X509Certificate2(cert.GetRawCertData());
        return true;
    }
};

var httpClient = new HttpClient(httpClientHandler);
await httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));

if(certificate == null)
{
    Console.WriteLine($"Certificate is null");
    return;
}

Console.WriteLine($"Subject Name: ${certificate.SubjectName.Name}");

foreach(var extension in certificate.Extensions)
{
    AsnEncodedData asndata = new AsnEncodedData(extension.Oid, extension.RawData);
    
    /*
    Console.WriteLine($"{extension.Oid.FriendlyName}: {extension.Oid.Value}");        
    Console.WriteLine("Extension type: {0}", extension.Oid.FriendlyName);
    Console.WriteLine("Oid value: {0}", asndata.Oid.Value);
    Console.WriteLine("Raw data length: {0} {1}", asndata.RawData.Length, Environment.NewLine);
    Console.WriteLine(asndata.Format(true));
    */

    if (extension.Oid.FriendlyName == "Subject Alternative Name")
        Console.WriteLine($"Subject Alternative Name: {asndata.Format(true)}");
}
