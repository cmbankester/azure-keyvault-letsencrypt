using AzureKeyVault.LetsEncrypt.Internal;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace AzureKeyVault.LetsEncrypt
{
  public static class GetCertificate
  {
    [FunctionName("GetCertificate")]
    public static async Task<HttpResponseMessage> GetCertificateForDomains(
      [HttpTrigger(AuthorizationLevel.Function, "get")] HttpRequestMessage req,
      ILogger log)
    {
      var request = await req.Content.ReadAsAsync<GetCertificateRequest>();
      if (request?.Domains == null || request.Domains.Length == 0)
      {
        return req.CreateErrorResponse(System.Net.HttpStatusCode.BadRequest, $"{nameof(request.Domains)} is empty.");
      }

      log.LogInformation($"Getting certificate for domains: {string.Join(',', request.Domains)}");

      var keyVaultClient = CreateKeyVaultClient();

      var certificates = await keyVaultClient.GetCertificatesAsync(Settings.Default.VaultBaseUrl);

      var currentDateTime = DateTime.UtcNow;

      var numDomains = request.Domains.Count();
      foreach (var certificate in certificates)
      {
        var thumbprint = ByteArrayToString(certificate.X509Thumbprint);
        var secretName = certificate.Identifier.Name;
        log.LogInformation($"Checking certificate {thumbprint}");
        if (
          certificate.Tags != null
          && certificate.Tags.TryGetValue("Issuer", out var issuer)
          && issuer == "letsencrypt.org"
          && certificate.Attributes.Enabled.Value
          && certificate.Attributes.Expires.Value > currentDateTime
        )
        {
          log.LogInformation("Certificate is current and issued by letsencrypt");
          var bundle = await keyVaultClient.GetCertificateAsync(certificate.Id);
          var domains = bundle.Policy.X509CertificateProperties.SubjectAlternativeNames.DnsNames.ToArray();
          log.LogInformation($"Domains for certificate {thumbprint}: {string.Join(',', domains)}");
          if (domains.Union(request.Domains).Count() == numDomains)
          {
            return req.CreateResponse(new { secretName, thumbprint });
          }
        }
      }
      return req.CreateResponse(System.Net.HttpStatusCode.NotFound);
    }

    private static string ByteArrayToString(byte[] ba)
    {
      StringBuilder hex = new StringBuilder(ba.Length * 2);
      foreach (byte b in ba)
        hex.AppendFormat("{0:x2}", b);
      return hex.ToString();
    }

    private static KeyVaultClient CreateKeyVaultClient()
    {
      var tokenProvider = new AzureServiceTokenProvider();

      return new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(tokenProvider.KeyVaultTokenCallback));
    }
  }

  public class GetCertificateRequest
  {
    public string[] Domains { get; set; }
  }
}
