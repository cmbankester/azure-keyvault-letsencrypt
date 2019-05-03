using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace AzureKeyVault.LetsEncrypt
{
  public static class GetCertificate
  {
    [FunctionName("GetCertificate")]
    public static async Task<HttpResponseMessage> GetCertificateForDomains(
      [HttpTrigger(AuthorizationLevel.Function, "get")] HttpRequestMessage req,
      [OrchestrationClient] DurableOrchestrationContext context,
      ILogger log)
    {
      var request = await req.Content.ReadAsAsync<GetCertificateRequest>();
      if (request?.Domains == null || request.Domains.Length == 0)
      {
        return req.CreateErrorResponse(System.Net.HttpStatusCode.BadRequest, $"{nameof(request.Domains)} is empty.");
      }

      log.LogInformation($"Getting certificate for domains: {string.Join(',', request.Domains)}");

      var certificates = await context.CallActivityAsync<IList<CertificateBundle>>(nameof(SharedFunctions.GetCertificates), context.CurrentUtcDateTime);
      var numDomains = request.Domains.Count();
      foreach (var certificate in certificates)
      {
        var domains = certificate.Policy.X509CertificateProperties.SubjectAlternativeNames.DnsNames;
        if (domains.Intersect(request.Domains).Count() == numDomains)
        {
          return req.CreateResponse(certificate);
        }
      }
      return req.CreateResponse(System.Net.HttpStatusCode.NotFound);
    }
  }

  public class GetCertificateRequest
  {
    public string[] Domains { get; set; }
  }
}
