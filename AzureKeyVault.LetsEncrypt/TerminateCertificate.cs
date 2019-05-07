using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using ACMESharp.Protocol;
using ACMESharp.Protocol.Resources;
using AzureKeyVault.LetsEncrypt.Internal;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AzureKeyVault.LetsEncrypt
{
  public static class TerminateCertificate
  {
    private static readonly HttpClient _acmeHttpClient = new HttpClient { BaseAddress = new Uri("https://acme-v02.api.letsencrypt.org/") };
    [FunctionName("TerminateCertificate")]
    public static async Task<HttpResponseMessage> TerminateCertificateForSecretName(
      [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestMessage req,
      ILogger log)
    {
      var request = await req.Content.ReadAsAsync<TerminateCertificateRequest>();
      if (request?.CertSecretName == null)
      {
        return req.CreateErrorResponse(HttpStatusCode.BadRequest, $"{nameof(request.CertSecretName)} is empty.");
      }
      var certName = request.CertSecretName;
      log.LogInformation($"Terminating certificate with secretName: {certName}");
      var keyVaultClient = CreateKeyVaultClient();
      var cert = await keyVaultClient.GetCertificateAsync(Settings.Default.VaultBaseUrl, certName);
      log.LogInformation($"Got cert from key vault: {JToken.FromObject(cert).ToString()}");
      var acme = await CreateAcmeClientAsync();
      await acme.RevokeCertificateAsync(cert.Cer);
      log.LogInformation("Revoked ACME certificate");
      var deletedBundle = await keyVaultClient.DeleteCertificateAsync(Settings.Default.VaultBaseUrl, certName);
      log.LogInformation($"Deleted cert from key vault: {JToken.FromObject(deletedBundle).ToString()}");

      return req.CreateResponse(HttpStatusCode.OK);
    }

    private static KeyVaultClient CreateKeyVaultClient()
    {
      var tokenProvider = new AzureServiceTokenProvider();

      return new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(tokenProvider.KeyVaultTokenCallback));
    }

    private static async Task<AcmeProtocolClient> CreateAcmeClientAsync()
    {
      var account = default(AccountDetails);
      var accountKey = default(AccountKey);
      var acmeDir = default(ServiceDirectory);

      LoadState(ref account, "account.json");
      LoadState(ref accountKey, "account_key.json");
      LoadState(ref acmeDir, "directory.json");

      var acme = new AcmeProtocolClient(_acmeHttpClient, acmeDir, account, accountKey?.GenerateSigner());

      if (acmeDir == null)
      {
        acmeDir = await acme.GetDirectoryAsync();

        SaveState(acmeDir, "directory.json");

        acme.Directory = acmeDir;
      }

      await acme.GetNonceAsync();

      if (account == null || accountKey == null)
      {
        account = await acme.CreateAccountAsync(new[] { "mailto:" + Settings.Default.Contacts }, true);

        accountKey = new AccountKey
        {
          KeyType = acme.Signer.JwsAlg,
          KeyExport = acme.Signer.Export()
        };

        SaveState(account, "account.json");
        SaveState(accountKey, "account_key.json");

        acme.Account = account;
      }

      return acme;
    }

    private static void LoadState<T>(ref T value, string path)
    {
      var fullPath = Environment.ExpandEnvironmentVariables(@"%HOME%\.acme\" + path);

      if (!File.Exists(fullPath))
      {
        return;
      }

      var json = File.ReadAllText(fullPath);

      value = JsonConvert.DeserializeObject<T>(json);
    }

    private static void SaveState<T>(T value, string path)
    {
      var fullPath = Environment.ExpandEnvironmentVariables(@"%HOME%\.acme\" + path);
      var directoryPath = Path.GetDirectoryName(fullPath);

      if (!Directory.Exists(directoryPath))
      {
        Directory.CreateDirectory(directoryPath);
      }

      var json = JsonConvert.SerializeObject(value, Formatting.Indented);

      File.WriteAllText(fullPath, json);
    }
  }

  public class TerminateCertificateRequest
  {
    public string CertSecretName { get; set; }
  }
}