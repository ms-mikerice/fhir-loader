using Microsoft.Azure.Services.AppAuthentication;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace FHIRBulkImport
{
    public static class ADUtils
    {
        public static bool isTokenExpired(string bearerToken)
        {
            if (bearerToken == null) return true;
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadToken(bearerToken) as JwtSecurityToken;
            var tokenExpiryDate = token.ValidTo;

            // If there is no valid `exp` claim then `ValidTo` returns DateTime.MinValue
            if (tokenExpiryDate == DateTime.MinValue) return true;

            // If the token is in the past then you can't use it
            if (tokenExpiryDate < DateTime.UtcNow) return true;
            return false;

        }
        public static async Task<string> GetOAUTH2BearerToken(string resource, string tenant = null, string clientid = null, string secret = null)
        {
            if (!string.IsNullOrEmpty(resource) && (string.IsNullOrEmpty(tenant) && string.IsNullOrEmpty(clientid) && string.IsNullOrEmpty(secret)))
            {
                //Assume Managed Service Identity with only resource provided.
                var azureServiceTokenProvider = new AzureServiceTokenProvider();
                var _accessToken = await azureServiceTokenProvider.GetAccessTokenAsync(resource);
                return _accessToken;
            }
            else
            {
                using HttpClient httpClient = new()
                {
                    BaseAddress = new Uri(ImportUtilityManager.GetEnvironmentVariable("AAD_Token_URL"))
                };

                var data = new[] {
                    new KeyValuePair<string, string>("grant_type","client_credentials"),
                    new KeyValuePair<string, string>("client_id", clientid),
                    new KeyValuePair<string, string>("client_secret", secret),
                    new KeyValuePair<string, string>("resource", resource)
                };

                using HttpResponseMessage response = await httpClient.PostAsync(
                  $"{tenant}/oauth2/token",
                  new FormUrlEncodedContent(data)
                );

                response.EnsureSuccessStatusCode();

                var result = await response.Content.ReadAsStringAsync();
                JObject obj = JObject.Parse(result);
                return (string)obj["access_token"];
            }
        }
    }
}
