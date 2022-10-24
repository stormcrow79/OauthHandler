using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace OauthHandler
{
    public class OauthHandler : DelegatingHandler
    {
        public OauthHandler(
            OauthHandlerSettings settings,
            HttpMessageHandler inner)
            : base(inner)
        {
            Settings = settings;
        }

        public OauthHandler(
            OauthHandlerSettings settings)
            : this(settings, new HttpClientHandler()) { }

        protected async Task ValidateToken()
        {
            if (Token != null && Token.ExpiresAt >= (DateTimeOffset.Now - Settings.TokenExpiryThreshold))
                return;

            try
            {
                using (var httpClient = new HttpClient { Timeout = Settings.AuthenticationTimeout })
                {
                    var parameters = new Dictionary<string, string>
                    {
                        { "grant_type", "client_credentials" },
                        { "client_id", Settings.ClientId },
                        { "client_secret", Settings.ClientSecret },
                    };

                    if (!string.IsNullOrWhiteSpace(Settings.Scopes))
                        parameters.Add("scope", Settings.Scopes);

                    //Log.Info($"Requesting access token ...");
                    var response = await httpClient.PostAsync(
                        Settings.TokenEndpoint, 
                        new FormUrlEncodedContent(parameters));
                    //Log.Error($"Response Status Code: {response.StatusCode}{(response.IsSuccessStatusCode ? " (Success)" : string.Empty)}");

                    var result = await response.Content.ReadAsStringAsync();

                    if (response.IsSuccessStatusCode)
                    {
                        Token = JsonSerializer.Deserialize<TokenResponse>(result);
                        return;
                    }

                    //Log.Error(new { responseContent = result });
                }
            }
            catch (Exception ex)
            {
                //Log.Debug("Exception", ex);
            }

            //Log.Debug("Token not acquired.");
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            await ValidateToken();
            request.Headers.Add("Authorization", $"Bearer {Token.AccessToken}");
            return await base.SendAsync(request, cancellationToken);
        }

        public OauthHandlerSettings Settings { get; internal set; }
        
        private TokenResponse Token { get; set; }
    }

    public class OauthHandlerSettings
    {
        public string TokenEndpoint { get; set; }

        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public string Scopes { get; set; }

        public TimeSpan AuthenticationTimeout { get; set; } = TimeSpan.FromSeconds(10);
        
        public TimeSpan TokenExpiryThreshold { get; set; } = TimeSpan.FromSeconds(20);
    }

    internal class TokenResponse
    {
        [JsonPropertyName("token_type")]
        public string TokenType { get; set; }

        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; }

        [JsonPropertyName("issues_token_type")]
        public string IssuesTokenType { get; set; }

        [JsonPropertyName("expires_in")]
        public int? ExpiresIn { get; set; }

        [JsonPropertyName("error")]
        public string Error { get; set; }

        [JsonPropertyName("error_description")]
        public string ErrorDescription { get; set; }

        public DateTimeOffset CreatedAt { get; internal set; } = DateTimeOffset.Now;

        public DateTimeOffset ExpiresAt => CreatedAt.AddSeconds(ExpiresIn ?? 0);
    }
}
