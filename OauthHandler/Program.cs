using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace OauthHandler
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            var settings = LoadSettings();

            var client = new HttpClient(
                new OauthHandler(settings.Authentication));

            var content = await client.GetStringAsync(
                $"{settings.EndpointUrl}/terminology/fhir/CodeSystem?_summary=true");

            Console.WriteLine(content);
        }

        static Settings LoadSettings()
        {
            return new[] { "settings.development.json", "settings.json" }
                .Where(File.Exists)
                .Select(x => File.ReadAllText(x))
                .Select(x => JsonSerializer.Deserialize<Settings>(x))
                .FirstOrDefault();
        }
    }

    internal class Settings
    {
        public string EndpointUrl { get; set; }
        public OauthHandlerSettings Authentication { get; set; }
    }
}
