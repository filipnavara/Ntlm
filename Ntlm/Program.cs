using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using NtlmHttp;

namespace NtlmTest
{
    class Program
    {
        static NetworkCredential nc;

        static async Task Main(string[] args)
        {
            string uri = args.Length > 0 ? args[0] : "http://testntlm.westus2.cloudapp.azure.com/testntlm.htm";
            string env = Environment.GetEnvironmentVariable("CREDENTIALS");

            if (String.IsNullOrEmpty(env))
            {
                // lame credentials. cab be updated for testing.
                nc = new NetworkCredential("testuser", "Wh9nPWEA3Xsg", "testntlm");
            }
            else
            {
                // assume domain\user:password
                string[] part1 = env.Split(new char[] { ':' }, 2);
                string[] part2 = part1[0].Split(new char[] { '\\' }, 2);
                if (part2.Length == 1)
                {
                    nc = new NetworkCredential(part1[0], part1[1]);
                }
                else
                {
                    nc = new NetworkCredential(part2[1], part1[1], part2[0]);
                }
            }

            await Test(uri, nc);
        }


        private async static Task Test(string uri, NetworkCredential networkCredential)
        {
            var handler = new NtlmHttpMessageHandler(new SocketsHttpHandler());
            handler.NetworkCredential = networkCredential;

            var client = new HttpClient(handler);
            var result = await client.GetAsync(uri, CancellationToken.None);

            Console.WriteLine(result);
        }
    }
}
