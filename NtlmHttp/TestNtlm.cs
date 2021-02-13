using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NtlmHttp
{
    public class TestNtlm
    {
        private NetworkCredential nc;

        public TestNtlm(NetworkCredential nc)
        {
            this.nc = nc;
        }

        private async Task Authenticate(String uri, bool useNtlm = true)
        {
            // var handler = new SocketsHttpHandler();
            // var client = new HttpClient(handler);
            var client = new HttpClient();
            client.DefaultRequestHeaders.Add("Accept", "*/*");

            var ntlm = new Ntlm(nc);
            // string msg = ntlm.CreateNegotiateMessage(spnego: !useNtlm);

            var message = new HttpRequestMessage(HttpMethod.Get, uri);
            message.Headers.Add("Authorization", ntlm.CreateNegotiateMessage(spnego: !useNtlm));

            Console.WriteLine(message);
            HttpResponseMessage response = await client.SendAsync(message, default);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                foreach (AuthenticationHeaderValue header in response.Headers.WwwAuthenticate)
                {
                    string blob = ntlm.ProcessChallenge(header);
                    if (!string.IsNullOrEmpty(blob))
                    {
                        message = new HttpRequestMessage(HttpMethod.Get, uri);
                        message.Headers.Add("Authorization", blob);
                        Console.WriteLine(message);
                        response = await client.SendAsync(message, default);
                    }
                }
            }

            Console.WriteLine(response);
        }

        public async Task Test(string uri)
        {
            var client = new HttpClient();
            HttpResponseMessage probe = await client.GetAsync(uri, CancellationToken.None);

            if (probe.StatusCode == HttpStatusCode.Unauthorized)
            {
                bool canDoNtlm = false;
                bool canDoNegotiate = false;

                foreach (AuthenticationHeaderValue header in probe.Headers.WwwAuthenticate)
                {
                    if (StringComparer.OrdinalIgnoreCase.Equals(header.Scheme, "NTLM"))
                    {
                        canDoNtlm = true;
                    }
                    else if (StringComparer.OrdinalIgnoreCase.Equals(header.Scheme, "Negotiate"))
                    {
                        canDoNegotiate = true;
                    }
                    else
                    {
                        Console.WriteLine($"{uri} offers {header.Scheme} authentication");
                    }
                }

                Console.WriteLine("{0} {1} do NTLM authentication", uri, canDoNtlm ? "can" : "cannot");
                Console.WriteLine("{0} {1} do Negotiate authentication", uri, canDoNegotiate ? "can" : "cannot");

                if (canDoNtlm)
                {
                    try
                    {
                        await Authenticate(uri, true);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("NTLM Authentication failed");
                        Console.WriteLine(ex);
                    }
                }

                if (canDoNegotiate)
                {
                    try
                    {
                        await Authenticate(uri, false);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Negotiate Authentication failed");
                        Console.WriteLine(ex);
                    }
                }
            }
            else
            {
                Console.WriteLine($"{uri} did not ask for authentication.");
                Console.WriteLine(probe);
            }
        }
    }
}
