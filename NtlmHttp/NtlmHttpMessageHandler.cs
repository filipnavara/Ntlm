using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace NtlmHttp
{
    public class NtlmHttpMessageHandler : DelegatingHandler
    {
        public  NetworkCredential NetworkCredential { get; set; }

        public NtlmHttpMessageHandler(HttpMessageHandler innerHandler) : base(innerHandler)
        {
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var result = await base.SendAsync(request, cancellationToken);

            if (result.StatusCode == HttpStatusCode.Unauthorized)
            {
                bool canDoNtlm = false;
                bool canDoNegotiate = false;

                foreach (AuthenticationHeaderValue header in result.Headers.WwwAuthenticate)
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
                        Console.WriteLine($"{request.RequestUri} offers {header.Scheme} authentication");
                    }
                }

                Console.WriteLine("{0} {1} do NTLM authentication", request.RequestUri, canDoNtlm ? "can" : "cannot");
                Console.WriteLine("{0} {1} do Negotiate authentication", request.RequestUri, canDoNegotiate ? "can" : "cannot");

                if (canDoNtlm)
                {
                    try
                    {
                        result = await SendAuthenticated(request, cancellationToken, true);
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
                        result = await SendAuthenticated(request, cancellationToken, false);
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
                Console.WriteLine($"{request.RequestUri} did not ask for authentication.");
                Console.WriteLine(result);
            }

            return result;
        }

        private async Task<HttpResponseMessage> SendAuthenticated(HttpRequestMessage request, CancellationToken cancellationToken, bool useNtlm = true)
        {
            //request.Headers.Add("Accept", "*/*");
            request.Headers.Accept.Clear();
            request.Headers.Add("Accept", "*/*");
            //request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*"));

            var ntlm = new Ntlm(NetworkCredential);

            request.Headers.Authorization = CreateAuthenticationHeaderValue(ntlm.CreateNegotiateMessage(spnego: !useNtlm));
            // request.Headers.Add("Authorization", ntlm.CreateNegotiateMessage(spnego: !useNtlm));

            Console.WriteLine(request);
            var response = await base.SendAsync(request, cancellationToken);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                foreach (AuthenticationHeaderValue header in response.Headers.WwwAuthenticate)
                {
                    string blob = ntlm.ProcessChallenge(header);
                    if (!string.IsNullOrEmpty(blob))
                    {
                        request.Headers.Clear();
                        request.Headers.Add("Accept", "*/*");
                        // request.Headers.Authorization = CreateAuthenticationHeaderValue(blob);
                        request.Headers.Add("Authorization", blob);

                        Console.WriteLine(request);
                        response = await base.SendAsync(request, cancellationToken);
                    }
                }
            }

            Console.WriteLine(response);
            return response;
        }

        private AuthenticationHeaderValue CreateAuthenticationHeaderValue(string authorizationValue)
        {
            var values = authorizationValue.Split(' ');

            return new AuthenticationHeaderValue(values[0], values[1]);
        }
    }
}
