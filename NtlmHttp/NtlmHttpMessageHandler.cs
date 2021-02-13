// #define NOT_WORKING

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

                        if (result.StatusCode != HttpStatusCode.Unauthorized)
                        {
                            return result;
                        }
                        // Else maybe try canDoNegotiate
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

#if NOT_WORKING
        private async Task<HttpResponseMessage> SendAuthenticated(HttpRequestMessage request, CancellationToken cancellationToken, bool useNtlm = true)
        {
            request.Headers.Accept.Clear();
            request.Headers.Add("Accept", "*/*");
            //request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*"));

            var ntlm = new Ntlm(NetworkCredential);

            request.Headers.Authorization = CreateAuthenticationHeaderValue(ntlm.CreateNegotiateMessage(spnego: !useNtlm));

            Console.WriteLine(request);
            var response = await base.SendAsync(request, cancellationToken);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                foreach (AuthenticationHeaderValue header in response.Headers.WwwAuthenticate)
                {
                    string blob = ntlm.ProcessChallenge(header);
                    if (!string.IsNullOrEmpty(blob))
                    {
                        request = new HttpRequestMessage(HttpMethod.Get, request.RequestUri);
                        request.Headers.Clear();
                        request.Headers.Add("Accept", "*/*");
                        request.Headers.Authorization = CreateAuthenticationHeaderValue(blob);

                        Console.WriteLine(request);

                        response = await base.SendAsync(request, cancellationToken);
                    }
                }
            }

            Console.WriteLine(response);
            return response;
        }
#else
        private async Task<HttpResponseMessage> SendAuthenticated(HttpRequestMessage request, CancellationToken cancellationToken, bool useNtlm = true)
        {
            var client = new HttpClient(InnerHandler); // TODO We would like to remove this

            // TODO we should duplicate request ?
            request = new HttpRequestMessage(HttpMethod.Get, request.RequestUri); // TODO We would like to remove this

            request.Headers.Accept.Clear();
            request.Headers.Add("Accept", "*/*");
            //request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*"));

            var ntlm = new Ntlm(NetworkCredential);

            request.Headers.Authorization = CreateAuthenticationHeaderValue(ntlm.CreateNegotiateMessage(spnego: !useNtlm));

            Console.WriteLine(request);
            // var response = await base.SendAsync(request, cancellationToken);     TODO we would like to do this but doesn't work ?!?!?
            var response = await client.SendAsync(request, cancellationToken);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                foreach (AuthenticationHeaderValue header in response.Headers.WwwAuthenticate)
                {
                    string blob = ntlm.ProcessChallenge(header);
                    if (!string.IsNullOrEmpty(blob))
                    {
                        // TODO we should duplicate request ?
                        request = new HttpRequestMessage(HttpMethod.Get, request.RequestUri);
                        request.Headers.Clear();
                        request.Headers.Add("Accept", "*/*");
                        request.Headers.Authorization = CreateAuthenticationHeaderValue(blob);

                        Console.WriteLine(request);
                        // response = await base.SendAsync(request, cancellationToken); // TODO we would like to do this
                        response = await client.SendAsync(request, cancellationToken);
                    }
                }
            }

            Console.WriteLine(response);
            return response;
        }

#endif


        private AuthenticationHeaderValue CreateAuthenticationHeaderValue(string authorizationValue)
        {
            var values = authorizationValue.Split(' ');

            return new AuthenticationHeaderValue(values[0], values[1]);
        }
    }
}
