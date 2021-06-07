/*
MIT License

Copyright (c) 2021 Tomas Weinfurt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

using System;
using System.IO;
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

        private async Task<HttpResponseMessage> SendAuthenticated(HttpRequestMessage request, CancellationToken cancellationToken, bool useNtlm = true)
        {
            var ntlm = new Ntlm(NetworkCredential);

            request = await request.CloneAsync();
            request.Headers.Authorization = CreateAuthenticationHeaderValue(ntlm.CreateNegotiateMessage(spnego: !useNtlm));
            // Use single connection since NTLM is session-based authentication
            request.Headers.ConnectionClose = false;
            // Enforce HTTP/1.1, newer HTTP version are not supported
            request.Version = new Version(1, 1);

            Console.WriteLine(request);
            var response = await base.SendAsync(request, cancellationToken);
            // Discard the content of server's reply
            await response.Content.CopyToAsync(Stream.Null);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                foreach (AuthenticationHeaderValue header in response.Headers.WwwAuthenticate)
                {
                    string blob = ntlm.ProcessChallenge(header);
                    if (!string.IsNullOrEmpty(blob))
                    {
                        request.Headers.Authorization = CreateAuthenticationHeaderValue(blob);

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
