using FluentAssertions;
using NtlmHttp;
using System;
using System.Text;
using Xunit;

namespace NtlmHttpTests
{
    public class Md4Tests
    {
        [Theory]
        [InlineData("", "31d6cfe0d16ae931b73c59d7e0c089c0")]
        [InlineData("a", "bde52cb31de33e46245e05fbdbd6fb24")]
        [InlineData("abc", "a448017aaf21d8525fc10ae87aa6729d")]
        [InlineData("message digest", "d9130a8164549fe818874806e1c7014b")]
        [InlineData("abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9")]
        [InlineData("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4")]
        [InlineData("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536")]
        public void HashTest(string input, string expected)
        {
            // Arrange
            var md4 = new MD4();
            var bytes = Encoding.ASCII.GetBytes(input);

            // Act
            var hash = md4.Hash(bytes);

            // Assert
            var hashString = BitConverter.ToString(hash).Replace("-", "").ToLower();
            hashString.Should().Be(expected);
        }
    }
}
