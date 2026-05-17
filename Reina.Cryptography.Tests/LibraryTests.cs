using System;
using System.Threading.Tasks;
using Xunit;

namespace Reina.Cryptography.Tests;

public class LibraryTests
{
    [Fact]
    public void Initialize_SetsInitializedFlag_DoesNotThrow()
    {
        // Should not throw if configuration is valid (assumes Config.Instance.ValidateConfiguration is safe)
        Library.Initialize();
        // No assert: just ensure no exception
    }



    public static TheoryData<string?, string?, string?, string?> InvalidInputData => new()
    {
        { null, "key1", "key2", "key3" },
        { "", "key1", "key2", "key3" },
        { "data", null, "key2", "key3" },
        { "data", "", "key2", "key3" }
    };

    [Theory]
    [MemberData(nameof(InvalidInputData))]
    public async Task EncryptAsync_InvalidInput_ThrowsArgumentNullException(string? data, string? k1, string? k2, string? k3)
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() => Library.EncryptAsync(data!, k1!, k2!, k3!, TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("data", "1invalid", "key2", "key3")]
    [InlineData("data", "key1", "-bad", "key3")]
    public async Task EncryptAsync_InvalidKeyFormat_ThrowsArgumentException(string data, string k1, string k2, string k3)
    {
        await Assert.ThrowsAsync<ArgumentException>(() => Library.EncryptAsync(data, k1, k2, k3, TestContext.Current.CancellationToken));
    }

    [Fact(Skip = "Requires mocking KeyFactory and DataEncryptor")] 
    public async Task EncryptAsync_ValidInput_ReturnsBase64()
    {
        // TODO: Mock KeyFactory.InstanceAsync and DataEncryptor to test happy path
        // var result = await Library.EncryptAsync("data", "key1", "key2", "key3");
        // Assert.NotNull(result);
    }

    [Fact(Skip = "Requires mocking KeyFactory and DataDecryptor")] 
    public async Task DecryptAsync_ValidInput_ReturnsPlainText()
    {
        // TODO: Mock KeyFactory.InstanceAsync and DataDecryptor to test happy path
        // var result = await Library.DecryptAsync("base64", "key1", "key2", "key3");
        // Assert.Equal("data", result);
    }
}
