using Amazon;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using Reina.Cryptography.Configuration;
using Reina.Cryptography.Interfaces;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Reina.Cryptography.KeyManagement
{
    internal class AWSKeyManager : IKeyManager
    {
        private readonly IAmazonSecretsManager _client;
        private static readonly ConcurrentDictionary<string, byte[]> _keyCache = new();

        // Lazy singleton to ensure a single instance is asynchronously initialized
        private static readonly Lazy<Task<AWSKeyManager>> _instance = new(new Func<Task<AWSKeyManager>>(() =>
        {
            var cfg = Config.Instance;
            cfg.ValidateConfiguration();

            if (string.IsNullOrWhiteSpace(cfg.AWSRegion))
                throw new InvalidOperationException("AWS Region is required.");

            var config = new AmazonSecretsManagerConfig
            {
                RegionEndpoint = RegionEndpoint.GetBySystemName(cfg.AWSRegion!)
            };

            var client = (cfg.AWSAccessKeyId != null && cfg.AWSSecretAccessKey != null)
                ? new AmazonSecretsManagerClient(cfg.AWSAccessKeyId, cfg.AWSSecretAccessKey, config)
                : new AmazonSecretsManagerClient(config);

            return Task.FromResult(new AWSKeyManager(client));
        }));


        /// <summary>
        /// Provides the singleton instance of the AWSKeyManager asynchronously.
        /// </summary>
        public static Task<AWSKeyManager> InstanceAsync() => _instance.Value;

        private AWSKeyManager(IAmazonSecretsManager client)
{
    _client = client;
}


        public async Task<byte[]> GetEncryptionKeyAsync(string baseKeyName)
        {
            if (_keyCache.TryGetValue(baseKeyName, out var cached))
                return cached;

            var (secretName, key) = await EnsureRotatedKeyAsync(baseKeyName).ConfigureAwait(false);
            _keyCache[baseKeyName] = key;
            return key;
        }

        public async Task<List<byte[]>> GetDecryptionKeysAsync(string baseKeyName)
        {
            var (latestName, _) = await EnsureRotatedKeyAsync(baseKeyName).ConfigureAwait(false);
            var versions = await ListVersionedSecretsAsync(baseKeyName).ConfigureAwait(false);

            var result = new List<byte[]>();
            foreach (var version in versions.OrderByDescending(v => v.Version))
            {
                if (_keyCache.TryGetValue(version.Name, out var cached))
                {
                    result.Add(cached);
                    continue;
                }

                var resp = await _client.GetSecretValueAsync(new GetSecretValueRequest { SecretId = version.Name }).ConfigureAwait(false);
                var key = Convert.FromBase64String(resp.SecretString);
                _keyCache[version.Name] = key;
                result.Add(key);
            }

            return result.Any() ? result : new List<byte[]> { (await GetEncryptionKeyAsync(baseKeyName).ConfigureAwait(false)) };
        }

        private async Task<(string Name, byte[] Key)> EnsureRotatedKeyAsync(string baseKeyName)
        {
            var cfg = Config.Instance;
            var versions = await ListVersionedSecretsAsync(baseKeyName).ConfigureAwait(false);

            if (!versions.Any())
                return await CreateNewVersion(baseKeyName, 1).ConfigureAwait(false);

            var latest = versions.OrderByDescending(v => v.Version).First();
            var desc = await _client.DescribeSecretAsync(new DescribeSecretRequest { SecretId = latest.Name }).ConfigureAwait(false);
            var lastChange = desc.LastChangedDate ?? DateTime.UtcNow;
            var now = DateTime.UtcNow;

            if (lastChange.Add(cfg.KeyRotationThreshold) <= now)
            {
                int newVersion = latest.Version + 1;
                await RetireOldVersions(versions, cfg.KeyRetentionPeriod).ConfigureAwait(false);
                return await CreateNewVersion(baseKeyName, newVersion).ConfigureAwait(false);
            }

            var resp = await _client.GetSecretValueAsync(new GetSecretValueRequest { SecretId = latest.Name }).ConfigureAwait(false);
            return (latest.Name, Convert.FromBase64String(resp.SecretString));
        }

        private async Task<List<(int Version, string Name)>> ListVersionedSecretsAsync(string baseKeyName)
        {
            var result = new List<(int, string)>();
            string? marker = null;

            do
            {
                var resp = await _client.ListSecretsAsync(new ListSecretsRequest { NextToken = marker }).ConfigureAwait(false);
                marker = resp.NextToken;

                foreach (var secret in resp.SecretList)
                {
                    if (secret.Name.StartsWith($"{baseKeyName}--v", StringComparison.OrdinalIgnoreCase)
                        && int.TryParse(secret.Name.Split(new[] { "--v" }, StringSplitOptions.None).Last(), out int v))
                        result.Add((v, secret.Name));
                }
            }
            while (marker != null);

            return result;
        }

        private async Task RetireOldVersions(IEnumerable<(int Version, string Name)> versions, TimeSpan retention)
        {
            var cutoff = DateTime.UtcNow.Subtract(retention);
            foreach (var v in versions)
            {
                var desc = await _client.DescribeSecretAsync(new DescribeSecretRequest { SecretId = v.Name }).ConfigureAwait(false);
                var lastChange = desc.LastChangedDate ?? DateTime.UtcNow;
                if (lastChange < cutoff)
                    await _client.DeleteSecretAsync(new DeleteSecretRequest
                    {
                        SecretId = v.Name,
                        RecoveryWindowInDays = 7
                    }).ConfigureAwait(false);
            }
        }

        private async Task<(string Name, byte[] Key)> CreateNewVersion(string baseKeyName, int version)
        {
            var name = $"{baseKeyName}--v{version}";
            var key = Generate256bitKey();
            await _client.CreateSecretAsync(new CreateSecretRequest
            {
                Name = name,
                SecretString = Convert.ToBase64String(key),
                Tags = new List<Tag> { new Tag { Key = "BaseKey", Value = baseKeyName } }
            }).ConfigureAwait(false);

            _keyCache[name] = key;
            return (name, key);
        }

        private static byte[] Generate256bitKey()
        {
            var key = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }
            return key;
        }
    }
}