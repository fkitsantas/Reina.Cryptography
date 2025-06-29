using Google.Cloud.SecretManager.V1;
using Google.Protobuf;
using Grpc.Core;
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
    /// <summary>
    /// Key manager for handling encryption key storage and retrieval using Google Cloud Secret Manager.
    /// Implements automatic key rotation and caching.
    /// </summary>
    internal class GoogleCloudKeyManager : IKeyManager
    {
        private readonly SecretManagerServiceClient _client;
        private readonly string _projectId;
        private static readonly ConcurrentDictionary<string, byte[]> _keyCache = new();

        // Lazy singleton to ensure a single instance is asynchronously initialized
        private static readonly Lazy<Task<GoogleCloudKeyManager>> _instance = new(async () =>
        {
            var cfg = Config.Instance;
            cfg.ValidateConfiguration();

            // Create Secret Manager client asynchronously
            var client = await SecretManagerServiceClient.CreateAsync().ConfigureAwait(false);
            return new GoogleCloudKeyManager(cfg.GoogleProjectId!, client);
        });

        /// <summary>
        /// Provides singleton instance of the Key Manager.
        /// </summary>
        public static Task<GoogleCloudKeyManager> InstanceAsync() => _instance.Value;

        private GoogleCloudKeyManager(string projectId, SecretManagerServiceClient client)
        {
            _projectId = projectId;
            _client = client;
        }

        /// <summary>
        /// Retrieves the current encryption key for the specified base key name.
        /// </summary>
        public async Task<byte[]> GetEncryptionKeyAsync(string baseKeyName)
        {
            if (_keyCache.TryGetValue(baseKeyName, out var cached))
                return cached;

            var (versionedName, key) = await EnsureRotatedKeyAsync(baseKeyName).ConfigureAwait(false);
            _keyCache[baseKeyName] = key;
            return key;
        }

        /// <summary>
        /// Retrieves all valid decryption keys for the specified base key name.
        /// </summary>
        public async Task<List<byte[]>> GetDecryptionKeysAsync(string baseKeyName)
        {
            var versions = new List<(int version, SecretVersion sv)>();
            var secretName = new SecretName(_projectId, baseKeyName);

            // Iterate through all enabled secret versions
            await foreach (var sv in _client.ListSecretVersionsAsync(secretName).ConfigureAwait(false))
            {
                if (sv.State == SecretVersion.Types.State.Enabled)
                {
                    var versionLabel = sv.Name.Split('/').Last();
                    if (int.TryParse(versionLabel.Split(new[] { "--v" }, StringSplitOptions.None).Last(), out int v))
                        versions.Add((v, sv));
                }
            }

            // Fallback: If no enabled versions, get a new one
            if (!versions.Any())
            {
                var first = await GetEncryptionKeyAsync(baseKeyName).ConfigureAwait(false);
                return new List<byte[]> { first };
            }

            var keys = new List<byte[]>();
            foreach (var (_, sv) in versions.OrderByDescending(v => v.version))
            {
                var access = await _client.AccessSecretVersionAsync(sv.SecretVersionName).ConfigureAwait(false);
                var data = access.Payload.Data.ToStringUtf8();
                keys.Add(Convert.FromBase64String(data));
            }

            await EnsureRotatedKeyAsync(baseKeyName).ConfigureAwait(false);
            return keys;
        }

        /// <summary>
        /// Ensures key rotation logic and returns the latest valid encryption key.
        /// </summary>
        private async Task<(string versionedName, byte[] key)> EnsureRotatedKeyAsync(string baseKeyName)
        {
            var cfg = Config.Instance;
            var secretName = new SecretName(_projectId, baseKeyName);
            Secret secret;

            try
            {
                secret = await _client.GetSecretAsync(secretName).ConfigureAwait(false);
            }
            catch (RpcException rpc) when (rpc.Status.StatusCode == StatusCode.NotFound)
            {
                // Secret does not exist — create new secret
                secret = await _client.CreateSecretAsync(new CreateSecretRequest
                {
                    Parent = $"projects/{_projectId}",
                    SecretId = baseKeyName,
                    Secret = new Secret
                    {
                        Replication = new Replication { Automatic = new Replication.Types.Automatic() }
                    }
                }).ConfigureAwait(false);
            }

            // Retrieve all version numbers
            var versionNumbers = new List<int>();
            await foreach (var sv in _client.ListSecretVersionsAsync(secretName).ConfigureAwait(false))
            {
                if (sv.State == SecretVersion.Types.State.Enabled)
                {
                    var versionLabel = sv.Name.Split('/').Last();
                    if (int.TryParse(versionLabel.Split(new[] { "--v" }, StringSplitOptions.None).Last(), out int v))
                        versionNumbers.Add(v);
                }
            }

            int latestVersion = versionNumbers.DefaultIfEmpty(0).Max();
            DateTimeOffset? latestTime = null;

            if (latestVersion > 0)
            {
                var svName = $"{baseKeyName}--v{latestVersion}";
                var sv = await _client.GetSecretVersionAsync(new SecretVersionName(_projectId, baseKeyName, svName)).ConfigureAwait(false);
                latestTime = sv.CreateTime.ToDateTimeOffset();
            }

            var now = DateTimeOffset.UtcNow;
            bool rotate = !latestTime.HasValue || now - latestTime >= cfg.KeyRotationThreshold;

            string versionedName;
            byte[] key;

            if (rotate)
            {
                // Generate and store new key version
                key = Generate256BitKey();
                int next = latestVersion + 1;
                versionedName = $"{baseKeyName}--v{next}";

                await _client.AddSecretVersionAsync(new AddSecretVersionRequest
                {
                    Parent = secretName.ToString(),
                    Payload = new SecretPayload
                    {
                        Data = ByteString.CopyFromUtf8(Convert.ToBase64String(key))
                    }
                }).ConfigureAwait(false);

                // Disable old keys beyond retention
                var cutoff = now - cfg.KeyRetentionPeriod;
                await foreach (var sv in _client.ListSecretVersionsAsync(secretName).ConfigureAwait(false))
                {
                    var created = sv.CreateTime.ToDateTimeOffset();
                    var label = sv.Name.Split('/').Last();

                    if (created < cutoff && label != versionedName)
                    {
                        await _client.DisableSecretVersionAsync(new DisableSecretVersionRequest
                        {
                            Name = sv.Name
                        }).ConfigureAwait(false);
                    }
                }
            }
            else
            {
                // Load latest key
                versionedName = $"{baseKeyName}--v{latestVersion}";
                var access = await _client.AccessSecretVersionAsync(new SecretVersionName(_projectId, baseKeyName, versionedName))
                                          .ConfigureAwait(false);
                key = Convert.FromBase64String(access.Payload.Data.ToStringUtf8());
            }

            return (versionedName, key);
        }

        /// <summary>
        /// Generates a new 256-bit symmetric encryption key using RNGCryptoServiceProvider.
        /// </summary>
        private static byte[] Generate256BitKey()
        {
            var key = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(key);
            return key;
        }
    }
}