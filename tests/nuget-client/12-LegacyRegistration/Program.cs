// Resolves a package's registration through one NuGet v3 source with NuGet.Protocol 6.3.4.
// Usage: dotnet run -- <index.json URL> [id] [version]; NORA_TOKEN in the env, if set, is the password.
using NuGet.Common;
using NuGet.Configuration;
using NuGet.Packaging.Core;
using NuGet.Protocol;
using NuGet.Protocol.Core.Types;
using NuGet.Versioning;

var source = new PackageSource(args[0], "nora");
var token = Environment.GetEnvironmentVariable("NORA_TOKEN");
if (!string.IsNullOrEmpty(token))
{
    source.Credentials = PackageSourceCredential.FromUserInput("nora", "token", token, storePasswordInClearText: true, null);
}
var id = new PackageIdentity(
    args.Length > 1 ? args[1] : "Newtonsoft.Json",
    NuGetVersion.Parse(args.Length > 2 ? args[2] : "13.0.3"));

var repo = Repository.Factory.GetCoreV3(source);
using var cache = new SourceCacheContext { NoCache = true };

var registration = await repo.GetResourceAsync<RegistrationResourceV3>();
if (registration?.BaseUri is null)
{
    Console.Error.WriteLine("FAIL: no RegistrationsBaseUrl the client accepts");
    return 1;
}
Console.WriteLine($"registration base: {registration.BaseUri}");

var metadata = await repo.GetResourceAsync<PackageMetadataResource>();
var found = await metadata.GetMetadataAsync(id, cache, NullLogger.Instance, CancellationToken.None);
if (found is null)
{
    Console.Error.WriteLine($"FAIL: {id} not resolved via registration");
    return 1;
}
Console.WriteLine($"resolved {found.Identity} via registration");
return 0;
