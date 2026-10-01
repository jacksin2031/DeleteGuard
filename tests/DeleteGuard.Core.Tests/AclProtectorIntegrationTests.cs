using DeleteGuard.Core.Security;
using Xunit;

namespace DeleteGuard.Core.Tests;

public sealed class AclProtectorIntegrationTests
{
    [Fact]
    public void GuardAcl_BlocksOrdinaryFileDelete_ThenCanBeRemoved()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var root = Path.Combine(Path.GetTempPath(), "DeleteGuard.AclTest", Guid.NewGuid().ToString("N"));
        var file = Path.Combine(root, "protected.txt");
        Directory.CreateDirectory(root);
        File.WriteAllText(file, "test");

        var applied = false;
        try
        {
            AclProtector.EnsureNtfs(root);
            applied = AclProtector.Apply(root);
            Assert.True(applied);
            Assert.True(AclProtector.HasGuardRule(root));
            Assert.Throws<UnauthorizedAccessException>(() => File.Delete(file));

            Assert.True(AclProtector.Remove(root));
            applied = false;
            File.Delete(file);
            Assert.False(File.Exists(file));
        }
        finally
        {
            if (applied && Directory.Exists(root))
            {
                AclProtector.Remove(root);
            }

            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }
}
