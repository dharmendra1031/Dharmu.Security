using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Dharmu.Security.Windows.Machine;

namespace Dharmu.Security.DeviceTool;

internal static class IisPermissions
{
    private static readonly string AppCmd = Path.Combine(Environment.SystemDirectory, "inetsrv", "appcmd.exe");
    private static readonly string Icacls = Path.Combine(Environment.SystemDirectory, "icacls.exe");

    internal static string[] ListPools()
    {
        EnsureAdministrator();
        return Run(AppCmd, "list", "apppool", "/text:name")
            .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    internal static void Configure(string pool, string licenseDirectory, string stateDirectory)
    {
        EnsureAdministrator();
        if (!ListPools().Contains(pool, StringComparer.Ordinal))
            throw new InvalidOperationException("Select an existing IIS application pool.");
        if (!string.Equals(Run(AppCmd, "list", "apppool", pool, "/text:processModel.identityType").Trim(),
                "ApplicationPoolIdentity", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Only ApplicationPoolIdentity is supported. Custom service accounts require manual configuration.");

        var sid = (SecurityIdentifier)new NTAccount("IIS APPPOOL", pool).Translate(typeof(SecurityIdentifier));
        var license = ValidateDirectory(licenseDirectory);
        var state = ValidateDirectory(stateDirectory);
        // Resolve both existing keys before changing permissions. Never provision or replace a key here.
        var deviceKey = KeyPath(WindowsMachineIdentityProvider.DeviceKeyName);
        var secretKey = KeyPath("DharmuSecuritySecretProtection");

        EnsureDirectory(license);
        EnsureDirectory(state);
        Grant(license, sid, "(OI)(CI)(RX)");
        Grant(state, sid, "(OI)(CI)(M)");
        Grant(deviceKey, sid, "(R)");
        Grant(secretKey, sid, "(R)");
    }

    private static void EnsureAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new UnauthorizedAccessException("Run Device Tool as administrator.");
        if (!File.Exists(AppCmd)) throw new InvalidOperationException("IIS management tools are not installed.");
    }

    private static string ValidateDirectory(string path)
    {
        var root = Path.TrimEndingDirectorySeparator(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        var relative = Path.GetRelativePath(root, full);
        if (relative == "." || relative == ".." || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) ||
            Path.IsPathRooted(relative) || relative.Split(Path.DirectorySeparatorChar).Length < 2 ||
            relative.Split(Path.DirectorySeparatorChar).Any(part => part.Equals("wwwroot", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("Use a dedicated application license directory under ProgramData, outside the website.");
        RejectReparsePoints(full);
        return full;
    }

    private static void RejectReparsePoints(string path)
    {
        for (string? current = path; current is not null; current = Path.GetDirectoryName(current))
        {
            try
            {
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException("Reparse points are not supported in permission targets: " + current);
            }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
        }
    }

    private static void EnsureDirectory(string path)
    {
        if (Directory.Exists(path)) return;
        var parent = Path.GetDirectoryName(path) ?? throw new InvalidOperationException("Missing parent directory.");
        EnsureDirectory(parent);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        foreach (var type in new[] { WellKnownSidType.BuiltinAdministratorsSid, WellKnownSidType.LocalSystemSid })
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(type, null),
                FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(path).Create(security);
    }

    private static string KeyPath(string name)
    {
        using var key = CngKey.Open(name, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey);
        var uniqueName = key.UniqueName ?? throw new CryptographicException("Missing key storage name.");
        if (Path.GetFileName(uniqueName) != uniqueName || key.ExportPolicy != CngExportPolicies.None)
            throw new CryptographicException("Unexpected CNG key storage or export policy.");
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Microsoft", "Crypto", "Keys", uniqueName);
        RejectReparsePoints(path);
        if (!File.Exists(path)) throw new FileNotFoundException("CNG key file not found.", path);
        return path;
    }

    private static void Grant(string path, SecurityIdentifier sid, string rights)
    {
        RejectReparsePoints(path);
        Run(Icacls, path, "/grant", "*" + sid.Value + ":" + rights);
    }

    private static string Run(string executable, params string[] arguments)
    {
        var info = new ProcessStartInfo(executable)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (var argument in arguments) info.ArgumentList.Add(argument);
        using var process = Process.Start(info) ?? throw new InvalidOperationException("Unable to start " + executable);
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(30000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("Permission command timed out.");
        }
        var result = output.GetAwaiter().GetResult();
        var errors = error.GetAwaiter().GetResult();
        if (process.ExitCode != 0)
            throw new InvalidOperationException($"{Path.GetFileName(executable)} failed: {result} {errors}");
        return result;
    }
}
