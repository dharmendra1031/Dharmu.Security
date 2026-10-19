namespace Dharmu.Security.Core.Machine;

public interface IMachineIdentityProvider
{
    string GetMachineCode();
    byte[] ExportPublicKey();
    byte[] Sign(byte[] data);
}
