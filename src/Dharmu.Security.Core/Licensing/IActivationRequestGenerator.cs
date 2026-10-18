namespace Dharmu.Security.Core.Licensing;

public interface IActivationRequestGenerator
{
    string Generate(string productCode, DateTime utcNow);
}
