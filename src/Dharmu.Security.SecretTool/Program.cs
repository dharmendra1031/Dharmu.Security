using Dharmu.Security.Windows.Secrets;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("Secret protection is supported only on Windows.");
    return 1;
}

Console.Write("Enter secret to protect: ");
var secret = ReadSecret();

if (string.IsNullOrWhiteSpace(secret))
{
    Console.Error.WriteLine("Secret cannot be empty.");
    return 1;
}

var protector = new DpapiSecretProtector();
var protectedValue = protector.Protect(secret);

Console.WriteLine();
Console.WriteLine("Protected value:");
Console.WriteLine(protectedValue);
Console.WriteLine();
Console.WriteLine(
    "Store only this protected value under ProtectedConnectionStrings. " +
    "Do not store the plaintext secret.");

return 0;

static string ReadSecret()
{
    if (Console.IsInputRedirected)
    {
        return Console.ReadLine() ?? string.Empty;
    }

    var characters = new List<char>();

    while (true)
    {
        var key = Console.ReadKey(intercept: true);

        if (key.Key == ConsoleKey.Enter)
        {
            break;
        }

        if (key.Key == ConsoleKey.Backspace)
        {
            if (characters.Count > 0)
            {
                characters.RemoveAt(characters.Count - 1);
            }

            continue;
        }

        if (!char.IsControl(key.KeyChar))
        {
            characters.Add(key.KeyChar);
        }
    }

    return new string(characters.ToArray());
}
