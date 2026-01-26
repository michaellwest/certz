namespace certz.Options;

internal static class OptionBuilders
{
    internal static Option<FileInfo?> CreateFileOption(bool isRequired, string[] aliases)
    {
        var allAliases = aliases ?? new[] { "--file", "--f" };
        var fileOption = new Option<FileInfo?>(allAliases[0], allAliases.Skip(1).ToArray())
        {
            Description = "Specifies the certificate.",
            Required = isRequired
        };

        return fileOption;
    }

    internal static Option<string?> CreateUrlOption(bool isRequired, string[] aliases)
    {
        var allAliases = aliases ?? new[] { "--url", "--u" };
        var urlOption = new Option<string?>(allAliases[0], allAliases.Skip(1).ToArray())
        {
            Description = "Specifies the remote URL to retrieve the certificate from.",
            Required = isRequired
        };

        return urlOption;
    }

    internal static Option<string> CreatePasswordOption()
    {
        var passwordOption = new Option<string>("--password", "--pass", "--p")
        {
            Description = "Password for the certificate."
        };

        return passwordOption;
    }

    internal static Option<int> CreateDaysOption(bool isRequired)
    {
        var daysOption = new Option<int>("--days")
        {
            Description = "Lifetime for the certificate.",
            DefaultValueFactory = _ => 365,
            Required = isRequired
        };

        return daysOption;
    }

    internal static Option<StoreName> CreateStoreNameOption()
    {
        var storeNameOption = new Option<StoreName>("--storename", "--sn")
        {
            Description = "Specifies the store name.",
            DefaultValueFactory = _ => StoreName.My
        };
        return storeNameOption;
    }

    internal static Option<StoreLocation> CreateStoreLocationOption()
    {
        var storeLocationOption = new Option<StoreLocation>("--storelocation", "--sl")
        {
            Description = "Specifies the store location.",
            DefaultValueFactory = _ => StoreLocation.LocalMachine
        };
        return storeLocationOption;
    }

    internal static Option<string> CreateThumbprintOption()
    {
        var thumbprintOption = new Option<string>("--thumbprint", "--thumb")
        {
            Description = "The unique thumbprint for the certificate."
        };
        return thumbprintOption;
    }

    internal static Option<FileInfo?> CreateOutputCertOption()
    {
        var outputCertOption = new Option<FileInfo?>("--out-cert", "--oc")
        {
            Description = "Specifies the output certificate file (PEM format).",
            Required = false
        };
        return outputCertOption;
    }

    internal static Option<FileInfo?> CreateOutputKeyOption()
    {
        var outputKeyOption = new Option<FileInfo?>("--out-key", "--ok")
        {
            Description = "Specifies the output private key file (PEM format).",
            Required = false
        };
        return outputKeyOption;
    }
}
