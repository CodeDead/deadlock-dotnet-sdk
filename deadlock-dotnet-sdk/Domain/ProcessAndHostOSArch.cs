using Windows.Win32.System.SystemInformation;

namespace deadlock_dotnet_sdk.Domain;

public record struct ProcessAndHostOSArch(IMAGE_FILE_MACHINE Process, IMAGE_FILE_MACHINE Host)
{
    public static implicit operator (IMAGE_FILE_MACHINE Process, IMAGE_FILE_MACHINE Host)(ProcessAndHostOSArch value)
        => (value.Process, value.Host);

    public static implicit operator ProcessAndHostOSArch((IMAGE_FILE_MACHINE Process, IMAGE_FILE_MACHINE Host) value)
        => new(value.Process, value.Host);
}
