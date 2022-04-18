# deadlock-dotnet-sdk

![GitHub release (latest by date)](https://img.shields.io/github/v/release/CodeDead/deadlock-dotnet-sdk)
![Nuget](https://img.shields.io/nuget/v/deadlock-dotnet-sdk)
![GitHub](https://img.shields.io/badge/language-C%23-green)
![GitHub](https://img.shields.io/github/license/CodeDead/deadlock-dotnet-sdk)

deadlock-dotnet-sdk is a simple-to-use SDK for unlocking files in C# / dotnet.

## Usage

Add deadlock-dotnet-sdk to your solution tree using NuGet:
```shell
Install-Package deadlock-dotnet-sdk
```

### Finding the processes that are locking a file

To find all the `FileLocker` objects that are locking a file, you can make use of the `FindLockingProcesses` method:
```c#
string path = @"C:\...\file.txt";
var lockers = DeadLock.FindLockingProcesses(path);
```

You can also run the code asynchronously by calling the `FindLockingProcessesAsync` method`:
```c#
string path = @"C:\...\file.txt";
var lockers = await DeadLock.FindLockingProcessesAsync(path);
```

### Unlocking a file

To unlock a `FileLocker`, you can execute the  `Unlock` method:
```c#
DeadLock.Unlock(locker);
```

You can also run the code asynchronously by running the `UnlockAsync` method:
```c#
DeadLock.UnlockAsync(locker);
```

## Credits

Images by: [RemixIcon](https://remixicon.com/)

## About

This library is maintained by CodeDead. You can find more about us using the following links:
* [Website](https://codedead.com)
* [Twitter](https://twitter.com/C0DEDEAD)
* [Facebook](https://facebook.com/deadlinecodedead)

Copyright © 2022 CodeDead
