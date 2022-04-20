# deadlock-dotnet-sdk

![GitHub release (latest by date)](https://img.shields.io/github/v/release/CodeDead/deadlock-dotnet-sdk)
![Nuget](https://img.shields.io/nuget/v/deadlock-dotnet-sdk)
![GitHub](https://img.shields.io/badge/language-C%23-green)
![GitHub](https://img.shields.io/github/license/CodeDead/deadlock-dotnet-sdk)

deadlock-dotnet-sdk is a simple-to-use SDK for unlocking files in C# / dotnet on Windows based operating systems.

## Usage

Add deadlock-dotnet-sdk to your solution tree using [NuGet](https://www.nuget.org/packages/deadlock-dotnet-sdk/):
```shell
Install-Package deadlock-dotnet-sdk
```

You can initialize a new `DeadLock` helper object like so:
```c#
DeadLock deadLock = new DeadLock();
```

In addition, if you would like to rethrow inner exceptions, you can change the `RethrowExceptions` property when declaring a new `DeadLock` object:
```c#
DeadLock deadLock = new DeadLock(`true` | `false`);
```

You can also change the property dynamically:
```c#
deadlock.RethrowExceptions = `true` | `false`
```

### Finding the processes that are locking a file

To find all the `FileLocker` objects that are locking a file, you can make use of the `FindLockingProcesses` method:
```c#
string path = @"C:\...\file.txt";
List<FileLocker> lockers = DeadLock.FindLockingProcesses(path);
```

You can also run the code asynchronously by calling the `FindLockingProcessesAsync` method`:
```c#
string path = @"C:\...\file.txt";
List<FileLocker> lockers = await DeadLock.FindLockingProcessesAsync(path);
```

To find the `Process` objects that are locking one or more files, you can invoke the `FindLockingProcesses` (or `FindLockingProcessesAsync`) method with multiple `path` parameters:
```c#
List<FileLocker> fileLockers = FindLockingProcesses("a", "c", "c");
```

### Unlocking a file

To unlock a `FileLocker`, you can execute the  `Unlock` method:
```c#
DeadLock.Unlock(locker);
```

You can also run the code asynchronously by running the `UnlockAsync` method:
```c#
await DeadLock.UnlockAsync(locker);
```

To unlock more than one `FileLocker` object, you can invoke the `Unlock` (or `UnlockAsync`) method with multiple `FileLocker` parameters:
```c#
Unlock(fileLockerA, fileLockerB, fileLockerC);
```

Alternatively, if you only want to unlock a file and you are not interested in using the `FileLocker` objects, you can do so by providing any of the `Unlock` or `UnlockAsync` methods with one or more `string` variables that represent the path or paths of the file(s) that should be unlocked:
```c#
// Unlock a single path
string path = @"C:\...\file.txt"; 
Unlock(path);

// Unlock multiple files
Unlock(path1, path2, path3);

// Asynchronously unlock one or more files
await UnlockAsync(path);
await UnlockAsync(path1, path2, path3);
```

### `FileLocker`

The `FileLocker` object contains a `List` of `System.Diagnostics.Process` objects that are locking a file.
You can retrieve the `List` of `Process` objects by retrieving the respective property:
```c#
List<Process> processes = fileLocker.Lockers;
```

To retrieve the path of the file that the `Process` objects are locking, you can make use of the `Path` property:
```c#
string path = fileLocker.Path;
```

### Error handling

deadlock-dotnet-sdk has three specific `Exception` types that might occur when trying to find the `Process` objects that are locking a file.

* `RegisterResourceException`
* `RmListException`
* `StartSessionException`

In case you want more detailed error messages, it is recommended that you call the `Marshal.GetLastWin32Error` method as soon as one of these `Exception` types occur:  
https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getlastwin32error?view=net-6.0

#### `RegisterResourceException`

This error occurs when the system goes out of memory, when a specific time-out occurs or if an invalid handle is detected. You can find more information about this exception here:  
https://docs.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmregisterresources#return-value

#### `RmListException`

This error occurs when the system goes out of memory, when a specific time-out occurs or if an invalid handle is detected. You can find more information about this exception here:  
https://docs.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmgetlist#return-value

#### `StartSessionException`

This error occurs when the system goes out of memory, when a specific time-out occurs or if an invalid handle is detected. You can find more information about this exception here:  
https://docs.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmstartsession#return-value

## Credits

* [RemixIcon](https://remixicon.com/)
* [dotnet](https://dotnet.microsoft.com/en-us/)

## About

This library is maintained by CodeDead. You can find more about us using the following links:
* [Website](https://codedead.com)
* [Twitter](https://twitter.com/C0DEDEAD)
* [Facebook](https://facebook.com/deadlinecodedead)

Copyright © 2022 CodeDead
