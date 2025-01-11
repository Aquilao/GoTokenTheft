# GoTokenTheft

Go 编写的 Token 窃取工具，用于后渗透时在目标机器上使用不同的用户权限来执行程序和命令

> [!IMPORTANT]
>
> Token 窃取的前提是需要启用 `SeDebugPrivilege`，在大多数后渗透场景下是 `NT AUTHORITY\SYSTEM` 权限或者 `bypass UAC`之后的人类用户权限，比如`Administrator`



## 编译

Windows 下编译

```cmd
go build -o GoTokenTheft.exe main.go
```

跨平台编译

```bash
GOOS=windows GOARCH=386 CC="i686-w64-mingw32-gcc" go build -o GoTokenTheft.exe main.go
```



## 使用

### 快速上手

Usage:
```
GoTokenTheft.exe -p <pid> -c <command>
```

e.g.
```
GoTokenTheft.exe -p 114514 -c cmd.exe
```



### 其他用法

查看系统内存在的所有`token`信息，包括权限和使用它的进程 pid，在实战场景下方便快速定位需要的`token`

```
GoTokenTheft.exe -t
```

查看系统内存在的所有进程信息，包括 pid 和进程名

```
GoTokenTheft.exe -p
```

查看帮助

```
GoTokenTheft.exe -h
```

