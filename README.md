# fileflip

```
Usage: fileflip [PID] [FILE]
```

[![asciicast](https://asciinema.org/a/285433.svg)](https://asciinema.org/a/285433)

## Why Need This
- force rotate logging files if a running program dont support rotate signal(eg: SIGHUP)
- redirect screen output to a text file when you find the command running too long

## TODO
- add test
- command argument for known file descriptor
- auto build
- support for other unix
