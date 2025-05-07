# mysh – A Simple Unix Shell

A minimal Unix shell implemented in C.

## Features
- Built-in commands: `cd`, `exit`, `bye`, `bgjobs`, `kill`, `mysh`
- Background job support (e.g., `sleep 5 &`)
- I/O redirection with `<` and `>`
- Command piping with `|`
- Nested script execution (`mysh script.mysh`)

## Usage
```bash
./mysh
mysh~~> echo Hello > file.txt
mysh~~> cat < file.txt | sort
Hello
