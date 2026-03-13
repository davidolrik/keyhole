# Colors

Keyhole colors list output by default — directory prefixes appear in blue. Colors are detected automatically:

| Condition                | Result     |
| ------------------------ | ---------- |
| Default                  | Colors on  |
| `NO_COLOR=1` forwarded   | Colors off |
| `TERM=dumb` forwarded    | Colors off |
| `ssh -t` (PTY allocated) | Colors on  |

## Disabling colors

To disable colors without `-t`:

```sh
ssh -o SetEnv=NO_COLOR=1 alice@keys.example.com list
```

Or add to `~/.ssh/config`:

```ssh-config
Host keys.example.com
    SetEnv NO_COLOR=1
```
