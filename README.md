# m

a mini make

Inspired by https://github.com/michaelfm1211/ec

Uses a comment block at the head of the source file to specify how to compile it.

(See the **m** source file for an example of usage.)

The comment type is determined from the file extension (see the function `get_comment` for the list of recognised extensions - edit to add more!), or may be determined by command line options.

## Rule Format

Specifically, **m** parses line comments at the head of the file, and stops parsing at the first non-comment. For each comment it looks for the following character sequences (after skipping any space/tab characters):

`::` Introduces a new rule. The rule name - which is a sequence of alphanumeric, as well as the `_` and `-`, characters - follows. The remainder of the line is the command to be executed.

`:+` Appends the remainder of the line to the current rule command.

`:&` Adds another command to be executed by the rule.

## Variable Expansion

Variables are indicated by the `$` character; unlike make, they are not enclosed in parenthesis.

### expansion modifiers

`"` causes the expansion to be enclosed in quotes.

`+` indicates an alternate form of expansion is to be made.

### expansion types

#### specials

`$:` expands to the name of the rule - the alternate form appends `.exe` on Windows.

`$!` expands to the full file name as passed on the command line - the alternate form replaces the file suffix with `.exe` on Windows.

`$/` expands to the directory path part of the file.

`$^` expands to the name of the file - the alternate form appends `.exe` on Windows.

`$.` expands to the extension part of the file.

`$$` results in a single `$`.

The alternate forms can be configured via the following rule/environment variables:

`M_ALT_RULE` for `$:`

`M_ALT_FILE` for `$!`

`M_ALT_PATH` for `$/`

`M_ALT_NAME` for `$^`

`M_ALT_EXT` for `$.`

#### arguments

A numeric variable name specifies the position index of an argument passed on the command line following the rule name, starting from 0.

`$*` expands all arguments, separating them with spaces. If the quote modifier is given, the arguments are individually quoted.

Expansion is recursive.

#### environment

Starting with `_` or an alphabetic character, and continuing with `-`, `_` and alphanumeric characters.

**m** attempts to obtain the value of the corresponding environment variable; if it fails, it is silently omitted, except in the case of `$CC`, `$DBG`, and `$RM` where it provides a system related default.

Expansion is recursive.

#### rules

Rules can also be used as variable, however, when a rule has multiple commands only the *first* command is expanded.

Rules take precedence over environment variables with the same name.

Expansion is recursive.
