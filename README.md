# m

a mini make

Inspired by https://github.com/michaelfm1211/ec

Uses a comment block in the source file to specify how to compile it.

(See the **m** source file for an example of usage.)

The comment type is determined from the file extension (see the function `get_comment` for the list of recognised extensions - edit to add more!), or may be determined by command line options.

If no extension is given **m** attempts to discover it by opening the file with known extensions; the order of opening can be overridden by the `M_EXT_ORDER` environment variable.

## Rule Format

Specifically, **m** first scans for a starting line comment, then parses a block of line comments, and stops parsing at a non-comment. For each comment it looks for the following character sequences (after skipping any space/tab characters):

`::` Introduces a new rule. There follows an optional rule condition, and then the rule name. The rule name - which is a sequence of alphanumeric, as well as the `_` and `-`, characters - follows. This is followed by an optional dependency list. The remainder of the line is the command to be executed.

`:+` Appends the remainder of the line to the current rule command.

`:&` Adds another command to be executed by the rule.

A rule condition is either a name or a shell command followed by either `?` or `!`:

`?` indicates that the rule is enabled if there is an existing rule or environment variable of the given name, or the execution of the shell command is succesful.

`!` indicates that the rule is enabled if there is no existing rule or environment variable of the given name, or the execution of the shell command is unsuccesful.

A shell command is a character sequence enclosed by the `(` and `)` characters.

A dependency list consists of one or more of: a colon (`:`) and a rule name. Dependency rules are executed first.

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

`$.` expands to the extension part of the file - the alternate form changes to `.exe` on Windows.

`$$` results in a single `$`.

The alternate forms can be configured via the following rule/environment variables:

`M_ALT_RULE` for `$:`

`M_ALT_FILE` for `$!`

`M_ALT_PATH` for `$/`

`M_ALT_NAME` for `$^`

`M_ALT_EXT` for `$.`

Alternate expansion is recursive.

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

The special rule `-` matches any rule name passed on the command line; it should therefore be placed _after_ all other rules that can specified on the command line.

Expansion is recursive.
