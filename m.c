#include <stdio.h>
static void license(void) {
	puts("MIT License");
	puts("");
	puts("Copyright (c) 2024 Tristan Styles");
	puts("");
	puts("Permission is hereby granted, free of charge, to any person obtaining a copy");
	puts("of this software and associated documentation files (the \"Software\"), to deal");
	puts("in the Software without restriction, including without limitation the rights");
	puts("to use, copy, modify, merge, publish, distribute, sublicense, and/or sell");
	puts("copies of the Software, and to permit persons to whom the Software is");
	puts("furnished to do so, subject to the following conditions:");
	puts("");
	puts("The above copyright notice and this permission notice shall be included in all");
	puts("copies or substantial portions of the Software.");
	puts("");
	puts("THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR");
	puts("IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,");
	puts("FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE");
	puts("AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER");
	puts("LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,");
	puts("OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE");
	puts("SOFTWARE.");
}
//
// Inspired by https://github.com/michaelfm1211/ec
//
// ::compile
// :+  $CC $CFLAGS $SMALL-BINARY
// :+      -DNDEBUG=1 -O3 -o $+^ $"!
//
// ::debug
// :+  $CC $CFLAGS
// :+      -Og -g -o $+: $"!
// :&  $DBG -tui --args $+: $"*
// :&  $RM $+:
//
// ::CFLAGS
// :+      -Wall -Wextra $WINFLAGS
//
// ::windir?WINFLAGS
// :+      -D__USE_MINGW_ANSI_STDIO=1
//
// ::SMALL-BINARY
// :+      -fmerge-all-constants -ffunction-sections -fdata-sections
// :+      -fno-unwind-tables -fno-asynchronous-unwind-tables
// :+      -Wl,--gc-sections -s
//
// ::test
// :+  echo $CC $CFLAGS
// :+      -Og -g -o $FILES $FILES.c
// :&  echo $DBG -tui --args $FILES $"*
// :&  echo $RM $FILES
//
// ::FILES
// :+  file1
// :&  file2
// :&  file3
//
static void usage(FILE *out);
static void readme(void) {
	puts("# m");
	puts("");
	puts("a mini make");
	puts("");
	puts("Inspired by https://github.com/michaelfm1211/ec");
	puts("");
	puts("Uses a comment block in the source file to specify how to compile it.");
	puts("");
	puts("(See the **m** source file for an example of usage.)");
	puts("");
	puts("The comment type is determined from the file extension (see the function `get_comment` for the list of recognised extensions - edit to add more!), or may be determined by command line options.");
	puts("");
	puts("If no extension is given **m** attempts to discover it by opening the file with known extensions; the order of opening can be overridden by the `M_EXT_ORDER` environment variable.");
	puts("");
	puts("## Command Line");
	puts("");
	puts("```");
	usage(stdout);
	puts("```");
	puts("");
	puts("## Rule Format");
	puts("");
	puts("Specifically, **m** first scans for a starting line comment, then parses a block of line comments, and stops parsing at a non-comment. For each comment it looks for the following character sequences (after skipping any space/tab characters):");
	puts("");
	puts("`::` Introduces a new rule. There follows an optional rule condition, and then the rule name. The rule name - which is a sequence of alphanumeric, as well as the `_` and `-`, characters - follows. This is followed by an optional dependency list. The remainder of the line is the command to be executed.");
	puts("");
	puts("`:+` Appends the remainder of the line to the current rule command.");
	puts("");
	puts("`:&` Adds another command to be executed by the rule.");
	puts("");
	puts("A rule condition is either a name or a shell command followed by either `?` or `!`:");
	puts("");
	puts("`?` indicates that the rule is enabled if there is an existing rule or environment variable of the given name, or the execution of the shell command is succesful.");
	puts("");
	puts("`!` indicates that the rule is enabled if there is no existing rule or environment variable of the given name, or the execution of the shell command is unsuccesful.");
	puts("");
	puts("A shell command is a character sequence enclosed by the `(` and `)` characters.");
	puts("");
	puts("A dependency list consists of one or more of: a colon (`:`) and a rule name. Dependency rules are executed first.");
	puts("");
	puts("## Variable Expansion");
	puts("");
	puts("Variables are indicated by the `$` character; unlike make, they are not enclosed in parenthesis.");
	puts("");
	puts("### expansion modifiers");
	puts("");
	puts("`\"` causes the expansion to be enclosed in quotes.");
	puts("");
	puts("`+` indicates an alternate form of expansion is to be made.");
	puts("");
	puts("### expansion types");
	puts("");
	puts("#### specials");
	puts("");
	puts("`$:` expands to the name of the rule - the alternate form appends `.exe` on Windows.");
	puts("");
	puts("`$!` expands to the full file name as passed on the command line - the alternate form replaces the file suffix with `.exe` on Windows.");
	puts("");
	puts("`$/` expands to the directory path part of the file.");
	puts("");
	puts("`$^` expands to the name of the file - the alternate form appends `.exe` on Windows.");
	puts("");
	puts("`$.` expands to the extension part of the file - the alternate form changes to `.exe` on Windows.");
	puts("");
	puts("`$$` results in a single `$`.");
	puts("");
	puts("The alternate forms can be configured via the following rule/environment variables:");
	puts("");
	puts("`M_ALT_RULE` for `$:`");
	puts("");
	puts("`M_ALT_FILE` for `$!`");
	puts("");
	puts("`M_ALT_PATH` for `$/`");
	puts("");
	puts("`M_ALT_NAME` for `$^`");
	puts("");
	puts("`M_ALT_EXT` for `$.`");
	puts("");
	puts("Alternate expansion is recursive.");
	puts("");
	puts("#### arguments");
	puts("");
	puts("A numeric variable name specifies the position index of an argument passed on the command line following the rule name, starting from 0.");
	puts("");
	puts("`$*` expands all arguments, separating them with spaces. If the quote modifier is given, the arguments are individually quoted.");
	puts("");
	puts("Expansion is recursive.");
	puts("");
	puts("#### environment");
	puts("");
	puts("Starting with `_` or an alphabetic character, and continuing with `-`, `_` and alphanumeric characters.");
	puts("");
	puts("**m** attempts to obtain the value of the corresponding environment variable; if it fails, it is silently omitted, except in the case of `$CC`, `$DBG`, and `$RM` where it provides a system related default.");
	puts("");
	puts("Expansion is recursive.");
	puts("");
	puts("#### rules");
	puts("");
	puts("Rules can also be used as variable; when a rule has multiple commands, each command is expanded separately, resulting in multiple command executions.");
	puts("");
	puts("Rules take precedence over environment variables with the same name.");
	puts("");
	puts("The special rule `-` matches any rule name passed on the command line; it should therefore be placed _after_ all other rules that can specified on the command line.");
	puts("");
	puts("Expansion is recursive.");
}

#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

static bool quiet = false;

#define perror(...)\
	(perror)(__VA_ARGS__+0)

#define exit(...)\
	(exit)(__VA_ARGS__+0)

#define fail(...)\
	(exit)(EXIT_FAILURE)

static int is_one_of(char const *cs, char const *ct, ...) {
	va_list val;
	va_start(val, ct);
	while(ct && strcmp(cs, ct)) {
		ct = va_arg(val, char const *);
	}
	va_end(val);
	return ct != NULL;
}
#define is_one_of(is_one_of__cs,...)\
	(is_one_of)((is_one_of__cs),__VA_ARGS__,NULL)

static bool streq(char const *cs, char const *ct) {
	return !strcmp(cs, ct);
}

static bool strneq(char const *cs, char const *ct, size_t n) {
	return !strncmp(cs, ct, n);
}

static void *non_null_pointer(void *p, char const *cs) {
	if(p) return p;
	perror(cs);
	fail();
	return NULL;
}
#define non_null_pointer(non_null_pointer__p,...)\
	(non_null_pointer)((non_null_pointer__p),__VA_ARGS__+0)

static inline void check_allocation_size(size_t z, size_t n) {
	if((SIZE_MAX / z) < n) {
		errno = ENOMEM;
		perror();
		fail();
	}
}

static inline void *xmalloc(size_t z, size_t n) {
	check_allocation_size(z, n);
	return non_null_pointer(malloc(z * n));
}

static inline void *xrealloc(void *p, size_t z, size_t n) {
	check_allocation_size(z, n);
	return non_null_pointer(realloc(p, z * n));
}

static inline char *duplicate(char const *cs, size_t n) {
	char  *s = xmalloc(sizeof(*s), n + 1);
	memcpy(s, cs, n);
	s[n] = '\0';
	return s;
}

static inline char *concatenate(char const *cs, size_t sn, char const *ct, size_t tn) {
	size_t n = sn + tn;
	char  *s = xrealloc((void *)cs, sizeof(*s), n + 1);
	memcpy(s + sn, ct, tn);
	s[n] = '\0';
	return s;
}

static void xfree(void const *p) {
	free((void *)p);
}

static char *read_line(FILE *in) {
	static char  *s = NULL;
	static size_t z = 0;
	for(size_t n = 0;;) {
		int c = fgetc(in);
		if((c != EOF) && (c != '\n')) {
			if(n == z) {
				z = (z + 1) + (z >> 1);
				s = xrealloc(s, sizeof(*s), z + 1);
			}
			s[n++] = c;
			continue;
		}
		if(n > 0) {
			char *t = s;
			while(isspace(*t)) t++, n--;
			while((n > 0) && isspace(t[n - 1])) n--;
			t[n] = '\0';
			return t;
		}
		if(c != EOF) {
			return "";
		}
		return NULL;
	}
}

struct string {
	size_t      n;
	char const *cs;
};

struct comment {
	struct string comment;
	struct string rule;
	struct string continuation;
	struct string aggregation;
};

#define COM(COM__cs)  { \
	.n  = sizeof(COM__cs)-1, \
	.cs = (COM__cs) \
}
static struct comment const c_style_comments = (struct comment){
	COM("//"), COM("::"), COM(":+"), COM(":&")
};
static struct comment const asm_style_comments = (struct comment){
	COM(";" ), COM("::"), COM(":+"), COM(":&")
};
static struct comment const shell_style_comments = (struct comment){
	COM("#" ), COM("::"), COM(":+"), COM(":&")
};
#undef COM

static struct extension {
	char const           *ext;
	struct comment const *com;
}	const extcom[] = {
	{ ".c"   ,     &c_style_comments },
	{ ".cc"  ,     &c_style_comments },
	{ ".c++" ,     &c_style_comments },
	{ ".cpp" ,     &c_style_comments },
	{ ".cxx" ,     &c_style_comments },
	{ ".d"   ,     &c_style_comments },
	{ ".java",     &c_style_comments },
	{ ".js"  ,     &c_style_comments },
	{ ".cs"  ,     &c_style_comments },
	{ ".fs"  ,     &c_style_comments },
	{ ".rs"  ,     &c_style_comments },
	{ ".go"  ,     &c_style_comments },
	{ ".asm" ,   &asm_style_comments },
	{ ".l"   ,   &asm_style_comments },
	{ ".cl"  ,   &asm_style_comments },
	{ ".ls"  ,   &asm_style_comments },
	{ ".lisp",   &asm_style_comments },
	{ ".scm" ,   &asm_style_comments },
	{ ".reb" ,   &asm_style_comments },
	{ ".red" ,   &asm_style_comments },
	{ ".sh"  , &shell_style_comments },
	{ ".rb"  , &shell_style_comments },
	{ ".pl"  , &shell_style_comments },
	{ ".py"  , &shell_style_comments },
	{ ""     , &shell_style_comments },
	{ NULL   ,  NULL                 }
};

static struct comment const *get_comment(char const *ext) {
	struct extension const *p = extcom;
	for(; p->ext && !streq(ext, p->ext); p++)
		;
	return p->com;
}

static int is_comment(struct comment const *com, char const *ln) {
	return strneq(ln, com->comment.cs, com->comment.n);
}

static int is_rule(struct comment const *com, char const *ln) {
	return strneq(ln, com->rule.cs, com->rule.n);
}

static int is_continuation(struct comment const *com, char const *ln) {
	return strneq(ln, com->continuation.cs, com->continuation.n);
}

static int is_aggregation(struct comment const *com, char const *ln) {
	return strneq(ln, com->aggregation.cs, com->aggregation.n);
}

struct rule {
	struct string  name;
	char const    *depends;
	size_t         n_commands;
	struct string *command;
	struct string *first;
};

static char const *get_var(char const *cs, size_t n_rules, struct rule const *rules, char const *cd) {
	char const *ct = NULL;
	for(size_t i = 0; i < n_rules; i++) {
		if(streq(cs, rules[i].name.cs)) {
			if(rules[i].n_commands > 0) {
				ct = rules[i].command[0].cs;
			}
			break;
		}
	}
	if(ct || (ct = getenv(cs))) {
		return ct;
	}
	return cd;
}

static size_t read_rules(char const *file, FILE *in, struct comment const *com, struct rule **rules) {
	struct rule   *r = NULL, *p = NULL;
	struct string *c = NULL;
	size_t         n = 0, m;

	size_t lineno = 1;
	char const *s = read_line(in), *cs;
	for(bool found_rule = false, skip_rule = false; !found_rule; ) {
		for(; s && !is_comment(com, s); s = read_line(in), ++lineno)
			;
		for(; s &&  is_comment(com, s); s = read_line(in), ++lineno) {
			for(s += com->comment.n; isspace(*s); s++);
			if(is_continuation(com, s)) {
				if(skip_rule || !p) continue;
				s += com->continuation.n;
				if(*s) for(size_t o = (c->n > 0); isspace(*(s + o)); s++);
				m = strlen(s);
				c->cs = concatenate(c->cs, c->n, s, m);
				c->n += m;
				continue;
			}
			if(is_aggregation(com, s)) {
				if(skip_rule || !p) continue;
				for(s += com->aggregation.n; isspace(*s); s++);
				goto append_command;
			}
			if(is_rule(com, s)) {
				found_rule = true;
				for(s += com->rule.n; isspace(*s); s++);
				bool system_call = (*s == '(');
				if(system_call) {
					for(cs = s; *s && (*s != ')'); s++);
					if(*s) s++;
				} else {
					for(cs = s; (*s == '_') || (*s == '-') || isalnum(*s); s++);
				}
				m = s - cs;
				cs = duplicate(cs, m);
				skip_rule = false;
				switch(*s) {
				default:
					if(!system_call) break;
					// fall-through
				case '?':
					skip_rule = true;
					// fall-through
				case '!':
					if(system_call) {
						if(system(cs) == 0) skip_rule = !skip_rule;
					} else {
						if(get_var(cs, n, r, NULL)) skip_rule = !skip_rule;
					}
					xfree(cs);
					if(skip_rule) continue;
					if((*s == '?') || (*s == '!')) s++;
					for(cs = s; (*s == '_') || (*s == '-') || isalnum(*s); s++);
					m = s - cs;
					cs = duplicate(cs, m);
				}
				r             = xrealloc(r, sizeof(*r), n + 1);
				p             = &r[n++];
				p->name.n     = m;
				p->name.cs    = cs;
				p->depends    = NULL;
				p->command    = p->first = NULL;
				p->n_commands = 0;
				if(*s == ':') {
					s++;
					for(cs = s; (*s == ':') || (*s == '_') || (*s == '-') || isalnum(*s); s++);
					m = s - cs;
					p->depends = duplicate(cs, m);
				}
				if(*s) s++;
		append_command:
				while(isspace(*s)) s++;
				p->command = xrealloc(p->command, sizeof(*(p->command)), p->n_commands + 1);
				c          = &p->command[p->n_commands++];
				c->n       = strlen(s);
				c->cs      = duplicate(s, c->n);
				continue;
			}
			p = NULL;
			c = NULL;
		}
	}
	if(!ferror(in)) {
		*rules = r;
		return n;
	}

	xfree(r);
	return 0;
}

static char const *get_file_path(char const *file, size_t *len) {
	char const *ct;
	if((ct = strrchr(file, '/'))
#if defined _WIN32
		|| (ct = strrchr(file, '\\'))
#endif
	) {
		if(len) *len = ct - file + 1;
		return file;
	}
	if(len) *len = 0;
	return "";
}
#define get_file_path(get_file_path__file,...)\
	(get_file_path)((get_file_path__file),__VA_ARGS__+0)

static char const *get_file_extension(char const *file, size_t *len) {
	char const *ct = strrchr(file, '.');
	if(ct) {
		if(!strchr(ct, '/')
#if defined _WIN32
			&& !strchr(ct, '\\')
#endif
		) {
			if(len) *len = strlen(ct);
			return ct;
		}
	}
	if(len) *len = 0;
	return "";
}
#define get_file_extension(get_file_extension__file,...)\
	(get_file_extension)((get_file_extension__file),__VA_ARGS__+0)

static char const *get_file_name(char const *file, size_t *len) {
	size_t n = strlen(file), m, u;
	(void)get_file_path(file, &m);
	(void)get_file_extension(file, &u);
	if(len) *len = n - m - u;
	return file + m;
}
#define get_file_name(get_file_name__file,...)\
	(get_file_name)((get_file_name__file),__VA_ARGS__+0)

#if defined _WIN32
#	define M_ALT_RULE  "$:.exe"
#	define M_ALT_FILE  "$/$^.exe"
#	define M_ALT_PATH  "$/"
#	define M_ALT_NAME  "$^.exe"
#	define M_ALT_EXT   ".exe"
#else
#	define M_ALT_RULE  "$:"
#	define M_ALT_FILE  "$!"
#	define M_ALT_PATH  "$/"
#	define M_ALT_NAME  "$^"
#	define M_ALT_EXT   "$."
#endif

struct cslist {
	char          const *cs;
	struct cslist const *next;
};
struct env {
	char                *s;
	bool                 pie;
	int                  argn;
	char               **argv;
	size_t               n_rules;
	struct rule         *rules;
	size_t               rule_len;
	char          const *rule;
	size_t               file_len;
	char          const *file;
	int                (*action)(char const *);
};

static int expander(struct env *e, size_t n, char const *cs, struct cslist const *next, bool is_quoted) {
	if(is_quoted) {
		e->s = concatenate(e->s, n, "\"", 1);
		n++;
	}
	for(int ec = EXIT_SUCCESS;;) {
		if(!cs || !*cs) {
			if(is_quoted) {
				is_quoted = false;
				e->s = concatenate(e->s, n, "\"", 1);
				n++;
			}
			if(next) {
				cs = next->cs;
				next = next->next;
				continue;
			}
			goto done;
		}
		size_t u;
		char const *ct = strchr(cs, '$');
		if(!ct) {
			if(*cs) {
				u    = strlen(cs);
				e->s = concatenate(e->s, n, cs, u);
				n   += u;
				cs  += u;
				continue;
			}
			goto done;
		}
		u = ct - cs;
		if(u > 0) {
			e->s = concatenate(e->s, n, cs, u);
			n   += u;
			cs  += u;
		}
		cs++;
		bool const quoted = *cs == '"';
		cs += quoted;
		bool const alt = *cs == '+';
		cs += alt;
#		define CONCATENATE(S,M,T,N) do { \
			if(quoted) { \
				S  = concatenate(S, M, "\"", 1); \
				M += 1; \
			} \
			S  = concatenate(S, M, T, N); \
			M += N; \
			if(quoted) { \
				S  = concatenate(S, M, "\"", 1); \
				M += 1; \
			} \
		} while(0)
#		define ALTERNATE_CONCATENATE(S,N,T) do { \
			struct cslist ALTERNATE_CONCATENATE__S = { .cs = cs, .next = next }; \
			char const *ALTERNATE_CONCATENATE__T = get_var(#T, e->n_rules, e->rules, T); \
			ec = expander(e, N, ALTERNATE_CONCATENATE__T, &ALTERNATE_CONCATENATE__S, quoted); \
		} while(0)
#		define RECURSIVE_CONCATENATE(S,N,T) do { \
			struct cslist RECURSIVE_CONCATENATE__S = { .cs = cs, .next = next }; \
			ec = expander(e, N, T, &RECURSIVE_CONCATENATE__S, quoted); \
		} while(0)
		int c = *cs;
		switch(c) {
		case ':':
			cs++;
			if(alt) {
				ALTERNATE_CONCATENATE(e->s, n, M_ALT_RULE);
				return ec;
			}
			CONCATENATE(e->s, n, e->rule, e->rule_len);
			continue;
		case '!':
			cs++;
			if(alt) {
				ALTERNATE_CONCATENATE(e->s, n, M_ALT_FILE);
				return ec;
			}
			CONCATENATE(e->s, n, e->file, e->file_len);
			continue;
		case '/':
			cs++;
			if(alt) {
				ALTERNATE_CONCATENATE(e->s, n, M_ALT_PATH);
				return ec;
			}
			ct = get_file_path(e->file, &u);
			CONCATENATE(e->s, n, ct, u);
			continue;
		case '^':
			cs++;
			if(alt) {
				ALTERNATE_CONCATENATE(e->s, n, M_ALT_NAME);
				return ec;
			}
			ct = get_file_name(e->file, &u);
			CONCATENATE(e->s, n, ct, u);
			continue;
		case '.':
			cs++;
			if(alt) {
				ALTERNATE_CONCATENATE(e->s, n, M_ALT_EXT);
				return ec;
			}
			ct = get_file_extension(e->file, &u);
			CONCATENATE(e->s, n, ct, u);
			continue;
		case '*':
			cs++;
			for(int argi = 0; argi < e->argn; argi++) {
				if(argi > 0) {
					e->s = concatenate(e->s, n, " ", 1);
					n += 1;
				}
				ct = e->argv[argi];
				u  = strlen(ct);
				CONCATENATE(e->s, n, ct, u);
			}
			continue;
		case '$':
			cs++;
			CONCATENATE(e->s, n, "$", 1);
			continue;
		}
		if(isdigit(c)) {
			int argi = 0;
			do {
				argi = (argi * 10) + (c - '0');
				cs++;
				c = *cs;
			} while(isdigit(c))
				;
			if(argi < e->argn) {
				ct = e->argv[argi];
				RECURSIVE_CONCATENATE(e->s, n, ct);
				return ec;
			}
			continue;
		}
		if((c == '_') || isalpha(c)) {
			ct = cs;
			do {
				cs++;
				c = *cs;
			} while((c == '_') || (c == '-') || isalnum(c))
				;
			u = cs - ct;
			ct = duplicate(ct, u);
			for(size_t i = 0; i < e->n_rules; i++) {
				if(streq(ct, e->rules[i].name.cs)) {
					xfree(ct);
					if(e->pie || !e->rules[i].first) {
						for(size_t j = 0; j < e->rules[i].n_commands; j++) {
							e->rules[i].first = &e->rules[i].command[j];
							ct = e->rules[i].command[j].cs;
							RECURSIVE_CONCATENATE(e->s, n, ct);
							if(ec != EXIT_SUCCESS) break;
						}
					} else {
						ct = e->rules[i].first->cs;
						RECURSIVE_CONCATENATE(e->s, n, ct);
					}
					return ec;
				}
			}
			char const *cv = getenv(ct);
			if(cv) {
				xfree(ct);
				RECURSIVE_CONCATENATE(e->s, n, cv);
				return ec;
			}
			if(streq(ct, "CC")) {
#if defined __GNUC__
				CONCATENATE(e->s, n, "gcc", 3);
#elif defined __clang__
				CONCATENATE(e->s, n, "clang", 5);
#else
				CONCATENATE(e->s, n, "cc", 2);
#endif
			} else if(streq(ct, "DBG")) {
#if defined __GNUC__
				CONCATENATE(e->s, n, "gdb", 3);
#elif defined __clang__
				CONCATENATE(e->s, n, "lldb", 4);
#endif
			} else if(streq(ct, "RM")) {
#if defined _WIN32
				CONCATENATE(e->s, n, "del", 3);
#else
				CONCATENATE(e->s, n, "rm", 2);
#endif
			}
			xfree(ct);
		}
#		undef RECURSIVE_CONCATENATE
#		undef ALTERNATE_CONCATENATE
#		undef CONCATENATE
#		undef cs
	}
done:
	if(!quiet) {
		puts(e->s);
	}
	return e->action(e->s);
}

static int expand(int (*action)(char const *), bool pie, char const *cs, int argn, char **argv, size_t n_rules, struct rule *rules, char const *rule, char const *file) {
	struct env e = {
		.s        = NULL,
		.pie      = pie,
		.argn     = argn,
		.argv     = argv,
		.n_rules  = n_rules,
		.rules    = rules,
		.rule_len = strlen(rule),
		.rule     = rule,
		.file_len = strlen(file),
		.file     = file,
		.action   = action,
	};
	for(size_t i = 0; i < n_rules; i++) {
		rules[i].first = NULL;
	}
	int ec = expander(&e, 0, cs, NULL, false);
	xfree(e.s);
	return ec;
}

static int execute(bool pie, int argn, char **argv, size_t n_rules, struct rule *rules, char const *rule, char const *file) {
	int ec = EXIT_SUCCESS;
	bool found = false;
	for(size_t i = 0; (ec == EXIT_SUCCESS) && (i < n_rules); i++) {
		if(streq(rule, rules[i].name.cs) || streq("-", rules[i].name.cs)) {
			found = true;
			if(rules[i].depends) {
				char const *cs = rules[i].depends;
				for(char const *cr; (ec == EXIT_SUCCESS); cs = cr + 1) {
					cr = strchr(cs, ':');
					size_t m = cr ? (size_t)(cr - cs) : strlen(cs);
					char const *ct = duplicate(cs, m);
					ec = execute(pie, argn, argv, n_rules, rules, ct, file);
					xfree(ct);
					if(!cr) break;
					if(ec) break;
				}
			}
			for(size_t j = 0;
				(ec == EXIT_SUCCESS) && (j < rules[i].n_commands);
				j++
			) {
				ec = expand(
					system,
					pie,
					rules[i].command[j].cs,
					argn, argv,
					n_rules, rules, rule,
					file
				);
			}
			break;
		}
	}
	if(!found) {
		fprintf(stderr, "%s: rule '%s' undefined\n", file, rule);
	}
	return ec;
}

static int print(char const *cs) {
	putchar('\t');
	puts(cs);
	return EXIT_SUCCESS;
}

static void version(FILE *out) {
	fputs("m 3.1.0\n", out);
}

static void usage(FILE *out) {
	fprintf(out, "usage: m [OPTION...] FILE [RULE] [ARGUMENTS]...\n");
	fprintf(out, "OPTION:\n");
	fprintf(out, "\t-h, --help         display help\n");
	fprintf(out, "\t-v, --version      display version\n");
	fprintf(out, "\t    --license      display license\n");
	fprintf(out, "\t    --readme       display readme\n");
	fprintf(out, "\t-r, --rules        display available rules\n");
	fprintf(out, "\t-c, --commands     display commands executed by rules\n");
	fprintf(out, "\t-q, --quiet        do not display commands as they are executed\n");
	fprintf(out, "\t-1, --single       when expanding multi-command rules,\n");
	fprintf(out, "\t                   only multiply expand the first instance\n");
	fprintf(out, "\t-t, --type         define rule sigils according to argument:\n");
	fprintf(out, "\t                   TYPE          - one of: .c .asm .sh\n");
	fprintf(out, "\t-s, --sigils       define rule sigils, has the arguments:\n");
	fprintf(out, "\t                   COMMENT       - the character sequence of an inline comment\n");
	fprintf(out, "\t                   RULE          - the character sequence indicating a new rule\n");
	fprintf(out, "\t                   CONTINUATION  - the character sequence indicating the continuation of rule command\n");
	fprintf(out, "\t                   AGGREGATION   - the character sequence indicating the start of a new rule command\n");
	fprintf(out, "\n");
	fprintf(out, "if RULE is the single character '-', the first rule is invoked\n");
	return;
}

int main(int argc, char **argv) {
	bool list_rules = false;
	bool list_commands = false;
	struct comment const *com = NULL;
	bool no_fail = false;
	bool pie = true;

	int argi = 1;
	for(; (argi < argc) && (argv[argi][0] == '-'); argi++) {
		if(is_one_of(argv[argi], "-h", "--help")) {
			no_fail = true;
			version(stdout);
			usage(stdout);
		} else if(is_one_of(argv[argi], "-v", "--version")) {
			no_fail = true;
			version(stdout);
		} else if(is_one_of(argv[argi], "--license")) {
			no_fail = true;
			license();
		} else if(is_one_of(argv[argi], "--readme")) {
			no_fail = true;
			readme();
		} else if(is_one_of(argv[argi], "-r", "--rules")) {
			no_fail = true;
			list_rules = true;
			list_commands = false;
			quiet = true;
		} else if(is_one_of(argv[argi], "-c", "--commands")) {
			no_fail = true;
			list_rules = list_commands = true;
			quiet = true;
		} else if(is_one_of(argv[argi], "-1", "--single")) {
			pie = false;
		} else if(is_one_of(argv[argi], "-t", "--type")) {
			no_fail = false;
			if((argc - argi) > 1) {
				com = get_comment(argv[++argi]);
				if(!com) {
					goto print_usage_and_fail;
				}
			} else {
				goto print_usage_and_fail;
			}
		} else if(is_one_of(argv[argi], "-q", "--quiet")) {
			quiet = true;
		} else if(is_one_of(argv[argi], "-s", "--sigils")) {
			no_fail = false;
			static struct comment ucom;
			if((argc - argi) > 4) {
				ucom.comment.cs      = argv[++argi];
				ucom.comment.n       = strlen(ucom.comment.cs);
				ucom.rule.cs         = argv[++argi];
				ucom.rule.n          = strlen(ucom.rule.cs);
				ucom.continuation.cs = argv[++argi];
				ucom.continuation.n  = strlen(ucom.continuation.cs);
				ucom.aggregation.cs  = argv[++argi];
				ucom.aggregation.n   = strlen(ucom.aggregation.cs);
				com = &ucom;
			} else {
				goto print_usage_and_fail;
			}
		} else {
			no_fail = false;
			goto print_usage_and_fail;
		}
	}
	if(argi >= argc) {
		if(no_fail) {
			return EXIT_SUCCESS;
		}
print_usage_and_fail:
		version(stderr);
		usage(stderr);
		fail();
	}

	char const *file = argv[argi++];

	FILE *in = fopen(file, "r");
	if(!in) {
		struct extension const *p = extcom;
		size_t           const  o = strlen(file);
		size_t                  w = 0;
		size_t                  z = 0;
		for(; p->ext; p++) {
			size_t n = strlen(p->ext);
			if(n > z) {
				z = n;
			}
			w += n;
		}
		char *ext_order = getenv("M_EXT_ORDER");
		if(!ext_order) {
			ext_order = xmalloc(sizeof(*ext_order), w + 1);
			for(w = 0, p = extcom; p->ext; p++) {
				size_t n = strlen(p->ext);
				strcpy(ext_order + w, p->ext);
				w += n;
			}
		}
		char *file_ext = xmalloc(sizeof(*file_ext), o + z + 1);
		strcpy(file_ext, file);
		for(char const *ext, *ct = ext_order; (ext = ct); ) {
			ct = strchr(ext + 1, '.');
			if(ct) {
				size_t n = ct - ext;
				strncpy(file_ext + o, ext, n);
				file_ext[o + n] = '\0';
			} else {
				strcpy(file_ext + o, ext);
			}
			in = fopen(file_ext, "r");
			if(in) {
				file = file_ext;
				com = p->com;
				break;
			}
		}
	}
	if(!in) {
		perror(file);
		fail();
	}

	if(!com) {
		char const *ext = get_file_extension(file);
		com = get_comment(ext);
		if(!com) {
			fprintf(stderr, "%s: unknown file type", file);
			fail();
		}
	}

	struct rule *rules   = NULL;
	size_t       n_rules = read_rules(file, in, com, &rules);
	if(!n_rules) {
		if(errno == 0) {
			fprintf(stderr, "%s: no rules found\n", file);
		} else {
			perror(file);
		}
		fail();
	}

	fclose(in);

	int ec = EXIT_SUCCESS;

	if(list_rules) {
		for(size_t i = 0; i < n_rules; i++) {
			if(list_commands) {
				if(rules[i].name.n > 0) {
					fputs(rules[i].name.cs, stdout), puts(":");
				}
				for(size_t j = 0; j < rules[i].n_commands; j++) {
					(void)expand(
						print,
						pie,
						rules[i].command[j].cs,
						argc - argi, &argv[argi],
						n_rules, rules, rules[i].name.cs,
						file
					);
				}
			} else if(rules[i].name.n > 0) {
				puts(rules[i].name.cs);
			}
		}
	} else {
		char const *rule = (argi < argc) ? argv[argi++] : "-";
		if(streq(rule, "-")) rule = rules[0].name.cs;
		ec = execute(pie, argc - argi, &argv[argi], n_rules, rules, rule, file);
	}

	return ec;
}
