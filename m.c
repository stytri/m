/*
MIT License

Copyright (c) 2024 Tristan Styles

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

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
// :&  $DBG $"* $+:
// :&  $RM $+:
//
// ::CFLAGS  -Wall -Wextra -D__USE_MINGW_ANSI_STDIO=1
//
// ::SMALL-BINARY
// :+      -fmerge-all-constants -ffunction-sections -fdata-sections
// :+      -fno-unwind-tables -fno-asynchronous-unwind-tables
// :+      -Wl,--gc-sections -s
//

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

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

static struct comment const *get_comment(char const *ext) {
#	define COM(COM__cs)  { \
		.n  = sizeof(COM__cs)-1, \
		.cs = (COM__cs) \
	}
	if(is_one_of(ext,
		".c", ".cc", ".c++", ".cpp", ".cxx", ".h", ".h++", ".hpp", ".hxx",
		".d", ".java", ".js", ".cs", ".fs", ".rs", ".go"
	)) {
		static struct comment const com = (struct comment){
			COM("//"), COM("::"), COM(":+"), COM(":&")
		};
		return &com;
	}
	if(is_one_of(ext,
		".asm",
		".l", ".cl", ".ls", ".lisp",
		".scm", ".reb", ".red"
	)) {
		static struct comment const com = (struct comment){
			COM(";"), COM("::"), COM(":+"), COM(":&")
		};
		return &com;
	}
	if(is_one_of(ext,
		"", ".sh", ".rb", ".pl", ".py"
	)) {
		static struct comment const com = (struct comment){
			COM("#"), COM("::"), COM(":+"), COM(":&")
		};
		return &com;
	}
	return NULL;
#	undef COM
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
	size_t         n_commands;
	struct string *command;
};

static size_t read_rules(char const *file, FILE *in, struct comment const *com, struct rule **rules) {
	struct rule   *r = NULL, *p = NULL;
	struct string *c = NULL;
	size_t         n = 0;

	size_t lineno = 1;
	char const *s = read_line(in);
	for(; s && !is_comment(com, s); s = read_line(in), ++lineno)
		;
	for(; s &&  is_comment(com, s); s = read_line(in), ++lineno) {
		for(s += com->comment.n; isspace(*s); s++);
		if(is_continuation(com, s)) {
			if(!p) {
				fprintf(stderr, "%s:%zu no rule\n", file, lineno);
				continue;
			}
			s += com->continuation.n;
			if(*s) for(size_t o = (c->n > 0); isspace(*(s + o)); s++);
			size_t m = strlen(s);
			c->cs    = concatenate(c->cs, c->n, s, m);
			c->n    += m;
			continue;
		}
		if(is_aggregation(com, s)) {
			if(!p) {
				fprintf(stderr, "%s:%zu no rule\n", file, lineno);
				continue;
			}
			for(s += com->aggregation.n; isspace(*s); s++);
			goto append_command;
		}
		if(is_rule(com, s)) {
			for(s += com->rule.n; isspace(*s); s++);
			char const *cs = s;
			while((*s == '_') || (*s == '-') || isalnum(*s)) s++;
			r             = xrealloc(r, sizeof(*r), n + 1);
			p             = &r[n++];
			p->name.n     = s - cs;
			p->name.cs    = duplicate(cs, p->name.n);
			p->command    = NULL;
			p->n_commands = 0;
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

static char const *expand(char const *ct, int argn, char **argv, size_t n_rules, struct rule const *rules, char const *rule, char const *file) {
	size_t rule_len = strlen(rule);
	size_t file_len = strlen(file);
	size_t m        = 0;
	char  *s        = NULL;
	for(char const *cs; (cs = strchr(ct, '$')); ) {
		size_t      u = cs - ct, w;
		char const *cv;
		if(u > 0) {
			s   = concatenate(s, m, ct, u);
			m  += u;
			ct += u;
		}
		ct++;
		bool const quoted = *ct == '"';
		ct += quoted;
		bool const alt = *ct == '+';
		ct += alt;
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
#		define ALTERNATE_CONCATENATE(S,M,T) do { \
			if(quoted) { \
				S  = concatenate(S, M, "\"", 1); \
				M += 1; \
			} \
			char const *ALTERNATE_CONCATENATE__V = get_var(#T, n_rules, rules, T); \
			char const *ALTERNATE_CONCATENATE__T = expand(ALTERNATE_CONCATENATE__V, argn, argv, n_rules, rules, rule, file);\
			size_t      ALTERNATE_CONCATENATE__N = strlen(ALTERNATE_CONCATENATE__T); \
			S  = concatenate(S, M, ALTERNATE_CONCATENATE__T, ALTERNATE_CONCATENATE__N); \
			M += ALTERNATE_CONCATENATE__N; \
			xfree(ALTERNATE_CONCATENATE__T);\
			if(quoted) { \
				S  = concatenate(S, M, "\"", 1); \
				M += 1; \
			} \
		} while(0)
#		define RECURSIVE_CONCATENATE(S,M,T,N) do { \
			if(quoted) { \
				S  = concatenate(S, M, "\"", 1); \
				M += 1; \
			} \
			char const *RECURSIVE_CONCATENATE__T = expand(T, argn, argv, n_rules, rules, rule, file);\
			size_t      RECURSIVE_CONCATENATE__N = strlen(RECURSIVE_CONCATENATE__T); \
			S  = concatenate(S, M, RECURSIVE_CONCATENATE__T, RECURSIVE_CONCATENATE__N); \
			M += RECURSIVE_CONCATENATE__N; \
			xfree(RECURSIVE_CONCATENATE__T);\
			if(quoted) { \
				S  = concatenate(S, M, "\"", 1); \
				M += 1; \
			} \
		} while(0)
		switch(*ct) {
		case ':':
			ct++;
			if(alt) {
				ALTERNATE_CONCATENATE(s, m, M_ALT_RULE);
				continue;
			}
			CONCATENATE(s, m, rule, rule_len);
			continue;
		case '!':
			ct++;
			if(alt) {
				ALTERNATE_CONCATENATE(s, m, M_ALT_FILE);
				continue;
			}
			CONCATENATE(s, m, file, file_len);
			continue;
		case '/':
			ct++;
			if(alt) {
				ALTERNATE_CONCATENATE(s, m, M_ALT_PATH);
				continue;
			}
			cv = get_file_path(file, &w);
			CONCATENATE(s, m, cv, w);
			continue;
		case '^':
			ct++;
			if(alt) {
				ALTERNATE_CONCATENATE(s, m, M_ALT_NAME);
				continue;
			}
			cv = get_file_name(file, &w);
			CONCATENATE(s, m, cv, w);
			continue;
		case '.':
			ct++;
			if(alt) {
				ALTERNATE_CONCATENATE(s, m, M_ALT_EXT);
				continue;
			}
			cv = get_file_extension(file, &w);
			CONCATENATE(s, m, cv, w);
			continue;
		case '*':
			ct++;
			for(int argi = 0; argi < argn; argi++) {
				if(argi > 0) {
					s  = concatenate(s, m, " ", 1);
					m += 1;
				}
				cv = argv[argi];
				w  = strlen(cv);
				CONCATENATE(s, m, cv, w);
			}
			continue;
		case '$':
			ct++;
			CONCATENATE(s, m, "$", 1);
			continue;
		}
		if(isdigit(*ct)) {
			int argi = 0;
			do {
				argi = (argi * 10) + (*ct - '0');
				ct++;
			} while(isdigit(*ct))
				;
			if(argi < argn) {
				cv = argv[argi];
				w  = strlen(cv);
				RECURSIVE_CONCATENATE(s, m, cv, w);
			}
		} else if((*ct == '_') || isalpha(*ct)) {
			cs = ct, u = 0;
			do {
				ct++, u++;
			} while((*ct == '_') || (*ct == '-') || isalnum(*ct))
				;
			cs = duplicate(cs, u);
			cv = get_var(cs, n_rules, rules, NULL);
			if(cv) {
				w = strlen(cv);
				RECURSIVE_CONCATENATE(s, m, cv, w);
			} else if(streq(cs, "CC")) {
#if defined __GNUC__
				CONCATENATE(s, m, "gcc", 3);
#elif defined __clang__
				CONCATENATE(s, m, "clang", 5);
#else
				CONCATENATE(s, m, "cc", 2);
#endif
			} else if(streq(cs, "DBG")) {
#if defined __GNUC__
				CONCATENATE(s, m, "gdb", 3);
#elif defined __clang__
				CONCATENATE(s, m, "lldb", 4);
#endif
			} else if(streq(cs, "RM")) {
#if defined _WIN32
				CONCATENATE(s, m, "del", 3);
#else
				CONCATENATE(s, m, "rm", 2);
#endif
			}
			xfree(cs);
		}
#		undef CONCATENATE_EXE
#		undef RECURSIVE_CONCATENATE
#		undef CONCATENATE
	}
	if(*ct) {
		s = concatenate(s, m, ct, strlen(ct));
	}
	return s;
}

static void version(FILE *out) {
	fputs("m 1.2.3\n", out);
}

static void usage(FILE *out) {
	fprintf(out, "usage: m [OPTION...] FILE [RULE] [ARGUMENTS]...\n");
	fprintf(out, "OPTION:\n");
	fprintf(out, "\t-h, --help         display help\n");
	fprintf(out, "\t-v, --version      display version\n");
	fprintf(out, "\t-r, --rules        display available rules\n");
	fprintf(out, "\t-c, --commands     display commands executed by rules\n");
	fprintf(out, "\t-e, --echo         display commands as they are executed\n");
	fprintf(out, "\t-s, --sigils       define rule sigils, has the arguments:\n");
	fprintf(out, "\t                   COMMENT       - the character sequence of an inline comment\n");
	fprintf(out, "\t                   RULE          - the character sequence indicating a new rule\n");
	fprintf(out, "\t                   CONTINUATION  - the character sequence indicating the continuation of rule command\n");
	fprintf(out, "\t                   AGGREGATION   - the character sequence indicating the start of a new rule command\n");
	fprintf(out, "\t-t, --type         define rule sigils according to argument:\n");
	fprintf(out, "\t                   TYPE          - one of: .c .asm .sh\n");
	fprintf(out, "\n");
	fprintf(out, "if RULE is the single character '-', the first rule is invoked\n");
	return;
}

#ifndef NDEBUG
int main(int argc__actual, char **argv__actual) {
	(void)argc__actual;
	char *argv[] = {
		argv__actual[0],
		"m.c",
		NULL,
	};
	int argc = (sizeof(argv) / sizeof(argv[1])) - 1;
#else
int main(int argc, char **argv) {
#endif
	bool echo = false;
	bool list_rules = false;
	bool list_commands = false;
	struct comment const *com = NULL;

	int argi = 1;
	for(; (argi < argc) && (argv[argi][0] == '-'); argi++) {
		if(is_one_of(argv[argi], "-h", "--help")) {
			version(stdout);
			usage(stdout);
			exit();
		} else if(is_one_of(argv[argi], "-v", "--version")) {
			version(stdout);
			exit();
		} else if(is_one_of(argv[argi], "-r", "--rules")) {
			list_rules = true;
			list_commands = false;
		} else if(is_one_of(argv[argi], "-c", "--commands")) {
			list_rules = list_commands = true;
		} else if(is_one_of(argv[argi], "-s", "--sigils")) {
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
		} else if(is_one_of(argv[argi], "-t", "--type")) {
			if((argc - argi) > 1) {
				com = get_comment(argv[++argi]);
				if(!com) {
					goto print_usage_and_fail;
				}
			} else {
				goto print_usage_and_fail;
			}
		} else if(is_one_of(argv[argi], "-e", "--echo")) {
			echo = true;
		} else {
			goto print_usage_and_fail;
		}
	}
	if(argi >= argc) {
print_usage_and_fail:
		version(stderr);
		usage(stderr);
		fail();
	}

	char const *file = argv[argi++];

	if(!com) {
		char const *ext = get_file_extension(file);
		com = get_comment(ext);
		if(!com) {
			fprintf(stderr, "%s: unknown file type", file);
			fail();
		}
	}

	FILE *in = fopen(file, "r");
	if(!in) {
		perror(file);
		fail();
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
					char const *cs = expand(
						rules[i].command[j].cs,
						argc - argi, &argv[argi],
						n_rules, rules, rules[i].name.cs,
						file
					);
					putchar('\t'), puts(cs);
					xfree(cs);
				}
			} else if(rules[i].name.n > 0) {
				puts(rules[i].name.cs);
			}
		}
	} else {
		char const *rule = (argi < argc) ? argv[argi++] : "-";
		if(streq(rule, "-")) rule = rules[0].name.cs;
		bool found = false;
		for(size_t i = 0; i < n_rules; i++) {
			if(strcmp(rule, rules[i].name.cs) == 0) {
				found = true;
				for(size_t j = 0; j < rules[i].n_commands; j++) {
					char const *cs = expand(
						rules[i].command[j].cs,
						argc - argi, &argv[argi],
						n_rules, rules, rules[i].name.cs,
						file
					);
					if(echo) {
						puts(cs);
					}
					ec = system(cs);
					xfree(cs);
					if(ec != EXIT_SUCCESS) {
						break;
					}
				}
				break;
			}
		}
		if(!found) {
			fprintf(stderr, "%s: rule '%s' undefined\n", file, rule);
		}
	}

	return ec;
}
