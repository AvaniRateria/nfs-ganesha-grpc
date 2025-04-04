/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* ----------------------------------------------------------------------------
 * Copyright CEA/DAM/DIF  (2007)
 * contributeur : Thomas LEIBOVICI  thomas.leibovici@cea.fr
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 * ---------------------------------------
 */

%{

#pragma GCC diagnostic ignored "-Wunused-value"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-function"

#include "config.h"
#include "config_parsing.h"
#include "conf_url.h"
#include "analyse.h"
#include "abstract_mem.h"
#include "conf_yacc.h"
#include "abstract_atomic.h"

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <libgen.h>
#include <dirent.h>
#include <fnmatch.h>
#include "log.h"
#include "common_utils.h"

#if HAVE_STRING_H
#   include <string.h>
#endif

/* Our versions of parser macros */

#define YY_USER_INIT \
do { \
	BEGIN YY_INIT; \
} while (0);

#define YY_USER_ACTION \
	yylloc->first_line = yylloc->last_line = yylineno; \
	yylloc->first_column = yylloc->last_column = yycolumn + yyleng -1; \
	yycolumn += yyleng; \
	yylloc->filename = stp->current_file;

#ifdef _DEBUG_PARSING
#define DEBUG_LEX   printf
#else
#define DEBUG_LEX(...) (void)0
#endif

#define BS_FLAG_NONE  0
#define BS_FLAG_URL   1

struct bufstack {
	struct bufstack *prev;
	YY_BUFFER_STATE bs;
	int lineno;
	char *filename;
	FILE *f;
	char *fbuf;
	uint32_t flags;
};

static char *filter_string(char *src, int esc);
static int new_file(char *filename, struct parser_state *st);
static int process_dir(char *d_name, struct parser_state *st);
static int fetch_url(char *name_tok, struct parser_state *st);
static int pop_file(struct parser_state *st);

%}

%option nounput
%option yylineno
%option reentrant
%option bison-bridge
%option bison-locations
%option extra-type="struct parser_state *"

SPACE        [ \t\r\f]
NL           [\n]
EQUALS       "="
COMMA        ","
SEMI         ";"
LCURLY       "\{"
RCURLY       "\}"
MINUS        "\-"
TWIDDLE      "\~"
SPLAT        "\*"
HUH          "\?"
BANG         "\!"
DOT          "\."
AT           "@"

CIDR         \/[1-9][0-9]{0,1}
V4OCTET      [0-9]{1,3}
IPV4ADDR     {V4OCTET}{DOT}{V4OCTET}{DOT}{V4OCTET}{DOT}{V4OCTET}
H16          [0-9A-Fa-f]{1,4}
LS32         {H16}:{H16}|{IPV4ADDR}
IPV6ADDR     ({H16}:){6}{LS32}|::({H16}:){5}{LS32}|({H16})?::({H16}:){4}{LS32}|(({H16}:){0,1}{H16})?::({H16}:){3}{LS32}|(({H16}:){0,2}{H16})?::({H16}:){2}{LS32}|(({H16}:){0,3}{H16})?::{H16}:{LS32}|(({H16}:){0,4}{H16})?::{LS32}|(({H16}:){0,5}{H16})?::{H16}|(({H16}:){0,6}{H16})?::

SQUOTE       \'[^\']*\'
DQUOTE       \"(\\.|[^\"])*\"
YES          [Yy][Ee][Ss]
TRUE         [Tt][Rr][Uu][Ee]
ON           [Oo][Nn]
NO           [Nn][Oo]
FALSE        [Ff][Aa][Ll][Ss][Ee]
OFF          [Oo][Ff][Ff]
OCTNUM       0[0-7][0-7]*
HEXNUM       0[xX][0-9a-fA-F]+
DECNUM       (0|[1-9][0-9]*)
NINEP        9[pP]

INCLPATH     \/?([a-zA-Z0-9\-\.\_])+(\/[a-zA-Z0-9\-\.\_]+)*
PATHNAME     \/([a-zA-Z0-9\-\.\_]+\/?)?
LONGPATH     (\/?[a-zA-Z0-9\-\.\_]+(\/[a-zA-Z0-9\-\.\_]+)+)\/?
TOKEN_CHARS  [a-zA-Z_\?][a-zA-Z0-9\._\-]*
DIR_PATH  \/?([a-zA-Z0-9\-\.\_])+(\/[a-zA-Z0-9\-\.\_\*]+)*\/?

WC           [a-zA-Z0-9\._\-]
WR           \[{BANG}?({WC})+\]
WP           ({WR}|{SPLAT}|{HUH})
WILDCARD     ({WC}*{WP})+{WC}*

COMMENTEXT	 #.*$
ID_CHARS [a-zA-Z_][a-zA-Z0-9_\-]*
NETGROUP_CHARS [a-zA-Z_][a-zA-Z0-9_.\-]*

/* URL types, e.g., (rados|http|ftp) */
URLTYPES     (rados)
INCLUDE_URL  {URLTYPES}:\/\/[a-zA-Z0-9\-\.\_&=\/]+

/* INCLUDE state is used for picking the name of the include file */
%START YY_INIT DEFINITION TERM INCLUDE URL INCL_DIR

%%
%{
	struct parser_state *stp = yyextra;
%}

<YY_INIT>"%include" { /* include file start */
	DEBUG_LEX("INCLUDE\n");
	BEGIN INCLUDE;
	/* not a token, return nothing */
}

<INCLUDE>{INCLPATH} {

	{
		int c;

		DEBUG_LEX("Calling new_file with unquoted %s\n", yytext);
		c = new_file(yytext, stp);
		if (c == ENOMEM)
			yyterminate();
		BEGIN YY_INIT;
		DEBUG_LEX("done new file\n");
	}
}

<INCLUDE>\"{INCLPATH}\" {
	{
		int c;

		DEBUG_LEX("Calling new_file with quoted %s\n", yytext);
		c = new_file(yytext, stp);
		if (c == ENOMEM)
			yyterminate();
		BEGIN YY_INIT;
		DEBUG_LEX("done new file\n");
	}
}

<YY_INIT>"%dir" { /* include file start */
        DEBUG_LEX("INCL_DIR\n");
        BEGIN INCL_DIR;
        /* not a token, return nothing */
}

<INCL_DIR>{DIR_PATH} {
        {
                int rc;

                DEBUG_LEX("Calling process_dir with unquoted %s\n", yytext);
                rc = process_dir(yytext, stp);
                if (rc) {
                        yyterminate();
		}
                BEGIN YY_INIT;
                DEBUG_LEX("done process_dir\n");
        }
}

<INCL_DIR>\"{DIR_PATH}\" {
        {
                int rc;

                DEBUG_LEX("Calling process_dir with unquoted %s\n", yytext);
                rc = process_dir(yytext, stp);
                if (rc) {
                        yyterminate();
		}
                BEGIN YY_INIT;
                DEBUG_LEX("done process_dir\n");
        }
}

<YY_INIT>"%url" { /* URL include file start */
	DEBUG_LEX("URL\n");
	BEGIN URL;
	/* not a token, return nothing */
}

<URL>{INCLUDE_URL} {

	{
		int c;

		DEBUG_LEX("Calling fetch_url with unquoted %s\n", yytext);
		c = fetch_url(yytext, stp);
		if (c == ENOMEM)
			yyterminate();
		BEGIN YY_INIT;
		DEBUG_LEX("done fetch url\n");
	}
}

<URL>\"{INCLUDE_URL}\" {
	{
		int c;

		DEBUG_LEX("Calling fetch_url with quoted %s\n", yytext);
		c = fetch_url(yytext, stp);
		if (c == ENOMEM)
			yyterminate();
		BEGIN YY_INIT;
		DEBUG_LEX("done fetch url\n");
	}
}

<<EOF>> { /* end of included file */
	DEBUG_LEX("<EOF>\n");
	if (pop_file(stp) == 0)
		yyterminate();
}

   /* Initial State.  We start with a block identifier */

<YY_INIT>{ID_CHARS} { /* first block */
	/* identifier */
	DEBUG_LEX("[block:%s]\n",yytext);
	yylval->token = save_token(yytext, false, false, stp);
	BEGIN DEFINITION;
	return IDENTIFIER;
}

<DEFINITION>{ID_CHARS} {
	DEBUG_LEX("[id:%s",yytext);
	yylval->token = save_token(yytext, false, false, stp);
	return IDENTIFIER;
}

{EQUALS} {
	DEBUG_LEX(" EQUALS ");
	BEGIN TERM;
	return EQUAL_OP;
}

{LCURLY} {
	DEBUG_LEX("BEGIN_BLOCK\n");
	BEGIN DEFINITION;
	stp->block_depth++;
	return LCURLY_OP;
}

{RCURLY}     {   /* end of block */
	DEBUG_LEX("END_BLOCK\n");
	stp->block_depth --;
	if (stp->block_depth <= 0)
		BEGIN YY_INIT;
	return RCURLY_OP;
}

{COMMA}  { /* another terminal to follow ',' */
	DEBUG_LEX(" ',' ");
	return COMMA_OP;
}

   /* End of statement */

{SEMI}  { /* end of statement */
	DEBUG_LEX("]\n");
	BEGIN DEFINITION;
	return SEMI_OP;
}


   /* Double Quote, allows char escaping */

<TERM>{DQUOTE}  {  /* start of a double quote string */
	DEBUG_LEX("quote value:<%s>", yytext);
	yylval->token = save_token(yytext, true, true, stp);
	return DQUOTE;
}

   /* Single Quote, single line with no escaping */

<TERM>{SQUOTE}   { /* start of a single quote string */
	DEBUG_LEX("lit value:<%s>", yytext);
	yylval->token = save_token(yytext, true, false, stp);
	return SQUOTE;
}

<TERM>{YES}|{TRUE}|{ON}  { /* a boolean TRUE */
	DEBUG_LEX("boolean TRUE:%s", yytext);
	yylval->token = save_token(yytext, false, false, stp);
	return TOK_TRUE;
}

<TERM>{NO}|{FALSE}|{OFF}  { /* a boolean FALSE */
	DEBUG_LEX("boolean FALSE:%s", yytext);
	yylval->token = save_token(yytext, false, false, stp);
	return TOK_FALSE;
}

<TERM>{MINUS}|{TWIDDLE} { /* an arithmetic op */
	DEBUG_LEX(" arith op:%s", yytext);
	yylval->token = save_token(yytext, false, false, stp);
	return TOK_ARITH_OP;
}

<TERM>{NINEP}  { /* "9P" is here to take precedence over numbers, this is a special */
	DEBUG_LEX("token value:%s",yytext);
	yylval->token = save_token(yytext, false, false, stp);
	return TOKEN;
}

<TERM>({OCTNUM}|{DECNUM}|{HEXNUM}){DOT}({OCTNUM}|{DECNUM}|{HEXNUM}) { /* an FSID */
	DEBUG_LEX(" FSID :%s", yytext);
	yylval->token = save_token(yytext, false, false, stp);
	return TOK_FSID;
}

<TERM>{OCTNUM}  { /* an octal number */
	DEBUG_LEX(" octal number:%s", yytext);
	yylval->token = save_token(yytext, false, false, stp);
	return TOK_OCTNUM;
}

<TERM>{HEXNUM}  { /* a hexadecimal number */
	DEBUG_LEX(" hex number:%s", yytext);
	yylval->token = save_token(yytext, false, false, stp);
	return TOK_HEXNUM;
}

<TERM>{DECNUM}  { /* a decimal number */
	DEBUG_LEX(" dec number:%s", yytext);
	yylval->token = save_token(yytext, false, false, stp);
	return TOK_DECNUM;
}

<TERM>{SPLAT}|(0{DOT}0{DOT}0{DOT}0)  { /* v4 address wildcard, ganesha only, not IETF */
	DEBUG_LEX(" V4 any:%s", yytext);
	yylval->token = save_token(yytext, false, false, stp);
	return TOK_V4_ANY;
}

<TERM>{IPV4ADDR}{CIDR}?  { /* V4 CIDR */
	DEBUG_LEX(" IPv4 :%s", yytext);
	yylval->token = save_token(yytext, false, false, stp);
	if (index(yylval->token, '/') == NULL)
		return TOK_V4ADDR;
	else
		return TOK_V4CIDR;
}

   /* Mere mortals are not supposed to grok the pattern for IPV6ADDR. */
   /* I got it from the Flex manual. */

<TERM>{IPV6ADDR}{CIDR}?  { /* V6 CIDR */
	DEBUG_LEX(" IPv6 :%s", yytext);
	yylval->token = save_token(yytext, false, false, stp);
	if (index(yylval->token, '/') == NULL)
		return TOK_V6ADDR;
	else
		return TOK_V6CIDR;
}

<TERM>{AT}{NETGROUP_CHARS} { /* a netgroup used for clients */
	DEBUG_LEX(" netgroup :%s", yytext);
	yylval->token = save_token(yytext, false, false, stp);
	return TOK_NETGROUP;
}

   /* Last resort terminals. PATHNAME is here because it can confuse */
   /* with a CIDR (precedence) and */
   /* TOKEN_CHARS gobbles anything other than white and ";" */

<TERM>{PATHNAME}|{LONGPATH}  { /* a POSIX pathname */
	DEBUG_LEX("pathname:%s", yytext);
	yylval->token = save_token(yytext, false, false, stp);
	return TOK_PATH;
}

<TERM>{TOKEN_CHARS}  { /* start of a number or label/tag */
	DEBUG_LEX("token value:%s",yytext);
	yylval->token = save_token(yytext, false, false, stp);
	return TOKEN;
}

<TERM>{WILDCARD}  { /* start of a number or label/tag as glob(7) string */
	DEBUG_LEX("token value:%s",yytext);
	yylval->token = save_token(yytext, false, false, stp);
	return REGEX_TOKEN;
}

   /* Skip over stuff we don't send upstairs */

{COMMENTEXT}  ;/* ignore */
{SPACE}        ;/* ignore */
{NL}           ;/* ignore */

   /* Unrecognized chars.  Must do better... */

. { /* ERROR: out of character character */
	DEBUG_LEX("unexpected stuff (%s)\n", yytext);
	config_parse_error(yylloc, stp,
		"Unexpected character (%s)", yytext);
	stp->err_type->scan = true;
	yylval->token = save_token(yytext, false, false, stp); /* for error rpt */
	return _ERROR_;
}

%%

int ganeshun_yywrap(void *yyscanner){
    return 1;
}

/*
 * This value represents a unique value for _this_ config_root. By tagging
 * each root with a value, we can propagate that value down to the structures
 * that this parsed tree touches. Then, later we can remove structures that
 * should no longer be present by looking to see if their generation number
 * predates this one.
 */
static uint64_t config_generation;

int ganeshun_yy_init_parser(char *srcfile, struct parser_state *st)
{
	FILE *in_file;
	void *yyscanner = st->scanner;
	/* reentrant scanner macro magic requires this... */
	struct yyguts_t * yyg = (struct yyguts_t*)yyscanner;
	struct file_list *flist;
	struct config_root *confroot;
	YY_BUFFER_STATE inbuf;
	int rc = ENOMEM;

	confroot = gsh_calloc(1, sizeof(struct config_root));

	glist_init(&confroot->root.node);
	glist_init(&confroot->root.u.nterm.sub_nodes);
	confroot->root.type = TYPE_ROOT;
	confroot->generation = atomic_inc_uint64_t(&config_generation);
	st->root_node = confroot;
	st->root_node->token_tree_initialized = false;
	ganeshun_yylex_init_extra(st, &st->scanner);
	rc = new_file(srcfile, st);
	if (rc == 0)
		confroot->root.filename = gsh_strdup(srcfile);
	return rc;
}

void ganeshun_yy_cleanup_parser(struct parser_state *st)
{
	int rc;

	if (st->curbs != NULL) {
		st->err_type->parse = true;
		while(pop_file(st) != 0);
	}
	ganeshun_yylex_destroy(st->scanner);
}

static int is_pattern(const char *str)
{
	if (strchr(str, '*') != NULL ||
		strchr(str, '?') != NULL ||
		strchr(str, '[') != NULL)
	return 1;

	return 0;
}

static int process_dir(char *d_name, struct parser_state *st)
{
	DIR *d;
	struct dirent *dir;
	void *yyscanner = st->scanner;
	struct yyguts_t * yyg = (struct yyguts_t*)yyscanner;
	char fname[MAXPATHLEN], dname[MAXPATHLEN], *tmp_dpath = NULL;
	char *pattern = NULL , *laststr = NULL, *dir_path = NULL;
	int rc = 0, dir_strlen;

	dir_strlen = strlen(d_name);
	if (dir_strlen > MAXPATHLEN)
	{
		config_parse_error(yylloc, st,
			"Error: Directory path length is > %d",
                         MAXPATHLEN);
		return 1;
	}

	if (*d_name == '\"') {
		strlcpy(dname, d_name + 1 , dir_strlen-1);
	} else {
		/* strlcpy copies n-1 char, so +1 */
		strlcpy(dname, d_name, dir_strlen+1);
	}

	DEBUG_LEX("Processing directory : %s\n", dname);

	/* check last string in path is pattern or not */
	tmp_dpath = gsh_strdupa(dname);
	laststr = gsh_strdup(basename(tmp_dpath));
	if (is_pattern(laststr))
	{
		pattern = laststr;
		dir_path = gsh_strdup(dirname(tmp_dpath));
	} else {
		dir_path = gsh_strdup(tmp_dpath);
	}

	DEBUG_LEX("Processing directory : %s pattern : \"%s\" \n",
						dir_path, pattern);

	d = opendir(dir_path);
	if (d)
	{
		while ((dir = readdir(d)) != NULL)
		{
			if (strlen(dir->d_name) + dir_strlen + 1 > MAXPATHLEN)
			{
				DEBUG_LEX("Warning: Path(%s/%s) length is > %d, \
						ignored", dir_path, dir->d_name,
						MAXPATHLEN);
				config_parse_error(yylloc, st,
					"Warning: Path(%s/%s) length is > %d, \
					ignored", dir_path, dir->d_name,
					MAXPATHLEN);
				continue;
			}

			if (dir->d_type != DT_REG ||
				strcmp(dir->d_name, ".") == 0 ||
				strcmp(dir->d_name, "..") == 0)
				continue;

			if (pattern == NULL ||
				fnmatch(pattern, dir->d_name, 0) == 0)
			{
				sprintf(fname, "%s/%s", dir_path, dir->d_name);
				DEBUG_LEX("Processing File : %s \n", fname);

				rc = new_file(fname, st);
				if (rc == ENOMEM)
				{
					DEBUG_LEX("Error: %s", strerror(rc));
					config_parse_error(yylloc, st,
						"Error:  %s", strerror(rc));
					rc = 1;
					goto errout;
				}
			}
		}
		closedir(d);
		goto out;
	} else {
		rc = errno;
		DEBUG_LEX("opendir() failed :%s ", strerror(rc));
		config_parse_error(yylloc, st,
			"opendir(%s) failed. Error: %s, ignored",
			dir_path, strerror(rc));
		goto out;
	}

errout:
	closedir(d);
out:
	gsh_free(dir_path);
	gsh_free(pattern);
	return rc;
}

static int new_file(char *name_tok,
	     struct parser_state *st)
{
	struct bufstack *bs = NULL;
	FILE *in_file;
	YY_BUFFER_STATE inbuf;
	struct file_list *flist = NULL;
	struct file_list *fp;
	void *yyscanner = st->scanner;
	struct yyguts_t * yyg = (struct yyguts_t*)yyscanner;
	struct config_root *confroot = st->root_node;
	char *fullpath = NULL;
	int rc = ENOMEM;
	char *filename;

	if (*name_tok == '\"') {
		 /* alloca'd memory freed on exit */
		filename = gsh_strdupa(name_tok + 1);
		filename[strlen(filename) - 1] = '\0';
	} else {
		/* alloca'd memory freed on exit */
		filename = gsh_strdupa(name_tok);
	}
	if (confroot->files == NULL) {
		if (filename[0] == '/') {
			char *path = gsh_strdupa(filename);
			confroot->conf_dir = gsh_strdup(dirname(path));
		} else {
			confroot->conf_dir = gsh_strdup(".");
		}
	}
	if (filename[0] == '/') {
		fullpath = gsh_strdup(filename);
	} else {
		fullpath = gsh_concat_sep(confroot->conf_dir, '/', filename);
	}
	/* loop detection */
	for (fp = confroot->files; fp != NULL; fp = fp->next) {
		if (!strcmp(fp->pathname, fullpath)) {
			config_parse_error(yylloc, st,
				"file (%s)already parsed, ignored",
				fullpath);
			rc = EINVAL;
			goto errout;
		}
	}
	bs = gsh_calloc(1, sizeof(struct bufstack));

	flist = gsh_calloc(1, sizeof(struct file_list));

	in_file = fopen(fullpath, "r" );
	if (in_file == NULL) {
		rc = errno;
		config_parse_error(yylloc, st,
			"new file (%s) open error (%s), ignored",
			fullpath, strerror(rc));
		goto errout;
	}
	bs->bs = ganeshun_yy_create_buffer(in_file,
					 YY_BUF_SIZE,
					 yyscanner);
	if (st->curbs)
		st->curbs->lineno = yylineno;
	bs->prev = st->curbs;
	bs->f = in_file;
	bs->filename = fullpath;
	ganeshun_yy_switch_to_buffer(bs->bs, yyscanner);
	st->current_file = fullpath;
	st->curbs = bs;
	flist->pathname = fullpath;
	flist->next = confroot->files;
	confroot->files = flist;
	return 0;

errout:
	if (rc == ENOMEM)
		st->err_type->resource = true;
	else
		st->err_type->scan = true;

	gsh_free(flist);
	gsh_free(bs);
	gsh_free(fullpath);

	return rc;
}

/* fetch_url */
static int fetch_url(char *name_tok, struct parser_state *st)
{
	struct bufstack *bs = NULL;
	YY_BUFFER_STATE inbuf;
	struct file_list *flist = NULL;
	struct file_list *fp;
	void *yyscanner = st->scanner;
	struct yyguts_t * yyg = (struct yyguts_t*)yyscanner;
	struct config_root *confroot = st->root_node;
	char *filename = NULL;
	int rc = ENOMEM;

#ifdef NO_URL_RECURSION
	/* forbid URL chasing */
	if (st->curbs && (st->curbs->flags & BS_FLAG_URL)) {
		config_parse_error(yylloc, st,
			"new url (%s) transitive fetch from (%s), ignored",
			name_tok, st->curbs->filename);
		goto errout;
	}
#endif
	filename = gsh_strdup(name_tok);

	bs = gsh_calloc(1, sizeof(struct bufstack));
	flist = gsh_calloc(1, sizeof(struct file_list));

	rc = config_url_fetch(filename, &bs->f, &bs->fbuf);
	if (bs->f == NULL) {
		config_parse_error(yylloc, st,
			"new url (%s) open error (%s), ignored",
			filename, strerror(rc));
		goto errout;
	}
	bs->bs = ganeshun_yy_create_buffer(bs->f, YY_BUF_SIZE, yyscanner);
	if (st->curbs)
		st->curbs->lineno = yylineno;
	bs->prev = st->curbs;
	bs->filename = filename;
	bs->flags = BS_FLAG_URL;
	ganeshun_yy_switch_to_buffer(bs->bs, yyscanner);
	st->current_file = gsh_strdup(bs->filename);
	st->curbs = bs;
	flist->pathname = gsh_strdup(bs->filename); /* XXX */
	flist->next = confroot->files;
	confroot->files = flist;
	return 0;

errout:
	if (rc == ENOMEM)
		st->err_type->resource = true;
	else
		st->err_type->scan = true;

	gsh_free(flist);
	gsh_free(bs);
	gsh_free(filename);

	return rc;
} /* fetch_url() */

static int pop_file(struct parser_state *st)
{
	struct bufstack *bs = st->curbs;
	struct bufstack *prevbs;
	void *yyscanner = st->scanner;
	struct yyguts_t * yyg = (struct yyguts_t*)yyscanner;

	if (bs == NULL)
		return 0;
	if (bs->flags & BS_FLAG_URL) {
		config_url_release(bs->f, bs->fbuf);
	} else {
		fclose(bs->f);
	}
	ganeshun_yy_delete_buffer(bs->bs, yyscanner);
	prevbs = bs->prev;
	st->curbs = prevbs;
	gsh_free(bs);
	if (prevbs == NULL)
		return 0;
	ganeshun_yy_switch_to_buffer(prevbs->bs, yyscanner);
	yylineno = st->curbs->lineno;
	st->current_file = st->curbs->filename;
	return 1;
}
