/* conf-parser.h - definitions for parser of pdnsd config files.
   Copyright (C) 2004 Paul A. Rombouts.

   The parser was rewritten in C from scratch and doesn't require (f)lex
   or yacc/bison.


This file is part of the pdnsd package.

pdnsd is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

pdnsd is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with pdsnd; see the file COPYING.  If not, write to
the Free Software Foundation, 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

#ifndef CONF_PARSER_H
#define CONF_PARSER_H

int confparse(FILE* in, globparm_t *global, servparm_array *servers, char **errstr);

#endif /* CONF_PARSER_H */
