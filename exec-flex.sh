#!/bin/sh
# $Id: exec-flex.sh,v 1.2 2000/06/03 19:59:35 thomas Exp $

# This is a script to run lex or flex and determine whether yylineno is available

lexer=$1;
cc=$2;
file=$3;
templ=$4;
shift 4;

if [ ! -x `which $lexer` ] ; then
    if [ $lexer = "flex"  && -x `which lex` ] ; then
	# if flex was specified, maybe we have lex instead...?
	lexer="lex";
    fi
    if [ ! -x `which $lexer` ] ; then
    	echo "Could not execute your scanner generator \"$lexer\"."
    	echo "If the name is incorrect, look into the Variable LEX in Makefile."
    	echo "If the executable does not reside in your path, please give the "
	echo "needed path in the LEX variable in the Makefile."
	echo "Otherwise, you may need to install flex or lex."
	return 1; 
   fi
fi

if [ $lexer = "flex" ] ; then
    sed  -e "s/\\/\\*YYLINENO-OPTION-LOCATION\\*\\//%option yylineno/" $templ > $file
else
    cp -f $templ $file
fi

rm -f lex.inc.h
touch lex.inc.h

$lexer $* $file
if [ $? -ne 0 ] ; then
    echo "$lexer failed. This is OK if the next call is successful."
    cp -f $templ $file
    $lexer $* $file
    if [ $? -ne 0 ] ; then
	echo "$lexer failed again..."
        return $?
    fi
fi

# write a test file and try to compile it. If successful, we have yylineno
echo "$0: Test compile for lexer."

cat > .yylineno.test.c <<EOF
#include "lex.yy.c"

YYSTYPE yylval;

int main()
{
    return yylineno;
}
EOF

$cc .yylineno.test.c -o .foo >/dev/null 2>/dev/null

if [ $? -ne 0 ] ; then
    #failed. We may not use yylineno then.
    echo "#define NO_YYLINENO" > lex.inc.h
fi

rm -f .yylineno.test.c
rm -f .foo

