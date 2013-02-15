# $Id$

all: for-subst

here := ${.PARSEDIR}
# this should not run foul of the parser
.for file in ${.PARSEFILE}
for-subst:	  ${file:S;^;${here}/;g}
	@echo ".for with :S;... OK"
.endfor
