
EXTENSION = uuid
DATA = uuid--1.0.sql
MODULE_big = uuid
OBJS = uuid.o md5.o sha1.o

SHLIB_LINK += $(filter -luuid, $(LIBS))

REGRESS = init v1 v35

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/uuid
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
