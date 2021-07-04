ifneq ($(CXGB4TOE_SRC),)
  ifeq ($(wildcard $(CXGB4TOE_SRC)/cxgb4),)
    $(error ERROR! Invalid cxgb4 source $(CXGB4TOE_SRC).)
  endif
  ifeq ($(wildcard $(CXGB4TOE_SRC)/$(modulesymfile)),)
    $(error ERROR! Missing cxgb4 module symvers file \
                   $(CXGB4TOE_SRC)/$(modulesymfile))
  endif
endif
