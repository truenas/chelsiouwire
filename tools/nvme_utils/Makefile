SHELL = /bin/bash
# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(error Please use the top-level Makefile to build this driver)
endif

PWD=$(shell pwd)
NVMCLIDIR=$(PWD)/nvme-cli
pythonver=$(shell python --version 2>&1 | awk '{print $$2}')
PY_MAJVER := $(word 1, $(subst ., ,$(pythonver)))
PY_MINVER := $(word 2, $(subst ., ,$(pythonver)))
PY_INST := $(shell [  $(PY_MAJVER) -lt 3 -a $(PY_MINVER) -lt 7 ] && echo 1 || echo 0 ;)
PYDIR := $(PWD)/Python-2.7.10
targetUtilsdir := $(PWD)

.PHONY: install
install: nvmecli_install nvmetcli_install

.PHONY: prep
prep:
	@ if [[ $(PY_INST) -eq 1 ]] ; then \
		( cd $(PYDIR) && ./configure --bindir=/usr/local/bin --libdir=/usr/local/lib && make && make install ) && \
	        echo "alias python='/usr/local/bin/python2.7'" >> ~/.bashrc && (source ~/.bashrc ; . ~/.bashrc 2>&1 > /dev/null) \
	    fi ; \
	  ( cd ${targetUtilsdir}/pyparsing-2.0.3 && \
		python setup.py install ) ; \
	  ( cd ${targetUtilsdir}/setuptools-18.0.1 && \
		python setup.py install ) ; \
	  ( cd ${targetUtilsdir}/six-1.9.0 && \
		python setup.py install ) ; \
	  ( cd ${targetUtilsdir}/rtslib-fb-2.1.fb63 && \
		python setup.py install ) ; \
	  ( cd ${targetUtilsdir}/configshell-fb-1.1.fb18 && \
		python setup.py install )

.PHONY: nvmecli
nvmecli:
	@ echo "################################################## " ;\
	  echo "#          Building nvme          # " ;\
	  echo "################################################## " ;
	@ make -C $(NVMCLIDIR) && ( $(call logs,NVMeF-utils,nvme,Build) ) || ( $(call logtemp,NVMeF-utils,nvme,Build) )

.PHONY: nvmecli_install
nvmecli_install:
	@ echo "################################################## " ;\
	  echo "#          Installing nvme          # " ;\
	  echo "################################################## " ;
	@ echo ; \
	  make -C $(NVMCLIDIR) install && ( $(call logs,NVMeF-utils,nvme,Install) ) || ( $(call logtemp,NVMeF-utils,nvme,Install) )

.PHONY: nvmetcli
nvmetcli: prep
	@ echo "################################################## " ;\
	  echo "#          Building nvmetcli          # " ;\
	  echo "################################################## " ;
	@ ( cd ${targetUtilsdir}/nvmetcli && \
	        python setup.py build bdist_egg ;\
	  ) && ( $(call logs,NVMeF-utils,nvmetcli,Build) ) || ( $(call logtemp,NVMeF-utils,nvmetcli,Build) )

.PHONY: nvmetcli_install
nvmetcli_install: prep
	@ echo "################################################## " ;\
	  echo "#          Installing nvmetcli          # " ;\
	  echo "################################################## " ;
	@ ( cd ${targetUtilsdir}/nvmetcli && \
		python setup.py install ; install -D -m 755 nvmetcli /usr/bin/ ; \
	  if [ ! -d /etc/target ] ; then \
		mkdir -p /etc/target ; \
	  fi ; \
	  ) && ( $(call logs,NVMeF-utils,nvmetcli,Install) ) || ( $(call logtemp,NVMeF-utils,nvmetcli,Install) )

.PHONY: tgtcli
tgtcli: prep
	@ ( cd ${targetUtilsdir}/targetcli-fb-2.1.fb41 && \
	        python setup.py build ; \
	  ) && ( if [ $(tgtsum) -ne 1 ] ; then ( $(call logs,LIO-Utils,targetcli,Build) ) || ( $(call logtemp,LIO-Utils,targetcli,Build) ) ; fi )

.PHONY: tgtcli_install
tgtcli_install: tgtcli
	@ ( cd ${targetUtilsdir}/targetcli-fb-2.1.fb41 && \
	        python setup.py install ; \
	  [[ ! -e /usr/bin/targetcli ]] && [[ -e /usr/local/bin/targetcli ]] && ln -sf /usr/local/bin/targetcli /usr/bin/targetcli ; \
	  if [ ! -d /etc/target ] ; then \
		mkdir -p /etc/target ; \
	  fi ; \
	  ) && ( if [ $(tgtsum) -ne 1 ] ; then ( $(call logs,LIO-Utils,targetcli,Install) ) || ( $(call logtemp,LIO-Utils,targetcli,Install) ) ; fi )


define logtemp
echo -e "$1\t\t$2\t\t$3\t\tFailed" >> $(logpath)/temp.log ;
endef

define logs
echo -e "$1\t\t$2\t\t$3\t\tSuccessful" >> $(logpath)/temp.log ;
endef
