# go makefile common include

#
# detect os
#
os := $(if $(SYSTEMROOT),windows,$(shell uname | tr A-Z a-z))

#
# os specific
#

ifeq ($(os),windows)
  hostname := $(shell windows_info hostname)
  fqdn := $(shell windows_info fqdn)
  os_version := $(shell windows_info version)
  arch := $(shell windows_info arch)
  windows := 1
endif

ifeq ($(os),linux)
  hostname := $(shell hostname -s)
  fqdn := $(shell hostname --fqdn)
  os_version := $(firstword $(subst +, ,$(subst -, ,$(shell uname -r))))
  arch := $(shell uname -m)
  linux := 1
endif

ifeq ($(os),openbsd)
  hostname := $(shell hostname -s)
  fqdn := $(shell hostname)
  os_version := $(shell uname -r)
  arch := $(shell uname -m)
  openbsd := 1
endif

binary_extension := $(if $(windows),.exe,)
binary := $(program)$(binary_extension)

#
# module versions
#
org = rstms
rstms_modules != awk <go.mod '/^module/{next} /rstms/{print $$1}'
common_go = $(wildcard */common.go) $(wildcard */*/common.go)
latest_module_release = $(shell gh --repo $(1) release list --json tagName --jq '.[0].tagName')

#
# release
#
latest_release = $(call latest_module_release,$(org)/$(program))
gitclean = $(if $(shell git status --porcelain),$(error git status is dirty),$(info git status is clean))

#
# local dist
#
release_binary := $(program)-v$(version)-$(os)-$(os_version)-$(arch)$(binary_extension)
dist_binary := $(program)-latest-$(os)-$(os_version)-$(arch)$(binary_extension)
dist_upload_host ?= $(shell [ -e ~/.dist_upload_host ] && cat ~/.dist_upload_host)
dist_upload = $(if $(dist_upload_host),scp -p $(1) $(dist_upload_host):$(2),@echo "dist_upload_host unset, not uploading $(2)")

#
# configuration
#
config_dir = $(if $(windows),$(shell cygpath -u $(APPDATA))/$(program),$(HOME)/.config/$(program))
cache_dir = $(if $(windows),$(shell cygpath -u $(LOCALAPPDATA))/$(program),$(HOME)/.cache/$(program))

#
# diagnostics
#
all_variables = \
    program version org \
    os os_version arch hostname fqdn windows openbsd linux \
    binary_extension binary \
    rstms_modules common_go \
    latest_release release_binary dist_target dist_binary dist_upload_host \
    config_dir cache_dir
