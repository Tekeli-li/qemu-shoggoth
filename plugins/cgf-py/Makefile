#/*
# * Rapid Analysis QEMU System Emulator
# *
# * Copyright (c) 2020 Cromulence LLC
# *
# * Distribution Statement A
# *
# * Approved for Public Release, Distribution Unlimited
# *
# * Authors:
# *  Joseph Walker
# *
# * This work is licensed under the terms of the GNU GPL, version 2 or later.
# * See the COPYING file in the top-level directory.
# * 
# * The creation of this code was funded by the US Government.
# */

CGF-PY_TGT=$(PLUGIN_PARENT_DIR)cgf-py/cgf-py.pyc
CGF-PY_SRC=$(PLUGIN_PARENT_DIR)cgf-py/cgf-py.py
PLUGIN_TARGETS += $(CGF-PY_TGT)

# At the minimum, you need a recipe that matches the directory
# name. This resides in a folder named cgf-py so:
.PHONY: cgf-py
cgf-py:
	@$(PYTHON) -m compileall -b $(CGF-PY_SRC)
	@echo 'A plugin can be found here - $(CGF-PY_TGT)'
