/*******************************************************************************
 *
 *                             Messenger Backend
 *                      Copyright (C) 2017 Björn Petersen
 *                   Contact: r10s@b44t.com, http://b44t.com
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see http://www.gnu.org/licenses/ .
 *
 *******************************************************************************
 *
 * File:    mrcmdline.ch
 * Purpose: declare mrmailbox_cmdline(), this file is optional
 *
 ******************************************************************************/


#ifndef __MRCMDLINE_H__
#define __MRCMDLINE_H__
#ifdef __cplusplus
extern "C" {
#endif


#include "mrmailbox.h"


/* Execute a simple command.
- The returned result may contain multiple lines  separated by `\n` and must be
  free()'d if no longer needed.
- some commands may use mrmailbox_log_info() for additional output.
- The command `help` gives an overview */
char* mrmailbox_cmdline (mrmailbox_t*, const char* cmd);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRCMDLINE_H__ */

