/*******************************************************************************
 *
 *                             Messenger Backend
 *     Copyright (C) 2016 Björn Petersen Software Design and Development
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
 * File:    mrerror.h
 * Authors: Björn Petersen
 * Purpose: Error handling
 *
 ******************************************************************************/


#ifndef __MRERROR_H__
#define __MRERROR_H__


#include <sqlite3.h>


void MrLogError  (const char* msg, const char* obj=NULL);
void MrLogWarning(const char* msg, const char* obj=NULL);
void MrLogInfo   (const char* msg, const char* obj=NULL);

void MrLogSqliteError(sqlite3*);


#endif // __MRERROR_H__

