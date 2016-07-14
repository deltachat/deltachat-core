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
 * File:    main.cpp
 * Authors: Björn Petersen
 * Purpose: Testing frame; if used as a lib, this file is obsolete.
 *
 ******************************************************************************/


#include <iostream>
#include "mrmailbox.h"


int main()
{
	MrMailbox obj;

	obj.Init("/home/bpetersen/temp/foobar.db");

    std::cout << "Hello world!" << std::endl;


    return 0;
}


