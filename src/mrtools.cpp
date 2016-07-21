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
 * File:    mrtools.cpp
 * Authors: Björn Petersen
 * Purpose: Some tools, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include <libetpan.h>
#include "mrtools.h"


/*******************************************************************************
 * carray tools
 ******************************************************************************/


bool carray_search(carray* haystack, void* needle, unsigned int* indx)
{
	void** data = carray_data(haystack);
	unsigned int  cnt = carray_count(haystack);
	for( unsigned int i=0; i<cnt; i++ )
	{
		if( data[i] == needle ) {
			if( indx ) {
				*indx = i;
			}
			return true;
		}
	}

	return false;
}


/*******************************************************************************
 * date/time tools
 ******************************************************************************/


static int tmcomp(struct tm * atmp, struct tm * btmp) // from mailcore2
{
    int    result;

    if ((result = (atmp->tm_year - btmp->tm_year)) == 0 &&
        (result = (atmp->tm_mon - btmp->tm_mon)) == 0 &&
        (result = (atmp->tm_mday - btmp->tm_mday)) == 0 &&
        (result = (atmp->tm_hour - btmp->tm_hour)) == 0 &&
        (result = (atmp->tm_min - btmp->tm_min)) == 0)
        result = atmp->tm_sec - btmp->tm_sec;
    return result;
}


static time_t mkgmtime(struct tm * tmp) // from mailcore2
{
    int            dir;
    int            bits;
    int            saved_seconds;
    time_t         t;
    struct tm      yourtm, mytm;

    yourtm = *tmp;
    saved_seconds = yourtm.tm_sec;
    yourtm.tm_sec = 0;
    /*
     ** Calculate the number of magnitude bits in a time_t
     ** (this works regardless of whether time_t is
     ** signed or unsigned, though lint complains if unsigned).
     */
    for (bits = 0, t = 1; t > 0; ++bits, t <<= 1)
        ;
    /*
     ** If time_t is signed, then 0 is the median value,
     ** if time_t is unsigned, then 1 << bits is median.
     */
    if(bits > 40) bits = 40;
    t = (t < 0) ? 0 : ((time_t) 1 << bits);
    for ( ; ; ) {
        gmtime_r(&t, &mytm);
        dir = tmcomp(&mytm, &yourtm);
        if (dir != 0) {
            if (bits-- < 0) {
                return INVALID_TIMESTAMP;
            }
            if (bits < 0)
                --t;
            else if (dir > 0)
                t -= (time_t) 1 << bits;
            else    t += (time_t) 1 << bits;
            continue;
        }
        break;
    }
    t += saved_seconds;
    return t;
}


time_t timestampFromDate(struct mailimf_date_time * date_time) // from mailcore2
{
    struct tm tmval;
    time_t timeval;
    int zone_min;
    int zone_hour;

    tmval.tm_sec  = date_time->dt_sec;
    tmval.tm_min  = date_time->dt_min;
    tmval.tm_hour = date_time->dt_hour;
    tmval.tm_mday = date_time->dt_day;
    tmval.tm_mon  = date_time->dt_month - 1;
    if (date_time->dt_year < 1000) {
        // workaround when century is not given in year
        tmval.tm_year = date_time->dt_year + 2000 - 1900;
    }
    else {
        tmval.tm_year = date_time->dt_year - 1900;
    }

    timeval = mkgmtime(&tmval);

    if (date_time->dt_zone >= 0) {
        zone_hour = date_time->dt_zone / 100;
        zone_min = date_time->dt_zone % 100;
    }
    else {
        zone_hour = -((- date_time->dt_zone) / 100);
        zone_min = -((- date_time->dt_zone) % 100);
    }
    timeval -= zone_hour * 3600 + zone_min * 60;

    return timeval;
}

