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
 * File:    mrosnative.c
 * Authors: Björn Petersen
 * Purpose: JNI handling, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>

#include "mrmailbox.h"
#include "mrosnative.h"


/*******************************************************************************
 * Android Natives
 ******************************************************************************/


#if defined(ANDROID) || defined(__ANDROID__)


#include <jni.h>


static JavaVM* s_jvm = NULL;


void mrosnative_init_android(JNIEnv* env)
{
	if( s_jvm ) {
		return; /* already initialized */
	}

	mrlog_info("Get Java VM...");

    (*env)->GetJavaVM(env, &s_jvm);

	mrlog_info("Got it.");
}


int mrosnative_setup_thread(void)
{
	if( s_jvm == NULL ) {
		mrlog_error("Cannot setup thread. mrosnative_init_android() not called successfully.");
		return 0;
	}

	mrlog_info("Attaching C-thread to Java VM...");

	JNIEnv* env = NULL;
	(*s_jvm)->AttachCurrentThread(s_jvm, &env, NULL);

	mrlog_info("Attaching ok");

	return 1;
}


void mrosnative_unsetup_thread(void)
{
	mrlog_info("Detaching C-thread from Java VM...");

	(*s_jvm)->DetachCurrentThread(s_jvm);

	mrlog_info("Detaching done.");
}


/*******************************************************************************
 * Empty Natives
 ******************************************************************************/


#else /* OS definition */


int mrosnative_setup_thread(void)
{
	return 1;
}


void mrosnative_unsetup_thread(void)
{
}


#endif /* OS definition */
