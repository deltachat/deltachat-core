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
 * File:    mrosnative.cpp
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


#if defined(__ANDROID) || defined(ANDROID)


static JavaVM* s_jvm = NULL; // TODO: how is this set up?
static jint s_version = 0;


JNIEXPORT void JNICALL Java_com_libmailcore_MainThreadUtils_setupNative(JNIEnv * env, jobject object)
{
	// AutoreleasePool * pool = new AutoreleasePool();

    env->GetJavaVM(&s_jvm);
    s_version = env->GetVersion();
    //s_mainThreadUtils = reinterpret_cast<jobject>(env->NewGlobalRef(object));
    //jclass localClass = env->FindClass("com/libmailcore/MainThreadUtils");
    //s_mainThreadUtilsClass = reinterpret_cast<jclass>(env->NewGlobalRef(localClass));
    //MCAssert(s_mainThreadUtilsClass != NULL);
    //MCTypesUtilsInit();

    //pool->release();
}


void MrAndroidSetupThread(void)
{
	assert(s_jvm);;

	JNIEnv* env = NULL;
	s_jvm->AttachCurrentThread(&env, NULL);
}


void MrAndroidUnsetupThread(void)
{
	s_jvm->DetachCurrentThread();
}


#endif // defined(__ANDROID) || defined(ANDROID)
