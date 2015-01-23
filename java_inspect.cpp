#include <string>
#include <iostream>
#include <fstream>
#include <jvmti.h>
#include <windows.h>
#include "stdlib.h"
#include <tchar.h>
#include <psapi.h> 
#include <fstream>
#define countof(array) (sizeof(array)/sizeof(array[0]))
using namespace std;
 bool setsecuritymanager_checked=false;
  
static void check(jvmtiEnv *jvmti, jvmtiError errnum, const char *str)
{
    if ( errnum != JVMTI_ERROR_NONE ) {
        char *errnum_str = NULL;
        jvmti->GetErrorName(errnum, &errnum_str);
     
        OutputDebugString("ERROR: JVMTI");
    }
}
void CondOutputDebugString(LPTSTR pszMessage)
{
	TCHAR szOutput[256];

	_sntprintf(szOutput, countof(szOutput), _TEXT("%s"), pszMessage);
	OutputDebugString(szOutput);
}
void CondOutputDebugStringF(LPTSTR pszFormat, ...)
{
	TCHAR szOutput[256];
	va_list vaArgs;

	va_start(vaArgs, pszFormat);
	_vsntprintf(szOutput, countof(szOutput), pszFormat, vaArgs);
	CondOutputDebugString(szOutput);
	va_end(vaArgs);
}

static void JNICALL Exception(jvmtiEnv *jvmti_env,JNIEnv* jni_env,jthread thread,jmethodID method,jlocation location,jobject exception,jmethodID catch_method,jlocation catch_location)
{
    char* method_name;
    char* method_signature;
    char* generic_ptr_method;
    char* generic_ptr_class;
    char* class_name;
    char* generic_ptr_class1;
    char* class_name1;
    jvmtiError error;
    jclass clazz;
    jclass klass;
    jint type;
    type=jni_env->GetObjectRefType(exception); 
    if(type>0)
    {
            
            klass=jni_env->GetObjectClass(exception);      
            jvmti_env->GetMethodName(method,&method_name,&method_signature,&generic_ptr_method);
            
            if(strcmp("setSecurityManager",method_name)==0)
               { 
                   jvmti_env->GetMethodDeclaringClass(method,&clazz);
                   jvmti_env->GetClassSignature(clazz, &class_name,&generic_ptr_class);
                   if(strcmp("Ljava/lang/System;",class_name)==0)
                      {
                       jvmti_env->GetClassSignature(klass, &class_name1,&generic_ptr_class1);
                       if(strcmp("Ljava/lang/NullPointerException;",class_name1)==0)
                       setsecuritymanager_checked=true;
                      }
               }
            else   /*next exception after setSecurityManager*/
            {
                if(setsecuritymanager_checked)
                {
                 if(strcmp("checkPermission",method_name)==0)
                 {
                   jvmti_env->GetClassSignature(klass, &class_name1,&generic_ptr_class1);
                   if(strcmp("Ljava/security/AccessControlException;",class_name1)==0)
                   OutputDebugString("setSecurityManager(null) present but no exploit detected\n");
                   jvmti_env->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_EXCEPTION,(jthread)NULL); 
            
                 }
                 else
                  OutputDebugString("Exploit Detected!!!!\n");
                   jvmti_env->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_EXCEPTION,(jthread)NULL); 
                   
                }
                
            }
    }       
}

 static void JNICALL loadClass(jvmtiEnv *jvmti_env,JNIEnv* jni_env,jthread thread,jclass klass)
 {
        char *class_name;
        char *generic_ptr_class;
        
        jvmti_env->GetClassSignature(klass, &class_name,&generic_ptr_class);
        
         if(strcmp("Ljava/applet/Applet;",class_name)==0)
         {
        
         
        
         jvmti_env->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_EXCEPTION,(jthread)NULL); 
         jvmti_env->SetEventNotificationMode(JVMTI_DISABLE,JVMTI_EVENT_CLASS_PREPARE,(jthread)NULL);
         }                                             
         
        jvmti_env->Deallocate((unsigned char *)class_name);
        jvmti_env->Deallocate((unsigned char *)generic_ptr_class);
}

 
JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved)
{
   static jvmtiEnv *jvmti=NULL;
   static jvmtiCapabilities capabilities;
   jvmtiEventCallbacks callbacks;
   jint res;
        
        
        OutputDebugString("Agent_OnLoad");
 
        res = vm->GetEnv((void **)&jvmti, JVMTI_VERSION_1);
        if (res != JNI_OK||jvmti==NULL) 
           {
            OutputDebugString("ERROR: Unable to access JVMTI Version 1");
           }
           
        
        (void)memset(&capabilities,0, sizeof(capabilities));
        
        capabilities.can_generate_exception_events=1;
        
        jvmtiError error = jvmti->AddCapabilities(&capabilities);
        
        check(jvmti,error,"Unable to get necessary capabilities.");
    
        (void)memset(&callbacks,0, sizeof(callbacks));
        
        callbacks.ClassPrepare = &loadClass;
        
        callbacks.Exception=&Exception;
        
        jvmti->SetEventCallbacks(&callbacks, (jint)sizeof(callbacks));
        
        jvmti->SetEventNotificationMode(JVMTI_ENABLE,JVMTI_EVENT_CLASS_PREPARE,(jthread)NULL);
    
    return JNI_OK;
}
 
    
JNIEXPORT void JNICALL Agent_OnUnload(JavaVM *vm)
{
    OutputDebugString("Agent_OnUnload\n");
    
}
