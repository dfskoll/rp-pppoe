/******************************************************************************
 *  CCL Project Reference C7032 - Dysprosium
 *
 *  FILE
 *      $Workfile: types.h $
 *      $Revision: 2496 $
 *      $Author: cjc2 $
 *
 *  ORIGINAL AUTHOR
 *      Monty Barlow
 *
 *  DESCRIPTION
 *      Definition of simple types.
 *
 *  REFERENCES
 *      C7032-DREP-026
 *
 ******************************************************************************/

#if !defined( __TYPES_H_INCLUDED__ )
#define __TYPES_H_INCLUDED__

/*********************************************************************** 
   MACRO DEFINITIONS 
***********************************************************************/ 

/*********************************************************************** 
   TYPE, STRUCT, UNION AND ENUM DEFINITIONS
***********************************************************************/ 
/* Typedefs */

#if !defined(ISU_H)
#define FALSE 0
#define TRUE 1
typedef int BOOL;
typedef unsigned int UINT32;
#endif /* !defined(ISU_H) */

typedef unsigned short t_uint16 ;
typedef signed short t_int16 ;
typedef unsigned long t_uint32 ;

typedef signed long t_int32 ;
typedef signed char t_int8 ;
typedef unsigned char t_uint8 ;


#ifndef NULL
#define NULL (0)
#endif

#endif /* !defined( __TYPES_H_INCLUDED__ ) */
