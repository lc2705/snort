
/*
**   ACSMX.H
**
**
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_types.h"
#include "acsmx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ACSMX3_H
#define ACSMX3_H

/*
*   Prototypes
*/


#define ALPHABET_SIZE    256

#define ACSM_FAIL_STATE   -1

typedef struct  {

    /* Next state - based on input character */
    int      NextState[ ALPHABET_SIZE ];

    /* Failure state - used while building NFA & DFA  */
    int      FailState;

    /* List of patterns that end here, if any */
    ACSM_PATTERN *MatchList;
    
    /*Depth of state in DFA three */
    int Depth;

}ACSM_STATETABLE3;


/*
* State machine Struct
*/
typedef struct {

    int acsmMaxStates;
    int acsmNumStates;

    ACSM_PATTERN    * acsmPatterns;
    ACSM_STATETABLE3 * acsmStateTable;

    int   bcSize;
    short bcShift[256];

    int numPatterns;
    void (*userfree)(void *p);
    void (*optiontreefree)(void **p);
    void (*neg_list_free)(void **p);

}ACSM_STRUCT3;


/*
*   Prototypes
*/
ACSM_STRUCT3 * acsmNew3 (void (*userfree)(void *p),
                       void (*optiontreefree)(void **p),
                       void (*neg_list_free)(void **p));

int acsmAddPattern3( ACSM_STRUCT3 * p, unsigned char * pat, int n,
          int nocase, int offset, int depth, int negative, void * id, int iid );

int acsmCompile3 ( ACSM_STRUCT3 * acsm,
             int (*build_tree)(void * id, void **existing_tree),
             int (*neg_list_func)(void *id, void **list));
struct _SnortConfig;
int acsmCompileWithSnortConf3 ( struct _SnortConfig *, ACSM_STRUCT3 * acsm,
                               int (*build_tree)(struct _SnortConfig *, void * id, void **existing_tree),
                               int (*neg_list_func)(void *id, void **list));

int acsmSearch3 ( ACSM_STRUCT3 * acsm,unsigned char * T, int n,
                 int (*Match)(void * id, void *tree, int index, void *data, void *neg_list),
                 void * data, int* current_state );

void acsmFree3 ( ACSM_STRUCT3 * acsm );
int acsmPatternCount3 ( ACSM_STRUCT3 * acsm );

int acsmPrintDetailInfo3(ACSM_STRUCT3 *);

int acsmPrintSummaryInfo3(void);

void acsm3ThreadCreate(void);
void acsm3ThreadDestroy(void);

#endif
