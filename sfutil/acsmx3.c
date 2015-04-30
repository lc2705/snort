/*
**
** $Id$
**
** Multi-Pattern Search Engine
**
** Aho-Corasick State Machine -  uses a Deterministic Finite Automata - DFA
**
** Multi_thread Search
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h> 
#include <pthread.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "acsmx3.h"
#include "util.h"
#include "snort_debug.h"

#ifdef DYNAMIC_PREPROC_CONTEXT
#include "sf_dynamic_preprocessor.h"
#endif //DYNAMIC_PREPROC_CONTEXT

#define MEMASSERT(p,s) if(!p){fprintf(stderr,"ACSM-No Memory: %s!\n",s);exit(0);}

#ifdef DEBUG_AC
static int max_memory = 0;
#endif

#define THREAD_NUM 2
#define MAX_PATTERN_LEN 200

/*
*
*/
static void *
AC_MALLOC (int n)
{
  void *p;
  p = calloc (1,n);
#ifdef DEBUG_AC
  if (p)
    max_memory += n;
#endif
  return p;
}

/*
*
*/
static void
AC_FREE (void *p)
{
  if (p)
    free (p);
}

/*
*    Simple QUEUE NODE
*/
typedef struct _qnode
{
   void *data;
   struct _qnode *next;
}
QNODE;

/*
*    Simple QUEUE Structure
*/
typedef struct _queue
{
  QNODE * head, *tail;
  int count;
}
QUEUE;

/*
*
*/
static void
queue_init (QUEUE * s)
{
  s->head = s->tail = 0;
  s->count = 0;
}


/*
*  Add Tail Item to queue
*/
static void
queue_add (QUEUE * s, void *data)
{
  QNODE * q;
  if (!s->head)
    {
      q = s->tail = s->head = (QNODE *) AC_MALLOC (sizeof (QNODE));
      MEMASSERT (q, "queue_add");
      q->data = data;
      q->next = 0;
    }
  else
    {
      q = (QNODE *) AC_MALLOC (sizeof (QNODE));
      MEMASSERT (q, "queue_add");
      q->data = data;
      q->next = 0;
      s->tail->next = q;
      s->tail = q;
    }
  s->count++;
}


/*
*  Remove Head Item from queue
*/
static void *
queue_remove (QUEUE * s)
{
  void * data = NULL;
  QNODE * q;
  if (s->head)
    {
      q = s->head;
      data = q->data;
      s->head = s->head->next;
      s->count--;
      if (!s->head)
      {
          s->tail = 0;
          s->count = 0;
      }
      AC_FREE (q);
    }
  return data;
}


/*
*
*/
static int
queue_count (QUEUE * s)
{
  return s->count;
}


/*
*
*/
static void
queue_free (QUEUE * s)
{
  while (queue_count (s))
    {
      queue_remove (s);
    }
}


/*
** Case Translation Table
*/
static unsigned char xlatcase[256];

static void
init_xlatcase ()
{
  int i;
  for (i = 0; i < 256; i++)
    {
      xlatcase[i] = (unsigned char)toupper (i);
    }
}

static inline void
ConvertCaseEx (unsigned char *d, unsigned char *s, int m)
{
  int i;
  for (i = 0; i < m; i++)
    {
      d[i] = xlatcase[s[i]];
    }
}

/*
*	Thread Task Struct 
*/
typedef struct
{
	ACSM_STRUCT3 *acsm;

	unsigned char * T;
	int n;

	int (*Match)(void * id, void *tree, int index, void *data, void *neg_list);
	void * data;
	int * current_state;

}TASK;
TASK				search_task;

/*
*   Search Thread 
*/
pthread_t * 		search_thread_array;
pthread_cond_t * 	search_cond_array;
pthread_mutex_t * 	search_mutex_array;
unsigned char *		search_added_array;

pthread_cond_t      packet_cond;
pthread_mutex_t     packet_mutex;
unsigned int        packet_finished;
pthread_barrier_t   thread_barrier;

int					StopSearch;
int					thread_num = THREAD_NUM;
static unsigned char Tc[THREAD_NUM][8*1024];  //64K

static void*  _multiThread(void * args);

void
acsm3ThreadCreate()
{
	int i;
	search_thread_array = calloc(thread_num,sizeof(pthread_t));
	search_mutex_array = calloc(thread_num,sizeof(pthread_mutex_t));
	search_cond_array = calloc(thread_num,sizeof(pthread_cond_t));
	search_added_array = calloc(thread_num,sizeof(unsigned char));
	StopSearch = 0;
	
	packet_finished = 0;
	pthread_mutex_init(&packet_mutex,NULL);
	pthread_cond_init(&packet_cond,NULL);
	pthread_barrier_init(&thread_barrier,NULL,thread_num); 
	for(i = 0;i < thread_num;i++)
	{
		pthread_mutex_init(&search_mutex_array[i],NULL);
		pthread_cond_init(&search_cond_array[i],NULL);		
		pthread_create(&search_thread_array[i],NULL,_multiThread,(void *)(intptr_t)i); 
	}
}

void 
acsm3ThreadDestroy()
{
	StopSearch = 1;

    int i,err;
    for(i = 0;i < thread_num;i++)
    {
        pthread_mutex_lock(&search_mutex_array[i]);
    	pthread_cond_signal(&search_cond_array[i]);
        pthread_mutex_unlock(&search_mutex_array[i]);
        err = pthread_join(search_thread_array[i],NULL);
        if(err != 0)
        {
            printf("can not join with thread %d:%s\n", i,strerror(err));
        }
		pthread_mutex_destroy(&search_mutex_array[i]);
		pthread_cond_destroy(&search_cond_array[i]);
    }
	free(search_mutex_array);
	free(search_cond_array);
	free(search_thread_array);
	free(search_added_array);
}

/*
*   Search Text or Binary Data for Pattern matches
*  	Add New Tasks for Threads 
*/
int
_acsmSearch (ACSM_STRUCT3 * acsm, int rank, int index, int n,
            int (*Match)(void * id, void *tree, int index, void *data, void *neg_list),
            void *data, int* current_state )
{   
	int state = 0;
    ACSM_PATTERN * mlist;
    unsigned char *Tend,*T;
    ACSM_STATETABLE3 * StateTable = acsm->acsmStateTable;
    int nfound = 0;

    T = Tc[rank];
    Tend = T + n;

    if ( !current_state )
    {
        return 0;
    }

    state = *current_state;

    for (; T < Tend; T++)
    {
        state = StateTable[state].NextState[*T];

        if( StateTable[state].MatchList != NULL )
        {
            mlist = StateTable[state].MatchList;
            index = index + T - mlist->n + 1 - Tc[rank];
            nfound++;
            if (Match (mlist->udata->id, mlist->rule_option_tree, index, data, mlist->neg_list) > 0)
            {
                *current_state = state;
                return nfound;
            }
        }
    }
    *current_state = state;
    return nfound;

}

int
_acsmSearchWithDepthcompare (ACSM_STRUCT3 * acsm, int rank,int index, int n,
            int (*Match)(void * id, void *tree, int index, void *data, void *neg_list),
            void *data, int* current_state )
{   

	int state = 0,step = 0;
    ACSM_PATTERN * mlist;
    unsigned char *Tend,*T;
    ACSM_STATETABLE3 * StateTable = acsm->acsmStateTable;
    int nfound = 0;
   
    T = Tc[rank];
    Tend = T + n;

    if ( !current_state )
    {
        return 0;
    }

    state = *current_state;

    for (; T < Tend; T++)
    {
    	step++;
        state = StateTable[state].NextState[*T];
        
		if(step >= StateTable[state].Depth)
			return nfound;

        if( StateTable[state].MatchList != NULL )
        {
            mlist = StateTable[state].MatchList;
            index = index + T - mlist->n + 1 - Tc[rank];
            nfound++;
            if (Match (mlist->udata->id, mlist->rule_option_tree, index, data, mlist->neg_list) > 0)
            {
                *current_state = state;
                return nfound;
            }
        }
    }
    *current_state = state;
    return nfound;
}

/*
*  callback function
*/ 
static void*
_multiThread(void * args)
{
	int rank = (int)(intptr_t)args;
	int state;
	int len;        //fragments length
	int index;      //fragment begin position in each packet
//	int nfound;
	TASK *t = &search_task;
	pthread_mutex_t *mutex = &search_mutex_array[rank];
	pthread_cond_t *cond = &search_cond_array[rank];
	
	while(1)
	{
		pthread_mutex_lock(mutex);
		while(!search_added_array[rank] && !StopSearch) 
		{
            printf("rank %d !search added \n",rank);
       /*     if(StopSearch)
            {
                pthread_mutex_unlock(mutex);
                return NULL;
            }
            */
            printf("rank %d cond wait \n",rank);
			pthread_cond_wait(cond,mutex);
		}
        if(!search_added_array[rank] && StopSearch)
        {
            pthread_mutex_unlock(mutex);
            break;
        }
		search_added_array[rank] = 0;
		pthread_mutex_unlock(mutex);
		
		state = *(t->current_state);
		len = t->n / thread_num;
		index = len * rank;
		if(rank < thread_num - 1)
		{
			ConvertCaseEx(Tc[rank],t->T + index,len + MAX_PATTERN_LEN - 1);	//case conversion
			_acsmSearch(t->acsm,rank,index,len,t->Match,t->data,&state);
			_acsmSearchWithDepthcompare(t->acsm,rank,index + len,MAX_PATTERN_LEN - 1,t->Match,t->data,&state);
		}
		else
		{
			len = t->n - index;
			ConvertCaseEx(Tc[rank],t->T + index,len);	//case conversion
			_acsmSearch(t->acsm,rank,index,len,t->Match,t->data,&state);
		}
		*(t->current_state) = state;
		
		pthread_barrier_wait(&thread_barrier);
		if(rank == 0)
		{
			pthread_mutex_lock(&packet_mutex);
			packet_finished = 1;
			pthread_mutex_unlock(&packet_mutex);
			pthread_cond_signal(&packet_cond);
		}	
	}
//	return NULL;
}

/*
*
*/
static ACSM_PATTERN *
CopyMatchListEntry (ACSM_PATTERN * px)
{
  ACSM_PATTERN * p;
  p = (ACSM_PATTERN *) AC_MALLOC (sizeof (ACSM_PATTERN));
  MEMASSERT (p, "CopyMatchListEntry");
  memcpy (p, px, sizeof (ACSM_PATTERN));
  px->udata->ref_count++;
  p->next = 0;
  return p;
}


/*
*  Add a pattern to the list of patterns terminated at this state.
*  Insert at front of list.
*/
static void
AddMatchListEntry (ACSM_STRUCT3 * acsm, int state, ACSM_PATTERN * px)
{
  ACSM_PATTERN * p;
  p = (ACSM_PATTERN *) AC_MALLOC (sizeof (ACSM_PATTERN));
  MEMASSERT (p, "AddMatchListEntry");
  memcpy (p, px, sizeof (ACSM_PATTERN));
  p->next = acsm->acsmStateTable[state].MatchList;
  acsm->acsmStateTable[state].MatchList = p;
}


/*
   Add Pattern States
*/
static void
AddPatternStates (ACSM_STRUCT3 * acsm, ACSM_PATTERN * p)
{
  unsigned char *pattern;
  int state=0, next, n;
  n = p->n;
  pattern = p->patrn;
  acsm->acsmStateTable[0].Depth= 0;

    /*
     *  Match up pattern with existing states
     */
    for (; n > 0; pattern++, n--)
    {
      next = acsm->acsmStateTable[state].NextState[*pattern];
      if (next == ACSM_FAIL_STATE)
        break;
      state = next;
    }

    /*
     *   Add new states for the rest of the pattern bytes, 1 state per byte
     */
    for (; n > 0; pattern++, n--)
    {
      acsm->acsmNumStates++;
      acsm->acsmStateTable[state].NextState[*pattern] = acsm->acsmNumStates;
      acsm->acsmStateTable[acsm->acsmNumStates].Depth = acsm->acsmStateTable[state].Depth + 1;
      state = acsm->acsmNumStates;
    }

  AddMatchListEntry (acsm, state, p);
}


/*
*   Build Non-Deterministic Finite Automata
*/
static void
Build_NFA (ACSM_STRUCT3 * acsm)
{
  int r, s;
  int i;
  QUEUE q, *queue = &q;
  ACSM_PATTERN * mlist=0;
  ACSM_PATTERN * px=0;

    /* Init a Queue */
    queue_init (queue);

    /* Add the state 0 transitions 1st */
    for (i = 0; i < ALPHABET_SIZE; i++)
    {
      s = acsm->acsmStateTable[0].NextState[i];
      if (s)
      {
        queue_add (queue,(void *)(intptr_t)s);
        acsm->acsmStateTable[s].FailState = 0;
      }
    }

    /* Build the fail state transitions for each valid state */
    while (queue_count (queue) > 0)
    {
      r = (int)(intptr_t)queue_remove (queue);

      /* Find Final States for any Failure */
      for (i = 0; i < ALPHABET_SIZE; i++)
      {
        int fs, next;
        if ((s = acsm->acsmStateTable[r].NextState[i]) != ACSM_FAIL_STATE)
        {
          queue_add (queue, (void *)(intptr_t)s);
          fs = acsm->acsmStateTable[r].FailState;

          /*
           *  Locate the next valid state for 'i' starting at s
           */
          while ((next=acsm->acsmStateTable[fs].NextState[i]) ==
                 ACSM_FAIL_STATE)
          {
            fs = acsm->acsmStateTable[fs].FailState;
          }

          /*
           *  Update 's' state failure state to point to the next valid state
           */
          acsm->acsmStateTable[s].FailState = next;

          /*
           *  Copy 'next'states MatchList to 's' states MatchList,
           *  we copy them so each list can be AC_FREE'd later,
           *  else we could just manipulate pointers to fake the copy.
           */
          for (mlist  = acsm->acsmStateTable[next].MatchList;
               mlist != NULL ;
               mlist  = mlist->next)
          {
              px = CopyMatchListEntry (mlist);

              if( !px )
              {
                FatalError("*** Out of memory Initializing Aho Corasick in acsmx.c ****");
              }

              /* Insert at front of MatchList */
              px->next = acsm->acsmStateTable[s].MatchList;
              acsm->acsmStateTable[s].MatchList = px;
          }
        }
      }
    }

    /* Clean up the queue */
    queue_free (queue);
}


/*
*   Build Deterministic Finite Automata from NFA
*/
static void
Convert_NFA_To_DFA (ACSM_STRUCT3 * acsm)
{
  int r, s;
  int i;
  QUEUE q, *queue = &q;

    /* Init a Queue */
    queue_init (queue);

    /* Add the state 0 transitions 1st */
    for (i = 0; i < ALPHABET_SIZE; i++)
    {
      s = acsm->acsmStateTable[0].NextState[i];
      if (s)
      {
        queue_add (queue, (void *)(intptr_t)s);
      }
    }

    /* Start building the next layer of transitions */
    while (queue_count (queue) > 0)
    {
      r = (int)(intptr_t)queue_remove (queue);

      /* State is a branch state */
      for (i = 0; i < ALPHABET_SIZE; i++)
      {
        if ((s = acsm->acsmStateTable[r].NextState[i]) != ACSM_FAIL_STATE)
        {
            queue_add (queue, (void *)(intptr_t)s);
        }
        else
        {
            acsm->acsmStateTable[r].NextState[i] =
            acsm->acsmStateTable[acsm->acsmStateTable[r].FailState].
            NextState[i];
        }
      }
    }

    /* Clean up the queue */
    queue_free (queue);
}


/*
*
*/
ACSM_STRUCT3 * acsmNew3 (void (*userfree)(void *p),
                       void (*optiontreefree)(void **p),
                       void (*neg_list_free)(void **p))
{
  ACSM_STRUCT3 * p;
  init_xlatcase ();
  p = (ACSM_STRUCT3 *) AC_MALLOC (sizeof (ACSM_STRUCT3));
  MEMASSERT (p, "acsmNew");
  if (p)
  {
    memset (p, 0, sizeof (ACSM_STRUCT3));
    p->userfree              = userfree;
    p->optiontreefree        = optiontreefree;
    p->neg_list_free         = neg_list_free;
  }
  return p;
}


/*
*   Add a pattern to the list of patterns for this state machine
*/
int
acsmAddPattern3 (ACSM_STRUCT3 * p, unsigned char *pat, int n, int nocase,
            int offset, int depth, int negative, void * id, int iid)
{
  ACSM_PATTERN * plist;
  plist = (ACSM_PATTERN *) AC_MALLOC (sizeof (ACSM_PATTERN));
  MEMASSERT (plist, "acsmAddPattern");
  plist->patrn = (unsigned char *) AC_MALLOC (n);
  ConvertCaseEx (plist->patrn, pat, n);
  plist->casepatrn = (unsigned char *) AC_MALLOC (n);
  memcpy (plist->casepatrn, pat, n);

  plist->udata = (ACSM_USERDATA *)AC_MALLOC(sizeof(ACSM_USERDATA));
  MEMASSERT (plist->udata, "acsmAddPattern");
  plist->udata->ref_count = 1;
  plist->udata->id = id;

  plist->n = n;
  plist->nocase = nocase;
  plist->negative = negative;
  plist->offset = offset;
  plist->depth = depth;
  plist->iid = iid;
  plist->next = p->acsmPatterns;
  p->acsmPatterns = plist;
  p->numPatterns++;
  return 0;
}

static int acsmBuildMatchStateTrees( ACSM_STRUCT3 * acsm,
                                     int (*build_tree)(void * id, void **existing_tree),
                                     int (*neg_list_func)(void *id, void **list) )
{
    int i, cnt = 0;
    ACSM_PATTERN * mlist;

    /* Find the states that have a MatchList */
    for (i = 0; i < acsm->acsmMaxStates; i++)
    {
        for ( mlist=acsm->acsmStateTable[i].MatchList;
              mlist!=NULL;
              mlist=mlist->next )
        {
            if (mlist->udata->id)
            {
                if (mlist->negative)
                {
                    neg_list_func(mlist->udata->id, &acsm->acsmStateTable[i].MatchList->neg_list);
                }
                else
                {
                    build_tree(mlist->udata->id, &acsm->acsmStateTable[i].MatchList->rule_option_tree);
                }
            }

            cnt++;
        }

        if (acsm->acsmStateTable[i].MatchList)
        {
            /* Last call to finalize the tree */
            build_tree(NULL, &acsm->acsmStateTable[i].MatchList->rule_option_tree);
        }
    }

    return cnt;
}

static int acsmBuildMatchStateTreesWithSnortConf( struct _SnortConfig *sc, ACSM_STRUCT3 * acsm,
                                                  int (*build_tree)(struct _SnortConfig *, void * id, void **existing_tree),
                                                  int (*neg_list_func)(void *id, void **list) )
{
    int i, cnt = 0;
    ACSM_PATTERN * mlist;

    /* Find the states that have a MatchList */
    for (i = 0; i < acsm->acsmMaxStates; i++)
    {
        for ( mlist=acsm->acsmStateTable[i].MatchList;
              mlist!=NULL;
              mlist=mlist->next )
        {
            if (mlist->udata->id)
            {
                if (mlist->negative)
                {
                    neg_list_func(mlist->udata->id, &acsm->acsmStateTable[i].MatchList->neg_list);
                }
                else
                {
                    build_tree(sc, mlist->udata->id, &acsm->acsmStateTable[i].MatchList->rule_option_tree);
                }
            }

            cnt++;
        }

        if (acsm->acsmStateTable[i].MatchList)
        {
            /* Last call to finalize the tree */
            build_tree(sc, NULL, &acsm->acsmStateTable[i].MatchList->rule_option_tree);
        }
    }

    return cnt;
}


/*
*   Compile State Machine
*/
static inline int
_acsmCompile (ACSM_STRUCT3 * acsm)
{
    int i, k;
    ACSM_PATTERN * plist;

    /* Count number of states */
    acsm->acsmMaxStates = 1;
    for (plist = acsm->acsmPatterns; plist != NULL; plist = plist->next)
    {
        acsm->acsmMaxStates += plist->n;
    }
    acsm->acsmStateTable =
        (ACSM_STATETABLE3 *) AC_MALLOC (sizeof (ACSM_STATETABLE3) *
                                        acsm->acsmMaxStates);
    MEMASSERT (acsm->acsmStateTable, "acsmCompile");
    memset (acsm->acsmStateTable, 0,
        sizeof (ACSM_STATETABLE3) * acsm->acsmMaxStates);

    /* Initialize state zero as a branch */
    acsm->acsmNumStates = 0;

    /* Initialize all States NextStates to FAILED */
    for (k = 0; k < acsm->acsmMaxStates; k++)
    {
        for (i = 0; i < ALPHABET_SIZE; i++)
        {
            acsm->acsmStateTable[k].NextState[i] = ACSM_FAIL_STATE;
        }
    }

    /* Add each Pattern to the State Table */
    for (plist = acsm->acsmPatterns; plist != NULL; plist = plist->next)
    {
        AddPatternStates (acsm, plist);
    }

    /* Set all failed state transitions to return to the 0'th state */
    for (i = 0; i < ALPHABET_SIZE; i++)
    {
        if (acsm->acsmStateTable[0].NextState[i] == ACSM_FAIL_STATE)
        {
            acsm->acsmStateTable[0].NextState[i] = 0;
        }
    }

    /* Build the NFA  */
    Build_NFA (acsm);

    /* Convert the NFA to a DFA */
    Convert_NFA_To_DFA (acsm);

    /*
      printf ("ACSMX-Max Memory: %d bytes, %d states\n", max_memory,
        acsm->acsmMaxStates);
     */

    //Print_DFA( acsm );

    return 0;
}

int
acsmCompile3 (ACSM_STRUCT3 * acsm,
             int (*build_tree)(void * id, void **existing_tree),
             int (*neg_list_func)(void *id, void **list))
{
    int rval;

    if ((rval = _acsmCompile (acsm)))
        return rval;

    if (build_tree && neg_list_func)
    {
        acsmBuildMatchStateTrees(acsm, build_tree, neg_list_func);
    }

    return 0;
}

int
acsmCompileWithSnortConf3 (struct _SnortConfig *sc, ACSM_STRUCT3 * acsm,
                          int (*build_tree)(struct _SnortConfig *, void * id, void **existing_tree),
                          int (*neg_list_func)(void *id, void **list))
{
    int rval;

    if ((rval = _acsmCompile (acsm)))
        return rval;

    if (build_tree && neg_list_func)
    {
        acsmBuildMatchStateTreesWithSnortConf(sc, acsm, build_tree, neg_list_func);
    }

    return 0;
}

/*
*   Search Text or Binary Data for Pattern matches
*  	Add New Tasks for Threads 
*/
int
acsmSearch3 (ACSM_STRUCT3 * acsm, unsigned char *Tx, int n,
            int (*Match)(void * id, void *tree, int index, void *data, void *neg_list),
            void *data, int* current_state )
{
	int i;
    TASK *t = &search_task;
    t->acsm = acsm;
    t->T = Tx;
    t->n = n;
    t->Match = Match;
    t->data = data;
    t->current_state = current_state;
    
    for(i = 0; i < thread_num;i++)
    {
    	pthread_mutex_lock(&search_mutex_array[i]);
    	search_added_array[i] = 1;
    	pthread_cond_signal(&search_cond_array[i]);
    	pthread_mutex_unlock(&search_mutex_array[i]);
    }
    
    pthread_mutex_lock(&packet_mutex);
   	while(!packet_finished)
   		pthread_cond_wait(&packet_cond,&packet_mutex);
	packet_finished = 0;
   	pthread_mutex_unlock(&packet_mutex);
    
	return 0;  //o or 1 ? 
}


/*
*   Free all memory
*/
void
acsmFree3 (ACSM_STRUCT3 * acsm)
{
    int i;
    ACSM_PATTERN * mlist, *ilist;
    
    
	for (i = 0; i < acsm->acsmMaxStates; i++)
    {
        mlist = acsm->acsmStateTable[i].MatchList;
        while (mlist)
        {
            ilist = mlist;
            mlist = mlist->next;

            ilist->udata->ref_count--;
            if (ilist->udata->ref_count == 0)
            {
                if (acsm->userfree && ilist->udata->id)
                    acsm->userfree(ilist->udata->id);

                AC_FREE(ilist->udata);
            }

            if (ilist->rule_option_tree && acsm->optiontreefree)
            {
                acsm->optiontreefree(&(ilist->rule_option_tree));
            }

            if (ilist->neg_list && acsm->neg_list_free)
            {
                acsm->neg_list_free(&(ilist->neg_list));
            }

            AC_FREE (ilist);
        }
    }
    AC_FREE (acsm->acsmStateTable);
    mlist = acsm->acsmPatterns;
    while(mlist)
    {
        ilist = mlist;
        mlist = mlist->next;
        AC_FREE(ilist->patrn);
        AC_FREE(ilist->casepatrn);
        AC_FREE(ilist);
    }
    AC_FREE (acsm);
}

int acsmPatternCount3 ( ACSM_STRUCT3 * acsm )
{
    return acsm->numPatterns;
}


int acsmPrintSummaryInfo3(void)
{
#ifdef XXXXX
    char * fsa[]={
      "TRIE",
      "NFA",
      "DFA",
    };

    ACSM_STRUCT * p = &summary.acsm;

    if( !summary.num_states )
        return;

    LogMessage("+--[Pattern Matcher:Aho-Corasick Summary]----------------------\n");
    LogMessage("| Alphabet Size    : %d Chars\n",p->acsmAlphabetSize);
    LogMessage("| Sizeof State     : %d bytes\n",sizeof(acstate_t));
    LogMessage("| Storage Format   : %s \n",sf[ p->acsmFormat ]);
    LogMessage("| Num States       : %d\n",summary.num_states);
    LogMessage("| Num Transitions  : %d\n",summary.num_transitions);
    LogMessage("| State Density    : %.1f%%\n",100.0*(double)summary.num_transitions/(summary.num_states*p->acsmAlphabetSize));
    LogMessage("| Finite Automatum : %s\n", fsa[p->acsmFSA]);
    if( max_memory < 1024*1024 )
    LogMessage("| Memory           : %.2fKbytes\n", (float)max_memory/1024 );
    else
    LogMessage("| Memory           : %.2fMbytes\n", (float)max_memory/(1024*1024) );
    LogMessage("+-------------------------------------------------------------\n");

#endif
    return 0;
}


#ifdef ACSMX_MAIN

/*
*  Text Data Buffer
*/
unsigned char text[512];

/*
*    A Match is found
*/
  int
MatchFound (unsigned id, int index, void *data)
{
  fprintf (stdout, "%s\n", (char *) id);
  return 0;
}


/*
*
*/
  int
main (int argc, char **argv)
{
  int i, nocase = 0;
  ACSM_STRUCT * acsm;
  if (argc < 3)

    {
      fprintf (stderr,
        "Usage: acsmx pattern word-1 word-2 ... word-n  -nocase\n");
      exit (0);
    }
  acsm = acsmNew ();
  strcpy (text, argv[1]);
  for (i = 1; i < argc; i++)
    if (strcmp (argv[i], "-nocase") == 0)
      nocase = 1;
  for (i = 2; i < argc; i++)

    {
      if (argv[i][0] == '-')
    continue;
      acsmAddPattern (acsm, argv[i], strlen (argv[i]), nocase, 0, 0,
            argv[i], i - 2);
    }
  acsmCompile (acsm);
  acsmSearch (acsm, text, strlen (text), MatchFound, (void *) 0);
  acsmFree (acsm);
  printf ("normal pgm end\n");
  return (0);
}
#endif /*  */

