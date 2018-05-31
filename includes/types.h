#ifndef DEF_TYPES_H
#define DEF_TYPES_H

#ifdef __x86_64__
typedef unsigned long long int regint;
#else
typedef long int regint;
#endif

#endif /* DEF_TYPES_H */
