/* not included in any kernel headers */
#ifndef AF_MPLS
# define AF_MPLS 28
#endif

#ifdef RD_DEFAULT
#define VRF_DEFAULT_ID RD_DEFAULT
#else
#define VRF_DEFAULT_ID 1
#endif
