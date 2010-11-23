#pragma once

#ifdef  __cplusplus
extern "C" {
#endif

#ifdef __GNUC__
#ifndef UNUSED
#define UNUSED __attribute__ ((unused))
#else
#error "UNUSED already defined"
#endif
#else
#define UNUSED
#endif

#ifdef  __cplusplus
}
#endif
