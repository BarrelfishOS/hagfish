#ifndef __HAGFISH_UTIL_H
#define __HAGFISH_UTIL_H

#define COVER(x, y) (((x) + ((y)-1)) / (y))
#define ROUNDUP(x, y) (COVER(x,y) * (y))

#endif /* __HAGFISH_UTIL_H */
