// Built by ctest: as is it must compile; with -DPATTY_BAD_SIG or
// -DPATTY_WRONG_MEMBER it must not.
#include <patty/scan/pattern.h>

using namespace patty::literals;

#ifdef PATTY_BAD_SIG
auto signature = "48 8G ?? 05"_sig;
#else
auto signature = "48 8B ?? 05"_sig;
#endif

#ifdef PATTY_WRONG_MEMBER
#include <patty/types.h>
struct A { int x; };
struct B { int y; };
auto wrong = patty::Remote<A>(0x1000)[&B::y];  // member of another type
#endif
