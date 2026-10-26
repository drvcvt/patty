// A tiny "game" to try patty on without touching anything real.
//
//   gcc -O1 -o toygame examples/toygame.c && ./toygame &
//   patty repl --name toygame
//
// It allows any process of yours to read it (PR_SET_PTRACER_ANY), so this
// works without setup.sh. The signatures in toygame.json were taken from a
// gcc 15 -O1 build; other compilers may need new ones.

#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>

typedef struct Player {
    float health;
    int level;
    const char* name;
    struct Player* target;
} Player;

Player* g_local;

__attribute__((noinline)) float tick(void) { return g_local ? g_local->health : 0.0f; }

int main(void) {
    // Demo only: let a process outside our tree read us under ptrace_scope=1.
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
    Player* enemy = calloc(1, sizeof *enemy);
    *enemy = (Player){40.0f, 3, "Grunt", NULL};
    g_local = calloc(1, sizeof *g_local);
    *g_local = (Player){87.5f, 12, "PlayerOne", enemy};
    printf("%d\n", getpid());
    fflush(stdout);
    for (;;) {
        volatile float h = tick();
        (void)h;
        sleep(1);
    }
}
