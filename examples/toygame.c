// A tiny "game" to practise on. TUTORIAL.md walks through it.
//
//   gcc -O1 -o toygame examples/toygame.c && ./toygame &
//   patty toygame
//
// `kill -USR1 <pid>` makes the player take 10 damage.
//
// Build with -DPATCH to get "version 1.1": a new field in Player and a new
// global, the kind of change that moves offsets around in a real update.
//
// It allows any process of yours to read it (PR_SET_PTRACER_ANY), so all of
// this works without setup.sh. The signatures in toygame.json come from a
// gcc 15 -O1 build; other compilers may need different ones.

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>

typedef struct Player {
#ifdef PATCH
    int team;  // new in 1.1, everything below moves
#endif
    float health;
    int level;
    const char* name;
    struct Player* target;
} Player;

Player* g_local;
#ifdef PATCH
Player* g_spectating;  // new in 1.1; gcc lays it out in front of g_local

// Also new in 1.1, and it pushes tick() further into the binary.
__attribute__((noinline)) int same_team(const Player* a, const Player* b) { return a->team == b->team; }
#endif

__attribute__((noinline)) float tick(void) { return g_local ? g_local->health : 0.0f; }

static void take_damage(int signal_number) {
    (void)signal_number;
    g_local->health -= 10.0f;
}

int main(void) {
    // Demo only: let a process outside our tree read us under ptrace_scope=1.
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);

    Player* enemy = calloc(1, sizeof *enemy);
    enemy->health = 40.0f;
    enemy->level = 3;
    enemy->name = "Grunt";

    g_local = calloc(1, sizeof *g_local);
    g_local->health = 87.5f;
    g_local->level = 12;
    g_local->name = "PlayerOne";
    g_local->target = enemy;
#ifdef PATCH
    g_local->team = enemy->team = 1;
    g_spectating = same_team(g_local, enemy) ? enemy : NULL;
#endif

#ifdef PATCH
    printf("toygame 1.1, pid %d\n", getpid());
#else
    printf("toygame 1.0, pid %d\n", getpid());
#endif
    fflush(stdout);
    signal(SIGUSR1, take_damage);
    for (;;) {
        if (tick() <= 0.0f)
            puts("game over");
        sleep(1);
    }
}
