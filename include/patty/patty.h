#pragma once

// patty: read-only memory pattern scanning for processes and binaries.

#include <patty/version.h>

#include "error.h"

#include "memory/region.h"
#include "memory/target.h"
#include "memory/image.h"
#include "memory/process.h"

#include "scan/pattern.h"
#include "scan/match.h"
#include "scan/resolve.h"
#include "scan/scanner.h"

#include "profile/profile.h"
#include "profile/check.h"
