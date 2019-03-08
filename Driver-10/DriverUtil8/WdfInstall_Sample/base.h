#pragma once
// C/C++ standard headers
#include <cstdint>
#include <array>
#include <string>
#include <vector>
#include <memory>
#include <iostream>
#include <sstream>
#include <iomanip>

// Other external headers
// Windows headers
#include <tchar.h>
#include <Windows.h>
#include <strsafe.h>
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

#include "../DriverUtil8/scope_exit.h"
#include "../DriverUtil8/unique_resource.h"

#pragma warning(disable : 4091)