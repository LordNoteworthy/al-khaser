#pragma once

VOID AntiDisassmConstantCondition();
VOID AntiDisassmAsmJmpSameTarget();
VOID AntiDisassmImpossibleDiasassm();
VOID AntiDisassmFunctionPointer();
VOID AntiDisassmReturnPointerAbuse();
VOID AntiDisassmSEHMisuse();