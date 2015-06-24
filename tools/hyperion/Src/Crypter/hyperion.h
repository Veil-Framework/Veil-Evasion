#ifndef HYPERION_H_INCLUDED
#define HYPERION_H_INCLUDED

#include "fileaccess.h"
#include "peanalysis.h"
#include "createoutput.h"
#include "pe.h"
#include "ostreamlog.h"

#define INFILE_SIZE_INC "Src\\FasmContainer32\\infile_size.inc"
#define INFILE_SIZE_LABEL "INFILE_SIZE"

#define IMAGE_BASE_INC "Src\\FasmContainer32\\image_base.inc"
#define IMAGE_BASE_LABEL "IMAGE_BASE"

#define CONTAINER_MAIN "Src\\FasmContainer32\\main.asm"

#define IMAGE_SIZE_INC "Src\\FasmContainer32\\image_size.inc"
#define IMAGE_SIZE_LABEL "IMAGE_SIZE"

#define KEY_SIZE_INC "Src\\FasmContainer32\\key_size.inc"

#define INFILE_CODE "Src\\FasmContainer32\\infile_code.asm"
#define INFILE_ARRAY "Src\\FasmContainer32\\infile_array.inc"

#define LOGFILE_SELECT_INC "Src\\FasmContainer32\\logfile_select.asm"

#define FASM_EXECUTABLE "Fasm\\FASM.EXE"

#endif // HYPERION_H_INCLUDED
