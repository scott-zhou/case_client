MKDIR_P = mkdir -p
BIN_DIR := bin
LIB_DIR := lib

all:output_dirs \
		case_client

output_dirs: ${BIN_DIR} \
		${LIB_DIR}

${BIN_DIR}:
		${MKDIR_P} ${BIN_DIR}

${LIB_DIR}:
		${MKDIR_P} ${LIB_DIR}

case_client:case_client.c
		c99 -Wall case_client.c -g -o bin/case_client

clean:
		rm -f ${LIB_DIR}/*
		rm -f ${BIN_DIR}/*
