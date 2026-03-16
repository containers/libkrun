#ifndef PARSER_H
#define PARSER_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define CONFIG_FILE_PATH "/.krun_config.json"
#define MAX_TOKENS 16384
#define MAX_ARGS 32

int config_parse_file(char ***argv, char **workdir);

#endif
