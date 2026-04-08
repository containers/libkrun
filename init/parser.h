#ifndef PARSER_H
#define PARSER_H

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CONFIG_FILE_PATH "/.krun_config.json"
#define MAX_TOKENS 16384

int config_parse_file(char ***argv, char **workdir);

#endif
