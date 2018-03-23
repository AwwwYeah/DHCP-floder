#ifndef __SET_SETTINGS_H__
#define __SET_SETTINGS_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "program_data.h"

#define DEF_IFACE "eth0"

/* Parsing of entered options */
struct user_opt *OptParser(char **main_arg, int arg_count, u_char *err);

/* Set the default options 
   Arguments: 1) user structure, 2) sender ip, 3) sender mac */
void InitSettings(struct user_opt *uopt, u_int s_ip, u_char *sender_mac);

/* String to MAC address */
void StrToMac(const u_char *string, u_char *mac);

void help(void);

/* Show default settings */
void ShowDefSet(void);

#endif
