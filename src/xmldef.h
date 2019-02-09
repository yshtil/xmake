#include <stdio.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

extern void xml_add_dep (xmlNodePtr nodep, struct dep *);
extern void xml_add_warning(const char *, struct file *);
extern void xml_add_info(const char *);
extern void xml_error(const char *);
extern xmlNodePtr xml_add_goal(struct file *);
extern void xml_add_command(struct file *, char *, unsigned char);
extern void xml_start(void);
extern void xml_finish(void);
extern void xml_print_variable (const void *item, void *arg);
extern int xml_load_file(const char **ldname);
extern void xml_add_directory(const char *);
