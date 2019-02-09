#include <assert.h>
#include "makeint.h"
#include "job.h"
#include "filedef.h"
#include "commands.h"
#include "variable.h"
#include "dep.h"
#include "xmldef.h"
#include <sys/types.h>
#include <sys/wait.h>

extern const char *xml_prefix;
extern int soft_error;
extern int wait_job_inprogress_flag;

static xmlDocPtr doc;
static xmlNodePtr root_node, phony_node = NULL;
static char *parse_error = NULL;
extern char *template;
extern struct file *new_job_file;
extern int posix_pedantic;
static int recurse_double_goal;
extern const floc *reading_file;
const char *program;
extern floc *current_floc;
extern unsigned char nonfatal_error;
extern int one_shell;

static void set_content(xmlNodePtr node, const char *value) {

  /* Set content */
  xmlChar * out = xmlEncodeEntitiesReentrant (doc, (const xmlChar *) value);
  xmlNodeSetContent(node, out);
  free(out);
}

void xml_start () {
  /* 
   * Creates a new document, a node and set it as a root node
   */
  doc = xmlNewDoc(BAD_CAST "1.0");
  root_node = xmlNewNode(NULL, BAD_CAST "root");
  xmlDocSetRootElement(doc, root_node);

  /* Add origin */
  {
    xmlNodePtr node = xmlNewTextChild(root_node,
                                      NULL,
                                      (const xmlChar *) "Origin", 
                                      NULL);

    /* Set content */
    set_content(node, program);
  }

  /* Add WaitJobsInProgress */
  {
    xmlNodePtr node = xmlNewTextChild(root_node,
                                      NULL,
                                      (const xmlChar *) "WaitJobsInProgress", 
                                      NULL);

    /* Set content */
    set_content(node, wait_job_inprogress_flag ? "1" : 0);
  }

  /* Add ONESHELL */
  {
    xmlNodePtr node = xmlNewTextChild(root_node,
                                      NULL,
                                      (const xmlChar *) "OneShell", 
                                      NULL);

    /* Set content */
    set_content(node, one_shell ? "1" : "0");
  }
}

/* Print XML and exit with 0, errors must be handled by the consumer of XML */
void xml_finish () {
  /* Add parse errors
     if (parse_error)
     xml_add_warning(parse_error);
     * Dump document to stdio
     */

  /* Add POSIX */
  if (posix_pedantic) {
    xmlNodePtr node = xmlNewTextChild(root_node, 
                                      NULL,
                                      (const xmlChar *) "Goal", 
                                      NULL);

    /* Add name attribute */
    xmlSetProp( node, 
                (const xmlChar *) "name", 
                (const xmlChar *) ".POSIX");
  }

  xmlSaveFormatFileEnc("-", doc, "UTF-8", 1);
  
  /*free the document */
  xmlFreeDoc(doc);

  exit(0);

}

/* Arg is file if any */
void
xml_print_variable (const void *item, void *arg)
{
  struct variable *v = (struct variable *) item;
  struct file *f = (struct file *)arg;
  xmlNodePtr parent, node;
  int export = 0;
  short found = 0;

  if (v->origin == o_automatic)
    return;

  if (!strcmp(v->name, "SHELL") && (!new_job_file || !v->fileinfo.filenm))
    return;

  /* Proceed if no prefix, or prefix matched */
  /* Always print exported variables */
  if (v->export != v_noexport && ((v->export == v_export) || (v->origin == o_command) || export_all_variables)) {
    export = 1;
    found = 1;
  } else if (v->export == v_noexport) {
    export = 0; /* Always print noexport */
    found = 1;
    }
  else if (!strcmp(v->name, ".DEFAULT_GOAL")
           || !strcmp(v->name, "MAKECMDGOALS")
           || !strcmp(v->name, ".SHELLFLAGS")
           || v->per_target) /* per target always */
    found = 1;
  else if (!strcmp(v->name, "MAKELEVEL")) {
    found = 1;
    export = 1;
    }

  if (!found && (!strcmp(xml_prefix, "-") || !strncmp(v->name, xml_prefix, strlen(xml_prefix))))
    found = 1;
        
  if (!found)
    return;

  /* Do not output empty .DEFAULT_GOAL */
  if (!strcmp(v->name, ".DEFAULT_GOAL") && v->value[0] == '\0')
    return;

  parent = f ? f->xml_ctxt : root_node;
  
  node = xmlNewTextChild(parent, 
                         NULL,
                         (const xmlChar *) "Variable", 
                         NULL);
  
  /* Add name attribute */
  xmlSetProp( node, (const xmlChar *) "name", (const xmlChar *) v->name);

  /* And export if needed */
  if (export)
    xmlSetProp( node, (const xmlChar *) "export", (const xmlChar *) "1");
  else if (getenv(v->name))
    xmlSetProp( node, (const xmlChar *) "export", (const xmlChar *) "0");

  if (v->recursive)
    xmlSetProp( node, (const xmlChar *) "recursive", (const xmlChar *) "1");

  /* if (!strcmp(v->name, "SHELL")) */
  /*   if (v->fileinfo.filenm) */
  /*     xmlSetProp( node, (const xmlChar *) "shell", (const xmlChar *) "1"); */
    
  /* Expand */
  if (export)
  {
    const char *expanded;
    /* Below breaks explicit */
    expanded = recursively_expand_for_file(v, f);

    set_content(node, expanded);
  } else
    set_content(node, v->value);
}

void xml_add_warning (const char *msg, struct file *file)
{
  floc *fl;
  xmlNodePtr parent = file ? file->xml_ctxt : root_node;
  xmlNodePtr node = xmlNewTextChild(parent, 
                                    NULL,
                                    (const xmlChar *) "Warning", 
                                    NULL);

  set_content(node, (char *)msg);

  if (file)
    fl = &file->cmds->fileinfo;
  else
    fl = (floc *)reading_file;
  
  /* Add location */
  {
    const char *fname = fl->filenm;
    char lnum = fl->lineno + fl->offset;
    char buf1[strlen(fname)+10];

    /* It is different for child errors, should be changed at the server executing stuff ???*/
    sprintf(buf1,"%s:%d", fname, lnum);
    xmlSetProp( node,
                (const xmlChar *) "location",
                (const xmlChar *) buf1);

  }

}

void xml_add_info (const char *msg)
{
  xmlNodePtr node = xmlNewTextChild(root_node,
                                    NULL,
                                    (const xmlChar *) "Info", 
                                    NULL);

  set_content(node, (char *)msg);
}

/* Finishes */
void xml_error (const char *msg)
{
  xmlNodePtr node = xmlNewTextChild(new_job_file ? new_job_file->xml_ctxt : root_node, 
                                    NULL,
                                    (const xmlChar *) "Error", 
                                    NULL);

  xmlChar *out = xmlEncodeEntitiesReentrant (doc, (const xmlChar *) msg);
  xmlNodeSetContent(node, out);
  free(out);

  /* Add nonfatal if needed */
  if (nonfatal_error)
    {
      xmlSetProp( node,
                  (const xmlChar *) "nonfatal",
                  (const xmlChar *) "1");

      nonfatal_error = 0;
    } else 
    {
      /* Add location attribute */

      const floc *fl = NULL;

      if (current_floc && current_floc->filenm)
        fl = current_floc;
      else if (reading_file)
        fl  = reading_file;
    
      if (fl && fl->filenm)
        {
          const char *fname = fl->filenm;
          char lnum = fl->lineno +  fl->offset;
          char buf1[strlen(fname)+10];
        
          sprintf(buf1,"%s:%d", fname, lnum);
          xmlSetProp( node,
                      (const xmlChar *) "location",
                      (const xmlChar *) buf1);
        }
    }
}

/* Creates a new text kids off root and returns it */
xmlNodePtr xml_add_goal(struct file *file)
{
  xmlNodePtr node;
  /* Command will be added later */
  /* And double colon */
  if (file->double_colon) {
    node = xmlNewTextChild(root_node, 
                           NULL,
                           (const xmlChar *) "DoubleColonGoal", 
                           NULL);
  } else
    node = xmlNewTextChild(root_node, 
                           NULL,
                           (const xmlChar *) "Goal", 
                           NULL);

  /* Add name attribute */
  xmlSetProp( node, 
              (const xmlChar *) "name", 
              (const xmlChar *) file->name);

  /* Add location attribute */
  if (file->cmds && file->cmds->fileinfo.filenm)
  {
    const char *fname = file->cmds->fileinfo.filenm;
    char lnum = file->cmds->fileinfo.lineno;
    char buf1[strlen(fname)+10];

    /* It is different for child errors, should be changed at the server executing stuff ???*/
    sprintf(buf1,"%s:%d", fname, lnum);
    xmlSetProp( node,
                (const xmlChar *) "location",
                (const xmlChar *) buf1);

  }

  /* Add phony if needed */
  if (file->phony)
    {
      struct dep *d = calloc(1, sizeof(struct dep));
      d->file = file;
      d->ignore_mtime = 0;
      if (!phony_node) {
        struct file *ff = calloc(1,sizeof(struct file));
        ff->name = ".PHONY";
        phony_node = xml_add_goal(ff);
        free(ff);
      }

      /* Add dependency */
      xml_add_dep(phony_node, d);
      free(d);
    }
  
  return node;
}

/* Adds XML dependency to goal */


void xml_add_dep (xmlNodePtr nodep, struct dep *d)
{
  xmlNodePtr node = xmlNewTextChild(nodep, 
                                    NULL,
                                    (const xmlChar *) "Prerequisite", 
                                    NULL);

  /* Set content */
  set_content(node, d->file->name);
}

/* static void process_tree(xmlNodePtr source, xmlNodePtr dest, int dc, xmlNodePtr dep) { */
/*   xmlNodePtr this = NULL, next; */
/*   /\* int i; *\/ */
/*   /\* char *print = getenv("_VERB"); *\/ */
/*   /\* char buf[level+1]; *\/ */

/*   /\* for (i=0;i<level;i++) *\/ */
/*   /\*   buf[i] = '-'; *\/ */

/*   /\* buf[i] = '\0'; *\/ */

/*   /\* if (print && (source->type == XML_ELEMENT_NODE)) *\/ */
/*   /\*   printf("\n%sStarted %s => %s\n", buf, source->name, dest->name); *\/ */
  
/*   for (this = source;this;this = this->next) { */
/*     if (this->type == XML_ELEMENT_NODE) { */
/*       xmlNodePtr newNode; */
/*       xmlAttr* attribute; */
/*       const char *ename; */
      
/*       /\* Skip default *\/ */
/*       if (!strcmp((char *)this->name, "Variable") && !strcmp((char *)xmlNodeListGetString(this->doc, this->properties->children, 1), ".DEFAULT_GOAL")) */
/*         continue; */

/*       /\* if (print) *\/ */
/*       /\*   printf("%sProcessing %s child of %s\n", buf, this->name, this->parent->name); *\/ */

/*       /\* Create new *\/ */
/*       ename = (!strcmp((char *)this->name, "Goal") && dc) ? "DoubleColonGoal" : (const char *)this->name; */
/*       newNode = xmlNewTextChild(dest,  */
/*                                 NULL, */
/*                                 (const xmlChar *) ename, */
/*                                 NULL); */

/*       /\* Transfer attributes *\/ */
/*       /\* if (print) *\/ */
/*       /\*   printf("%sCreated child %s of parent %s\n", buf, ename, dest->name); *\/ */

/*       for (attribute = this->properties;attribute && attribute->name && attribute->children;attribute = attribute->next) { */
/*         xmlChar* value = xmlNodeListGetString(this->doc, attribute->children, 1); */
/*         xmlNewProp(newNode, attribute->name, value); */
/*         /\* if (print) *\/ */
/*         /\*   printf("%sAdded attribute %s=%s\n", buf, attribute->name, value); *\/ */
        
/*         /\* Add prerequisite if needed *\/ */
/*         if (dep && !strcmp((char *)attribute->name, "name") && !strcmp((char *)this->name, "Goal")) { */
/*           xmlNodePtr prereq = xmlNewTextChild(dep,  */
/*                                               NULL, */
/*                                               (const xmlChar *) "Prerequisite",  */
/*                                               NULL); */
/*           /\* Set content *\/ */
/*           set_content(prereq, value); */
/*         } */

/*         xmlFree(value);       */
/*       } */

/*       /\* And content for Command and variable  *\/ */
/*       if (!strcmp((char *)this->name, "Command") || !strcmp((char *)this->name, "Variable")) { */
/*         const xmlChar * cont = xmlNodeGetContent(this);  */
/*         xmlNodeSetContent(newNode, cont); */
/*         /\* if (print) *\/ */
/*         /\*   printf("%sAdded content %s\n", buf, cont); *\/ */
/*       } */

/*       for (next = this->children;next;next = next->next) */
/*         if (next->type == XML_ELEMENT_NODE) */
/*           process_tree(next, newNode, dc, NULL); */

/*       /\* if (print) *\/ */
/*       /\*   printf("%sMoving to next\n", buf); *\/ */
/*     }  */
/*   } */

/*   /\* if (print) *\/ */
/*   /\*   printf("\n%sFinished %s => %s\n", buf, source->name, dest->name); *\/ */

/*   /\* Unlink it *\/ */
/*   xmlUnlinkNode(source); */
/*   xmlFreeNode(source); */
      
/* } */

/* void merge_xml(struct file *file, char *commands, int dc) */
/* { */
/*   /\* Recurse and merge xml *\/ */
/*   char *end = NULL; */
/*   char **argv; */
/*   char **p; */
/*   int len = 0; */
/*   FILE *outfile; */
/*   char *f_nm; */
/*   char *makeval = variable_expand("$(MAKE)"); */
/*   int prog_len = strlen(makeval); */
/*   static int var_len = strlen("$(MAKE)"); */
/*   char *buf; */
/*   pid_t pid; */
/*   char **envp = target_environment (file); */

/*   int stat; */
  
/*   /\* Add -x to the command *\/ */
/*   for (p = xml_prefix;*p;p++) { */
/*     /\* Add 3 chars per -x and len + space + 2 (for quotes) per x value, quotes ignored for now *\/ */
/*     len += */
/*       5 + /\* SPACE -x SPACE QUOTE*\/ */
/*       strlen(*p)  /\* x value *\/ */
/*       + 1;        /\* End quote *\/ */
/*   } */

/*   /\* Adjust for replacing $(MAKE) with makeval *\/ */
/*   len += prog_len - var_len; */

/*   buf = malloc(strlen(commands) + 1 + len); */

/*   /\* Copy makeval *\/ */
/*   strcpy(buf, makeval); */

/*   /\* Copy args *\/ */
/*   strcpy(buf+prog_len, commands+var_len); */
/*   for (p = xml_prefix;*p;p++) { */
/*     strcat(buf, " -x \""); /\* Space -x space open quote*\/ */
/*     strcat(buf, *p);       /\* value *\/ */
/*     strcat(buf, "\"");     /\* Close quote *\/ */
/*   } */

/*   commands = realloc(commands, strlen(buf) + 1); */
/*   strcpy(commands, buf); */
/*   free(buf); */

/*   argv = construct_command_argv (commands, &end, file, */
/*                                  1, */
/*                                  &end); */
/*   /\* Get output file *\/ */
/*   outfile = get_tmpfile (&f_nm, template); */
/*   if (outfile == 0) */
/*     pfatal_with_name (_("fopen (temporary file)")); */

/*   /\* Fork and redirect into the file *\/ */
      
/*   pid = fork(); */

/*   if (pid == -1) { */
/*     perror("fork()"); */
/*   } */
/*   else if (pid == 0) { */
/*     /\* Child *\/ */
/*     dup2(fileno(outfile), 1);   /\* redirect child stdout to out[1] *\/ */
/*     dup2(fileno(outfile), 2);   /\* redirect child stderr to out1[1] *\/ */
/*     execve("/bin/sh", argv, envp);  /\* actual command execution *\/ */
/*     perror("execve()"); */
/*   } */

/*   /\* Parent, wait for completion *\/ */
/*   pid = wait(&stat); */
/*   if (WEXITSTATUS(stat)) { */
/*     printf("FAILED\n"); */
/*     return; /\* What to do ? *\/ */
/*   } */

/*   /\* Create new document *\/ */
/*   { */
/*     xmlDocPtr newdoc = xmlReadFile(f_nm, NULL, 0); */
/*     xmlNodePtr newroot = xmlDocGetRootElement(newdoc); */

/*     /\* Process recursively *\/ */
/*     process_tree(newroot->children, root_node, dc, file->xml_ctxt); */
/*     xmlFreeDoc(newdoc); */
/*   } */

/*   /\* Reads the file *\/ */
/*   /\* { *\/ */
/*   /\*   static xmlSAXHandler my_handler =  { *\/ */
/*   /\*     NULL, /\\* internalSubsetSAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* isStandaloneSAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* hasInternalSubsetSAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* hasExternalSubsetSAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* resolveEntitySAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* getEntitySAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* entityDeclSAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* notationDeclSAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* attributeDeclSAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* elementDeclSAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* unparsedEntityDeclSAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* setDocumentLocatorSAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* startDocumentSAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* endDocumentSAXFunc *\\/ *\/ */
/*   /\*     &start_element, /\\* startElementSAXFunc *\\/ *\/ */
/*   /\*     &end_element, /\\* endElementSAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* referenceSAXFunc *\\/ *\/ */
/*   /\*     &get_characters, /\\* charactersSAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* ignorableWhitespaceSAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* processingInstructionSAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* commentSAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* warningSAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* errorSAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* fatalErrorSAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* getParameterEntitySAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* cdataBlockSAXFunc *\\/ *\/ */
/*   /\*     NULL, /\\* externalSubsetSAXFunc *\\/ *\/ */
/*   /\*     0, *\/ */
/*   /\*     NULL, *\/ */
/*   /\*     NULL, /\\* startElementNsSAX2Func *\\/ *\/ */
/*   /\*     NULL, /\\* endElementNsSAX2Func *\\/ *\/ */
/*   /\*     NULL, /\\* xmlStructuredErrorFunc *\\/ *\/ */
/*   /\*   }; *\/ */

/*   /\*   int s = xmlSAXUserParseFile(&my_handler, *\/ */
/*   /\*                           NULL, *\/ */
/*   /\*                               f_nm); *\/ */

/*   unlink(f_nm); */
/* } */

void xml_add_command(struct file *file, char *command, unsigned char flags)
{
  xmlNodePtr node, nodep = file->xml_ctxt;
  const char *fname = file->cmds->fileinfo.filenm;
  char lnum = file->cmds->fileinfo.lineno;
  const char *bufp;

  node = xmlNewTextChild(nodep,
                                  NULL,
                                  (const xmlChar *) "Command",
                                  NULL);

  /* Set proper attributes */
  if (flags & COMMANDS_SILENT)
    xmlSetProp( node,
                (const xmlChar *) "silent",
                (const xmlChar *) "1");


  if (flags & COMMANDS_NOERROR)
    xmlSetProp( node,
                (const xmlChar *) "ignore_error",
                (const xmlChar *) "1");

      /* Change to double colon */
  if (recurse_double_goal)
    xmlNodeSetName(nodep, (const xmlChar *) "DoubleColonGoal");

  if (fname) {
    char buf1[strlen(fname)+10];
    sprintf(buf1,"%s;%d", fname, lnum);
    bufp = strdup(buf1);
  }
  else
    bufp = strdup("<builtin>");
    
  xmlSetProp( node,
              (const xmlChar *) "location",
              (const xmlChar *) bufp);

  free((void *)bufp);

  /* Set content */
  set_content(node, command);
}
  
int xml_load_file(const char **ldname) {
  xmlNodePtr node = xmlNewTextChild(root_node, 
                                    NULL,
                                    (const xmlChar *) "Load", 
                                    NULL);

  /* Add name attribute */
  xmlSetProp( node, 
              (const xmlChar *) "name", 
              (const xmlChar *) *ldname);

  
  return 1;
}

void xml_add_directory(const char *dir) {

  xmlNodePtr node = xmlNewTextChild(root_node, 
                                    NULL,
                                    (const xmlChar *) "Directory", 
                                    NULL);

  set_content(node, dir);
}

void 
xmlGenericErrorDefaultFunc(void *ctx ATTRIBUTE_UNUSED, const char *msg, ...) {
    va_list args;
    char buf[1000];

    if (!parse_error)
      parse_error = strdup("");

    if (xmlGenericErrorContext == NULL)
	xmlGenericErrorContext = (void *) stderr;

    va_start(args, msg);
    vsprintf(buf, msg, args);
    /*    vprintf((FILE *)xmlGenericErrorContext, msg, args); */
    va_end(args);

    parse_error = realloc(parse_error, strlen(parse_error)+ strlen(buf) + 1);
    strcpy(parse_error, buf);
}

