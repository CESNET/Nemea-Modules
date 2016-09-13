/**
 * \file device_classifier.c
 * \brief Module for labeling devices according to their network traffic.
 * \author Zdenek Kasner <kasnezde@fit.cvut.cz>
 * \date 2016
 */
/*
 * Copyright (C) 2016 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */

#include "device_classifier.h"

// #define DEBUG

UR_FIELDS(
  ipaddr SRC_IP,      // Source address of a flow
  ipaddr DST_IP,      // Destination address of a flow
  uint16 SRC_PORT,    // Source transport-layer port
  uint16 DST_PORT,    // Destination transport-layer port
  uint8 PROTOCOL,     // L4 protocol (TCP, UDP, ICMP, etc.)
  uint32 PACKETS,     // Number of packets in a flow or in an interval
  uint64 BYTES,       // Number of bytes in a flow or in an interval
  time TIME_FIRST,    // Timestamp of the first packet of a flow
  time TIME_LAST,     // Timestamp of the last packet of a flow
)

trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("Device classifier","Module classifies devices according to their network behavior.",1,0)

#define MODULE_PARAMS(PARAM) \
  PARAM('a', "accumulate", "Do not discard collected statistics each time the output is generated.", no_argument, "none") \
  PARAM('f', "filter", "Classify only IP addresses (or subnets) specified in file given as parameter.", required_argument, "string") \
  PARAM('F', "file", "Save results to JSON file given as parameter.", required_argument, "string") \
  PARAM('l', "list", "Print a list of known labels and exit.", no_argument, "none") \
  PARAM('m', "minutes", "Period after which the output is generated (default 0 = no period)", required_argument, "int32") \
  PARAM('p', "peers", "Add only devices with equal or greater number of peers to output.", required_argument, "int32") \
  PARAM('t', "train", "Run in a training mode. Training rules are specified in file given as parameter.", required_argument, "string") \

// Get time in milliseconds from ur_time_t
#define TIMESTAMP(UR_TIME) \
   ((ur_time_get_sec(UR_TIME) * 1000) + (ur_time_get_msec(UR_TIME)))

#define MAX(x,y) (((x)>(y))?(x):(y))

static int stop = 0;
static uint64_t flow_cnt = 0;
int verbose;
bool generate_output = false; // SIGUSR1

// Params from cli
static int peers_threshold = 0;
static int dump_mins = 0;                                      // 0 = output only at the end of stream
static bool accumulate_stats = false;
static bool train_mode = false;


// Training data
FILE *train_db = NULL;

// Models
model_t models[MAX_MODELS];
int model_cnt = 0;              // existing models
int train_model_cnt = 0;        // existing + new models (training mode)

// Filter rules
ip_rule_t *rules = NULL;
int rule_cnt = 0;

// Whitelist rules
ip_rule_t whitelist[MAX_RESERVED_SUBNETS];
int wl_cnt = 0;

// Function to handle SIGTERM and SIGINT signals (used to stop the module)
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

// Handler for SIGUSR1 to set flag for generating the output
void generate_output_signal_handler(int signum) {
   generate_output = true;
}

// IPv4 addresses comparator
int compare_ipv4(void *a, void *b)
{
   uint32_t *h1, *h2;
   h1 = (uint32_t*)a;
   h2 = (uint32_t*)b;

   if (*h1 == *h2) {
      return EQUAL;
   }
   else if (*h1 < *h2) {
      return LESS;
   }
   return MORE;
}

// Models comparator
int cmp_models(const void * a, const void * b)
{
   return ((((model_t*)a)->id)-(((model_t*)b)->id));
}

// SVM nodes comparator
int cmp_svm_nodes(const void * a, const void * b)
{
   return ((((struct svm_node*)a)->index)-(((struct svm_node*)b)->index));
}

/**
 * Count lines in file
 *
 * @param f File in which the lines should be counted
 */
int count_lines(FILE *f) 
{
   int lines = 1;
   while(!feof(f)) {
      if(fgetc(f) == '\n') {
         lines++;
      }
   }
   rewind(f);
   return lines;
}

/**
 * Find if a rule exists in the set of rules for given IP address
 *
 * @param ip_addr IP address
 */
ip_rule_t *get_rule(ip_addr_t *ip_addr, ip_rule_t *rules, int cnt) 
{
   uint32_t mask = -1;
   uint32_t a,b;

   a = ip_get_v4_as_int(ip_addr);

   for (int i = 0; i < cnt; i++) {
      b = ip_get_v4_as_int(&(rules[i].ip_addr));

      if (rules[i].subnet != -1) {  // subnet defined
         mask = ((uint32_t) -1) << (IP_VERSION_4_BYTES * 8 - rules[i].subnet); // get mask for a subnet
         if ((a & mask) == (b & mask)) { // compare masked IP addresses
            return &(rules[i]);
         }
      } else { // subnet not defined
         if (a == b) {
            return &(rules[i]);
         }
      }
   }
   return NULL; 
}

/**
 * Get IP address and subnet mask from string
 *
 * @param buff String to parse
 * @param ip_addr Structure where IP address will be saved
 * @param subnet Integer where mask will be saved
 */
int parse_ip_with_subnet(char *buff, ip_addr_t *ip_addr, int *subnet) 
{
   char* subnet_ptr = NULL;

   // Subnet is specified
   if ((subnet_ptr = strchr(buff, '/')) != NULL) {
      if (sscanf(subnet_ptr+1, "%d", subnet) != 1) { // get subnet mask
         return -1;
      } 
      if (*subnet > IP_VERSION_4_BYTES * 8) { // check subnet mask value
         fprintf(stderr, "Error: Invalid subnet value %d\n", *subnet);
         return -1;
      }
      *subnet_ptr = '\0'; // cut the IP address
   } else {
      *subnet = -1;
   }

   if (ip_from_str(buff, ip_addr) == 0) {  // get the IP address
      return -1;
   }
   return 0;
}

/**
 * Add label to be trained. 
 * If label does not exist yet, a new label is created.
 *
 * @param label String with label
 * @param labels Rule for IP address that should be labeled
 */
void add_label(const char *label, ip_rule_t *rule) 
{
   int i;
   for (i = 0; i < train_model_cnt; i++) {
      if (strcmp(models[i].name, label) == 0) {  // label already known, use it
         rule->labels[i] = true;
         break;
      }
   }
   if (i == train_model_cnt) {  // label is not known yet, create a new label
      printf("[NEW]");
      models[i].id = train_model_cnt > 0 ? models[train_model_cnt-1].id + 1 : 1; // models are sorted by id, max is the last
      models[i].name = strdup(label);
      rule->labels[i] = true;
      train_model_cnt++;
   }
}

/**
 * Load rules from file.
 * Rules can contain only IP addresses / subnets (filtering) or IP addresses / subnets with labels (training)
 *
 * @param fname File to parse
 */
int load_rules(const char *fname) 
{
   FILE *fp_rules = NULL;
   char *line = NULL;
   char *token = NULL;
   const char *delims = " ,\n";
   size_t len = 0;
   ssize_t read = 0;

   if ((fp_rules = fopen(fname, "r")) == NULL) {
      fprintf(stderr, "Error: Filter %s cannot be opened.\n", fname);
      return -1;
   };
   rules = (ip_rule_t *) malloc(count_lines(fp_rules) * sizeof(ip_rule_t));

   printf("Filter: ");
   while (!feof(fp_rules)) {
      if ((read = getline(&line, &len, fp_rules)) <= 0) {
         break;
      } 
      token = strtok(line, delims);
      printf("%s", token);
      if (parse_ip_with_subnet(token,
                              &(rules[rule_cnt].ip_addr), 
                              &(rules[rule_cnt].subnet)) != 0) { // parse ip address
         fprintf(stderr, "Error: %s: Cannot read ip address on line %d: %s\n", fname, rule_cnt+1, token);
         return -1;
      }
      if (train_mode) {  // in training mode -> parse labels too
         printf(" -> ");
         if ((token = strtok(NULL, delims)) == NULL) {
            fprintf(stderr, "Error: No labels specified for ip address on line %d.\n", rule_cnt+1);
            return -1;
         }

         while (token != NULL) {
            printf(" %s", token);
            add_label(token, &(rules[rule_cnt]));
            token = strtok(NULL, delims);
         }
         printf("\n");
      } else {
         printf(" ");
      }
      
      rule_cnt++;
   }
   printf("\n");
   free(line);
   fclose(fp_rules);
   return 0;
}

/**
 * Load a list of existing models from text file.
 *
 * @param fname File with a list of models
 */
int init_model_list(const char *fname)
{
   FILE *fp_model_list = NULL;
   size_t len = 0;
   ssize_t read = 0;
   char *line = NULL;
   char ip_buff[100];

   if ((fp_model_list = fopen(fname, "r")) == NULL) {
      fprintf(stderr, "Error: Model list %s cannot be opened.\n", fname);
      return -1;
   }

   while (!feof(fp_model_list)) {
      if ((read = getline(&line, &len, fp_model_list)) <= 0) {
         break;
      }
      switch (line[0]) {
      case '#':
      case '\n':
         break;
      case '@':
         whitelist[wl_cnt].label_name = (char *) malloc(read * sizeof(char));

         if (sscanf(line+1, "%[^:]:%s\n", ip_buff, whitelist[wl_cnt].label_name) != 2) {
            fprintf(stderr, "Error: Model list %s is corrupted.\n", fname);
            return -1;
         }
         if (parse_ip_with_subnet(ip_buff,
                              &(whitelist[wl_cnt].ip_addr), 
                              &(whitelist[wl_cnt].subnet)) != 0) {
            fprintf(stderr, "Error: Model list %s is corrupted.\n", fname);
            return -1;
         }
         wl_cnt++;
         break;
      default:
         models[model_cnt].name = (char *) malloc(read * sizeof(char));

         if (sscanf(line, "%d:%s\n", &(models[model_cnt].id), models[model_cnt].name) != 2) {
            fprintf(stderr, "Error: Model list %s is corrupted.\n", fname);
            return -1;
         }
         model_cnt++;
         break;
      }
   }
   qsort(models, model_cnt, sizeof(model_t), cmp_models);
   // printf("Loaded %d models\n", model_cnt);

   free(line);
   fclose(fp_model_list);
   return 0;
}


/**
 * Print a list of existing labels.
 */
void print_model_list()
{
   printf("Labels: \n");
   printf("----------\n");
   for (int i = 0; i < model_cnt; i++) {
      printf("%s\n", models[i].name);
   }
   printf("----------\n");
}

/**
 * Add new trained model to the list of models.
 *
 * @param fname File with a list of models
 */
void update_models_list(const char *fname) 
{
   FILE *fp_model_list = NULL;

   if (train_model_cnt > model_cnt) {
      if ((fp_model_list = fopen(fname, "a")) == NULL) {
         fprintf(stderr, "Error: Model list %s cannot be opened in write mode.\n", optarg);
      }
      for (int i = model_cnt; i < train_model_cnt; i++) {
         fprintf(fp_model_list, "%d:%s\n", models[i].id, models[i].name);
      }
   }
}

/**
 * Load the models.
 * The model for each label is in a separate file specified by models list (see init_model_list())
 *
 * @param m Directory where the models are located
 */
int init_models(const char *m)
{
   char path[256];

   // Load the models
   for (int i = 0; i < model_cnt; i++) {
      sprintf(path, "%s/%d", m, models[i].id);

      // Model not found, maybe not trained
      if ((models[i].model = svm_load_model(path)) == 0) {
         fprintf(stderr,"Warning: File %s as model %s not found. Check %s.\n", path, models[i].name, models_lst_fname);
         models[i].model = NULL;
      }
   }
   return 0;
}

/**
 * Export new trained features to training database.
 *
 * @param node Node with calculated features
 * @param rule Rule with trained labels
 */
void export_trained_data(node_t *node, ip_rule_t *rule) 
{
   // Print labels
   int printed = 0;
   for (int i = 0; i < train_model_cnt; i++) {
      if (rule->labels[i] == true) {
         if (printed > 0) {
            fprintf(train_db, ",");
         }
         fprintf(train_db, "%d", models[i].id);
         printed++;
      }
   }
   // Print features
   for (int i = 0; node->features[i].index != -1; i++) {
      fprintf(train_db, " %d:%g", node->features[i].index, node->features[i].value);
   }
   fprintf(train_db, "\n");
}

/**
 * Predict labels of an IP address.
 *
 * @param node Device for which labels should be predicted. Features have to be calculated in advance.
 */
int predict(node_t *node)
{
   double predict_label;

   for (int i = 0; i < model_cnt; i++) {
      if (models[i].model != NULL) {
          predict_label = svm_predict(models[i].model, node->features);

          if (predict_label == 1) {
             node->labels[i] = true;
          } else {
             node->labels[i] = false;
          }
      }
   }
   return 0;
}

/**
 * Compute SVM features from statistics of a device.
 *
 * @param node Device with computed basic statistics
 */
void compute_features(node_t *node)
{
   double ratio;
   int i;
   double ex, ex_2, var;

   node->features = (struct svm_node *) malloc((BASIC_STATS_CNT + node->port_cnt + 1) * sizeof(struct svm_node));

   for (i = 0; i < BASIC_STATS_CNT; i++) {
        node->features[i].index = i+1;
   }
   // Ratio of biflows initialized vs. total
   node->features[0].value = node->total_inits / (double)node->total_biflows;

   // Ratio of traffic in source flows [B] vs. total [B]
   node->features[1].value = node->bytes_src / (double)(node->bytes_dst + node->bytes_src);

   // Packets per source flow (ex and sd)
   ex = node->flows_src ? (node->packets_src / (double)node->flows_src) : 0;
   var = (double)node->packets_src_2 / ((double)node->flows_src) - ex*ex;
   node->features[2].value = ex;
   node->features[3].value = (node->flows_src && var > 0) ? sqrt(var): 0;

   // Packets per destination flow (ex and sd)
   ex = node->flows_dst ? (node->packets_dst / (double)node->flows_dst) : 0;
   var = (double)node->packets_dst_2 / ((double)node->flows_dst) - ex*ex;
   node->features[4].value = ex;
   node->features[5].value = (node->flows_dst && var > 0)? sqrt(var): 0;

   // Seconds per source flow (ex and sd)
   ex = node->flows_src ? ((node->time_src_msec / 1000) / (double)(node->flows_src)) : 0;
   ex_2 = ((double)(node->time_src_msec_2) / (1000*1000)) / ((double)(node->flows_src));
   node->features[6].value = ex;
   node->features[7].value = (node->flows_src && (ex_2 - ex*ex > 0)) ? sqrt(ex_2 - ex*ex): 0;

   // Seconds per destination flow (ex and sd)
   ex = node->flows_dst ? ((node->time_dst_msec / 1000) / (double)(node->flows_dst)) : 0;
   ex_2 = ((double)(node->time_dst_msec_2) / (1000*1000)) / ((double)(node->flows_dst));
   node->features[8].value = ex;
   node->features[9].value = (node->flows_dst && (ex_2 - ex*ex > 0)) ? sqrt(ex_2 - ex*ex): 0;

   // Scaling features 2-9 in between <0,1> using tanh(). 
   // Important: This scaling is not linear and it only makes sense with this particular problem.
   // Division by constant is used only to move the number more to the left on the tanh() curve 
   // to get more reasonable numbers for better learning.
   for (int i = 2; i <= 9; i++) {
      node->features[i].value = tanh((node->features[i].value)/100);
   }
   // TCP vs. UDP
   node->features[10].value = node->tcp_cnt / (double)(node->flows_src + node->flows_dst);

   // Go through linked list of ports and copy their ratio
   port_t *port_node = node->port_head;
   while (port_node != NULL) {
      ratio = (port_node->total) / ((double)(node->flows_src + node->flows_dst));

      if (port_node->total > 0 && ratio > USAGE_THRESHOLD) {
         node->features[i].index = port_node->port + BASIC_STATS_CNT + 1;
         node->features[i].value = tanh(ratio * 3); // scaling, the same as above applies
         i++;
      }
      port_node = port_node->next;
   }
   // Ports have not been sorted, sort them
   qsort(node->features, i, sizeof(struct svm_node), cmp_svm_nodes);
   node->features[i].index = -1;
}

/**
 * Add port to the linked list.
 *
 * @param node Device with statistics
 * @param port Port to be added
 */
void add_port(node_t *node, uint16_t port) 
{
   // No ports have been added yet
   if (node->port_head == NULL) {
      node->port_head = (port_t*) malloc(sizeof(port_t));
      node->port_head->port = port;
      node->port_head->total = 1;
      node->port_head->next = NULL;
      node->port_cnt++;
      return;
   }
   // Try to find a matching port in the list
   port_t *port_node = node->port_head;
   do {
      if (port_node->port == port) {
         port_node->total++;
         return;
      }
      if (port_node->next == NULL) {
         break;
      }
   } while ((port_node = port_node->next));

   // No matching existing port, add a new one
   port_node->next = (port_t*) malloc(sizeof(port_t));
   port_node->next->port = port;
   port_node->next->total = 1;
   port_node->next->next = NULL;
   node->port_cnt++;
}

/**
 * Recursively destroy the linked list with ports.
 *
 * @param port_node Root node of the linked list
 */
void destroy_ports(port_t *port_node) 
{
   if (port_node != NULL) {
      destroy_ports(port_node->next);
      free(port_node);
   }
}

/**
 * Delete all devices in a tree.
 *
 * @param tree Tree with devices to be deleted
 */
void clear_tree(void *tree) 
{
   bool is_there_next;
   bpt_list_item_t *b_item;
   node_t *node;

   b_item = bpt_list_init(tree);
   is_there_next = bpt_list_start(tree, b_item);

   while (is_there_next) {
      node = (node_t*)b_item->value;
      if (node->peer_tree != NULL) {
         bpt_clean(node->peer_tree);
         node->peer_tree = NULL;
      }
      if (node->features != NULL) {
         free(node->features);
         node->features = NULL;
      }
      destroy_ports(node->port_head);
      is_there_next = bpt_list_item_del(tree, b_item);
   }
   bpt_list_clean(b_item);
} 

/**
 * Export devices from tree to JSON file.
 *
 * @param tree Tree with devices to be exported
 * @param fp_out Output JSON file
 * @param append Flag to signalize if this export appends to a previous one
 */
void export_tree(void *tree, FILE *fp_out, bool append) 
{
   bool is_there_next;
   bpt_list_item_t *b_item;
   node_t *node;
   char ip_buff[100];
   int printed = -1; // flag to discriminate a first vs. next label

   b_item = bpt_list_init(tree);
   is_there_next = bpt_list_start(tree, b_item);

   if (!append) {
      fprintf(fp_out, "[["); // start JSON array for all exports
   } else {
      fprintf(fp_out, ",\n["); // append only array for this export
   }

   while (is_there_next) {
      node = (node_t*)b_item->value;

      // Node will be included in export
      if (node->peers > peers_threshold) {
         ip_addr_t ip_to_translate = ip_from_int(*((uint32_t*)b_item->key));
         ip_to_str(&ip_to_translate, ip_buff); // get IP address of the node

         if (printed != -1) { // previous item should be separated
            fprintf(fp_out, ",\n");
         }
         fprintf(fp_out, "{\n\t\"ip\" : \"%s\",\n\t\"labels\" : [", ip_buff);

         // Print labels
         printed = 0;
         for (int i = 0; i < model_cnt; i++) {
            if (!node->labels[i]) {
               continue;
            }
            if (printed > 0) {
               fprintf(fp_out, ",");
            }
            fprintf(fp_out, "\"%s\"", models[i].name);
            printed++;
         }
         fprintf(fp_out, "]\n}"); // finalize this item
               
      }
      is_there_next = bpt_list_item_next(tree, b_item);
   }

   fprintf(fp_out, "]"); // finalize the array with items
   bpt_list_clean(b_item);
}

/**
 * Finalize a JSON file. Called after the last export.
 *
 * @param fp_out Output JSON file
 */
void export_tree_finalize(FILE *fp_out) {
   fprintf(fp_out, "]\n"); // finalize the array with all items
   fclose(fp_out);
}

/**
 * Print devices from tree.
 *
 * @param tree Tree with devices to be printed
 * @param append Flag to signalize if this print appends to a previous one
 */
void print_tree(void *tree, bool append) 
{
   bool is_there_next;
   bpt_list_item_t *b_item;
   node_t *node;
   char ip_buff[100];
   int printed = 0;
   ip_rule_t *rule;

   b_item = bpt_list_init(tree);
   is_there_next = bpt_list_start(tree, b_item);

   if (!append) {
      printf("ip_address");

      #ifdef DEBUG
      printf("\t%6s", "peers");
      printf("\t%6s", "flows");
      printf("%10s", "init");
      printf("%10s", "data");
      printf("%10s", "p/src");
      printf("%10s", "ps-sd");
      printf("%10s", "p/dst");
      printf("%10s", "pd-sd");
      printf("%10s", "s/src");
      printf("%10s", "ss-sd");
      printf("%10s", "s/dst");
      printf("%10s", "sd-sd");
      printf("%10s", "tcp");
      #endif /* DEBUG */

      printf("\tlabels\n");
   }
   while (is_there_next) {
      node = (node_t*)b_item->value;

      // Node will be included in output
      if (node->peers > peers_threshold) {
         ip_addr_t ip_to_translate = ip_from_int(*((uint32_t*)b_item->key));
         ip_to_str(&ip_to_translate, ip_buff); // get IP address of the node
         printf("%s\t", ip_buff);

         #ifdef DEBUG
         printf("%6lu", node->peers);

         printf("%8lu", node->flows_src+node->flows_dst);

         for (int i = 0; i < BASIC_STATS_CNT; i++) {
            printf("%10.3f", node->features[i].value);
         }
         printf("\nlabels:");
         #endif /* DEBUG */

         // Whitelist
         if ((rule = get_rule(&ip_to_translate, whitelist, wl_cnt)) != NULL && rule->label_name != NULL) {
            printf("%s\n", rule->label_name);
         // Training mode
         } else if (train_mode) {
            printf("[TRAINING...]\n");
         // Print labels
         } else {
            printed = 0;
            for (int i = 0; i < model_cnt; i++) {
               if (!node->labels[i]) {
                  continue;
               }
               if (printed > 0) {
                  printf(",");
               }
               printf("%s", models[i].name);
               printed++;
            }
            printf("\n");
         }

         #ifdef DEBUG
         printf("ports:");
         for (int i = BASIC_STATS_CNT;;i++) {
            if (node->features[i].index == -1) {
               break;
            }
            if (printed > 0) {
               printf(" ");
            }
            // if (printed > 10) {
            //    printf("... ");
            //    break;
            // }    
            printf("%d:%.2f", node->features[i].index-BASIC_STATS_CNT-1, node->features[i].value);
            printed++;
         }
         printf("\n\n\n");
         #endif /* DEBUG */
      }
      is_there_next = bpt_list_item_next(tree, b_item);
   }
   bpt_list_clean(b_item);
}

/**
 * Process all the IP addresses in a tree.
 * Compute statistics and features, predict labels.
 *
 * @param tree B+ tree to process
 */
void process_tree(void *tree) 
{
   bool is_there_next;
   bpt_list_item_t *b_item;
   node_t *node;

   b_item = bpt_list_init(tree);
   is_there_next = bpt_list_start(tree, b_item);

   while (is_there_next) {
      node = (node_t*)b_item->value;
      node->peers = ((bpt_t*)(node->peer_tree))->count_of_values;

      if (node->peers > peers_threshold) {
         ip_addr_t ip_addr = ip_from_int(*((uint32_t*)b_item->key));
         
         compute_features(node);

         if (train_mode) {
            ip_rule_t *rule = get_rule(&ip_addr, rules, rule_cnt);
            if (rule != NULL) { // features of this IP address should be exported for training
               export_trained_data(node, rule);
            }
         } else {
            predict(node);
         }
      }
      is_there_next = bpt_list_item_next(tree, b_item);
   }
   bpt_list_clean(b_item);
}

/**
 * Process and append a received flow.
 *
 * @param tree B+ tree where the flow will be added
 * @param ip_addr_src Main IP address
 * @param ip_addr_dst Peer IP address
 * @param is_source Indicates if main IP address is also the source IP of this flow
 */
int add_flow(void *tree, flow_t *flow, ip_addr_t *ip_addr_src, ip_addr_t *ip_addr_dst, bool is_source) 
{
   node_t *node;
   peer_t *peer_stats;
   uint32_t node_ip;
   uint32_t peer_ip;

   node_ip = ip_get_v4_as_int(ip_addr_src);
   
   node = (node_t*) bpt_search_or_insert(tree, &node_ip);

   if (node != NULL) { // node found / created
      if (node->peer_tree == NULL) { // create tree for peers of this node
         node->peer_tree = bpt_init(5, &compare_ipv4, sizeof(peer_t), IP_VERSION_4_BYTES);
      }
      peer_ip = ip_get_v4_as_int(ip_addr_dst);
      peer_stats = (peer_t*) bpt_search_or_insert(node->peer_tree, &peer_ip);

      if (peer_stats != NULL) {
         if ((flow->time_first - peer_stats->time_last) > PAUSE_THRESHOLD) { // a new biflow
            if (is_source) { // source of a biflow
               node->total_inits++;
            }
            node->total_biflows++;
         }
         peer_stats->time_last=flow->time_last; // update the time
      }
      if (flow->protocol == 6) {
         node->tcp_cnt++;
      }
      if (is_source) {
         node->flows_src++;
         node->bytes_src+=flow->bytes;
         node->packets_src+=flow->packets;
         node->packets_src_2+=flow->packets * flow->packets;
         node->time_src_msec+=flow->time_last-flow->time_first;
         node->time_src_msec_2+=(flow->time_last-flow->time_first)*(flow->time_last-flow->time_first);
         add_port(node, flow->src_port);
      } else {
         node->flows_dst++;
         node->bytes_dst+=flow->bytes;
         node->packets_dst+=flow->packets;
         node->packets_dst_2+=flow->packets * flow->packets;
         node->time_dst_msec+=flow->time_last-flow->time_first;
         node->time_dst_msec_2+=(flow->time_last-flow->time_first)*(flow->time_last-flow->time_first);
         add_port(node, flow->dst_port);
      }
   }
   return 0;
}

/**
 * Finalize, clean up all the structures.
 */
void cleanup() 
{
   if (train_db != NULL) {
      fclose(train_db); 
   }
   if (rules != NULL) {
      free(rules);
   }
   for (int i = 0; i < model_cnt; i++) {
      free(models[i].name);
      svm_free_and_destroy_model(&(models[i].model));
   }
   for (int i = 0; i < wl_cnt; i++) {
      free(whitelist[i].label_name);
   }
}

int main(int argc, char **argv)
{
   int ret;
   signed char opt;
   uint64_t start = 0;
   char *rules_fname = NULL;
   bool append = false;

   FILE *fp_out = NULL;
   char *out_fname = NULL;
   void *tree_ipv4 = NULL;

   ip_addr_t *ip_addr_dst;
   ip_addr_t *ip_addr_src;

   // Let TRAP library parse command-line arguments and extract its parameters
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

   // Register signal handler.
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   // Register signal handler for generating the output
   signal(SIGUSR1, generate_output_signal_handler);

   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      // Filter IP addresses
      case 'f':
         if (rules_fname != NULL) {
            fprintf(stderr, "Error: Cannot use both filter and training rules.\n");
         }
         rules_fname = optarg;
         break;
      // File to save results
      case 'F':
         out_fname = optarg;
         break;
      case 'l':
         if (init_model_list(models_lst_fname) != 0) {
            fprintf(stderr, "Error: Cannot load model list.\n");
            return 1;
         }
         print_model_list();
         exit(0);
      // Output only IP addresses with p peers
      case 'p':
         peers_threshold = atoi(optarg);
         break;
      // Output every m minutes
      case 'm':
         dump_mins = atoi(optarg);
         break;
      // Do not delete statistics after each output
      case 'a':
         accumulate_stats = true;
         break; 
      // Training mode
      case 't':
         if (rules_fname != NULL) {
            fprintf(stderr, "Error: Cannot use both filter and training rules.\n");
         }
         train_mode = true;
         rules_fname = optarg;
         break;
      default:
         fprintf(stderr, "Error: Invalid arguments.\n");
         // Do all necessary cleanup before exiting
         TRAP_DEFAULT_FINALIZATION();
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return 2;
      }
   }
   verbose = trap_get_verbose_level();
   if (verbose >= 0) {
      printf("Verbosity level: %i\n", verbose);
   }
   ur_template_t *in_tmplt = ur_create_input_template(0, "SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,TIME_FIRST,TIME_LAST", NULL);

   if (in_tmplt == NULL) {
      fprintf(stderr, "Error: Invalid UniRec specifier.\n");
      trap_finalize();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return 1;
   }
   // Create tree for devices
   tree_ipv4 = bpt_init(5, &compare_ipv4, sizeof(node_t), IP_VERSION_4_BYTES);

   if (init_model_list(models_lst_fname) != 0) {
      fprintf(stderr, "Error: Cannot load model list.\n");
      return 1;
   }
   if (train_mode) {
      printf("\n(TRAINING MODE)\n");
      train_model_cnt = model_cnt;
      if ((train_db = fopen(train_db_fname, "a")) == NULL) {
         fprintf(stderr, "Error: Cannot open training database.\n");
         return 1;
      }
   } else { // models are not used in training mode
      if (init_models(models_dir) != 0) {
         fprintf(stderr, "Error: Cannot load models. Check %s.\n", models_lst_fname);
         return 1;
      }
   }
   if (rules_fname != NULL) {
      if (load_rules(rules_fname) != 0) {
         fprintf(stderr, "Error: Cannot load %s.\n", train_mode ? "filter" : "training file");
         return 1;
      }
   }
   if (out_fname != NULL) {
      if ((fp_out = fopen(out_fname, "w")) == NULL) {
         fprintf(stderr, "Error: Cannot open output file. Do you have enough privileges?\n");
      }
   }    

   // Main loop
   while (!stop) {
      const void *in_rec;
      uint16_t in_rec_size;
      flow_t flow;

      // Receive data from input interface 0.
      // Block if data are not available immediately (unless a timeout is set using trap_ifcctl)
      ret = TRAP_RECEIVE(0, in_rec, in_rec_size, in_tmplt);
      // Handle possible errors
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);
      // Check size of received data
      if (in_rec_size < ur_rec_fixlen_size(in_tmplt)) {
         if (in_rec_size <= 1) {
            break; // End of data (used for testing purposes)
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_fixlen_size(in_tmplt), in_rec_size);
            break;
         }
      }
      flow_cnt++;

      ip_addr_src = &ur_get(in_tmplt, in_rec, F_SRC_IP);
      ip_addr_dst = &ur_get(in_tmplt, in_rec, F_DST_IP);

      if (!ip_is4(ip_addr_src)) { // no support for ipv6 yet
         continue;
      }
      flow.src_port = ur_get(in_tmplt, in_rec, F_SRC_PORT);
      flow.src_port = flow.src_port < PORT_CNT ? flow.src_port : PORT_CNT;

      flow.dst_port = ur_get(in_tmplt, in_rec, F_DST_PORT);
      flow.dst_port = flow.dst_port < PORT_CNT ? flow.dst_port : PORT_CNT;

      flow.protocol = ur_get(in_tmplt, in_rec, F_PROTOCOL);
      flow.packets = ur_get(in_tmplt, in_rec, F_PACKETS);
      flow.bytes = ur_get(in_tmplt, in_rec, F_BYTES);
      flow.time_first = TIMESTAMP(ur_get(in_tmplt, in_rec, F_TIME_FIRST));
      flow.time_last = TIMESTAMP(ur_get(in_tmplt, in_rec, F_TIME_LAST));

      // Check whether IP addressses are filtered
      if (!rules || get_rule(ip_addr_src, rules, rule_cnt) != NULL) {
         add_flow(tree_ipv4, &flow, ip_addr_src, ip_addr_dst, true);
      }
      if (!rules || get_rule(ip_addr_dst, rules, rule_cnt) != NULL) {
         add_flow(tree_ipv4, &flow, ip_addr_dst, ip_addr_src, false);
      }
      if (start == 0) {
         start = flow.time_first;
      }

      // Check if output should be printed now
      if ((dump_mins > 0 && abs(flow.time_first - start) > 1000 * 60 * dump_mins)
            || generate_output == true) {
         process_tree(tree_ipv4);
         print_tree(tree_ipv4, append);

         if (fp_out && !train_mode) {
            export_tree(tree_ipv4, fp_out, append);
         }
         if (!accumulate_stats) {
            clear_tree(tree_ipv4);
         }
         append = true; // next output will be appended
         generate_output = false;
         start = flow.time_first;
      }
   }
   // Output should be printed only at the end
   if (dump_mins == 0 && flow_cnt > 0) {
      process_tree(tree_ipv4);
      print_tree(tree_ipv4, append);

      if (fp_out && !train_mode) {
         export_tree(tree_ipv4, fp_out, append);
      }
   }
   if (fp_out && !train_mode) {
      export_tree_finalize(fp_out);
   }
   
   if (train_mode && flow_cnt > 0) {
      update_models_list(models_lst_fname);

      printf("\nData collected. Do you wish to launch the training script now (Y/N)?\n");
      char c = getchar();
      if (c == 'Y' || c == 'y') {
         printf("Training may take a few minutes, please wait.\n");
         if ((ret = system(train_script)) != 0) {
            printf("Error: Training failed. Check %s\n", train_script);
         } else {
            printf("\nTraining finished succesfully.\n");
         }
      } else {
         printf("You can finish training by launching the program in training mode again.\n"
                "You can delete the data by removing %s or run the scipt %s manually to add them to the dataset now.\n\n",
                train_db_fname, train_script);
      }
   }

   // printf("total flows: %lu\n", flow_cnt);

   if (tree_ipv4 != NULL) {
      clear_tree(tree_ipv4);
      bpt_clean(tree_ipv4);
   }
   cleanup();

   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   ur_free_template(in_tmplt);
   ur_finalize();

   return 0;
}

