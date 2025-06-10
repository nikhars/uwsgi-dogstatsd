#include <uwsgi.h>

#define MAX_BUFFER_SIZE 8192
#define DELTA_LIST_INITIAL_SIZE 64

/*

this is a stats pusher plugin for DogStatsD:

--stats-push dogstatsd:address[,prefix]

example:

--stats-push dogstatsd:127.0.0.1:8125,myinstance

exports values exposed by the metric subsystem to a Datadog Agent StatsD server

*/

extern struct uwsgi_server uwsgi;

// Fixed entry for storing previous metric values
struct delta_metric {
    char *metric_name;
    int64_t prev_value;
    uint32_t name_len;
};

struct dogstatsd_config {
    int no_workers;
    int all_gauges;
    char *extra_tags;
    struct uwsgi_string_list *metrics_whitelist;
    struct uwsgi_string_list *delta_metrics;
    struct delta_metric *delta_lookup;  // Fixed sorted array
    uint32_t delta_count;               // Number of delta metrics
} u_dogstatsd_config;

static struct uwsgi_option dogstatsd_options[] = {
  {"dogstatsd-no-workers", no_argument, 0, "disable generation of single-worker metrics", uwsgi_opt_true, &u_dogstatsd_config.no_workers, 0},
  {"dogstatsd-all-gauges", no_argument, 0, "push all metrics to dogstatsd as gauges", uwsgi_opt_true, &u_dogstatsd_config.all_gauges, 0},
  {"dogstatsd-extra-tags", required_argument, 0, "add these extra tags to all metrics (example: foo:bar,qin,baz:qux)", uwsgi_opt_set_str, &u_dogstatsd_config.extra_tags, 0},
  {"dogstatsd-whitelist-metric", required_argument, 0, "use one or more times to send only the whitelisted metrics (do not add prefix)", uwsgi_opt_add_string_list, &u_dogstatsd_config.metrics_whitelist, 0},
  {"dogstatsd-delta-metric", required_argument, 0, "send delta values for this metric instead of accumulated values", uwsgi_opt_add_string_list, &u_dogstatsd_config.delta_metrics, 0},
  UWSGI_END_OF_OPTIONS
};

// configuration of a dogstatsd node
struct dogstatsd_node {
  int fd;
  union uwsgi_sockaddr addr;
  socklen_t addr_len;
  char *prefix;
  uint16_t prefix_len;
};

// Compare function for binary search and sorting
static int compare_metric_names(const char *name1, uint32_t len1, const char *name2, uint32_t len2) {
  if (len1 == len2) {
    // Same length - just compare the strings directly
    return memcmp(name1, name2, len1);
  } else {
    // Different lengths - compare common prefix, then use length difference
    uint32_t min_len = len1 < len2 ? len1 : len2;
    int cmp = memcmp(name1, name2, min_len);
    if (cmp != 0) return cmp;
    return (int)len1 - (int)len2;
  }
}

// Search key structure for bsearch
struct delta_search_key {
  const char *metric_name;
  uint32_t name_len;
};

// Comparison function for bsearch
static int compare_for_bsearch(const void *key, const void *element) {
  const struct delta_search_key *search_key = (const struct delta_search_key *)key;
  const struct delta_metric *metric = (const struct delta_metric *)element;
  
  return compare_metric_names(search_key->metric_name, search_key->name_len, 
                             metric->metric_name, metric->name_len);
}

// Binary search using standard library bsearch
static struct delta_metric* find_delta_metric(const char *metric_name, uint32_t name_len) {
  if (!u_dogstatsd_config.delta_lookup || u_dogstatsd_config.delta_count == 0) {
    return NULL;
  }
  
  struct delta_search_key key = {metric_name, name_len};
  
  return (struct delta_metric*)bsearch(&key, 
                                      u_dogstatsd_config.delta_lookup,
                                      u_dogstatsd_config.delta_count,
                                      sizeof(struct delta_metric),
                                      compare_for_bsearch);
}

// Compare function for qsort
static int compare_delta_metrics(const void *a, const void *b) {
  const struct delta_metric *m1 = (const struct delta_metric *)a;
  const struct delta_metric *m2 = (const struct delta_metric *)b;
  return compare_metric_names(m1->metric_name, m1->name_len, m2->metric_name, m2->name_len);
}

// Initialize fixed lookup table from configured delta metrics
static void init_delta_lookup(void) {
  if (!u_dogstatsd_config.delta_metrics) {
    return;
  }
  
  // Count the number of delta metrics from the configuration list.
  // This is a list of metrics that should be sent as delta values.
  // We need to count the number of metrics in the list so that we
  // can allocate the correct amount of memory for the lookup table array.
  struct uwsgi_string_list *item = u_dogstatsd_config.delta_metrics;
  uint32_t count = 0;
  while (item) {
    count++;
    item = item->next;
  }
  
  if (count == 0) {
    return;
  }
  
  // Allocate fixed array
  u_dogstatsd_config.delta_lookup = uwsgi_calloc(count * sizeof(struct delta_metric));
  u_dogstatsd_config.delta_count = count;
  
  // Populate array
  item = u_dogstatsd_config.delta_metrics;
  for (uint8_t i = 0; i < count && item; i++) {
    struct delta_metric *entry = &u_dogstatsd_config.delta_lookup[i];
    entry->name_len = item->len;
    entry->metric_name = uwsgi_malloc(item->len + 1);
    memcpy(entry->metric_name, item->value, item->len);
    entry->metric_name[item->len] = '\0';
    entry->prev_value = 0;  // Initialize to 0
    item = item->next;
  }
  
  // Sort the array for binary search when we need to find a metric
  qsort(u_dogstatsd_config.delta_lookup, count, sizeof(struct delta_metric), compare_delta_metrics);
}

// Get delta for metric (returns 0 if not found or first measurement)
static int64_t get_and_update_delta(const char *metric_name, uint32_t name_len, int64_t current_value) {
  struct delta_metric *entry = find_delta_metric(metric_name, name_len);
  
  if (entry) {
    // Found - calculate delta and update
    int64_t delta = current_value - entry->prev_value;
    entry->prev_value = current_value;
    return delta;
  }
  
  // Not a delta metric - return original value
  return current_value;
}

static int dogstatsd_generate_tags(char *metric, size_t metric_len, char *datatog_metric_name, char *datadog_tags) {
  char *start = metric;
  size_t metric_offset = 0;

  static char metric_separator[] = ".";
  static char tag_separator[] = ",";
  static char tag_colon = ':';
  static char tag_prefix[] = "|#";

  long string_to_int;
  char *token = NULL;
  char *ctxt = NULL;
  char *key = NULL;
  char *next_character = NULL;

  errno = 0;

  token = strtok_r(start, metric_separator, &ctxt);

  if (!token)
    return -1;

  if (u_dogstatsd_config.extra_tags && strlen(u_dogstatsd_config.extra_tags)) {
    strncat(datadog_tags, tag_prefix, (MAX_BUFFER_SIZE - strlen(datadog_tags) - strlen(tag_prefix) - 1));
    strncat(datadog_tags, u_dogstatsd_config.extra_tags, (MAX_BUFFER_SIZE - strlen(datadog_tags) - strlen(u_dogstatsd_config.extra_tags) - 1));
  }

  while (token != NULL && metric_len >= metric_offset) {

    metric_offset += strlen(token) + 1;
    start = metric + metric_offset;

    // try to convert token into integer
    string_to_int = strtol(token, &next_character, 10);

    // stop processing if string_to_int is out of range
    if ((string_to_int == LONG_MIN || string_to_int == LONG_MAX) && errno == ERANGE)
      return -1;

    // if we've got a number and a tag value:
    if (next_character != token && key) {

      // start with tag_separator if we already have some tags
      //   otherwise put the tag_prefix
      if (strlen(datadog_tags))
       strncat(datadog_tags, tag_separator, (MAX_BUFFER_SIZE - strlen(datadog_tags) - strlen(tag_separator) - 1));
      else
       strncat(datadog_tags, tag_prefix, (MAX_BUFFER_SIZE - strlen(datadog_tags) - strlen(tag_prefix) - 1));

      // append new tag
      strncat(datadog_tags, key, (MAX_BUFFER_SIZE - strlen(datadog_tags) - strlen(key) - 1));
      strncat(datadog_tags, &tag_colon, 1);
      strncat(datadog_tags, token, (MAX_BUFFER_SIZE - strlen(datadog_tags) - strlen(token) - 1));

    } else {

      // store token as a key for the next iteration
      key = token;

      // start with metric_separator if we already have some metrics
      if (strlen(datatog_metric_name))
       strncat(datatog_metric_name, metric_separator, (MAX_BUFFER_SIZE - strlen(datatog_metric_name) - strlen(metric_separator) - 1));

      // add token
      strncat(datatog_metric_name, token, (MAX_BUFFER_SIZE - strlen(datatog_metric_name) - strlen(token) - 1));
    }

    // try to generate tokens before we iterate again
    token = strtok_r(NULL, metric_separator, &ctxt);
  }

  return strlen(datatog_metric_name);
}


static int dogstatsd_send_metric(struct uwsgi_buffer *ub, struct uwsgi_stats_pusher_instance *uspi, char *metric, size_t metric_len, int64_t value, char type[2]) {
  struct dogstatsd_node *sn = (struct dogstatsd_node *) uspi->data;

  char datatog_metric_name[MAX_BUFFER_SIZE];
  char datadog_tags[MAX_BUFFER_SIZE];
  char raw_metric_name[MAX_BUFFER_SIZE];

  int extracted_tags = 0;

  // check if we can handle such a metric length
  if (metric_len >= MAX_BUFFER_SIZE)
    return -1;

  // reset the buffer
  ub->pos = 0;

  // sanitize buffers
  memset(datadog_tags, 0, MAX_BUFFER_SIZE);
  memset(datatog_metric_name, 0, MAX_BUFFER_SIZE);

  // let's copy original metric name before we start
  strncpy(raw_metric_name, metric, metric_len + 1);

  // try to extract tags
  extracted_tags = dogstatsd_generate_tags(raw_metric_name, metric_len, datatog_metric_name, datadog_tags);

  if (extracted_tags < 0)
    return -1;

  if (u_dogstatsd_config.metrics_whitelist && !uwsgi_string_list_has_item(u_dogstatsd_config.metrics_whitelist, datatog_metric_name, strlen(datatog_metric_name))) {
    return 0;
  }

  // Check if this metric should use delta calculation
  int64_t value_to_send = value;
  if (u_dogstatsd_config.delta_lookup) {
    char *metric_name_to_check = extracted_tags ? datatog_metric_name : (char *)metric;
    uint32_t name_len_to_check = extracted_tags ? strlen(datatog_metric_name) : strlen(metric);
    
    if (find_delta_metric(metric_name_to_check, name_len_to_check)) {
      value_to_send = get_and_update_delta(metric_name_to_check, name_len_to_check, value);
    }
  }

  if (uwsgi_buffer_append(ub, sn->prefix, sn->prefix_len)) return -1;
  if (uwsgi_buffer_append(ub, ".", 1)) return -1;

  // put the datatog_metric_name if we found some tags
  if (extracted_tags) {
    if (uwsgi_buffer_append(ub, datatog_metric_name, strlen(datatog_metric_name))) return -1;
  } else {
    if (uwsgi_buffer_append(ub, metric, strlen(metric))) return -1;
  }

  if (uwsgi_buffer_append(ub, ":", 1)) return -1;
  if (uwsgi_buffer_num64(ub, value_to_send)) return -1;
  if (uwsgi_buffer_append(ub, type, 2)) return -1;

  // add tags metadata if there are any
  if (extracted_tags) {
    if (uwsgi_buffer_append(ub, datadog_tags, strlen(datadog_tags))) return -1;
  }

  if (sendto(sn->fd, ub->buf, ub->pos, 0, (struct sockaddr *) &sn->addr.sa_in, sn->addr_len) < 0) {
    uwsgi_error("dogstatsd_send_metric()/sendto()");
  }

  return 0;
}


static void stats_pusher_dogstatsd(struct uwsgi_stats_pusher_instance *uspi, time_t now, char *json, size_t json_len) {

  if (!uspi->configured) {
    struct dogstatsd_node *sn = uwsgi_calloc(sizeof(struct dogstatsd_node));
    char *comma = strchr(uspi->arg, ',');
    if (comma) {
      sn->prefix = comma+1;
      sn->prefix_len = strlen(sn->prefix);
      *comma = 0;
    }
    else {
      sn->prefix = "uwsgi";
      sn->prefix_len = 5;
    }

    char *colon = strchr(uspi->arg, ':');
    if (!colon) {
      uwsgi_log("invalid dd address %s\n", uspi->arg);
      if (comma) *comma = ',';
      free(sn);
      return;
    }
    sn->addr_len = socket_to_in_addr(uspi->arg, colon, 0, &sn->addr.sa_in);

    sn->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sn->fd < 0) {
      uwsgi_error("stats_pusher_dogstatsd()/socket()");
      if (comma) *comma = ',';
                        free(sn);
                        return;
    }
    uwsgi_socket_nb(sn->fd);
    if (comma) *comma = ',';
    uspi->data = sn;
    uspi->configured = 1;
  }

  // we use the same buffer for all of the packets
  if (uwsgi.metrics_cnt <= 0) {
    uwsgi_log(" *** WARNING: Dogstatsd stats pusher configured but there are no metrics to push ***\n");
    return;
  }

  struct uwsgi_buffer *ub = uwsgi_buffer_new(uwsgi.page_size);
  struct uwsgi_metric *um = uwsgi.metrics;
  while(um) {
    if (u_dogstatsd_config.no_workers && !uwsgi_starts_with(um->name, um->name_len, "worker.", 7)) {
      um = um->next;
      continue;
    }

    uwsgi_rlock(uwsgi.metrics_lock);
    // ignore return value
    if (u_dogstatsd_config.all_gauges || um->type == UWSGI_METRIC_GAUGE) {
      dogstatsd_send_metric(ub, uspi, um->name, um->name_len, *um->value, "|g");
    }
    else {
      dogstatsd_send_metric(ub, uspi, um->name, um->name_len, *um->value, "|c");
    }
    uwsgi_rwunlock(uwsgi.metrics_lock);
    if (um->reset_after_push){
      uwsgi_wlock(uwsgi.metrics_lock);
      *um->value = um->initial_value;
      uwsgi_rwunlock(uwsgi.metrics_lock);
    }
    um = um->next;
  }
  uwsgi_buffer_destroy(ub);
}

static void dogstatsd_init(void) {
  struct uwsgi_stats_pusher *usp = uwsgi_register_stats_pusher("dogstatsd", stats_pusher_dogstatsd);
  // we use a custom format not the JSON one
  usp->raw = 1;
  
  // Initialize the fixed delta lookup table
  init_delta_lookup();
}

struct uwsgi_plugin dogstatsd_plugin = {

    .name = "dogstatsd",
    .options = dogstatsd_options,
    .on_load = dogstatsd_init,
};
