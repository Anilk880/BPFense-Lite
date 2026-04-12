#ifndef FEATURE_EXTRACTOR_H
#define FEATURE_EXTRACTOR_H

/* ---------------- RULE LOADING ---------------- */

/* Load feature rules from config file */
void load_feature_rules(const char *path);

/* ---------------- FEATURE UPDATES ---------------- */

/* Apply file-based feature rules */
void apply_file_rules(const char *pod,
                      const char *filename,
                      int type,
                      const char *comm);

/* Apply network-based feature rules */
void apply_network_rules(const char *pod);

/* ---------------- OUTPUT ---------------- */

/* Flush collected features to file */
void flush_features();

#endif /* FEATURE_EXTRACTOR_H */
