#include "targets.h"

static int push_target(t_config *cfg, const char *s)
{
	char **tmp = realloc(cfg->targets, (cfg->target_count + 1) * sizeof(char *));
	if (!tmp) return -1;
	cfg->targets = tmp;

	cfg->targets[cfg->target_count] = strdup(s);
	if (!cfg->targets[cfg->target_count]) return -1;

	cfg->target_count++;
	return 0;
}

static char *trim_inplace(char *s)
{
	char *end;

	while (*s && isspace((unsigned char)*s))
		s++;

	if (*s == '\0')
		return s;

	end = s + strlen(s) - 1;
	while (end > s && (isspace((unsigned char)*end) || *end == '\n' || *end == '\r'))
		*end-- = '\0';

	return s;
}

static void strip_inline_comment(char *s)
{
	for (size_t i = 0; s[i]; i++) {
		if (s[i] == '#') {
			s[i] = '\0';
			return;
		}
	}
}

int set_single_target(t_config *cfg, const char *ip_or_host)
{
	if (!ip_or_host || !*ip_or_host)
		return -1;
	return push_target(cfg, ip_or_host);
}

int load_targets_from_file(t_config *cfg, const char *path)
{
	FILE *f = fopen(path, "r");
	char line[2048];

	if (!f) return -1;

	while (fgets(line, sizeof(line), f)) {
		strip_inline_comment(line);
		char *t = trim_inplace(line);

		if (*t == '\0')
			continue;

		// comma-separated targets in one line
		char *save = NULL;
		char *tok = strtok_r(t, ",", &save);
		while (tok) {
			char *x = trim_inplace(tok);
			if (*x != '\0') {
				if (push_target(cfg, x) != 0) {
					fclose(f);
					return -1;
				}
			}
			tok = strtok_r(NULL, ",", &save);
		}
	}

	fclose(f);
	return (cfg->target_count > 0) ? 0 : -1;
}

void dedupe_targets(t_config *cfg)
{
	// O(n^2) is fine (targets list is small)
	for (size_t i = 0; i < cfg->target_count; i++) {
		if (!cfg->targets[i]) continue;

		for (size_t j = i + 1; j < cfg->target_count; j++) {
			if (!cfg->targets[j]) continue;

			if (strcasecmp(cfg->targets[i], cfg->targets[j]) == 0) {
				free(cfg->targets[j]);
				cfg->targets[j] = NULL;
			}
		}
	}

	// compact
	size_t w = 0;
	for (size_t i = 0; i < cfg->target_count; i++) {
		if (cfg->targets[i]) {
			cfg->targets[w++] = cfg->targets[i];
		}
	}
	cfg->target_count = w;

	if (cfg->targets) {
		char **tmp = realloc(cfg->targets, cfg->target_count * sizeof(char *));
		if (tmp || cfg->target_count == 0)
			cfg->targets = tmp;
	}
}

void free_targets(t_config *cfg)
{
	for (size_t i = 0; i < cfg->target_count; i++)
		free(cfg->targets[i]);
	free(cfg->targets);

	cfg->targets = NULL;
	cfg->target_count = 0;
}