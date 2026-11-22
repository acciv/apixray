#ifndef APIXRAY_H
#define APIXRAY_H

#ifdef __cplusplus
extern "C" {
#endif

const char *apixray_version(void);
char *apixray_analyze(const char *input);
char *apixray_scan(const char *text);
char *apixray_generate_fake(const char *provider);
void apixray_free(char *ptr);

#ifdef __cplusplus
}
#endif

#endif
