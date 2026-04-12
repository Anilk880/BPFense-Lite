#ifndef MODEL_VERIFY_H
#define MODEL_VERIFY_H

int verify_model_signature(const char *model_path,
                           const char *sig_path,
                           const char *pubkey_path);

#endif
