#!/bin/bash

# ============================================

# BPFense - ML Model Signing Script

# ============================================

# Purpose:

# - Generate RSA keys (if not present)

# - Sign model.pkl

# - Output model.sig + public.pem

#

# Security:

# - private.pem MUST NOT be committed

# ============================================

set -e

MODEL_PATH="ai-engine/ml/model.pkl"
SIG_PATH="ai-engine/ml/model.sig"
PRIVATE_KEY="scripts/private.pem"
PUBLIC_KEY="ai-engine/ml/public.pem"

echo "============================================"
echo "[BPFense] Model Signing Process Started"
echo "============================================"

# --------------------------------------------

# Step 1: Validate model exists

# --------------------------------------------

if [ ! -f "$MODEL_PATH" ]; then
echo "[ERROR] model.pkl not found at: $MODEL_PATH"
exit 1
fi

echo "[OK] Found model: $MODEL_PATH"

# --------------------------------------------

# Step 2: Generate private key (if not exists)

# --------------------------------------------

if [ ! -f "$PRIVATE_KEY" ]; then
echo "[INFO] Generating RSA private key..."
openssl genpkey -algorithm RSA -out "$PRIVATE_KEY" -pkeyopt rsa_keygen_bits:2048
echo "[OK] Private key generated: $PRIVATE_KEY"
else
echo "[INFO] Private key already exists: $PRIVATE_KEY"
fi

# --------------------------------------------

# Step 3: Generate public key

# --------------------------------------------

echo "[INFO] Generating public key..."
openssl rsa -pubout -in "$PRIVATE_KEY" -out "$PUBLIC_KEY"
echo "[OK] Public key generated: $PUBLIC_KEY"

# --------------------------------------------

# Step 4: Sign model

# --------------------------------------------

echo "[INFO] Signing model..."
openssl dgst -sha256 -sign "$PRIVATE_KEY" -out "$SIG_PATH" "$MODEL_PATH"
echo "[OK] Model signed: $SIG_PATH"

# --------------------------------------------

# Step 5: Show SHA256 (for debugging / audit)

# --------------------------------------------

echo "[INFO] Model SHA256:"
openssl dgst -sha256 "$MODEL_PATH"

# --------------------------------------------

# Step 6: Final summary

# --------------------------------------------

echo "============================================"
echo "[SUCCESS] Signing completed"
echo "Generated files:"
echo "  - Signature : $SIG_PATH"
echo "  - Public Key: $PUBLIC_KEY"
echo ""
echo "IMPORTANT:"
echo "  - DO NOT commit: $PRIVATE_KEY"
echo "  - Keep private key secure"
echo "============================================"

