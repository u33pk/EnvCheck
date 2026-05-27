#!/bin/bash
# 生成 4096 位 RSA 根密钥，并自签发根证书 (有效期 10 年)
openssl req -x509 \
  -newkey rsa:4096 \
  -keyout fake_root_key.pem \
  -out fake_root_cert.pem \
  -days 3650 \
  -nodes \
  -subj "/C=US/O=Google/CN=Fake Google Hardware Root CA"

openssl ecparam -name prime256v1 -genkey -noout -out fake_strongbox_key.pem

# 生成 CSR
openssl req -new \
  -key fake_strongbox_key.pem \
  -out fake_strongbox.csr \
  -subj "/C=US/O=Google/OU=Titan M/CN=Fake StrongBox TEE"

# 签发叶子证书 (有效期 1 年)
openssl x509 -req \
  -in fake_strongbox.csr \
  -CA fake_root_cert.pem \
  -CAkey fake_root_key.pem \
  -CAcreateserial \
  -out fake_strongbox_cert.pem \
  -days 365 \
  -extfile strongbox_ext.cnf \
  -extensions v3_req

# 打印证书内容，检查 Extensions 部分
openssl x509 -in fake_strongbox_cert.pem -text -noout

# 1. 生成假 StrongBox 的 RSA 私钥
openssl genrsa -out fake_strongbox_rsa_key.pem 2048

# 2. 生成请求
openssl req -new \
  -key fake_strongbox_rsa_key.pem \
  -out fake_strongbox_rsa.csr \
  -subj "/C=US/O=Google/OU=Titan M/CN=Fake StrongBox TEE (RSA)"

# 3. 再次使用之前的 Fake Root CA 和 strongbox_ext.cnf 配置文件注入扩展！
openssl x509 -req \
  -in fake_strongbox_rsa.csr \
  -CA fake_root_cert.pem \
  -CAkey fake_root_key.pem \
  -CAcreateserial \
  -out fake_strongbox_rsa_cert.pem \
  -days 365 \
  -extfile strongbox_ext.cnf \
  -extensions v3_req

python3 gen.py > attest.rs

rm -rf *.pem *.srl *.csr