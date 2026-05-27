import base64

def pem_to_quoted_hex(pem_path: str, chars_per_line: int = 64) -> str:
    # 1. 读取 PEM 文件
    with open(pem_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    # 2. 提取 Base64 内容（过滤掉 -----BEGIN/END----- 和空行）
    b64_data = ''.join(line.strip() for line in lines if line.strip() and not line.startswith('-----'))

    # 3. 解码为 DER 二进制数据
    der_bytes = base64.b64decode(b64_data)

    # 4. 转为十六进制字符串（小写，与 xxd -p 一致）
    hex_str = der_bytes.hex()

    # 5. 按指定长度分割，每行包裹双引号 + ,
    quoted_lines = [
        f'"{hex_str[i:i+chars_per_line]}",'
        for i in range(0, len(hex_str), chars_per_line)
    ]

    return '\n'.join(quoted_lines)

def attest_fmt(var_name, hex_data):
    result = "const {_name}: &str = concat!(\n{_data}\n);".format(_name = var_name, _data=hex_data)
    print(result)

if __name__ == '__main__':
    # fake_strongbox_rsa_key.pem -> RSA_ATTEST_KEY
    # fake_strongbox_rsa_cert.pem -> RSA_ATTEST_CERT
    # fake_root_cert.pem -> RSA_ATTEST_ROOT_CERT

    # fake_strongbox_key.pem -> EC_ATTEST_KEY
    # fake_strongbox_rsa_cert.pem -> EC_ATTEST_CERT
    # fake_root_cert.pem -> EC_ATTEST_ROOT_CERT
    rsa_atk = pem_to_quoted_hex('fake_strongbox_rsa_key.pem', 64)
    attest_fmt("RSA_ATTEST_KEY", rsa_atk)
    rsa_atc = pem_to_quoted_hex('fake_strongbox_rsa_cert.pem', 64)
    attest_fmt("RSA_ATTEST_CERT", rsa_atc)
    rsa_atr = pem_to_quoted_hex('fake_root_cert.pem', 64)
    attest_fmt("RSA_ATTEST_ROOT_CERT", rsa_atr)

    ec_atk = pem_to_quoted_hex('fake_strongbox_key.pem', 64)
    attest_fmt("EC_ATTEST_KEY", ec_atk)
    ec_atc = pem_to_quoted_hex('fake_strongbox_cert.pem', 64)
    attest_fmt("EC_ATTEST_CERT", ec_atc)
    ec_atr = pem_to_quoted_hex('fake_root_cert.pem', 64)
    attest_fmt("EC_ATTEST_ROOT_CERT", ec_atr)
