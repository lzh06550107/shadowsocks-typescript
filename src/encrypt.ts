import crypto from "crypto";
import util from "node:util"
import { merge_sort } from './merge_sort.js';

const int32Max = Math.pow(2, 32);

const cachedTables = {};

export function getTable(key: string): number[][] {
  if (cachedTables[key]) {
    return cachedTables[key];
  }
  util.log('calculating ciphers'); // 计算密码算法
  let table = new Array(256);
  const decrypt_table = new Array(256);
  const md5sum = crypto.createHash('md5');
  md5sum.update(key); // 对密码进行散列
  // 表示创建 Buffer 时将数据视为二进制数据。这意味着生成的 Buffer 将包含原始字节数据
  const hash = md5sum.digest();
  const al = hash.readUInt32LE(0); // 低位
  const ah = hash.readUInt32LE(4); // 高位
  let i = 0;
  while (i < 256) {
    table[i] = i;
    i++;
  }
  i = 1;
  while (i < 1024) {
    // 为何进行 1024 次排序？
    // 排序
    table = merge_sort(table, function (x, y) {
      return (
        (((ah % (x + i)) * int32Max + al) % (x + i)) -
        (((ah % (y + i)) * int32Max + al) % (y + i))
      );
    });
    i++;
  }
  i = 0;
  while (i < 256) {
    decrypt_table[table[i]] = i;
    ++i;
  }
  const result = [table, decrypt_table];
  cachedTables[key] = result; // 密码对应的加密和解密
  return result;
};

/**
 * 替换密码
 * @param table
 * @param buf
 * @returns {*}
 */
function substitute(table: number[], buf) {
  let i = 0;
  while (i < buf.length) {
    buf[i] = table[buf[i]];
    i++;
  }
  return buf;
};

const bytes_to_key_results = {};

/**
 * 根据密码获取 key 和 初始化向量
 * @param password 密码
 * @param key_len 密钥长度
 * @param iv_len 初始化向量长度
 * @returns {*|*[]}
 * @constructor
 */
function EVP_BytesToKey(password: Buffer, key_len: number, iv_len: number): Buffer[] {
  if (bytes_to_key_results["" + password + ":" + key_len + ":" + iv_len]) {
    return bytes_to_key_results["" + password + ":" + key_len + ":" + iv_len];
  }
  const m = [];
  let i = 0;
  let count = 0;
  while (count < key_len + iv_len) {
    const md5 = crypto.createHash('md5');
    let data = password;
    if (i > 0) {
      // 用于连接多个 Buffer 对象的方法。它可以将一个 Buffer 数组合并成一个新的 Buffer，常用于处理二进制数据
      data = Buffer.concat([m[i - 1], password]); // 这是一个包含两个 Buffer 对象的数组
    }
    md5.update(data);
    const d = md5.digest();
    m.push(d);
    count += d.length;
    i += 1;
  }
  const ms = Buffer.concat(m);
  const key = ms.slice(0, key_len);
  const iv = ms.slice(key_len, key_len + iv_len);
  bytes_to_key_results["" + password + ":" + key_len + ":" + iv_len] = [key, iv];
  return [key, iv];
};

const method_supported = {
  'aes-128-cfb': [16, 16], // 加密方法和密钥长度、初始化向量长度
  'aes-192-cfb': [24, 16],
  'aes-256-cfb': [32, 16],
  'bf-cfb': [16, 8],
  'camellia-128-cfb': [16, 16],
  'camellia-192-cfb': [24, 16],
  'camellia-256-cfb': [32, 16],
  'cast5-cfb': [16, 8],
  'des-cfb': [8, 8],
  'idea-cfb': [16, 8],
  'rc2-cfb': [16, 8],
  'rc4': [16, 0],
  'rc4-md5': [16, 16],
  'seed-cfb': [16, 16]
};

function create_rc4_md5_cipher(key, iv, op): crypto.Cipher {
  const md5 = crypto.createHash('md5');
  md5.update(key);
  md5.update(iv);
  const rc4_key = md5.digest();
  if (op === 1) {
    // 创建对称加密算法的加密器
    return crypto.createCipheriv('rc4', rc4_key, '');
  } else {
    // 用于创建对称加密算法的解密器
    return crypto.createDecipheriv('rc4', rc4_key, '');
  }
};

export class Encryptor {

  key: string;
  method: string;
  iv_sent: boolean;
  cipher: crypto.Cipher | null;
  encryptTable: number[];
  decryptTable: number[];
  cipher_iv: Buffer;
  decipher: crypto.Cipher | null;

  constructor(key: string, method: string) {
    this.key = key;
    this.method = method;
    this.iv_sent = false;

    if (this.method === 'table') {
      this.method = null;
    }
    if (this.method != null) {
      this.cipher = this.get_cipher(this.key, this.method, 1, crypto.randomBytes(32)); // 随机初始化向量
    } else {
      [this.encryptTable, this.decryptTable] = getTable(this.key);
    }
  }

  get_cipher_len(method:string) {
    method = method.toLowerCase();
    return method_supported[method];
  }

  get_cipher(password: string, method: string, op: number, iv: Buffer): crypto.Cipher | null {
    let iv_, key;
    method = method.toLowerCase();
    const password1 = Buffer.from(password, 'binary');
    const m = this.get_cipher_len(method);
    if (m != null) {
      [key, iv_] = EVP_BytesToKey(password1, m[0], m[1]);
      if (iv == null) {
        iv = iv_;
      }
      if (op === 1) {
        this.cipher_iv = iv.slice(0, m[1]);
      }
      iv = iv.slice(0, m[1]);
      if (method === 'rc4-md5') {
        return create_rc4_md5_cipher(key, iv, op);
      } else {
        if (op === 1) {
          return crypto.createCipheriv(method, key, iv);
        } else {
          return crypto.createDecipheriv(method, key, iv);
        }
      }
    } else {
      return null;
    }
  }

  encrypt(buf) {
    let result;
    if (this.method != null) {
      result = this.cipher.update(buf);
      if (this.iv_sent) {
        return result;
      } else {
        this.iv_sent = true;
        return Buffer.concat([this.cipher_iv, result]);
      }
    } else {
      return substitute(this.encryptTable, buf);
    }
  };

  decrypt(buf) {
    let decipher_iv, decipher_iv_len, result;
    if (this.method != null) {
      if (this.decipher == null) {
        decipher_iv_len = this.get_cipher_len(this.method)[1];
        decipher_iv = buf.slice(0, decipher_iv_len);
        this.decipher = this.get_cipher(this.key, this.method, 0, decipher_iv);
        result = this.decipher.update(buf.slice(decipher_iv_len));
        return result;
      } else {
        result = this.decipher.update(buf);
        return result;
      }
    } else {
      return substitute(this.decryptTable, buf);
    }
  };
}

export function encryptAll(password, method, op, data) {
  let cipher, decryptTable, encryptTable, iv, ivLen, key, keyLen, result;
  if (method === 'table') {
    method = null;
  }
  if (method == null) {
    [encryptTable, decryptTable] = getTable(password);
    if (op === 0) {
      return substitute(decryptTable, data);
    } else {
      return substitute(encryptTable, data);
    }
  } else {
    result = [];
    method = method.toLowerCase();
    [keyLen, ivLen] = method_supported[method];
    password = Buffer.from(password, 'binary');
    [key, ] = EVP_BytesToKey(password, keyLen, ivLen);
    if (op === 1) {
      iv = crypto.randomBytes(ivLen);
      result.push(iv);
    } else {
      iv = data.slice(0, ivLen);
      data = data.slice(ivLen);
    }
    if (method === 'rc4-md5') {
      cipher = create_rc4_md5_cipher(key, iv, op);
    } else {
      if (op === 1) {
        cipher = crypto.createCipheriv(method, key, iv);
      } else {
        cipher = crypto.createDecipheriv(method, key, iv);
      }
    }
    result.push(cipher.update(data));
    result.push(cipher.final());
    return Buffer.concat(result);
  }
};
