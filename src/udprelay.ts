import * as utils from "./utils.js";
import * as inet from "./inet.js"
import * as encryptor from "./encrypt.js"
import * as dgram from 'node:dgram';
import net from 'net'

class LRUCache<T> {

  timeout: number;
  interval: NodeJS.Timeout;
  dict: Map<string, T>;

  constructor(timeout: number, sweepInterval: number) {
    this.timeout = timeout;
    this.interval = setInterval(() => this.sweep(), sweepInterval);
    this.dict = new Map<string, T>();
  }

  setItem(key: string, value: T) {
    return this.dict[key] = [value, process.hrtime()];
  }

  getItem(key: string): T | null {
    const v = this.dict[key];
    if (v) {
      v[1] = process.hrtime();
      return v[0];
    }
    return null;
  }

  delItem(key: string): boolean {
    return delete this.dict[key];
  }

  destroy(): void {
    clearInterval(this.interval);
  }

  sweep(): void {
    let diff, k, swept, v, v0, _i, _len;
    utils.debug("sweeping");
    const dict = this.dict;
    const keys = Object.keys(dict);
    swept = 0;
    for (_i = 0, _len = keys.length; _i < _len; _i++) {
      k = keys[_i];
      v = dict[k];
      diff = process.hrtime(v[1]);
      if (diff[0] > this.timeout * 0.001) {
        swept += 1;
        v0 = v[0];
        v0.close();
        delete dict[k];
      }
    }
    utils.debug("" + swept + " keys swept");
  }
}

// 加密
function encrypt(password, method, data) {
  let e;
  try {
    return encryptor.encryptAll(password, method, 1, data);
  } catch (_error) {
    e = _error;
    utils.error(e);
    return null;
  }
};

// 解密
function decrypt(password, method, data) {
  let e;
  try {
    return encryptor.encryptAll(password, method, 0, data);
  } catch (_error) {
    e = _error;
    utils.error(e);
    return null;
  }
};

// 解析ss协议头获取目标ip和端口以及协议头长度
function parseHeader(data, requestHeaderOffset) {
  let addrLen, addrtype, destAddr, destPort, e, headerLength;
  try {
    addrtype = data[requestHeaderOffset];
    if (addrtype === 3) {
      addrLen = data[requestHeaderOffset + 1];
    } else if (addrtype !== 1 && addrtype !== 4) {
      utils.warn("unsupported addrtype: " + addrtype);
      return null;
    }
    if (addrtype === 1) {
      destAddr = utils.inetNtoa(data.slice(requestHeaderOffset + 1, requestHeaderOffset + 5));
      destPort = data.readUInt16BE(requestHeaderOffset + 5);
      headerLength = requestHeaderOffset + 7;
    } else if (addrtype === 4) {
      destAddr = inet.inet_ntop(data.slice(requestHeaderOffset + 1, requestHeaderOffset + 17));
      destPort = data.readUInt16BE(requestHeaderOffset + 17);
      headerLength = requestHeaderOffset + 19;
    } else {
      destAddr = data.slice(requestHeaderOffset + 2, requestHeaderOffset + 2 + addrLen).toString("binary");
      destPort = data.readUInt16BE(requestHeaderOffset + 2 + addrLen);
      headerLength = requestHeaderOffset + 2 + addrLen + 2;
    }
    return [addrtype, destAddr, destPort, headerLength];
  } catch (_error) {
    e = _error;
    utils.error(e);
    return null;
  }
};

export function createServer(listenAddr, listenPort, remoteAddr, remotePort, password, method, timeout, isLocal) {
  let clientKey, clients, listenIPType, server, udpTypeToListen, udpTypesToListen, _i, _len;

  udpTypesToListen = [];
  if (listenAddr == null) {
    udpTypesToListen = ['udp4', 'udp6'];
  } else {
    listenIPType = net.isIP(listenAddr);
    if (listenIPType === 6) {
      udpTypesToListen.push('udp6');
    } else {
      udpTypesToListen.push('udp4');
    }
  }

  // 配置中存在多个udp服务器配置
  for (_i = 0, _len = udpTypesToListen.length; _i < _len; _i++) {
    udpTypeToListen = udpTypesToListen[_i];
    server = dgram.createSocket(udpTypeToListen);
    clients = new LRUCache(timeout, 10 * 1000);
    clientKey = function(localAddr, localPort, destAddr, destPort) {
      return "" + localAddr + ":" + localPort + ":" + destAddr + ":" + destPort;
    };

    server.on("message", function(data, rinfo) {
      let client, clientUdpType, dataToSend, destAddr, destPort, frag, headerLength, headerResult, requestHeaderOffset, sendDataOffset, serverAddr, serverPort;

      requestHeaderOffset = 0;
      if (isLocal) {
        requestHeaderOffset = 3;
        frag = data[2];
        if (frag !== 0) {
          utils.debug("frag:" + frag);
          utils.warn("drop a message since frag is not 0");
          return;
        }
      } else {
        // 解密数据
        data = decrypt(password, method, data);
        if (data == null) {
          return;
        }
      }

      // 解析ss协议头
      headerResult = parseHeader(data, requestHeaderOffset);
      if (headerResult === null) {
        return;
      }
      [, destAddr, destPort, headerLength] = headerResult;
      if (isLocal) {
        sendDataOffset = requestHeaderOffset;
        [serverAddr, serverPort] = [remoteAddr, remotePort]
      } else {
        sendDataOffset = headerLength; // 请求体偏移地址
        [serverAddr,serverPort] = [destAddr, destPort];
      }

      // local udp 地址
      const key = clientKey(rinfo.address, rinfo.port, destAddr, destPort);
      client = clients.getItem(key);
      if (client == null) {
        // 返回一个数字：
        // 0：如果输入不是有效的 IP 地址。
        // 4：如果输入是有效的 IPv4 地址。
        // 6：如果输入是有效的 IPv6 地址。
        clientUdpType = net.isIP(serverAddr);
        if (clientUdpType === 6) {
          client = dgram.createSocket("udp6");
        } else {
          client = dgram.createSocket("udp4");
        }
        clients.setItem(key, client);
        client.on("message", function(data1, rinfo1) {
          let data2, responseHeader, serverIPBuf;
          if (!isLocal) {
            // 封装ss协议并加密
            utils.debug("UDP recv from " + rinfo1.address + ":" + rinfo1.port);
            serverIPBuf = utils.inetAton(rinfo1.address);
            responseHeader = Buffer.alloc(7);
            responseHeader.write('\x01', 0); // ss 协议 第一个字节 表示ipv4地址
            serverIPBuf.copy(responseHeader, 1, 0, 4);
            responseHeader.writeUInt16BE(rinfo1.port, 5);
            data2 = Buffer.concat([responseHeader, data1]);
            data2 = encrypt(password, method, data2);
            if (data2 == null) {
              return;
            }
          } else {
            responseHeader = Buffer.from("\x00\x00\x00");
            data1 = decrypt(password, method, data1);
            if (data1 == null) {
              return;
            }
            headerResult = parseHeader(data1, 0);
            if (headerResult === null) {
              return;
            }
            [, destAddr, destPort, headerLength] = headerResult;
            utils.debug("UDP recv from " + destAddr + ":" + destPort);
            data2 = Buffer.concat([responseHeader, data1]);
          }

          return server.send(data2, 0, data2.length, rinfo.port, rinfo.address, function() {
            return utils.debug("remote to local sent");
          });
        });

        client.on("error", function(err) {
          return utils.error("UDP client error: " + err);
        });

        client.on("close", function() {
          utils.debug("UDP client close");
          return clients.delItem(key);
        });
      }

      utils.debug("pairs: " + (Object.keys(clients.dict).length));
      dataToSend = data.slice(sendDataOffset, data.length);
      if (isLocal) {
        dataToSend = encrypt(password, method, dataToSend);
        if (dataToSend == null) {
          return;
        }
      }
      utils.debug("UDP send to " + destAddr + ":" + destPort);
      return client.send(dataToSend, 0, dataToSend.length, serverPort, serverAddr, function() {
        return utils.debug("local to remote sent");
      });
    });

    server.on("listening", function() {
      const address = server.address();
      return utils.info("UDP server listening " + address.address + ":" + address.port);
    });

    server.on("close", function() {
      utils.info("UDP server closing");
      return clients.destroy();
    });

    if (listenAddr != null) {
      server.bind(listenPort, listenAddr);
    } else {
      server.bind(listenPort);
    }
    return server;
  }
};
