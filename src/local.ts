import net from 'net';
import fs from 'fs';
import path from 'path';
import * as udpRelay from './udprelay.js';
import * as utils from './utils.js';
import * as inet from './inet.js';
import { Encryptor } from './encrypt.js';

let connections = 0;

export function createServer(serverAddr, serverPort, port, key, method, timeout, local_address) {

  if (local_address == null) {
    local_address = '127.0.0.1';
  }

  // udp中继服务器
  const udpServer = udpRelay.createServer(local_address, port, serverAddr, serverPort, key, method, timeout, true);

  function getServer() {
    let aPort, aServer;
    aPort = serverPort;
    aServer = serverAddr;
    if (serverPort instanceof Array) {
      aPort = serverPort[Math.floor(Math.random() * serverPort.length)];
    }
    if (serverAddr instanceof Array) {
      aServer = serverAddr[Math.floor(Math.random() * serverAddr.length)];
    }
    // 匹配 example.com:8080 这类
    const r = /^([^:]*):(\d+)$/.exec(aServer);
    if (r != null) {
      aServer = r[1]; // example.com
      aPort = +r[2]; // 8080
    }
    return [aServer, aPort];
  };

  // tcp中继服务器
  const server = net.createServer(function(connection) {
    let addrLen, addrToSend, connected, encryptor, headerLength, remote, remoteAddr, remotePort, stage;

    connections += 1;
    connected = true;
    encryptor = new Encryptor(key, method);
    stage = 0;
    headerLength = 0;
    remote = null;
    addrLen = 0;
    remoteAddr = null;
    remotePort = null;
    addrToSend = "";
    utils.debug("connections: " + connections);

    function clean() {
      utils.debug("clean");
      connections -= 1;
      remote = null;
      connection = null;
      encryptor = null;
      return utils.debug("connections: " + connections);
    };

    connection.on("data", function(data) {
      let aPort, aServer, addrToSendBuf, addrtype, buf, cmd, e, piece, reply, tempBuf;
      utils.log(utils.LEVEL.EVERYTHING, "connection on data");

      if (stage === 5) {
        data = encryptor.encrypt(data);
        if (!remote.write(data)) {
          connection.pause();
        }
        return;
      }

      if (stage === 0) {
        tempBuf = Buffer.alloc(2);
        // socks5协议，0x00 NO AUTHENTICATION REQUIRED 不需要认证
        tempBuf.write("\u0005\u0000", 0);
        connection.write(tempBuf);
        stage = 1;
        utils.debug("stage = 1");
        return;
      }

      if (stage === 1) {
        try {
          cmd = data[1]; // socks5 的 cmd
          addrtype = data[3];
          if (cmd === 1) { // socks5 CONNECT 0x01 连接

          } else if (cmd === 3) { // socks5 UDP ASSOCIATE 0x03 使用UDP
            utils.info("UDP assc request from " + connection.localAddress + ":" + connection.localPort);
            reply = Buffer.alloc(10);
            // socks5服务端 回复
            reply.write("\u0005\u0000\u0000\u0001", 0, 4, "binary");
            utils.debug(connection.localAddress);
            utils.inetAton(connection.localAddress).copy(reply, 4);
            reply.writeUInt16BE(connection.localPort, 8);
            connection.write(reply);
            stage = 10; // TODO 需要完善
          } else {
            utils.error("unsupported cmd: " + cmd);
            reply = Buffer.from("\u0005\u0007\u0000\u0001", "binary");
            connection.end(reply);
            return;
          }

          if (addrtype === 3) {
            addrLen = data[4];
          } else if (addrtype !== 1 && addrtype !== 4) {
            utils.error("unsupported addrtype: " + addrtype);
            connection.destroy();
            return;
          }

          addrToSend = data.slice(3, 4).toString("binary");
          if (addrtype === 1) {
            remoteAddr = utils.inetNtoa(data.slice(4, 8));
            addrToSend += data.slice(4, 10).toString("binary");
            remotePort = data.readUInt16BE(8);
            headerLength = 10;
          } else if (addrtype === 4) {
            remoteAddr = inet.inet_ntop(data.slice(4, 20));
            addrToSend += data.slice(4, 22).toString("binary");
            remotePort = data.readUInt16BE(20);
            headerLength = 22;
          } else {
            remoteAddr = data.slice(5, 5 + addrLen).toString("binary");
            addrToSend += data.slice(4, 5 + addrLen + 2).toString("binary");
            remotePort = data.readUInt16BE(5 + addrLen);
            headerLength = 5 + addrLen + 2;
          }

          if (cmd === 3) {
            utils.info("UDP assc: " + remoteAddr + ":" + remotePort);
            return;
          }
          buf = Buffer.alloc(10);
          buf.write("\u0005\u0000\u0000\u0001", 0, 4, "binary");
          buf.write("\u0000\u0000\u0000\u0000", 4, 4, "binary");
          buf.writeInt16BE(2222, 8); // 2222为写入的值，8为偏移量
          connection.write(buf);
          [aServer, aPort] = getServer();
          utils.info("connecting " + aServer + ":" + aPort);
          // 连接远程
          remote = net.connect(aPort, aServer, function() {
            if (remote) {
              remote.setNoDelay(true);
            }
            stage = 5;
            return utils.debug("stage = 5");
          });

          remote.on("data", function(data) {
            if (!connected) {
              return;
            }
            utils.log(utils.LEVEL.EVERYTHING, "remote on data");
            try {
              if (encryptor) {
                data = encryptor.decrypt(data);
                if (!connection.write(data)) { // 解密数据
                  return remote.pause();
                }
              } else {
                return remote.destroy();
              }
            } catch (_error) {
              utils.error(_error);
              if (remote) {
                remote.destroy();
              }
              if (connection) {
                return connection.destroy();
              }
            }
          });

          remote.on("end", function() {
            utils.debug("remote on end");
            if (connection) {
              connection.end();
            }
          });

          remote.on("error", function(e) {
            utils.debug("remote on error");
            utils.error("remote " + remoteAddr + ":" + remotePort + " error: " + e);
          });

          remote.on("close", function(had_error) {
            utils.debug("remote on close:" + had_error);
            if (had_error) {
              if (connection) {
                connection.destroy();
              }
            } else {
              if (connection) {
                connection.end();
              }
            }
          });

          remote.on("drain", function() {
            utils.debug("remote on drain");
            if (connection) {
              connection.resume();
            }
          });

          remote.setTimeout(timeout, function() {
            utils.debug("remote on timeout");
            if (remote) {
              remote.destroy();
            }
            if (connection) {
              connection.destroy();
            }
          });

          // 加密数据并发送
          addrToSendBuf = Buffer.from(addrToSend, "binary");
          addrToSendBuf = encryptor.encrypt(addrToSendBuf);
          remote.setNoDelay(false);
          remote.write(addrToSendBuf);
          if (data.length > headerLength) {
            buf = Buffer.alloc(data.length - headerLength);
            data.copy(buf, 0, headerLength);
            piece = encryptor.encrypt(buf);
            remote.write(piece);
          }
          stage = 4;
          return utils.debug("stage = 4");
        } catch (_error) {
          e = _error;
          utils.error(e);
          if (connection) {
            connection.destroy();
          }
          if (remote) {
            remote.destroy();
          }
          return clean();
        }
      } else if (stage === 4) {
        if (remote == null) {
          if (connection) {
            connection.destroy();
          }
          return;
        }
        data = encryptor.encrypt(data);
        remote.setNoDelay(true);
        if (!remote.write(data)) {
          return connection.pause();
        }
      }
    });

    connection.on("end", function() {
      connected = false;
      utils.debug("connection on end");
      if (remote) {
        return remote.end();
      }
    });

    connection.on("error", function(e) {
      utils.debug("connection on error");
      return utils.error("local error: " + e);
    });

    connection.on("close", function(had_error) {
      connected = false;
      utils.debug("connection on close:" + had_error);
      if (had_error) {
        if (remote) {
          remote.destroy();
        }
      } else {
        if (remote) {
          remote.end();
        }
      }
      return clean();
    });

    connection.on("drain", function() {
      utils.debug("connection on drain");
      if (remote && stage === 5) {
        return remote.resume();
      }
    });

    return connection.setTimeout(timeout, function() {
      utils.debug("connection on timeout");
      if (remote) {
        remote.destroy();
      }
      if (connection) {
        connection.destroy();
      }
    });
  });

  server.listen(port, local_address, function() {
    const addressInfo = server.address() as net.AddressInfo; // 类型断言
    utils.info("local listening at " + (addressInfo.address) + ":" + port);
  });

  server.on("error", function(e: Error) {
    const error = e as NodeJS.ErrnoException; // 类型断言
    if (error.code === "EADDRINUSE") {
      utils.error("Address in use, aborting");
    } else {
      utils.error(e);
    }
  });

  server.on("close", function() {
    return udpServer.close();
  });

  return server;
};

export function main(): void {
  let config, configContent, configPath;
  console.log(utils.version);
  const configFromArgs = utils.parseArgs();
  configPath = 'config.json';
  if (configFromArgs?.config_file) {
    configPath = configFromArgs.config_file;
  } else {
    utils.info('no config file found.');
    process.exit(1);
  }
  if (!fs.existsSync(configPath)) {
    configPath = path.resolve(__dirname, "config.json");
    if (!fs.existsSync(configPath)) {
      configPath = path.resolve(__dirname, "../../config.json");
      if (!fs.existsSync(configPath)) {
        configPath = null;
      }
    }
  }
  if (configPath) {
    utils.info('loading config from ' + configPath);
    configContent = fs.readFileSync(configPath);
    try {
      config = JSON.parse(configContent);
    } catch (_error) {
      utils.error('found an error in config.json: ' + _error.message);
      process.exit(1);
    }
  } else {
    config = {};
  }
  for (const k in configFromArgs) {
    config[k] = configFromArgs[k];
  }
  if (config.verbose) {
    utils.config(utils.LEVEL.DEBUG);
  }
  utils.checkConfig(config);
  const SERVER = config.server; // 远程服务器地址
  const REMOTE_PORT = config.server_port; // 远程服务器端口
  const PORT = config.local_port; // 本地监听端口
  const KEY = config.password; // 加密密码
  const METHOD = config.method; // 加密方式
  const local_address = config.local_address; // 本地监听地址
  if (!(SERVER && REMOTE_PORT && PORT && KEY)) {
    utils.warn('config.json not found, you have to specify all config in commandline');
    process.exit(1);
  }
  const timeout = Math.floor(config.timeout * 1000) || 600000;
  const s = createServer(SERVER, REMOTE_PORT, PORT, KEY, METHOD, timeout, local_address);
  s.on("error", function() {
    return process.stdout.on('drain', function() {
      return process.exit(1);
    });
  });
};
