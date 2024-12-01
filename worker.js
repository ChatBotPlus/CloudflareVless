// src/index.js
import { connect } from "cloudflare:sockets";
var userID = "90cd4a77-141a-43c9-991b-08263cfe9c10";
var proxyIP = "";
var sub = "";
var subconverter = "SUBAPI.fxxk.dedyn.io";
var subconfig = "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_MultiMode.ini";
var subProtocol = "https";
var socks5Address = "";
if (!isValidUUID(userID)) {
  throw new Error("uuid is not valid");
}
var parsedSocks5Address = {};
var enableSocks = false;
var fakeUserID;
var fakeHostName;
var noTLS = "false";
var expire = 4102329600;
var proxyIPs;
var socks5s;
var go2Socks5s = [
  "*ttvnw.net"
];
var addresses = [
  //当sub为空时启用本地优选域名/优选IP，若不带端口号 TLS默认端口为443，#号后为备注别名
  /*
  'Join.my.Telegram.channel.CMLiussss.to.unlock.more.premium.nodes.cf.090227.xyz#加入我的频道t.me/CMLiussss解锁更多优选节点',
  'visa.cn:443',
  'www.visa.com:8443',
  'cis.visa.com:2053',
  'africa.visa.com:2083',
  'www.visa.com.sg:2087',
  'www.visaeurope.at:2096',
  'www.visa.com.mt:8443',
  'qa.visamiddleeast.com',
  'time.is',
  'www.wto.org:8443',
  'chatgpt.com:2087',
  'icook.hk',
  '104.17.0.0#IPv4',
  '[2606:4700::]#IPv6'
  */
];
var addressesapi = [];
var addressesnotls = [
  //当sub为空且域名带有"worker"字样时启用本地优选域名/优选IP，若不带端口号 noTLS默认端口为80，#号后为备注别名
  /*
  'usa.visa.com',
  'myanmar.visa.com:8080',
  'www.visa.com.tw:8880',
  'www.visaeurope.ch:2052',
  'www.visa.com.br:2082',
  'www.visasoutheasteurope.com:2086',
  '[2606:4700::1]:2095#IPv6'
  */
];
var addressesnotlsapi = [];
var addressescsv = [];
var DLS = 8;
var FileName = "edgetunnel";
var BotToken = "";
var ChatID = "";
var proxyhosts = [];
var proxyhostsURL = "https://raw.githubusercontent.com/cmliu/CFcdnVmess2sub/main/proxyhosts";
var RproxyIP = "false";
var src_default = {
  /**
   * @param {import("@cloudflare/workers-types").Request} request
   * @param {{UUID: string, PROXYIP: string}} env
   * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
   * @returns {Promise<Response>}
   */
  async fetch(request, env, ctx) {
    try {
      const UA = request.headers.get("User-Agent") || "null";
      const userAgent = UA.toLowerCase();
      userID = (env.UUID || userID).toLowerCase();
      const currentDate = /* @__PURE__ */ new Date();
      currentDate.setHours(0, 0, 0, 0);
      const timestamp = Math.ceil(currentDate.getTime() / 1e3);
      const fakeUserIDMD5 = await MD5MD5(`${userID}${timestamp}`);
      fakeUserID = fakeUserIDMD5.slice(0, 8) + "-" + fakeUserIDMD5.slice(8, 12) + "-" + fakeUserIDMD5.slice(12, 16) + "-" + fakeUserIDMD5.slice(16, 20) + "-" + fakeUserIDMD5.slice(20);
      fakeHostName = fakeUserIDMD5.slice(6, 9) + "." + fakeUserIDMD5.slice(13, 19);
      proxyIP = env.PROXYIP || proxyIP;
      proxyIPs = await ADD(proxyIP);
      proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
      socks5Address = env.SOCKS5 || socks5Address;
      socks5s = await ADD(socks5Address);
      socks5Address = socks5s[Math.floor(Math.random() * socks5s.length)];
      socks5Address = socks5Address.split("//")[1] || socks5Address;
      sub = env.SUB || sub;
      subconverter = env.SUBAPI || subconverter;
      if (subconverter.includes("http://")) {
        subconverter = subconverter.split("//")[1];
        subProtocol = "http";
      } else {
        subconverter = subconverter.split("//")[1] || subconverter;
      }
      subconfig = env.SUBCONFIG || subconfig;
      if (socks5Address) {
        try {
          parsedSocks5Address = socks5AddressParser(socks5Address);
          RproxyIP = env.RPROXYIP || "false";
          enableSocks = true;
        } catch (err) {
          let e = err;
          console.log(e.toString());
          RproxyIP = env.RPROXYIP || !proxyIP ? "true" : "false";
          enableSocks = false;
        }
      } else {
        RproxyIP = env.RPROXYIP || !proxyIP ? "true" : "false";
      }
      if (env.ADD)
        addresses = await ADD(env.ADD);
      if (env.ADDAPI)
        addressesapi = await ADD(env.ADDAPI);
      if (env.ADDNOTLS)
        addressesnotls = await ADD(env.ADDNOTLS);
      if (env.ADDNOTLSAPI)
        addressesnotlsapi = await ADD(env.ADDNOTLSAPI);
      if (env.ADDCSV)
        addressescsv = await ADD(env.ADDCSV);
      DLS = env.DLS || DLS;
      BotToken = env.TGTOKEN || BotToken;
      ChatID = env.TGID || ChatID;
      if (env.GO2SOCKS5)
        go2Socks5s = await ADD(env.GO2SOCKS5);
      const upgradeHeader = request.headers.get("Upgrade");
      const url = new URL(request.url);
      if (url.searchParams.has("sub") && url.searchParams.get("sub") !== "")
        sub = url.searchParams.get("sub");
      FileName = env.SUBNAME || FileName;
      if (url.searchParams.has("notls"))
        noTLS = "true";
      if (!upgradeHeader || upgradeHeader !== "websocket") {
        switch (url.pathname.toLowerCase()) {
          case "/":
            const envKey = env.URL302 ? "URL302" : env.URL ? "URL" : null;
            if (envKey) {
              const URLs = await ADD(env[envKey]);
              const URL2 = URLs[Math.floor(Math.random() * URLs.length)];
              return envKey === "URL302" ? Response.redirect(URL2, 302) : fetch(new Request(URL2, request));
            }
            return new Response(JSON.stringify(request.cf, null, 4), { status: 200 });
          case `/${fakeUserID}`:
            const fakeConfig = await getVLESSConfig(userID, request.headers.get("Host"), sub, "CF-Workers-SUB", RproxyIP, url);
            return new Response(`${fakeConfig}`, { status: 200 });
          case `/${userID}`: {
            await sendMessage(`#\u83B7\u53D6\u8BA2\u9605 ${FileName}`, request.headers.get("CF-Connecting-IP"), `UA: ${UA}</tg-spoiler>
\u57DF\u540D: ${url.hostname}
<tg-spoiler>\u5165\u53E3: ${url.pathname + url.search}</tg-spoiler>`);
            const vlessConfig = await getVLESSConfig(userID, request.headers.get("Host"), sub, UA, RproxyIP, url);
            const now = Date.now();
            const today = new Date(now);
            today.setHours(0, 0, 0, 0);
            const UD = Math.floor((now - today.getTime()) / 864e5 * 24 * 1099511627776 / 2);
            let pagesSum = UD;
            let workersSum = UD;
            let total = 24 * 1099511627776;
            if (env.CFEMAIL && env.CFKEY) {
              const email = env.CFEMAIL;
              const key = env.CFKEY;
              const accountIndex = env.CFID || 0;
              const accountId = await getAccountId(email, key);
              if (accountId) {
                const now2 = /* @__PURE__ */ new Date();
                now2.setUTCHours(0, 0, 0, 0);
                const startDate = now2.toISOString();
                const endDate = (/* @__PURE__ */ new Date()).toISOString();
                const Sum = await getSum(accountId, accountIndex, email, key, startDate, endDate);
                pagesSum = Sum[0];
                workersSum = Sum[1];
                total = 102400;
              }
            }
            if (userAgent && userAgent.includes("mozilla")) {
              return new Response(`${vlessConfig}`, {
                status: 200,
                headers: {
                  "Content-Type": "text/plain;charset=utf-8",
                  "Profile-Update-Interval": "6",
                  "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`
                }
              });
            } else {
              return new Response(`${vlessConfig}`, {
                status: 200,
                headers: {
                  "Content-Disposition": `attachment; filename=${FileName}; filename*=utf-8''${encodeURIComponent(FileName)}`,
                  "Content-Type": "text/plain;charset=utf-8",
                  "Profile-Update-Interval": "6",
                  "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`
                }
              });
            }
          }
          default:
            return new Response("Not found", { status: 404 });
        }
      } else {
        proxyIP = url.searchParams.get("proxyip") || proxyIP;
        if (new RegExp("/proxyip=", "i").test(url.pathname))
          proxyIP = url.pathname.toLowerCase().split("/proxyip=")[1];
        else if (new RegExp("/proxyip.", "i").test(url.pathname))
          proxyIP = `proxyip.${url.pathname.toLowerCase().split("/proxyip.")[1]}`;
        socks5Address = url.searchParams.get("socks5") || socks5Address;
        if (new RegExp("/socks5=", "i").test(url.pathname))
          socks5Address = url.pathname.split("5=")[1];
        else if (new RegExp("/socks://", "i").test(url.pathname) || new RegExp("/socks5://", "i").test(url.pathname)) {
          socks5Address = url.pathname.split("://")[1].split("#")[0];
          if (socks5Address.includes("@")) {
            let userPassword = socks5Address.split("@")[0];
            const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
            if (base64Regex.test(userPassword) && !userPassword.includes(":"))
              userPassword = atob(userPassword);
            socks5Address = `${userPassword}@${socks5Address.split("@")[1]}`;
          }
        }
        if (socks5Address) {
          try {
            parsedSocks5Address = socks5AddressParser(socks5Address);
            enableSocks = true;
          } catch (err) {
            let e = err;
            console.log(e.toString());
            enableSocks = false;
          }
        } else {
          enableSocks = false;
        }
        return await vlessOverWSHandler(request);
      }
    } catch (err) {
      let e = err;
      return new Response(e.toString());
    }
  }
};
async function vlessOverWSHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();
  let address = "";
  let portWithRandomLog = "";
  const log = (info, event) => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
  };
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
  let remoteSocketWapper = {
    value: null
  };
  let isDns = false;
  readableWebSocketStream.pipeTo(new WritableStream({
    async write(chunk, controller) {
      if (isDns) {
        return await handleDNSQuery(chunk, webSocket, null, log);
      }
      if (remoteSocketWapper.value) {
        const writer = remoteSocketWapper.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }
      const {
        hasError,
        message,
        addressType,
        portRemote = 443,
        addressRemote = "",
        rawDataIndex,
        vlessVersion = new Uint8Array([0, 0]),
        isUDP
      } = processVlessHeader(chunk, userID);
      address = addressRemote;
      portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? "udp " : "tcp "} `;
      if (hasError) {
        throw new Error(message);
        return;
      }
      if (isUDP) {
        if (portRemote === 53) {
          isDns = true;
        } else {
          throw new Error("UDP \u4EE3\u7406\u4EC5\u5BF9 DNS\uFF0853 \u7AEF\u53E3\uFF09\u542F\u7528");
          return;
        }
      }
      const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
      const rawClientData = chunk.slice(rawDataIndex);
      if (isDns) {
        return handleDNSQuery(rawClientData, webSocket, vlessResponseHeader, log);
      }
      log(`\u5904\u7406 TCP \u51FA\u7AD9\u8FDE\u63A5 ${addressRemote}:${portRemote}`);
      handleTCPOutBound(remoteSocketWapper, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log);
    },
    close() {
      log(`readableWebSocketStream \u5DF2\u5173\u95ED`);
    },
    abort(reason) {
      log(`readableWebSocketStream \u5DF2\u4E2D\u6B62`, JSON.stringify(reason));
    }
  })).catch((err) => {
    log("readableWebSocketStream \u7BA1\u9053\u9519\u8BEF", err);
  });
  return new Response(null, {
    status: 101,
    // @ts-ignore
    webSocket: client
  });
}
async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log) {
  async function useSocks5Pattern(address) {
    if (go2Socks5s.includes(atob("YWxsIGlu")) || go2Socks5s.includes(atob("Kg==")))
      return true;
    return go2Socks5s.some((pattern) => {
      let regexPattern = pattern.replace(/\*/g, ".*");
      let regex = new RegExp(`^${regexPattern}$`, "i");
      return regex.test(address);
    });
  }
  async function connectAndWrite(address, port, socks = false) {
    log(`connected to ${address}:${port}`);
    const tcpSocket2 = socks ? await socks5Connect(addressType, address, port, log) : connect({
      hostname: address,
      port
    });
    remoteSocket.value = tcpSocket2;
    const writer = tcpSocket2.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket2;
  }
  async function retry() {
    if (enableSocks) {
      tcpSocket = await connectAndWrite(addressRemote, portRemote, true);
    } else {
      if (!proxyIP || proxyIP == "")
        proxyIP = atob("cHJveHlpcC5meHhrLmRlZHluLmlv");
      tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote);
    }
    tcpSocket.closed.catch((error) => {
      console.log("retry tcpSocket closed error", error);
    }).finally(() => {
      safeCloseWebSocket(webSocket);
    });
    remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
  }
  let useSocks = false;
  if (go2Socks5s.length > 0 && enableSocks)
    useSocks = await useSocks5Pattern(addressRemote);
  let tcpSocket = await connectAndWrite(addressRemote, portRemote, useSocks);
  remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
}
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    // 当流开始时的初始化函数
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) {
          return;
        }
        const message = event.data;
        controller.enqueue(message);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) {
          return;
        }
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        log("WebSocket \u670D\u52A1\u5668\u53D1\u751F\u9519\u8BEF");
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },
    // 当使用者从流中拉取数据时调用
    pull(controller) {
    },
    // 当流被取消时调用
    cancel(reason) {
      if (readableStreamCancel) {
        return;
      }
      log(`\u53EF\u8BFB\u6D41\u88AB\u53D6\u6D88\uFF0C\u539F\u56E0\u662F ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    }
  });
  return stream;
}
function processVlessHeader(vlessBuffer, userID2) {
  if (vlessBuffer.byteLength < 24) {
    return {
      hasError: true,
      message: "invalid data"
    };
  }
  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  let isValidUser = false;
  let isUDP = false;
  if (stringify(new Uint8Array(vlessBuffer.slice(1, 17))) === userID2) {
    isValidUser = true;
  }
  if (!isValidUser) {
    return {
      hasError: true,
      message: `invalid user ${new Uint8Array(vlessBuffer.slice(1, 17))}`
    };
  }
  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
  const command = new Uint8Array(
    vlessBuffer.slice(18 + optLength, 18 + optLength + 1)
  )[0];
  if (command === 1) {
  } else if (command === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`
    };
  }
  const portIndex = 18 + optLength + 1;
  const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  let addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(
    vlessBuffer.slice(addressIndex, addressIndex + 1)
  );
  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(
        vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
      ).join(".");
      break;
    case 2:
      addressLength = new Uint8Array(
        vlessBuffer.slice(addressValueIndex, addressValueIndex + 1)
      )[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(
        vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
      );
      break;
    case 3:
      addressLength = 16;
      const dataView = new DataView(
        vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
      );
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invild addressType is ${addressType}`
      };
  }
  if (!addressValue) {
    return {
      hasError: true,
      message: `addressValue is empty, addressType is ${addressType}`
    };
  }
  return {
    hasError: false,
    addressRemote: addressValue,
    // 解析后的远程地址
    addressType,
    // 地址类型
    portRemote,
    // 远程端口
    rawDataIndex: addressValueIndex + addressLength,
    // 原始数据的实际起始位置
    vlessVersion: version,
    // VLESS 协议版本
    isUDP
    // 是否是 UDP 请求
  };
}
async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
  let remoteChunkCount = 0;
  let chunks = [];
  let vlessHeader = vlessResponseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable.pipeTo(
    new WritableStream({
      start() {
      },
      /**
       * 处理每个数据块
       * @param {Uint8Array} chunk 数据块
       * @param {*} controller 控制器
       */
      async write(chunk, controller) {
        hasIncomingData = true;
        if (webSocket.readyState !== WS_READY_STATE_OPEN) {
          controller.error(
            "webSocket.readyState is not open, maybe close"
          );
        }
        if (vlessHeader) {
          webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
          vlessHeader = null;
        } else {
          webSocket.send(chunk);
        }
      },
      close() {
        log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
      },
      abort(reason) {
        console.error(`remoteConnection!.readable abort`, reason);
      }
    })
  ).catch((error) => {
    console.error(
      `remoteSocketToWS has exception `,
      error.stack || error
    );
    safeCloseWebSocket(webSocket);
  });
  if (hasIncomingData === false && retry) {
    log(`retry`);
    retry();
  }
}
function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}
function isValidUUID(uuid) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}
var WS_READY_STATE_OPEN = 1;
var WS_READY_STATE_CLOSING = 2;
function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error", error);
  }
}
var byteToHex = [];
for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 256).toString(16).slice(1));
}
function unsafeStringify(arr, offset = 0) {
  return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}
function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) {
    throw TypeError(`\u751F\u6210\u7684 UUID \u4E0D\u7B26\u5408\u89C4\u8303 ${uuid}`);
  }
  return uuid;
}
async function handleDNSQuery(udpChunk, webSocket, vlessResponseHeader, log) {
  try {
    const dnsServer = "8.8.4.4";
    const dnsPort = 53;
    let vlessHeader = vlessResponseHeader;
    const tcpSocket = connect({
      hostname: dnsServer,
      port: dnsPort
    });
    log(`\u8FDE\u63A5\u5230 ${dnsServer}:${dnsPort}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(udpChunk);
    writer.releaseLock();
    await tcpSocket.readable.pipeTo(new WritableStream({
      async write(chunk) {
        if (webSocket.readyState === WS_READY_STATE_OPEN) {
          if (vlessHeader) {
            webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
            vlessHeader = null;
          } else {
            webSocket.send(chunk);
          }
        }
      },
      close() {
        log(`DNS \u670D\u52A1\u5668(${dnsServer}) TCP \u8FDE\u63A5\u5DF2\u5173\u95ED`);
      },
      abort(reason) {
        console.error(`DNS \u670D\u52A1\u5668(${dnsServer}) TCP \u8FDE\u63A5\u5F02\u5E38\u4E2D\u65AD`, reason);
      }
    }));
  } catch (error) {
    console.error(
      `handleDNSQuery \u51FD\u6570\u53D1\u751F\u5F02\u5E38\uFF0C\u9519\u8BEF\u4FE1\u606F: ${error.message}`
    );
  }
}
async function socks5Connect(addressType, addressRemote, portRemote, log) {
  const { username, password, hostname, port } = parsedSocks5Address;
  const socket = connect({
    hostname,
    // SOCKS5 服务器的主机名
    port
    // SOCKS5 服务器的端口
  });
  const socksGreeting = new Uint8Array([5, 2, 0, 2]);
  const writer = socket.writable.getWriter();
  await writer.write(socksGreeting);
  log("\u5DF2\u53D1\u9001 SOCKS5 \u95EE\u5019\u6D88\u606F");
  const reader = socket.readable.getReader();
  const encoder = new TextEncoder();
  let res = (await reader.read()).value;
  if (res[0] !== 5) {
    log(`SOCKS5 \u670D\u52A1\u5668\u7248\u672C\u9519\u8BEF: \u6536\u5230 ${res[0]}\uFF0C\u671F\u671B\u662F 5`);
    return;
  }
  if (res[1] === 255) {
    log("\u670D\u52A1\u5668\u4E0D\u63A5\u53D7\u4EFB\u4F55\u8BA4\u8BC1\u65B9\u6CD5");
    return;
  }
  if (res[1] === 2) {
    log("SOCKS5 \u670D\u52A1\u5668\u9700\u8981\u8BA4\u8BC1");
    if (!username || !password) {
      log("\u8BF7\u63D0\u4F9B\u7528\u6237\u540D\u548C\u5BC6\u7801");
      return;
    }
    const authRequest = new Uint8Array([
      1,
      // 认证子协议版本
      username.length,
      // 用户名长度
      ...encoder.encode(username),
      // 用户名
      password.length,
      // 密码长度
      ...encoder.encode(password)
      // 密码
    ]);
    await writer.write(authRequest);
    res = (await reader.read()).value;
    if (res[0] !== 1 || res[1] !== 0) {
      log("SOCKS5 \u670D\u52A1\u5668\u8BA4\u8BC1\u5931\u8D25");
      return;
    }
  }
  let DSTADDR;
  switch (addressType) {
    case 1:
      DSTADDR = new Uint8Array(
        [1, ...addressRemote.split(".").map(Number)]
      );
      break;
    case 2:
      DSTADDR = new Uint8Array(
        [3, addressRemote.length, ...encoder.encode(addressRemote)]
      );
      break;
    case 3:
      DSTADDR = new Uint8Array(
        [4, ...addressRemote.split(":").flatMap((x) => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]
      );
      break;
    default:
      log(`\u65E0\u6548\u7684\u5730\u5740\u7C7B\u578B: ${addressType}`);
      return;
  }
  const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 255]);
  await writer.write(socksRequest);
  log("\u5DF2\u53D1\u9001 SOCKS5 \u8BF7\u6C42");
  res = (await reader.read()).value;
  if (res[1] === 0) {
    log("SOCKS5 \u8FDE\u63A5\u5DF2\u5EFA\u7ACB");
  } else {
    log("SOCKS5 \u8FDE\u63A5\u5EFA\u7ACB\u5931\u8D25");
    return;
  }
  writer.releaseLock();
  reader.releaseLock();
  return socket;
}
function socks5AddressParser(address) {
  let [latter, former] = address.split("@").reverse();
  let username, password, hostname, port;
  if (former) {
    const formers = former.split(":");
    if (formers.length !== 2) {
      throw new Error('\u65E0\u6548\u7684 SOCKS \u5730\u5740\u683C\u5F0F\uFF1A\u8BA4\u8BC1\u90E8\u5206\u5FC5\u987B\u662F "username:password" \u7684\u5F62\u5F0F');
    }
    [username, password] = formers;
  }
  const latters = latter.split(":");
  port = Number(latters.pop());
  if (isNaN(port)) {
    throw new Error("\u65E0\u6548\u7684 SOCKS \u5730\u5740\u683C\u5F0F\uFF1A\u7AEF\u53E3\u53F7\u5FC5\u987B\u662F\u6570\u5B57");
  }
  hostname = latters.join(":");
  const regex = /^\[.*\]$/;
  if (hostname.includes(":") && !regex.test(hostname)) {
    throw new Error("\u65E0\u6548\u7684 SOCKS \u5730\u5740\u683C\u5F0F\uFF1AIPv6 \u5730\u5740\u5FC5\u987B\u7528\u65B9\u62EC\u53F7\u62EC\u8D77\u6765\uFF0C\u5982 [2001:db8::1]");
  }
  return {
    username,
    // 用户名，如果没有则为 undefined
    password,
    // 密码，如果没有则为 undefined
    hostname,
    // 主机名，可以是域名、IPv4 或 IPv6 地址
    port
    // 端口号，已转换为数字类型
  };
}
function revertFakeInfo(content, userID2, hostName, isBase64) {
  if (isBase64)
    content = atob(content);
  content = content.replace(new RegExp(fakeUserID, "g"), userID2).replace(new RegExp(fakeHostName, "g"), hostName);
  if (isBase64)
    content = btoa(content);
  return content;
}
async function MD5MD5(text) {
  const encoder = new TextEncoder();
  const firstPass = await crypto.subtle.digest("MD5", encoder.encode(text));
  const firstPassArray = Array.from(new Uint8Array(firstPass));
  const firstHex = firstPassArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  const secondPass = await crypto.subtle.digest("MD5", encoder.encode(firstHex.slice(7, 27)));
  const secondPassArray = Array.from(new Uint8Array(secondPass));
  const secondHex = secondPassArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  return secondHex.toLowerCase();
}
async function ADD(envadd) {
  var addtext = envadd.replace(/[	|"'\r\n]+/g, ",").replace(/,+/g, ",");
  if (addtext.charAt(0) == ",")
    addtext = addtext.slice(1);
  if (addtext.charAt(addtext.length - 1) == ",")
    addtext = addtext.slice(0, addtext.length - 1);
  const add = addtext.split(",");
  return add;
}
function checkSUB(host) {
  if ((!sub || sub == "") && addresses.length + addressesapi.length + addressesnotls.length + addressesnotlsapi.length + addressescsv.length == 0) {
    addresses = [
      "Join.my.Telegram.channel.CMLiussss.to.unlock.more.premium.nodes.cf.090227.xyz#\u52A0\u5165\u6211\u7684\u9891\u9053t.me/CMLiussss\u89E3\u9501\u66F4\u591A\u4F18\u9009\u8282\u70B9",
      "visa.cn:443",
      "www.visa.com:8443",
      "cis.visa.com:2053",
      "africa.visa.com:2083",
      "www.visa.com.sg:2087",
      "www.visaeurope.at:2096",
      "www.visa.com.mt:8443",
      "qa.visamiddleeast.com",
      "time.is",
      "www.wto.org:8443",
      "chatgpt.com:2087",
      "icook.hk",
      //'104.17.0.0#IPv4',
      "[2606:4700::]#IPv6"
    ];
    if (host.includes(".workers.dev"))
      addressesnotls = [
        "usa.visa.com:2095",
        "myanmar.visa.com:8080",
        "www.visa.com.tw:8880",
        "www.visaeurope.ch:2052",
        "www.visa.com.br:2082",
        "www.visasoutheasteurope.com:2086"
      ];
  }
}
var \u5565\u5565\u5565_\u5199\u7684\u8FD9\u662F\u5565\u554A = "dmxlc3M=";
function \u914D\u7F6E\u4FE1\u606F(UUID, \u57DF\u540D\u5730\u5740) {
  const \u534F\u8BAE\u7C7B\u578B = atob(\u5565\u5565\u5565_\u5199\u7684\u8FD9\u662F\u5565\u554A);
  const \u522B\u540D = FileName;
  let \u5730\u5740 = \u57DF\u540D\u5730\u5740;
  let \u7AEF\u53E3 = 443;
  const \u7528\u6237ID = UUID;
  const \u52A0\u5BC6\u65B9\u5F0F = "none";
  const \u4F20\u8F93\u5C42\u534F\u8BAE = "ws";
  const \u4F2A\u88C5\u57DF\u540D = \u57DF\u540D\u5730\u5740;
  const \u8DEF\u5F84 = "/?ed=2560";
  let \u4F20\u8F93\u5C42\u5B89\u5168 = ["tls", true];
  const SNI = \u57DF\u540D\u5730\u5740;
  const \u6307\u7EB9 = "randomized";
  if (\u57DF\u540D\u5730\u5740.includes(".workers.dev")) {
    \u5730\u5740 = "visa.cn";
    \u7AEF\u53E3 = 80;
    \u4F20\u8F93\u5C42\u5B89\u5168 = ["", false];
  }
  const v2ray = `${\u534F\u8BAE\u7C7B\u578B}://${\u7528\u6237ID}@${\u5730\u5740}:${\u7AEF\u53E3}?encryption=${\u52A0\u5BC6\u65B9\u5F0F}&security=${\u4F20\u8F93\u5C42\u5B89\u5168[0]}&sni=${SNI}&fp=${\u6307\u7EB9}&type=${\u4F20\u8F93\u5C42\u534F\u8BAE}&host=${\u4F2A\u88C5\u57DF\u540D}&path=${encodeURIComponent(\u8DEF\u5F84)}#${encodeURIComponent(\u522B\u540D)}`;
  const clash = `- type: ${\u534F\u8BAE\u7C7B\u578B}
  name: ${FileName}
  server: ${\u5730\u5740}
  port: ${\u7AEF\u53E3}
  uuid: ${\u7528\u6237ID}
  network: ${\u4F20\u8F93\u5C42\u534F\u8BAE}
  tls: ${\u4F20\u8F93\u5C42\u5B89\u5168[1]}
  udp: false
  sni: ${SNI}
  client-fingerprint: ${\u6307\u7EB9}
  ws-opts:
    path: "${\u8DEF\u5F84}"
    headers:
      host: ${\u4F2A\u88C5\u57DF\u540D}`;
  return [v2ray, clash];
}
var subParams = ["sub", "base64", "b64", "clash", "singbox", "sb"];
async function getVLESSConfig(userID2, hostName, sub2, UA, RproxyIP2, _url) {
  checkSUB(hostName);
  const userAgent = UA.toLowerCase();
  const Config = \u914D\u7F6E\u4FE1\u606F(userID2, hostName);
  const v2ray = Config[0];
  const clash = Config[1];
  let proxyhost = "";
  if (hostName.includes(".workers.dev") || hostName.includes(".pages.dev")) {
    if (proxyhostsURL && (!proxyhosts || proxyhosts.length == 0)) {
      try {
        const response = await fetch(proxyhostsURL);
        if (!response.ok) {
          console.error("\u83B7\u53D6\u5730\u5740\u65F6\u51FA\u9519:", response.status, response.statusText);
          return;
        }
        const text = await response.text();
        const lines = text.split("\n");
        const nonEmptyLines = lines.filter((line) => line.trim() !== "");
        proxyhosts = proxyhosts.concat(nonEmptyLines);
      } catch (error) {
      }
    }
    if (proxyhosts.length != 0)
      proxyhost = proxyhosts[Math.floor(Math.random() * proxyhosts.length)] + "/";
  }
  if (userAgent.includes("mozilla") && !subParams.some((_searchParams) => _url.searchParams.has(_searchParams))) {
    const newSocks5s = socks5s.map((socks5Address2) => {
      if (socks5Address2.includes("@"))
        return socks5Address2.split("@")[1];
      else if (socks5Address2.includes("//"))
        return socks5Address2.split("//")[1];
      else
        return socks5Address2;
    });
    let socks5List = "";
    if (go2Socks5s.length > 0 && enableSocks) {
      socks5List = `${decodeURIComponent("SOCKS5%EF%BC%88%E7%99%BD%E5%90%8D%E5%8D%95%EF%BC%89%3A%20")}`;
      if (go2Socks5s.includes(atob("YWxsIGlu")) || go2Socks5s.includes(atob("Kg==")))
        socks5List += `${decodeURIComponent("%E6%89%80%E6%9C%89%E6%B5%81%E9%87%8F")}
`;
      else
        socks5List += `
  ${go2Socks5s.join("\n  ")}
`;
    }
    let \u8BA2\u9605\u5668 = "";
    if (!sub2 || sub2 == "") {
      if (enableSocks)
        \u8BA2\u9605\u5668 += `CFCDN\uFF08\u8BBF\u95EE\u65B9\u5F0F\uFF09: Socks5
  ${newSocks5s.join("\n  ")}
${socks5List}`;
      else if (proxyIP && proxyIP != "")
        \u8BA2\u9605\u5668 += `CFCDN\uFF08\u8BBF\u95EE\u65B9\u5F0F\uFF09: ProxyIP
  ${proxyIPs.join("\n  ")}
`;
      else
        \u8BA2\u9605\u5668 += `CFCDN\uFF08\u8BBF\u95EE\u65B9\u5F0F\uFF09: \u65E0\u6CD5\u8BBF\u95EE, \u9700\u8981\u60A8\u8BBE\u7F6E proxyIP/PROXYIP \uFF01\uFF01\uFF01
`;
      \u8BA2\u9605\u5668 += `
\u60A8\u7684\u8BA2\u9605\u5185\u5BB9\u7531 \u5185\u7F6E addresses/ADD* \u53C2\u6570\u53D8\u91CF\u63D0\u4F9B
`;
      if (addresses.length > 0)
        \u8BA2\u9605\u5668 += `ADD\uFF08TLS\u4F18\u9009\u57DF\u540D&IP\uFF09: 
  ${addresses.join("\n  ")}
`;
      if (addressesnotls.length > 0)
        \u8BA2\u9605\u5668 += `ADDNOTLS\uFF08noTLS\u4F18\u9009\u57DF\u540D&IP\uFF09: 
  ${addressesnotls.join("\n  ")}
`;
      if (addressesapi.length > 0)
        \u8BA2\u9605\u5668 += `ADDAPI\uFF08TLS\u4F18\u9009\u57DF\u540D&IP \u7684 API\uFF09: 
  ${addressesapi.join("\n  ")}
`;
      if (addressesnotlsapi.length > 0)
        \u8BA2\u9605\u5668 += `ADDNOTLSAPI\uFF08noTLS\u4F18\u9009\u57DF\u540D&IP \u7684 API\uFF09: 
  ${addressesnotlsapi.join("\n  ")}
`;
      if (addressescsv.length > 0)
        \u8BA2\u9605\u5668 += `ADDCSV\uFF08IPTest\u6D4B\u901Fcsv\u6587\u4EF6 \u9650\u901F ${DLS} \uFF09: 
  ${addressescsv.join("\n  ")}
`;
    } else {
      if (enableSocks)
        \u8BA2\u9605\u5668 += `CFCDN\uFF08\u8BBF\u95EE\u65B9\u5F0F\uFF09: Socks5
  ${newSocks5s.join("\n  ")}
${socks5List}`;
      else if (proxyIP && proxyIP != "")
        \u8BA2\u9605\u5668 += `CFCDN\uFF08\u8BBF\u95EE\u65B9\u5F0F\uFF09: ProxyIP
  ${proxyIPs.join("\n  ")}
`;
      else if (RproxyIP2 == "true")
        \u8BA2\u9605\u5668 += `CFCDN\uFF08\u8BBF\u95EE\u65B9\u5F0F\uFF09: \u81EA\u52A8\u83B7\u53D6ProxyIP
`;
      else
        \u8BA2\u9605\u5668 += `CFCDN\uFF08\u8BBF\u95EE\u65B9\u5F0F\uFF09: \u65E0\u6CD5\u8BBF\u95EE, \u9700\u8981\u60A8\u8BBE\u7F6E proxyIP/PROXYIP \uFF01\uFF01\uFF01
`;
      \u8BA2\u9605\u5668 += `
SUB\uFF08\u4F18\u9009\u8BA2\u9605\u751F\u6210\u5668\uFF09: ${sub2}`;
    }
    return `
################################################################
Subscribe / sub \u8BA2\u9605\u5730\u5740, \u652F\u6301 Base64\u3001clash-meta\u3001sing-box \u8BA2\u9605\u683C\u5F0F
---------------------------------------------------------------
\u5FEB\u901F\u81EA\u9002\u5E94\u8BA2\u9605\u5730\u5740:
https://${proxyhost}${hostName}/${userID2}
https://${proxyhost}${hostName}/${userID2}?sub

Base64\u8BA2\u9605\u5730\u5740:
https://${proxyhost}${hostName}/${userID2}?b64
https://${proxyhost}${hostName}/${userID2}?base64

clash\u8BA2\u9605\u5730\u5740:
https://${proxyhost}${hostName}/${userID2}?clash

singbox\u8BA2\u9605\u5730\u5740:
https://${proxyhost}${hostName}/${userID2}?sb
https://${proxyhost}${hostName}/${userID2}?singbox
---------------------------------------------------------------
################################################################
${FileName} \u914D\u7F6E\u4FE1\u606F
---------------------------------------------------------------
HOST: ${hostName}
UUID: ${userID2}
FKID: ${fakeUserID}
UA: ${UA}

${\u8BA2\u9605\u5668}
SUBAPI\uFF08\u8BA2\u9605\u8F6C\u6362\u540E\u7AEF\uFF09: ${subProtocol}://${subconverter}
SUBCONFIG\uFF08\u8BA2\u9605\u8F6C\u6362\u914D\u7F6E\u6587\u4EF6\uFF09: ${subconfig}
---------------------------------------------------------------
################################################################
v2ray
---------------------------------------------------------------
${v2ray}
---------------------------------------------------------------
################################################################
clash-meta
---------------------------------------------------------------
${clash}
---------------------------------------------------------------
################################################################
telegram \u4EA4\u6D41\u7FA4 \u6280\u672F\u5927\u4F6C~\u5728\u7EBF\u53D1\u724C!
https://t.me/CMLiussss
---------------------------------------------------------------
github \u9879\u76EE\u5730\u5740 Star!Star!Star!!!
https://github.com/cmliu/edgetunnel
---------------------------------------------------------------
################################################################
`;
  } else {
    if (typeof fetch != "function") {
      return "Error: fetch is not available in this environment.";
    }
    let newAddressesapi = [];
    let newAddressescsv = [];
    let newAddressesnotlsapi = [];
    let newAddressesnotlscsv = [];
    if (hostName.includes(".workers.dev")) {
      noTLS = "true";
      fakeHostName = `${fakeHostName}.workers.dev`;
      newAddressesnotlsapi = await getAddressesapi(addressesnotlsapi);
      newAddressesnotlscsv = await getAddressescsv("FALSE");
    } else if (hostName.includes(".pages.dev")) {
      fakeHostName = `${fakeHostName}.pages.dev`;
    } else if (hostName.includes("worker") || hostName.includes("notls") || noTLS == "true") {
      noTLS = "true";
      fakeHostName = `notls${fakeHostName}.net`;
      newAddressesnotlsapi = await getAddressesapi(addressesnotlsapi);
      newAddressesnotlscsv = await getAddressescsv("FALSE");
    } else {
      fakeHostName = `${fakeHostName}.xyz`;
    }
    console.log(`\u865A\u5047HOST: ${fakeHostName}`);
    let url = `${subProtocol}://${sub2}/sub?host=${fakeHostName}&uuid=${fakeUserID}&edgetunnel=cmliu&proxyip=${RproxyIP2}`;
    let isBase64 = true;
    if (!sub2 || sub2 == "") {
      if (hostName.includes("workers.dev") || hostName.includes("pages.dev")) {
        if (proxyhostsURL && (!proxyhosts || proxyhosts.length == 0)) {
          try {
            const response = await fetch(proxyhostsURL);
            if (!response.ok) {
              console.error("\u83B7\u53D6\u5730\u5740\u65F6\u51FA\u9519:", response.status, response.statusText);
              return;
            }
            const text = await response.text();
            const lines = text.split("\n");
            const nonEmptyLines = lines.filter((line) => line.trim() !== "");
            proxyhosts = proxyhosts.concat(nonEmptyLines);
          } catch (error) {
            console.error("\u83B7\u53D6\u5730\u5740\u65F6\u51FA\u9519:", error);
          }
        }
        proxyhosts = [...new Set(proxyhosts)];
      }
      newAddressesapi = await getAddressesapi(addressesapi);
      newAddressescsv = await getAddressescsv("TRUE");
      url = `https://${hostName}/${fakeUserID}`;
      if (hostName.includes("worker") || hostName.includes("notls") || noTLS == "true")
        url += "?notls";
      console.log(`\u865A\u5047\u8BA2\u9605: ${url}`);
    }
    if (!userAgent.includes("CF-Workers-SUB".toLowerCase())) {
      if (userAgent.includes("clash") && !userAgent.includes("nekobox") || _url.searchParams.has("clash") && !userAgent.includes("subconverter")) {
        url = `${subProtocol}://${subconverter}/sub?target=clash&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subconfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
        isBase64 = false;
      } else if (userAgent.includes("sing-box") || userAgent.includes("singbox") || (_url.searchParams.has("singbox") || _url.searchParams.has("sb")) && !userAgent.includes("subconverter")) {
        url = `${subProtocol}://${subconverter}/sub?target=singbox&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subconfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
        isBase64 = false;
      }
    }
    try {
      let content;
      if ((!sub2 || sub2 == "") && isBase64 == true) {
        content = await subAddresses(fakeHostName, fakeUserID, noTLS, newAddressesapi, newAddressescsv, newAddressesnotlsapi, newAddressesnotlscsv);
      } else {
        const response = await fetch(url, {
          headers: {
            "User-Agent": `${UA} CF-Workers-edgetunnel/cmliu`
          }
        });
        content = await response.text();
      }
      if (_url.pathname == `/${fakeUserID}`)
        return content;
      return revertFakeInfo(content, userID2, hostName, isBase64);
    } catch (error) {
      console.error("Error fetching content:", error);
      return `Error fetching content: ${error.message}`;
    }
  }
}
async function getAccountId(email, key) {
  try {
    const url = "https://api.cloudflare.com/client/v4/accounts";
    const headers = new Headers({
      "X-AUTH-EMAIL": email,
      "X-AUTH-KEY": key
    });
    const response = await fetch(url, { headers });
    const data = await response.json();
    return data.result[0].id;
  } catch (error) {
    return false;
  }
}
async function getSum(accountId, accountIndex, email, key, startDate, endDate) {
  try {
    const startDateISO = new Date(startDate).toISOString();
    const endDateISO = new Date(endDate).toISOString();
    const query = JSON.stringify({
      query: `query getBillingMetrics($accountId: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
				viewer {
					accounts(filter: {accountTag: $accountId}) {
						pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) {
							sum {
								requests
							}
						}
						workersInvocationsAdaptive(limit: 10000, filter: $filter) {
							sum {
								requests
							}
						}
					}
				}
			}`,
      variables: {
        accountId,
        filter: { datetime_geq: startDateISO, datetime_leq: endDateISO }
      }
    });
    const headers = new Headers({
      "Content-Type": "application/json",
      "X-AUTH-EMAIL": email,
      "X-AUTH-KEY": key
    });
    const response = await fetch(`https://api.cloudflare.com/client/v4/graphql`, {
      method: "POST",
      headers,
      body: query
    });
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const res = await response.json();
    const pagesFunctionsInvocationsAdaptiveGroups = res?.data?.viewer?.accounts?.[accountIndex]?.pagesFunctionsInvocationsAdaptiveGroups;
    const workersInvocationsAdaptive = res?.data?.viewer?.accounts?.[accountIndex]?.workersInvocationsAdaptive;
    if (!pagesFunctionsInvocationsAdaptiveGroups && !workersInvocationsAdaptive) {
      throw new Error("\u627E\u4E0D\u5230\u6570\u636E");
    }
    const pagesSum = pagesFunctionsInvocationsAdaptiveGroups.reduce((a, b) => a + b?.sum.requests, 0);
    const workersSum = workersInvocationsAdaptive.reduce((a, b) => a + b?.sum.requests, 0);
    return [pagesSum, workersSum];
  } catch (error) {
    return [0, 0];
  }
}
async function getAddressesapi(api) {
  if (!api || api.length === 0) {
    return [];
  }
  let newapi = "";
  const controller = new AbortController();
  const timeout = setTimeout(() => {
    controller.abort();
  }, 2e3);
  try {
    const responses = await Promise.allSettled(api.map((apiUrl) => fetch(apiUrl, {
      method: "get",
      headers: {
        "Accept": "text/html,application/xhtml+xml,application/xml;",
        "User-Agent": "CF-Workers-edgetunnel/cmliu"
      },
      signal: controller.signal
      // 将AbortController的信号量添加到fetch请求中，以便于需要时可以取消请求
    }).then((response) => response.ok ? response.text() : Promise.reject())));
    for (const response of responses) {
      if (response.status === "fulfilled") {
        const content = await response.value;
        newapi += content + "\n";
      }
    }
  } catch (error) {
    console.error(error);
  } finally {
    clearTimeout(timeout);
  }
  const newAddressesapi = await ADD(newapi);
  return newAddressesapi;
}
async function getAddressescsv(tls) {
  if (!addressescsv || addressescsv.length === 0) {
    return [];
  }
  let newAddressescsv = [];
  for (const csvUrl of addressescsv) {
    try {
      const response = await fetch(csvUrl);
      if (!response.ok) {
        console.error("\u83B7\u53D6CSV\u5730\u5740\u65F6\u51FA\u9519:", response.status, response.statusText);
        continue;
      }
      const text = await response.text();
      let lines;
      if (text.includes("\r\n")) {
        lines = text.split("\r\n");
      } else {
        lines = text.split("\n");
      }
      const header = lines[0].split(",");
      const tlsIndex = header.indexOf("TLS");
      const ipAddressIndex = 0;
      const portIndex = 1;
      const dataCenterIndex = tlsIndex + 1;
      if (tlsIndex === -1) {
        console.error("CSV\u6587\u4EF6\u7F3A\u5C11\u5FC5\u9700\u7684\u5B57\u6BB5");
        continue;
      }
      for (let i = 1; i < lines.length; i++) {
        const columns = lines[i].split(",");
        const speedIndex = columns.length - 1;
        if (columns[tlsIndex].toUpperCase() === tls && parseFloat(columns[speedIndex]) > DLS) {
          const ipAddress = columns[ipAddressIndex];
          const port = columns[portIndex];
          const dataCenter = columns[dataCenterIndex];
          const formattedAddress = `${ipAddress}:${port}#${dataCenter}`;
          newAddressescsv.push(formattedAddress);
        }
      }
    } catch (error) {
      console.error("\u83B7\u53D6CSV\u5730\u5740\u65F6\u51FA\u9519:", error);
      continue;
    }
  }
  return newAddressescsv;
}
function subAddresses(host, UUID, noTLS2, newAddressesapi, newAddressescsv, newAddressesnotlsapi, newAddressesnotlscsv) {
  const regex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[.*\]):?(\d+)?#?(.*)?$/;
  addresses = addresses.concat(newAddressesapi);
  addresses = addresses.concat(newAddressescsv);
  let notlsresponseBody;
  if (noTLS2 == "true") {
    addressesnotls = addressesnotls.concat(newAddressesnotlsapi);
    addressesnotls = addressesnotls.concat(newAddressesnotlscsv);
    const uniqueAddressesnotls = [...new Set(addressesnotls)];
    notlsresponseBody = uniqueAddressesnotls.map((address) => {
      let port = "-1";
      let addressid = address;
      const match = addressid.match(regex);
      if (!match) {
        if (address.includes(":") && address.includes("#")) {
          const parts = address.split(":");
          address = parts[0];
          const subParts = parts[1].split("#");
          port = subParts[0];
          addressid = subParts[1];
        } else if (address.includes(":")) {
          const parts = address.split(":");
          address = parts[0];
          port = parts[1];
        } else if (address.includes("#")) {
          const parts = address.split("#");
          address = parts[0];
          addressid = parts[1];
        }
        if (addressid.includes(":")) {
          addressid = addressid.split(":")[0];
        }
      } else {
        address = match[1];
        port = match[2] || port;
        addressid = match[3] || address;
      }
      const httpPorts = ["8080", "8880", "2052", "2082", "2086", "2095"];
      if (!isValidIPv4(address) && port == "-1") {
        for (let httpPort of httpPorts) {
          if (address.includes(httpPort)) {
            port = httpPort;
            break;
          }
        }
      }
      if (port == "-1")
        port = "80";
      let \u4F2A\u88C5\u57DF\u540D = host;
      let \u6700\u7EC8\u8DEF\u5F84 = "/?ed=2560";
      let \u8282\u70B9\u5907\u6CE8 = "";
      const \u534F\u8BAE\u7C7B\u578B = atob(\u5565\u5565\u5565_\u5199\u7684\u8FD9\u662F\u5565\u554A);
      const vlessLink = `${\u534F\u8BAE\u7C7B\u578B}://${UUID}@${address}:${port}?encryption=none&security=&type=ws&host=${\u4F2A\u88C5\u57DF\u540D}&path=${encodeURIComponent(\u6700\u7EC8\u8DEF\u5F84)}#${encodeURIComponent(addressid + \u8282\u70B9\u5907\u6CE8)}`;
      return vlessLink;
    }).join("\n");
  }
  const uniqueAddresses = [...new Set(addresses)];
  const responseBody = uniqueAddresses.map((address) => {
    let port = "-1";
    let addressid = address;
    const match = addressid.match(regex);
    if (!match) {
      if (address.includes(":") && address.includes("#")) {
        const parts = address.split(":");
        address = parts[0];
        const subParts = parts[1].split("#");
        port = subParts[0];
        addressid = subParts[1];
      } else if (address.includes(":")) {
        const parts = address.split(":");
        address = parts[0];
        port = parts[1];
      } else if (address.includes("#")) {
        const parts = address.split("#");
        address = parts[0];
        addressid = parts[1];
      }
      if (addressid.includes(":")) {
        addressid = addressid.split(":")[0];
      }
    } else {
      address = match[1];
      port = match[2] || port;
      addressid = match[3] || address;
    }
    const httpsPorts = ["2053", "2083", "2087", "2096", "8443"];
    if (!isValidIPv4(address) && port == "-1") {
      for (let httpsPort of httpsPorts) {
        if (address.includes(httpsPort)) {
          port = httpsPort;
          break;
        }
      }
    }
    if (port == "-1")
      port = "443";
    let \u4F2A\u88C5\u57DF\u540D = host;
    let \u6700\u7EC8\u8DEF\u5F84 = "/?ed=2560";
    let \u8282\u70B9\u5907\u6CE8 = "";
    if (proxyhosts.length > 0 && (\u4F2A\u88C5\u57DF\u540D.includes(".workers.dev") || \u4F2A\u88C5\u57DF\u540D.includes("pages.dev"))) {
      \u6700\u7EC8\u8DEF\u5F84 = `/${\u4F2A\u88C5\u57DF\u540D}${\u6700\u7EC8\u8DEF\u5F84}`;
      \u4F2A\u88C5\u57DF\u540D = proxyhosts[Math.floor(Math.random() * proxyhosts.length)];
      \u8282\u70B9\u5907\u6CE8 = ` \u5DF2\u542F\u7528\u4E34\u65F6\u57DF\u540D\u4E2D\u8F6C\u670D\u52A1\uFF0C\u8BF7\u5C3D\u5FEB\u7ED1\u5B9A\u81EA\u5B9A\u4E49\u57DF\uFF01`;
    }
    const \u534F\u8BAE\u7C7B\u578B = atob(\u5565\u5565\u5565_\u5199\u7684\u8FD9\u662F\u5565\u554A);
    const vlessLink = `${\u534F\u8BAE\u7C7B\u578B}://${UUID}@${address}:${port}?encryption=none&security=tls&sni=${\u4F2A\u88C5\u57DF\u540D}&fp=random&type=ws&host=${\u4F2A\u88C5\u57DF\u540D}&path=${encodeURIComponent(\u6700\u7EC8\u8DEF\u5F84)}#${encodeURIComponent(addressid + \u8282\u70B9\u5907\u6CE8)}`;
    return vlessLink;
  }).join("\n");
  let base64Response = responseBody;
  if (noTLS2 == "true")
    base64Response += `
${notlsresponseBody}`;
  return btoa(base64Response);
}
async function sendMessage(type, ip, add_data = "") {
  if (BotToken !== "" && ChatID !== "") {
    let msg = "";
    const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
    if (response.status == 200) {
      const ipInfo = await response.json();
      msg = `${type}
IP: ${ip}
\u56FD\u5BB6: ${ipInfo.country}
<tg-spoiler>\u57CE\u5E02: ${ipInfo.city}
\u7EC4\u7EC7: ${ipInfo.org}
ASN: ${ipInfo.as}
${add_data}`;
    } else {
      msg = `${type}
IP: ${ip}
<tg-spoiler>${add_data}`;
    }
    let url = "https://api.telegram.org/bot" + BotToken + "/sendMessage?chat_id=" + ChatID + "&parse_mode=HTML&text=" + encodeURIComponent(msg);
    return fetch(url, {
      method: "get",
      headers: {
        "Accept": "text/html,application/xhtml+xml,application/xml;",
        "Accept-Encoding": "gzip, deflate, br",
        "User-Agent": "Mozilla/5.0 Chrome/90.0.4430.72"
      }
    });
  }
}
function isValidIPv4(address) {
  const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(address);
}
export {
  src_default as default
};
//# sourceMappingURL=index.js.map
