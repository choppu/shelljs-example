import ShellJS from "@choppu/shelljs";
import TransportWebHID from "@choppu/shelljs-web-hid";
import * as secp from '@noble/secp256k1';
import { keccak256 } from 'js-sha3';
import { recoverPersonalSignature, recoverTypedSignature } from '@metamask/eth-sig-util';
import { publicToAddress, hexToBytes, bytesToHex, PrefixedHexString } from "@ethereumjs/util";
import Transport, { StatusCodes } from "@choppu/shelljs/lib/transport";
import Commands from "@choppu/shelljs/lib/commands";
import { Buffer } from "buffer";


const connectBtn = document.getElementById("btn-connect") as HTMLButtonElement;
const disconnectBtn = document.getElementById("btn-disconnect") as HTMLButtonElement;
const getAddressBtn = document.getElementById("btn-get-address") as HTMLButtonElement;
const getConfBtn = document.getElementById("btn-get-conf") as HTMLButtonElement;
const logsContainer = document.getElementById("logs-container");
const txSignBtn = document.getElementById("btn-sign-tx") as HTMLButtonElement;
const signPSBTBtn = document.getElementById("btn-sign-psbt") as HTMLButtonElement;
const signData = document.getElementById("sign-data") as HTMLTextAreaElement;
const eip712SignBtn = document.getElementById("btn-sign-eip712") as HTMLButtonElement;
const pMessSignBtn = document.getElementById("btn-sign-message") as HTMLButtonElement;
const path = document.getElementById("sign-path") as HTMLInputElement;
const fw = document.getElementById("load-fw") as HTMLInputElement;
const db = document.getElementById("load-erc20") as HTMLInputElement;
const loadFWBtn = document.getElementById("btn-load-fw") as HTMLButtonElement;
const loadERC20Btn = document.getElementById("btn-load-erc20") as HTMLButtonElement;

let data: string;
let date: number;

function addMessage(message: string, container: HTMLElement): void {
  let m = document.createElement('p');
  m.innerHTML = message;
  container.appendChild(m);
}

function addLogsMessage(success: boolean, succMessage: string, errMessage: string) {
  let message = success ? succMessage : errMessage;
  addMessage(message, logsContainer);
}

function padTo2Digits(n: number): string {
  return n.toString().padStart(2, '0');
}

function formattedDate(): string {
  let date = new Date(Date.now());
  let d = [
    padTo2Digits(date.getDate()),
    padTo2Digits(date.getMonth() + 1),
    date.getFullYear(),
  ].join('-');

  let t = [
    padTo2Digits(date.getHours()),
    padTo2Digits(date.getMinutes()),
    padTo2Digits(date.getSeconds()),
  ].join(':');

  return d + " " + t;
}

function fromHex(hexStr: string): ArrayBuffer {
  return new Uint8Array(hexStr.match(/../g).map(h => parseInt(h, 16))).buffer;
}

function prefixedHex(hex: string): PrefixedHexString {
  return ("0x" + hex.replace(/^0x/i, "")) as PrefixedHexString;
}

// Shell reports the public key as hex ("0x"-prefixed or not) in SEC1 form, "04" + X||Y.
// @ethereumjs/util wants the bare 64-byte X||Y; noble wants the 65-byte SEC1 form.
function publicKeyBytes(pubKey: string, sec1: boolean): Uint8Array {
  let hex = pubKey.replace(/^0x/i, "");

  if (hex.length == 130) hex = hex.substring(2);
  if (sec1 && hex.length == 128) hex = "04" + hex;

  return hexToBytes(prefixedHex(hex));
}

function getV(v: number): number {
  if (v <= 1) {
    return v;
  } else {
    return ~(v & 1) & 1;
  }
}

function verifySign(s: { v: string, r: string, s: string }, message: string, pubKey: string): { signature: string, signed: boolean } {
  let messageHash = keccak256(fromHex(message));
  let sigV = getV(Number(s.v));
  let signature = new secp.Signature(BigInt("0x" + s.r), BigInt("0x" + s.s), sigV);
  let sigBytes = signature.toBytes();

  return { signature: secp.etc.bytesToHex(sigBytes), signed: secp.verify(sigBytes, hexToBytes(prefixedHex(messageHash)), publicKeyBytes(pubKey, true), { prehash: false }) };
}

function verifyMessSign(s: { v: number, r: string, s: string }, address: Uint8Array, m: any, f: (options: {}) => {}): { signature: string, signed: boolean } {
  let sigV = getV(s.v);
  let signature = "0x" + s.r + s.s + (sigV ? "01" : "00");
  let recAddress = f({ data: m, signature: signature, version: "V4" });

  return { signature: signature, signed: recAddress == bytesToHex(address) };
}

async function readFile(file: Blob): Promise<ArrayBuffer> {
  let res = await new Promise((resolve) => {
    let fileReader = new FileReader();
    fileReader.onload = () => resolve(fileReader.result);
    fileReader.readAsArrayBuffer(file);
  });

  return res as ArrayBuffer;
}

function main(): void {
  let transport: Transport;
  let cmdSet: Commands;

  connectBtn.addEventListener("click", async () => {
    try {
      transport = await TransportWebHID.create();
      cmdSet = new ShellJS.Commands(transport);
      disconnectBtn.disabled = false;
      getAddressBtn.disabled = false;
      getConfBtn.disabled = false;
      signPSBTBtn.disabled = false;
      txSignBtn.disabled = false;
      eip712SignBtn.disabled = false;
      pMessSignBtn.disabled = false;
      loadFWBtn.disabled = false;
      loadERC20Btn.disabled = false;
      connectBtn.disabled = true;

      let message = formattedDate() + "&nbsp;" + "Shell connected";
      addMessage(message, logsContainer);
    } catch (err) {
      let errMsg = `${formattedDate()} &nbsp; ${err}`;
      addMessage(errMsg, logsContainer);
    }
  });

  getAddressBtn.addEventListener("click", async () => {
    try {
      if (cmdSet) {
        const { fingerprint, publicKey, chainCode } = await cmdSet.getPublicKey(path.value, true);
        let message = `${formattedDate()} &nbsp; Public key - <span style="color: green;">0x${publicKey}</span>, Fingerprint - <span style="color: green;">${fingerprint}</span>`;
        addMessage(message, logsContainer);
      }
    } catch (err) {
      let errMsg = `${formattedDate()} &nbsp; ${err}`;
      addMessage(errMsg, logsContainer);
    }

  });

  getConfBtn.addEventListener("click", async () => {
    try {
      if (cmdSet) {
        date = Date.now();
        const { fwVersion, dbVersion, serialNumber, publicKey, fwVariant, fwBeta } = await cmdSet.getAppConfiguration();
        const fwVar = ((fwVariant != undefined) && (fwVariant == 1)) ? "Bitcoin only" : "Multi-coin";
        const fwB = ((fwBeta != undefined) && (fwBeta == 1)) ? `${fwVersion}-beta-${fwBeta}` : `${fwVersion}-release`;
        let message = `${formattedDate()} &nbsp; Firmware version - <span style="color: green;">${fwVersion}</span>, Firmware variant - <span style="color: green;">${fwVar}</span>, Firmware type - <span style="color: green;">${fwB}</span>, DB version - <span style="color: green;">${dbVersion}</span>, Serial number - <span style="color: green;">0x${serialNumber}</span>, Public key - <span style="color: green;">0x${publicKey}</span>`;
        addMessage(message, logsContainer);
      }
    } catch (err) {
      let errMsg = `${formattedDate()} &nbsp; ${err}`;
      addMessage(errMsg, logsContainer);
    }

  });

  signPSBTBtn.addEventListener("click", async () => {
    if (cmdSet) {
      try {
        let data = fromHex(signData.value);
        let res = await cmdSet.signPSBT(data);
        let succMessage = `${formattedDate()} &nbsp; Transaction successfully signed. PSBT - <span style="color: green;">${Buffer.from(res).toString("hex")}</span>`;
        addMessage(succMessage, logsContainer);
      } catch (err) {
        let errMsg = `${formattedDate()} &nbsp; ${err}`;
        addMessage(errMsg, logsContainer);
      }
    }
  });

  txSignBtn.addEventListener("click", async () => {
    try {
      if (cmdSet) {
        data = signData.value;
        let { publicKey } = await cmdSet.getPublicKey(path.value);
        let res = await cmdSet.signEthTransaction(path.value, data);
        let { signature, signed } = verifySign(res, data, publicKey);
        let succMessage = `${formattedDate()} &nbsp; Transaction successfully signed. Signature - <span style="color: green;">0x${signature}</span>`;
        let errMessage = formattedDate() + "&nbsp;" + "Error. Invalid signature";
        addLogsMessage(signed, succMessage, errMessage);
      }
    } catch (err) {
      let errMsg = `${formattedDate()} &nbsp; ${err}`;
      addMessage(errMsg, logsContainer);
    }
  });

  pMessSignBtn.addEventListener("click", async () => {
    try {
      if (cmdSet) {
        date = Date.now();
        data = signData.value;

        let { publicKey } = await cmdSet.getPublicKey(path.value);
        let res = await cmdSet.signEthPersonalMessage(path.value, data);
        let r = verifyMessSign(res, publicToAddress(publicKeyBytes(publicKey, false)), new TextEncoder().encode(data), recoverPersonalSignature);
        let succMessage = `${formattedDate()} &nbsp; Personal message successfully signed. Signature - <span style="color: green;">${r.signature}</span>`;
        let errMessage = formattedDate() + "&nbsp;" + "Error. Invalid signature";
        addLogsMessage(r.signed, succMessage, errMessage);
      }
    } catch (err) {
      let errMsg = `${formattedDate()} &nbsp; ${err}`;
      addMessage(errMsg, logsContainer);
    }

  });

  eip712SignBtn.addEventListener("click", async () => {
    try {
      if (cmdSet) {
        let eip712MessJSON = JSON.parse(signData.value);
        let { publicKey } = await cmdSet.getPublicKey(path.value);
        let res = await cmdSet.signEIP712Message(path.value, eip712MessJSON);
        let r = verifyMessSign(res, publicToAddress(publicKeyBytes(publicKey, false)), eip712MessJSON, recoverTypedSignature);
        let succMessage = `${formattedDate()} &nbsp; EIP712 Message successfully signed. Signature - <span style="color: green;">${r.signature}</span>`;
        let errMessage = formattedDate() + "&nbsp;" + "Error. Invalid signature";
        addLogsMessage(r.signed, succMessage, errMessage);
      }
    } catch (err) {
      let errMsg = `${formattedDate()} &nbsp; ${err}`;
      addMessage(errMsg, logsContainer);
    }

  });

  loadFWBtn.addEventListener("click", async () => {
    const f = fw.files[0];
    let message: string;

    if (f && cmdSet) {
      let firmware = await readFile(f);

      try {
        message = formattedDate() + "&nbsp;" + "Updating firmware...";
        addMessage(message, logsContainer);
        await cmdSet.loadFirmware(firmware);
        message = formattedDate() + "&nbsp;" + "Firmware updated successfuly"
        addMessage(message, logsContainer);
      } catch (e) {
        let err = e.statusCode == StatusCodes.SECURITY_STATUS_NOT_SATISFIED ? "Firmware update canceled by user" : e;
        message = formattedDate() + "&nbsp;" + "Error: " + err;
        addMessage(message, logsContainer);
      }
    } else {
      message = f ? (formattedDate() + "&nbsp;" + "Error. Shell is disconnected") : (formattedDate() + "&nbsp;" + "No firmware file found");
      addMessage(message, logsContainer);
    }
  });

  loadERC20Btn.addEventListener("click", async () => {
    const dbF = db.files[0];
    let message: string;

    if (dbF && cmdSet) {
      let database = await readFile(dbF);

      try {
        message = formattedDate() + "&nbsp;" + "Updating database...";
        addMessage(message, logsContainer);
        await cmdSet.loadDatabase(database);
        message = formattedDate() + "&nbsp;" + "Database updated successfuly"
        addMessage(message, logsContainer);
      } catch (e) {
        let err = e.statusCode == StatusCodes.SECURITY_STATUS_NOT_SATISFIED ? "Firmware update canceled by user" : e;
        message = formattedDate() + "&nbsp;" + "Error: " + err;
        addMessage(message, logsContainer);
      }
    } else {
      message = dbF ? (formattedDate() + "&nbsp;" + "Error. Shell is disconnected") : (formattedDate() + "&nbsp;" + "No database file found");
      addMessage(message, logsContainer);
    }
  });

  disconnectBtn.addEventListener("click", async () => {
    if (transport) {
      await transport.close();
      disconnectBtn.disabled = true;
      getAddressBtn.disabled = true;
      getConfBtn.disabled = true;
      txSignBtn.disabled = true;
      eip712SignBtn.disabled = true;
      pMessSignBtn.disabled = true;
      loadFWBtn.disabled = true;
      loadERC20Btn.disabled = true;
      connectBtn.disabled = false;

      let message = formattedDate() + "&nbsp;" + "Shell disconnected"
      addMessage(message, logsContainer);
    }
  });
}

main();

