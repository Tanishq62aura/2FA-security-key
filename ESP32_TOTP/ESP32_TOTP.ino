#include <Arduino.h>
#include <Preferences.h>
#include "mbedtls/md.h"
#include "mbedtls/aes.h"
#include <esp_system.h>   // esp_fill_random, ESP.getEfuseMac()
#include "USB.h"
#include "USBHIDKeyboard.h"

USBHIDKeyboard Keyboard;

// =======================================================
//  CONFIGURATION
// =======================================================

// Hardware pins (EDIT THESE IF NEEDED)
const int BUTTON_PIN   = 0;         // 0 = BOOT button
#ifndef LED_BUILTIN
#define LED_BUILTIN 48
#endif
const int LED_PIN      = LED_BUILTIN;

const uint32_t TOTP_PERIOD = 30; // 30s TOTP window

// Default secret used only for migration / first boot (not auto-used here)
const char* DEFAULT_BASE32_SECRET = "JBSWY3DPEHPK3PXP";

// 20-byte sync key (hex). MUST match Python server for secure time sync
const char* SYNC_KEY_HEX = "00112233445566778899AABBCCDDEEFF00112233";

// Account system limits
static const int MAX_ACCOUNTS = 10;
static const int MAX_NAME_LEN = 16;

// Long-press detection for button (ms)
const uint32_t LONG_PRESS_MS = 20;

// =======================================================
//  GLOBAL STATE
// =======================================================

// Time sync
static uint64_t baseUnix   = 0;
static uint32_t baseMillis = 0;
static bool     timeSynced = false;

// NVS
Preferences prefs;

// Sync key (binary)
uint8_t syncKey[32];
int     syncKeyLen = 0;

// ENCRYPTED STORAGE: AES-CTR
uint8_t g_masterKey[32];   // 256-bit derived key
bool    g_masterKeyReady = false;

// PIN LOCK SYSTEM
static bool   deviceLocked      = true;
static uint8_t storedPinHash[32];   // SHA-256(pin + salt)
static uint8_t storedSalt[16];
static bool   pinSet            = false;
static uint8_t failCount        = 0;
static const uint8_t MAX_FAILS  = 5;

// ACCOUNT STRUCTURE
struct Account {
  bool    present;
  char    name[MAX_NAME_LEN + 1];
  uint8_t key[32];
  uint8_t keyLen;
};

Account accounts[MAX_ACCOUNTS];
uint8_t activeAccount = 0;

// Button state
bool     btnPrev      = false;
uint32_t btnDownMs    = 0;

uint32_t greenUntil   = 0;

// Suppress periodic TIME/STATUS broadcast while responding to commands
static bool suppressBroadcast = false;


#define MAX_SEEN_NONCES 16
static uint32_t seenNonces[MAX_SEEN_NONCES];
static int      seenNonceCount = 0;
static uint64_t lastSyncUnix   = 0;

bool isNonceSeen(uint32_t nonce) {
  for (int i = 0; i < seenNonceCount; i++) {
    if (seenNonces[i] == nonce) return true;
  }
  return false;
}

void recordNonce(uint32_t nonce) {
  if (seenNonceCount < MAX_SEEN_NONCES) {
    seenNonces[seenNonceCount++] = nonce;
  } else {
    // Ring buffer — evict oldest
    memmove(seenNonces, seenNonces + 1,
            (MAX_SEEN_NONCES - 1) * sizeof(uint32_t));
    seenNonces[MAX_SEEN_NONCES - 1] = nonce;
  }
}

// =======================================================
//  HELPERS: Base32 / Hex
// =======================================================

int base32Lookup(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= '2' && c <= '7') return (c - '2') + 26;
  return -1;
}

int base32Decode(const char* encoded, uint8_t* out, int outSize) {
  int buffer = 0, bitsLeft = 0, count = 0;
  for (int i = 0; encoded[i] != 0; i++) {
    int val = base32Lookup(encoded[i]);
    if (val < 0) continue;
    buffer = (buffer << 5) | val;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      if (count >= outSize) return -1;
      out[count++] = (buffer >> (bitsLeft - 8)) & 0xFF;
      bitsLeft -= 8;
    }
  }
  return count;
}

int hexToBytes(const char* hex, uint8_t* out, int outSize) {
  int len = strlen(hex);
  if (len % 2 != 0) return -1;
  int bytes = len / 2;
  if (bytes > outSize) return -1;
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
  };
  for (int i = 0; i < bytes; i++) {
    int n1 = nibble(hex[2 * i]);
    int n2 = nibble(hex[2 * i + 1]);
    if (n1 < 0 || n2 < 0) return -1;
    out[i] = (uint8_t)((n1 << 4) | n2);
  }
  return bytes;
}

// =======================================================
//  HASH HELPERS (SHA-256, HMAC-SHA1)
// =======================================================

void sha256(const uint8_t* in, size_t len, uint8_t out[32]) {
  mbedtls_md_context_t ctx;
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, info, 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, in, len);
  mbedtls_md_finish(&ctx, out);
  mbedtls_md_free(&ctx);
}

void hmacSha1(const uint8_t* key, size_t keyLen,
              const uint8_t* data, size_t dataLen,
              uint8_t out[20]) {
  mbedtls_md_context_t ctx;
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);

  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, info, 1);

  mbedtls_md_hmac_starts(&ctx, key, keyLen);
  mbedtls_md_hmac_update(&ctx, data, dataLen);
  mbedtls_md_hmac_finish(&ctx, out);

  mbedtls_md_free(&ctx);
}

// =======================================================
//  TOTP
// =======================================================

uint32_t generateTOTP(const uint8_t* key, int keyLen, uint64_t unixTime) {
  uint64_t timestep = unixTime / TOTP_PERIOD;
  uint8_t msg[8];
  for (int i = 7; i >= 0; i--) {
    msg[i] = timestep & 0xFF;
    timestep >>= 8;
  }
  uint8_t hash[20];
  hmacSha1(key, keyLen, msg, 8, hash);

  int offset = hash[19] & 0x0F;
  uint32_t binary =
    ((hash[offset] & 0x7F) << 24) |
    ((hash[offset + 1]) << 16)    |
    ((hash[offset + 2]) << 8)     |
    (hash[offset + 3]);

  return binary % 1000000;
}

// =======================================================
//  TIME SYNC / TSYNC
// =======================================================

void applyTimeSync(uint64_t ts) {
  baseUnix   = ts;
  baseMillis = millis();
  timeSynced = true;
  Serial.print("TIME_SYNC_OK:");
  Serial.println((unsigned long long)ts);
}

uint64_t currentUnix() {
  if (!timeSynced) return 0;
  uint32_t elapsedMs = millis() - baseMillis;
  return baseUnix + (elapsedMs / 1000);
}

uint8_t secondsLeftInWindow(uint64_t unixTime) {
  uint8_t offset = unixTime % TOTP_PERIOD;
  return (uint8_t)(TOTP_PERIOD - offset);
}

// Legacy plain TIME:<unix> handler (for debugging)
void handlePlainTimePacket(String line) {
  line.trim();
  if (!line.startsWith("TIME:")) return;
  String tsStr = line.substring(5);
  tsStr.trim();

  uint64_t ts = 0;
  for (int i = 0; i < tsStr.length(); i++) {
    char c = tsStr[i];
    if (c < '0' || c > '9') return;
    ts = ts * 10 + (uint64_t)(c - '0');
  }
  applyTimeSync(ts);
}

void handleSecureTimePacket(String line) {
  line.trim();
  if (!line.startsWith("TSYNC:")) return;

  String rest = line.substring(6);
  int p1 = rest.indexOf(':');
  int p2 = rest.indexOf(':', p1 + 1);
  if (p1 < 0 || p2 < 0) {
    Serial.println("ERR:TSYNC_FORMAT");
    return;
  }

  String tsStr    = rest.substring(0, p1);
  String nonceStr = rest.substring(p1 + 1, p2);
  String hmacStr  = rest.substring(p2 + 1);

  tsStr.trim(); nonceStr.trim(); hmacStr.trim();

  String msgStr = tsStr + ":" + nonceStr;
  int msgLen = msgStr.length();
  if (msgLen <= 0 || msgLen > 64) {
    Serial.println("ERR:TSYNC_MSGLEN");
    return;
  }

  uint8_t msgBuf[64];
  memcpy(msgBuf, msgStr.c_str(), msgLen);

  uint8_t mac[20];
  hmacSha1(syncKey, syncKeyLen, msgBuf, msgLen, mac);

  char macHex[41];
  for (int i = 0; i < 20; i++) {
    sprintf(&macHex[i * 2], "%02X", mac[i]);
  }
  macHex[40] = '\0';

  hmacStr.toUpperCase();
  if (hmacStr.length() != 40 || !hmacStr.equals(String(macHex))) {
    Serial.println("ERR:TSYNC_HMAC");
    return;
  }

  uint64_t ts = 0;
  for (int i = 0; i < tsStr.length(); i++) {
    char c = tsStr[i];
    if (c < '0' || c > '9') {
      Serial.println("ERR:TSYNC_TIME");
      return;
    }
    ts = ts * 10 + (uint64_t)(c - '0');
  }

  applyTimeSync(ts);
  Serial.println("TSYNC_OK");


  if (ts < lastSyncUnix) {
  Serial.println("ERR:TSYNC_REPLAY_TIME");
  return;
}

int64_t drift = (int64_t)ts - (int64_t)(currentUnix());
if (drift < -60 || drift > 60) {
  Serial.println("ERR:TSYNC_WINDOW");
  return;
}

// Parse nonce hex to uint32
uint32_t nonceVal = (uint32_t)strtoul(nonceStr.c_str(), nullptr, 16);
if (isNonceSeen(nonceVal)) {
  Serial.println("ERR:TSYNC_REPLAY_NONCE");
  return;
}

recordNonce(nonceVal);
lastSyncUnix = ts;
applyTimeSync(ts);


}

// =======================================================
//  ACCOUNT STORAGE IN NVS (AES-CTR)
// =======================================================

String keyName(const char* prefix, int idx) {
  return String(prefix) + idx;
}

void deriveMasterKey() {
  uint8_t mac[8];
  uint64_t mac64 = ESP.getEfuseMac();
  for (int i = 0; i < 8; i++) {
    mac[7 - i] = (mac64 >> (i * 8)) & 0xFF;
  }

  const char* salt = "TOTP_MASTER_KEY_V1"; // we use first 16 bytes
  uint8_t buf[8 + 16];
  memcpy(buf, mac, 8);
  memcpy(buf + 8, salt, 16);

  sha256(buf, sizeof(buf), g_masterKey);  // 32-byte output
  g_masterKeyReady = true;
}

bool aesCtrCrypt(const uint8_t* key, const uint8_t iv[16],
                 const uint8_t* in, uint8_t* out, size_t len)
{
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);

  // 256-bit key
  if (mbedtls_aes_setkey_enc(&ctx, key, 256) != 0) {
    mbedtls_aes_free(&ctx);
    return false;
  }

  uint8_t nonce_counter[16];
  uint8_t stream_block[16];
  memcpy(nonce_counter, iv, 16);
  memset(stream_block, 0, 16);

  size_t nc_off = 0;
  int r = mbedtls_aes_crypt_ctr(&ctx, len, &nc_off,
                                nonce_counter, stream_block,
                                in, out);

  mbedtls_aes_free(&ctx);
  return (r == 0);
}

void saveAccountToNVS(int idx) {
  if (idx < 0 || idx >= MAX_ACCOUNTS) return;
  Account &acc = accounts[idx];

  String accKey = keyName("acc", idx);
  String nmKey  = keyName("nm",  idx);
  String lnKey  = keyName("ln",  idx);
  String ivKey  = keyName("iv",  idx);
  String ctKey  = keyName("ct",  idx);

  if (!acc.present) {
    prefs.putBool(accKey.c_str(), false);
    return;
  }

  if (!g_masterKeyReady) deriveMasterKey();

  uint8_t iv[16];
  esp_fill_random(iv, sizeof(iv));

  uint8_t ct[32];
  if (!aesCtrCrypt(g_masterKey, iv, acc.key, ct, acc.keyLen)) {
    Serial.println("ERR:AES_ENCRYPT");
    return;
  }

  prefs.putBool(accKey.c_str(), true);
  prefs.putString(nmKey.c_str(), String(acc.name));
  prefs.putUChar(lnKey.c_str(), acc.keyLen);
  prefs.putBytes(ivKey.c_str(), iv, sizeof(iv));
  prefs.putBytes(ctKey.c_str(), ct, acc.keyLen);
}

void deleteAccountFromNVS(int idx) {
  if (idx < 0 || idx >= MAX_ACCOUNTS) return;
  accounts[idx].present = false;
  accounts[idx].keyLen = 0;
  accounts[idx].name[0] = '\0';
  saveAccountToNVS(idx);
}

void loadAccountsFromNVS() {
  if (!g_masterKeyReady) deriveMasterKey();

  for (int i = 0; i < MAX_ACCOUNTS; i++) {
    accounts[i].present = false;
    accounts[i].keyLen  = 0;
    accounts[i].name[0] = '\0';
  }

  int found = 0;

  for (int i = 0; i < MAX_ACCOUNTS; i++) {
    String accKey = keyName("acc", i);
    if (!prefs.getBool(accKey.c_str(), false)) continue;

    String nmKey  = keyName("nm",  i);
    String lnKey  = keyName("ln",  i);
    String ivKey  = keyName("iv",  i);
    String ctKey  = keyName("ct",  i);

    uint8_t len = prefs.getUChar(lnKey.c_str(), 0);
    if (len == 0 || len > 32) continue;

    uint8_t iv[16];
    uint8_t ct[32];
    uint8_t pt[32];

    size_t ivGot = prefs.getBytes(ivKey.c_str(), iv, sizeof(iv));
    size_t ctGot = prefs.getBytes(ctKey.c_str(), ct, len);
    if (ivGot != 16 || ctGot != len) continue;

    if (!aesCtrCrypt(g_masterKey, iv, ct, pt, len)) {
      Serial.println("ERR:AES_DECRYPT");
      continue;
    }

    accounts[i].present = true;
    accounts[i].keyLen  = len;
    memcpy(accounts[i].key, pt, len);

    String name = prefs.getString(nmKey.c_str(), String("ACC") + i);
    name.toCharArray(accounts[i].name, MAX_NAME_LEN);
    accounts[i].name[MAX_NAME_LEN] = 0;

    found++;
  }

  if (found == 0) {
    Serial.println("NO_ACCOUNTS_FOUND");
  }

  uint8_t storedActive = prefs.getUChar("active", 0);
  if (storedActive < MAX_ACCOUNTS && accounts[storedActive].present) {
    activeAccount = storedActive;
  } else {
    for (int i = 0; i < MAX_ACCOUNTS; i++) {
      if (accounts[i].present) {
        activeAccount = i;
        break;
      }
    }
    prefs.putUChar("active", activeAccount);
  }
}

bool hasActiveAccount() {
  return activeAccount < MAX_ACCOUNTS &&
         accounts[activeAccount].present &&
         accounts[activeAccount].keyLen > 0;
}

// =======================================================
//  PIN STORAGE
// =======================================================

void savePinToNVS() {
  prefs.putBool("pinset", pinSet);
  prefs.putBytes("pinhash", storedPinHash, 32);
  prefs.putBytes("pinsalt", storedSalt, 16);
}

void loadPinFromNVS() {
  pinSet = prefs.getBool("pinset", false);

  if (pinSet) {
    prefs.getBytes("pinhash", storedPinHash, 32);
    prefs.getBytes("pinsalt", storedSalt, 16);
    deviceLocked = true; // always boot locked if PIN exists
  } else {
    deviceLocked = false; // first boot unlocked
  }
}

// =======================================================
//  ACCOUNT COMMANDS
// =======================================================

void cmdListAcc() {
  for (int i = 0; i < MAX_ACCOUNTS; i++) {
    Account &acc = accounts[i];
    Serial.print("ACC:");
    Serial.print(i);
    Serial.print(" PRESENT:");
    Serial.print(acc.present ? 1 : 0);
    Serial.print(" ACTIVE:");
    Serial.print((i == activeAccount) ? 1 : 0);
    Serial.print(" NAME:");
    if (acc.present) Serial.print(acc.name);
    Serial.print(" LEN:");
    Serial.println(acc.present ? acc.keyLen : 0);
  }
}

void cmdSetAcc(String line) {
  // SETACC:<idx>:<name>:<base32>
  String rest = line.substring(strlen("SETACC:"));
  int p1 = rest.indexOf(':');
  int p2 = rest.indexOf(':', p1 + 1);
  if (p1 < 0 || p2 < 0) {
    Serial.println("ERR:SETACC_FORMAT");
    return;
  }

  String idxStr  = rest.substring(0, p1);
  String nameStr = rest.substring(p1 + 1, p2);
  String secStr  = rest.substring(p2 + 1);

  idxStr.trim(); nameStr.trim(); secStr.trim();

  int idx = idxStr.toInt();
  if (idx < 0 || idx >= MAX_ACCOUNTS) {
    Serial.println("ERR:SETACC_INDEX");
    return;
  }
  if (nameStr.length() == 0 || nameStr.length() > MAX_NAME_LEN) {
    Serial.println("ERR:SETACC_NAME");
    return;
  }

  char nameBuf[MAX_NAME_LEN + 1];
  nameStr.toCharArray(nameBuf, sizeof(nameBuf));

  char secBuf[128];
  if (secStr.length() <= 0 || secStr.length() >= (int)sizeof(secBuf)) {
    Serial.println("ERR:SETACC_SECRET_LEN");
    return;
  }
  secStr.toUpperCase();
  secStr.toCharArray(secBuf, sizeof(secBuf));

  uint8_t tmp[32];
  int decoded = base32Decode(secBuf, tmp, sizeof(tmp));
  if (decoded <= 0) {
    Serial.println("ERR:SETACC_DECODE");
    return;
  }

  accounts[idx].present = true;
  accounts[idx].keyLen  = decoded;
  memcpy(accounts[idx].key, tmp, decoded);
  strncpy(accounts[idx].name, nameBuf, MAX_NAME_LEN);
  accounts[idx].name[MAX_NAME_LEN] = '\0';

  saveAccountToNVS(idx);

  Serial.print("ACC_SET_OK:");
  Serial.println(idx);
}

void cmdDelAcc(String line) {
  // DELACC:<idx>
  String rest = line.substring(strlen("DELACC:"));
  rest.trim();
  int idx = rest.toInt();
  if (idx < 0 || idx >= MAX_ACCOUNTS) {
    Serial.println("ERR:DELACC_INDEX");
    return;
  }

  deleteAccountFromNVS(idx);

  if (idx == activeAccount) {
    activeAccount = 0;
    for (int i = 0; i < MAX_ACCOUNTS; i++) {
      if (accounts[i].present) {
        activeAccount = i;
        break;
      }
    }
    prefs.putUChar("active", activeAccount);
  }

  Serial.print("ACC_DEL_OK:");
  Serial.println(idx);
}

void cmdSetActive(String line) {
  // SETACTIVE:<idx>
  String rest = line.substring(strlen("SETACTIVE:"));
  rest.trim();
  int idx = rest.toInt();
  if (idx < 0 || idx >= MAX_ACCOUNTS) {
    Serial.println("ERR:SETACTIVE_INDEX");
    return;
  }
  if (!accounts[idx].present) {
    Serial.println("ERR:SETACTIVE_EMPTY");
    return;
  }
  activeAccount = idx;
  prefs.putUChar("active", activeAccount);

  Serial.print("ACTIVE_SET_OK:");
  Serial.println(idx);
}

void cmdCurrentAcc() {
  if (!hasActiveAccount()) {
    Serial.println("ERR:NO_ACTIVE_ACC");
    return;
  }
  Account &acc = accounts[activeAccount];
  Serial.print("ACTIVE_IDX:");
  Serial.print(activeAccount);
  Serial.print(" NAME:");
  Serial.print(acc.name);
  Serial.print(" LEN:");
  Serial.println(acc.keyLen);
}

// Optional: next account (auto-switch)
void cmdNextAcc() {
  if (!hasActiveAccount()) {
    Serial.println("ERR:NO_ACTIVE_ACC");
    return;
  }
  int start = activeAccount;
  for (int i = 1; i < MAX_ACCOUNTS; i++) {
    int idx = (start + i) % MAX_ACCOUNTS;
    if (accounts[idx].present) {
      activeAccount = idx;
      prefs.putUChar("active", activeAccount);
      Serial.print("ACTIVE_SET_OK:");
      Serial.println(idx);
      return;
    }
  }
  Serial.println("ERR:NO_OTHER_ACC");
}

// =======================================================
//  COMMON REQUIREMENTS
// =======================================================

bool requireSyncedAndAccount() {
  if (!timeSynced) {
    Serial.println("ERR:NOT_SYNCED");
    return false;
  }
  if (!hasActiveAccount()) {
    Serial.println("ERR:NO_ACTIVE_ACC");
    return false;
  }
  return true;
}

// HID: type OTP for current time
bool typeOtpNow() {
  if (!requireSyncedAndAccount()) return false;

  uint64_t now = currentUnix();
  Account &acc = accounts[activeAccount];
  uint32_t otp = generateTOTP(acc.key, acc.keyLen, now);

  char buf[7];
  snprintf(buf, sizeof(buf), "%06u", otp);

  Keyboard.print(buf);
  Keyboard.write(KEY_RETURN);

  Serial.print("TYPE_OTP_SENT:");
  Serial.println(buf);
  greenUntil = millis() + 1000; // Flash green for 1 second
  return true;
}

// Type account name over HID
bool typeAccountName() {
  if (!hasActiveAccount()) {
    Serial.println("ERR:NO_ACTIVE_ACC");
    return false;
  }
  Account &acc = accounts[activeAccount];
  Keyboard.print(acc.name);
  Keyboard.write(KEY_RETURN);
  Serial.print("TYPE_ACCNAME_SENT:");
  Serial.println(acc.name);
  return true;
}

// Type all accounts with current OTPs (one per line)
bool typeAllAccounts() {
  if (!timeSynced) {
    Serial.println("ERR:NOT_SYNCED");
    return false;
  }
  bool any = false;
  uint64_t now = currentUnix();

  for (int i = 0; i < MAX_ACCOUNTS; i++) {
    if (!accounts[i].present) continue;
    Account &acc = accounts[i];
    uint32_t otp = generateTOTP(acc.key, acc.keyLen, now);

    char buf[7];
    snprintf(buf, sizeof(buf), "%06u", otp);

    Keyboard.print(acc.name);
    Keyboard.print(": ");
    Keyboard.println(buf);

    any = true;
  }
  if (!any) {
    Serial.println("ERR:NO_ACCOUNTS");
    return false;
  }
  Serial.println("TYPE_ALL_SENT");
  return true;
}

// =======================================================
//  COMMAND HANDLER
// =======================================================

void handleCommand(String line) {
  line.trim();

  // --- Time sync commands ---

  if (deviceLocked){
    Serial.println("ERR:LOCKED");
    return  ;
  }

  if (line.startsWith("TSYNC:")) {
    suppressBroadcast = true;
    handleSecureTimePacket(line);
    suppressBroadcast = false;
    return;
  }
  if (line.startsWith("TIME:")) {
    suppressBroadcast = true;
    handlePlainTimePacket(line);
    suppressBroadcast = false;
    return;
  }

  // --- Basic ping ---
  if (line.equalsIgnoreCase("PING")) {
    Serial.println("PONG");
    return;
  }

  // --- Account commands (allowed even when locked) ---
  if (line.equalsIgnoreCase("LISTACC")) {
    suppressBroadcast = true;
    delay(20);
    cmdListAcc();
    suppressBroadcast = false;
    return;
  }
  if (line.startsWith("SETACC:")) {
    suppressBroadcast = true;
    cmdSetAcc(line);
    suppressBroadcast = false;
    return;
  }
  if (line.startsWith("DELACC:")) {
    suppressBroadcast = true;
    cmdDelAcc(line);
    suppressBroadcast = false;
    return;
  }
  if (line.startsWith("SETACTIVE:")) {
    suppressBroadcast = true;
    cmdSetActive(line);
    suppressBroadcast = false;
    return;
  }
  if (line.equalsIgnoreCase("CURRENTACC?")) {
    suppressBroadcast = true;
    cmdCurrentAcc();
    suppressBroadcast = false;
    return;
  }
  if (line.equalsIgnoreCase("NEXTACC")) {
    suppressBroadcast = true;
    cmdNextAcc();
    suppressBroadcast = false;
    return;
  }

  // --- PIN / lock management (must work even when locked) ---
  if (line.startsWith("SETPIN:")) {
    String pin = line.substring(7);
    pin.trim();

    if (pin.length() < 4 || pin.length() > 12) {
      Serial.println("ERR:PIN_LEN");
      return;
    }

    esp_fill_random(storedSalt, 16);

    uint8_t buf[64];
    int plen = pin.length();
    memcpy(buf, pin.c_str(), plen);
    memcpy(buf + plen, storedSalt, 16);

    sha256(buf, plen + 16, storedPinHash);

    pinSet = true;
    failCount = 0;
    savePinToNVS();

    Serial.println("PIN_SET_OK");
    return;
  }

  if (line.startsWith("UNLOCK:")) {
    String pin = line.substring(7);
    pin.trim();

    if (!pinSet) {
      Serial.println("ERR:NO_PIN_SET");
      return;
    }

    if (failCount >= MAX_FAILS) {
      Serial.println("ERR:LOCKED_OUT");
      return;
    }

    uint8_t buf[64];
    int plen = pin.length();
    memcpy(buf, pin.c_str(), plen);
    memcpy(buf + plen, storedSalt, 16);

    uint8_t checkHash[32];
    sha256(buf, plen + 16, checkHash);

    if (memcmp(checkHash, storedPinHash, 32) == 0) {
      deviceLocked = false;
      failCount = 0;
      Serial.println("UNLOCK_OK");
    } else {
      failCount++;
      Serial.print("ERR:BAD_PIN:");
      Serial.println(failCount);
    }
    return;
  }

  if (line.equalsIgnoreCase("LOCK")) {
    deviceLocked = true;
    Serial.println("LOCKED");
    return;
  }

  if (line.equalsIgnoreCase("LOCKED?")) {
    Serial.print("LOCKED:");
    Serial.println(deviceLocked ? "YES" : "NO");
    return;
  }

  // If locked, everything below is blocked
  if (deviceLocked) {
    Serial.println("ERR:LOCKED");
    return;
  }

  // --- Status / OTP / HID ---
  if (line.equalsIgnoreCase("STATUS?")) {
    suppressBroadcast = true;

    Serial.print("SYNCED:");
    Serial.println(timeSynced ? "YES" : "NO");

    Serial.print("ACTIVE_ACC_PRESENT:");
    Serial.println(hasActiveAccount() ? "YES" : "NO");

    if (timeSynced && hasActiveAccount()) {
      uint64_t now = currentUnix();
      uint8_t left = secondsLeftInWindow(now);
      Account &acc = accounts[activeAccount];
      uint32_t otp = generateTOTP(acc.key, acc.keyLen, now);

      Serial.print("ACTIVE_IDX:");
      Serial.println(activeAccount);
      Serial.print("ACTIVE_NAME:");
      Serial.println(acc.name);

      Serial.print("NOW_UNIX:");
      Serial.println((unsigned long long)now);
      Serial.print("CURRENT_OTP:");
      if (otp < 100000) Serial.print('0');
      Serial.println(otp);
      Serial.print("SECONDS_LEFT:");
      Serial.println(left);
    }

    suppressBroadcast = false;
    return;
  }

  if (line.equalsIgnoreCase("OTP?")) {
    if (!requireSyncedAndAccount()) return;

    suppressBroadcast = true;

    uint64_t now = currentUnix();
    uint8_t left = secondsLeftInWindow(now);
    Account &acc = accounts[activeAccount];
    uint32_t otp = generateTOTP(acc.key, acc.keyLen, now);

    Serial.print("OTP:");
    if (otp < 100000) Serial.print('0');
    Serial.print(otp);
    Serial.print(" LEFT:");
    Serial.println(left);

    suppressBroadcast = false;
    return;
  }

  if (line.equalsIgnoreCase("TYPEOTP")) {
    suppressBroadcast = true;
    typeOtpNow();
    suppressBroadcast = false;
    return;
  }

  if (line.equalsIgnoreCase("TYPEACCNAME")) {
    suppressBroadcast = true;
    typeAccountName();
    suppressBroadcast = false;
    return;
  }

  if (line.equalsIgnoreCase("TYPEALLACCOUNTS")) {
    suppressBroadcast = true;
    typeAllAccounts();
    suppressBroadcast = false;
    return;
  }

  // Unknown
  Serial.print("ERR:UNKNOWN_CMD:");
  Serial.println(line);
}

// =======================================================
//  BUTTON HANDLING (LONG PRESS = TYPEOTP)
// =======================================================

void handleButton() {
  if (BUTTON_PIN < 0) return; // feature disabled

  bool pressed = (digitalRead(BUTTON_PIN) == LOW); // assume pull-up

  if (pressed && !btnPrev) {
    btnDownMs = millis();
  }

  if (!pressed && btnPrev) {
    uint32_t held = millis() - btnDownMs;
    if (held >= LONG_PRESS_MS) {
      // Long press -> type OTP
      if (!deviceLocked) {
        suppressBroadcast = true;
        typeOtpNow();
        suppressBroadcast = false;
      } else {
        Serial.println("ERR:LOCKED");
      }
    }
  }

  btnPrev = pressed;
}

// =======================================================
//  LED STATE
// =======================================================

void updateLed() {
#ifdef RGB_BUILTIN
  uint32_t nowMs = millis();

  if (nowMs < greenUntil) {
    // OTP typed successfully (Green)
    neopixelWrite(RGB_BUILTIN, 0, 30, 0);
  } else if (!timeSynced || !hasActiveAccount()) {
    // Inserted but not synced (Dim Red)
    neopixelWrite(RGB_BUILTIN, 10, 0, 0);
  } else {
    // Synced and ready (Blue)
    neopixelWrite(RGB_BUILTIN, 0, 0, 20);
  }
#else
  // Fallback for non-RGB LEDs
  if (LED_PIN < 0) return;
  static uint32_t lastBlink = 0;
  static bool ledState = false;
  uint32_t nowMs = millis();

  if (nowMs < greenUntil) {
    digitalWrite(LED_PIN, HIGH);
  } else if (!timeSynced || !hasActiveAccount()) {
    if (nowMs - lastBlink > 200) {
      lastBlink = nowMs;
      ledState = !ledState;
      digitalWrite(LED_PIN, ledState ? HIGH : LOW);
    }
  } else {
    digitalWrite(LED_PIN, HIGH);
  }
#endif
}

// =======================================================
//  SETUP / LOOP
// =======================================================

void setup() {
  Serial.begin(115200);
  delay(300);

  // Start USB HID first
  USB.begin();
  Keyboard.begin();

  if (BUTTON_PIN >= 0) {
    pinMode(BUTTON_PIN, INPUT_PULLUP);
  }
  if (LED_PIN >= 0) {
    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, LOW);
  }

  Serial.println();
  Serial.println("=== ESP32-S3 OFFLINE TOTP KEY v2.0 (Multi-Account + TSYNC + PIN + HID + Button/LED) ===");

  prefs.begin("totp", false);
  deriveMasterKey();
  loadAccountsFromNVS();
  loadPinFromNVS();

  syncKeyLen = hexToBytes(SYNC_KEY_HEX, syncKey, sizeof(syncKey));
  Serial.print("SYNC_KEY_LEN:");
  Serial.println(syncKeyLen);

  Serial.print("ACTIVE_ACCOUNT:");
  Serial.println(activeAccount);

  Serial.print("LOCKED:");
  Serial.println(deviceLocked ? "YES" : "NO");

  Serial.println("Commands:");
  Serial.println("  TSYNC:<unix>:<nonce_hex>:<hmac_hex>");
  Serial.println("  TIME:<unix>                 (legacy/debug)");
  Serial.println("  STATUS?");
  Serial.println("  OTP?");
  Serial.println("  PING");
  Serial.println("  LISTACC");
  Serial.println("  SETACC:<idx>:<name>:<base32>");
  Serial.println("  DELACC:<idx>");
  Serial.println("  SETACTIVE:<idx>");
  Serial.println("  CURRENTACC?");
  Serial.println("  NEXTACC");
  Serial.println("  TYPEOTP             (type current OTP over USB HID)");
  Serial.println("  TYPEACCNAME         (type active account name)");
  Serial.println("  TYPEALLACCOUNTS     (type all accounts + current OTPs)");
  Serial.println("  SETPIN:1234");
  Serial.println("  UNLOCK:1234");
  Serial.println("  LOCK");
  Serial.println("  LOCKED?");
  Serial.println("======================================================");
}

void loop() {
  if (Serial.available()) {
    String line = Serial.readStringUntil('\n');
    handleCommand(line);
  }

  handleButton();
  updateLed();

  static uint32_t lastBroadcast = 0;
  if (!suppressBroadcast && millis() - lastBroadcast >= 1000) {
    lastBroadcast = millis();

    if (deviceLocked) {
      Serial.println("STATUS:LOCKED");
      return;
    }

    if (!timeSynced || !hasActiveAccount()) {
      Serial.println("STATUS:NOT_READY");
      return;
    }

    uint64_t now = currentUnix();
    uint8_t left = secondsLeftInWindow(now);
    Account &acc = accounts[activeAccount];
    uint32_t otp = generateTOTP(acc.key, acc.keyLen, now);

    Serial.print("TIME:");
    Serial.print((unsigned long long)now);
    Serial.print(" OTP:");
    if (otp < 100000) Serial.print('0');
    Serial.print(otp);
    Serial.print(" LEFT:");
    Serial.println(left);
  }
}
