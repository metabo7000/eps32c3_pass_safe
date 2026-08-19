/*
 * Security layers:
 *   1. BLE passkey (6-digit PIN shown on Serial monitor, entered on phone)
 *   2. Master password typed after every connection
 *
 * Commands (after unlock):
 *   add <n> <password>   store / overwrite an entry
 *   get <n>              retrieve a password
 *   del <n>              delete an entry
 *   list                    list all entry names
 *   lock                    re-lock the session
 *   help                    show this list
 */

#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include <Preferences.h>

// ── CONFIGURATION ─────────────────────────────────────────────────────────────
static const char*    DEVICE_NAME     = "PasswordSafe";
static const uint32_t BLE_PASSKEY     = 123456;        // 6-digit pairing PIN
static const char*    MASTER_PASSWORD = "1234";   // Session unlock password
static const char*    NVS_NAMESPACE   = "pwsafe";
static const char*    INDEX_KEY       = "__index__";
static const int      MAX_ENTRIES     = 30;
static const int      MAX_KEY_LEN     = 14;            // NVS key length limit
// ─────────────────────────────────────────────────────────────────────────────

// Nordic UART Service UUIDs (recognised by most BLE terminal apps)
#define NUS_SERVICE_UUID  "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
#define NUS_RX_UUID       "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"  // phone -> ESP32
#define NUS_TX_UUID       "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"  // ESP32 -> phone

BLEServer*         pServer           = nullptr;
BLECharacteristic* pTxCharacteristic = nullptr;
bool               deviceConnected   = false;
bool               sessionUnlocked   = false;
Preferences        prefs;
String             inputBuffer       = "";

// ── BLE SEND ──────────────────────────────────────────────────────────────────

void btPrint(const String& msg) {
  String line = msg + "\r\n";
  // Chunk into 20-byte packets for compatibility with all BLE stacks
  int offset = 0;
  while (offset < (int)line.length()) {
    int chunk = min(20, (int)line.length() - offset);
    pTxCharacteristic->setValue((uint8_t*)(line.c_str() + offset), chunk);
    pTxCharacteristic->notify();
    delay(20);
    offset += chunk;
  }
  Serial.println(msg);
}

// ── HELPERS ───────────────────────────────────────────────────────────────────

String trimStr(const String& s) {
  int start = 0, end = (int)s.length() - 1;
  while (start <= end && (s[start] == ' ' || s[start] == '\t' ||
                           s[start] == '\r' || s[start] == '\n')) start++;
  while (end >= start && (s[end]   == ' ' || s[end]   == '\t' ||
                           s[end]   == '\r' || s[end]   == '\n')) end--;
  return s.substring(start, end + 1);
}

void splitOnFirst(const String& s, String& word, String& rest) {
  int sp = s.indexOf(' ');
  if (sp == -1) { word = s; rest = ""; }
  else           { word = s.substring(0, sp); rest = trimStr(s.substring(sp + 1)); }
}

// ── NVS INDEX ─────────────────────────────────────────────────────────────────

String readIndex()                   { return prefs.getString(INDEX_KEY, ""); }
void   writeIndex(const String& idx) { prefs.putString(INDEX_KEY, idx); }

int countEntries(const String& idx) {
  if (idx.length() == 0) return 0;
  int c = 1;
  for (unsigned int i = 0; i < idx.length(); i++) if (idx[i] == ',') c++;
  return c;
}

bool indexContains(const String& idx, const String& name) {
  int start = 0;
  while (start < (int)idx.length()) {
    int comma = idx.indexOf(',', start);
    if (comma == -1) comma = idx.length();
    if (idx.substring(start, comma) == name) return true;
    start = comma + 1;
  }
  return false;
}

String removeFromIndex(const String& idx, const String& name) {
  String result = "";
  int start = 0;
  while (start < (int)idx.length()) {
    int comma = idx.indexOf(',', start);
    if (comma == -1) comma = idx.length();
    String token = idx.substring(start, comma);
    if (token != name) {
      if (result.length() > 0) result += ",";
      result += token;
    }
    start = comma + 1;
  }
  return result;
}

// ── COMMANDS ──────────────────────────────────────────────────────────────────

void cmdHelp() {
  btPrint("──────────────────────────");
  btPrint("  PasswordSafe commands");
  btPrint("──────────────────────────");
  btPrint("  add <n> <pass>");
  btPrint("  get <n>");
  btPrint("  del <n>");
  btPrint("  list");
  btPrint("  lock");
  btPrint("  help");
  btPrint("──────────────────────────");
}

void cmdAdd(const String& args) {
  String name, password;
  splitOnFirst(args, name, password);

  if (name.length() == 0 || password.length() == 0) {
    btPrint("[ERROR] Usage: add <n> <password>"); return;
  }
  if ((int)name.length() > MAX_KEY_LEN) {
    btPrint("[ERROR] Name too long (max " + String(MAX_KEY_LEN) + " chars)"); return;
  }
  if (name == INDEX_KEY) {
    btPrint("[ERROR] That name is reserved."); return;
  }

  String idx   = readIndex();
  bool   isNew = !indexContains(idx, name);

  if (isNew && countEntries(idx) >= MAX_ENTRIES) {
    btPrint("[ERROR] Max " + String(MAX_ENTRIES) + " entries reached."); return;
  }

  prefs.putString(name.c_str(), password);

  if (isNew) {
    if (idx.length() > 0) idx += ",";
    idx += name;
    writeIndex(idx);
    btPrint("[OK] Added: " + name);
  } else {
    btPrint("[OK] Updated: " + name);
  }
}

void cmdGet(const String& args) {
  String name = trimStr(args);
  if (name.length() == 0) { btPrint("[ERROR] Usage: get <n>"); return; }
  if (!indexContains(readIndex(), name)) {
    btPrint("[ERROR] No entry: " + name); return;
  }
  btPrint("[" + name + "] " + prefs.getString(name.c_str(), ""));
}

void cmdDel(const String& args) {
  String name = trimStr(args);
  if (name.length() == 0) { btPrint("[ERROR] Usage: del <n>"); return; }
  String idx = readIndex();
  if (!indexContains(idx, name)) {
    btPrint("[ERROR] No entry: " + name); return;
  }
  prefs.remove(name.c_str());
  writeIndex(removeFromIndex(idx, name));
  btPrint("[OK] Deleted: " + name);
}

void cmdList() {
  String idx = readIndex();
  if (idx.length() == 0) { btPrint("[INFO] No passwords stored."); return; }
  btPrint("── " + String(countEntries(idx)) + " entries ──");
  int start = 0, n = 1;
  while (start < (int)idx.length()) {
    int comma = idx.indexOf(',', start);
    if (comma == -1) comma = idx.length();
    btPrint("  " + String(n++) + ". " + idx.substring(start, comma));
    start = comma + 1;
  }
}

void dispatchCommand(const String& line) {
  String cmd, args;
  splitOnFirst(line, cmd, args);
  cmd.toLowerCase();

  if      (cmd == "help")               cmdHelp();
  else if (cmd == "add")                cmdAdd(args);
  else if (cmd == "get")                cmdGet(args);
  else if (cmd == "del" || cmd == "delete") cmdDel(args);
  else if (cmd == "list" || cmd == "ls") cmdList();
  else if (cmd == "lock") {
    sessionUnlocked = false;
    btPrint("[OK] Locked.");
    btPrint("Enter master password:");
  }
  else btPrint("[ERROR] Unknown: " + cmd + ". Type 'help'.");
}

// ── BLE CALLBACKS ─────────────────────────────────────────────────────────────

class ServerCallbacks : public BLEServerCallbacks {
  void onConnect(BLEServer* pSvr) override {
    deviceConnected = true;
    sessionUnlocked = false;
    inputBuffer     = "";
    Serial.println("[BLE] Client connected.");
    delay(400);
    btPrint("=== ESP32 Password Safe ===");
    btPrint("Enter master password:");
  }
  void onDisconnect(BLEServer* pSvr) override {
    deviceConnected = false;
    sessionUnlocked = false;
    inputBuffer     = "";
    Serial.println("[BLE] Disconnected. Restarting advertising.");
    BLEDevice::startAdvertising();
  }
};

class RxCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic* pChar) override {
    std::string raw = pChar->getValue();
    for (char c : raw) {
      if (c == '\n' || c == '\r') {
        String line = trimStr(inputBuffer);
        inputBuffer = "";
        if (line.length() == 0) continue;
        if (!sessionUnlocked) {
          if (line == MASTER_PASSWORD) {
            sessionUnlocked = true;
            btPrint("[OK] Unlocked. Type 'help'.");
          } else {
            btPrint("[DENIED] Wrong password. Try again:");
          }
        } else {
          dispatchCommand(line);
        }
      } else {
        inputBuffer += c;
      }
    }
  }
};

class SecurityCallbacks : public BLESecurityCallbacks {
  uint32_t onPassKeyRequest() override { return BLE_PASSKEY; }
  void onPassKeyNotify(uint32_t passKey) override {
    Serial.printf("[BLE] Passkey to enter on phone: %06lu\n", passKey);
  }
  bool onConfirmPIN(uint32_t passKey) override { return true; }
  bool onSecurityRequest()            override { return true; }
  void onAuthenticationComplete(esp_ble_auth_cmpl_t cmpl) override {
    Serial.println(cmpl.success ? "[BLE] Paired OK." : "[BLE] Pairing FAILED.");
  }
};

// ── SETUP ─────────────────────────────────────────────────────────────────────

void setup() {
  Serial.begin(115200);
  prefs.begin(NVS_NAMESPACE, false);

  BLEDevice::init(DEVICE_NAME);
  BLEDevice::setEncryptionLevel(ESP_BLE_SEC_ENCRYPT);
  BLEDevice::setSecurityCallbacks(new SecurityCallbacks());

  BLESecurity* pSecurity = new BLESecurity();
  pSecurity->setAuthenticationMode(ESP_LE_AUTH_REQ_SC_MITM_BOND);
  pSecurity->setCapability(ESP_IO_CAP_OUT);  // We display passkey on Serial
  pSecurity->setInitEncryptionKey(ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK);
  pSecurity->setStaticPIN(BLE_PASSKEY);

  pServer = BLEDevice::createServer();
  pServer->setCallbacks(new ServerCallbacks());

  BLEService* pService = pServer->createService(NUS_SERVICE_UUID);

  pTxCharacteristic = pService->createCharacteristic(
    NUS_TX_UUID,
    BLECharacteristic::PROPERTY_NOTIFY
  );
  pTxCharacteristic->addDescriptor(new BLE2902());

  BLECharacteristic* pRxChar = pService->createCharacteristic(
    NUS_RX_UUID,
    BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_WRITE_NR
  );
  pRxChar->setCallbacks(new RxCallbacks());

  pService->start();

  BLEAdvertising* pAdv = BLEDevice::getAdvertising();
  pAdv->addServiceUUID(NUS_SERVICE_UUID);
  pAdv->setScanResponse(true);
  BLEDevice::startAdvertising();

  Serial.printf("PasswordSafe ready. Passkey: %06lu\n", BLE_PASSKEY);
}

void loop() {
  delay(10);
}
