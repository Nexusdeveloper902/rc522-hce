# Wiring the RC522

> **8-bit AVR (UNO/Nano/Mega):** add the ArduinoSTL library for
> `std::string` support (see README install notes). 32-bit boards need no
> shim. Prefer a Mega or a 32-bit board over the UNO for real HCE use —
> the full app overflows the ATmega328P's 2 KB RAM (verified), while the
> Mega sits at 31%.

The RC522 is a **3.3 V device** — power it from 3.3 V, never 5 V. Its logic
pins are 5 V-tolerant on most breakouts, but the safe rule is: **VCC → 3V3,
GND → GND**, and on 5 V boards (UNO, Mega, Nano) put a level shifter or at
least a voltage divider on the board's MOSI/SCK/SS lines if you see corrupt
reads. MISO comes *from* the RC522 at 3.3 V, which 5 V boards read fine.

Run the RC522 SPI bus at **1 MHz**, not the MFRC522 library's 4 MHz default
(`-DMFRC522_SPICLOCK=1000000u` in PlatformIO `build_flags`). The largest
transfer here is a ~60 B frame, so the speed buys nothing, while 4 MHz over
Dupont jumpers on a rail that sags during RF transmission is the classic
source of corrupt reads and wedged transactions.

## Tap distance — phones must sit 2–3 cm above the sensor

This is the single most important placement rule for HCE taps, so it gets
its own section: **hold the phone flat, centered over the antenna, about
2–3 cm above the sensor, and keep it still until the tap registers.**

Why it matters:

- A phone's load modulation is far weaker than a MIFARE card's. Beyond
  ~4 cm the ATS/RATS handshake starts failing (`SAK=0x20 ATS=0B` in the
  log) even though cards read fine at the same distance.
- Pressing the phone directly *against* the reader can detune the antenna
  and kill the session mid-exchange.
- An HCE tap is a whole conversation (RATS/ATS, SELECT, CHALLENGE, and
  usually several S(WTX) rounds) — roughly half a second of radio contact,
  not the instant blip of a card UID read. Lifting the phone early aborts
  it; the log will show `HCE SELECT failed` or `HCE CHALLENGE timeout`.
- Remove thick cases with metal (rings, stands, MagSafe wallets) and keep
  other NFC cards away from the phone while tapping.

## Pin tables (RC522 pin → board pin)

### ESP32 DevKit (VSPI — the constructor defaults)

| RC522 | ESP32 GPIO |
|---|---|
| SDA (SS) | 5 |
| SCK | 18 |
| MOSI | 23 |
| MISO | 19 |
| RST | 27 (or strap RST → 3V3 and pass 255) |
| VCC / GND | 3V3 / GND |

```cpp
rc522hce::Rc522HceReader radio;  // defaults are this table
```

### Arduino UNO / Nano (hardware SPI)

| RC522 | UNO/Nano |
|---|---|
| SDA (SS) | 10 |
| SCK | 13 |
| MOSI | 11 |
| MISO | 12 |
| RST | 9 (or strap RST → 3V3 and pass 255) |
| VCC / GND | 3V3 / GND |

```cpp
rc522hce::Rc522HceReader radio(10, 9, 13, 12, 11);
```

### Arduino Mega (hardware SPI)

| RC522 | Mega |
|---|---|
| SDA (SS) | 53 |
| SCK | 52 |
| MOSI | 51 |
| MISO | 50 |
| RST | 5 (any free digital pin; or 3V3-strapped) |
| VCC / GND | 3V3 / GND |

```cpp
rc522hce::Rc522HceReader radio(53, 5, 52, 50, 51);
```

### ESP8266 (NodeMCU)

| RC522 | ESP8266 GPIO |
|---|---|
| SDA (SS) | 15 (D8) |
| SCK | 14 (D5) |
| MOSI | 13 (D7) |
| MISO | 12 (D6) |
| RST | 5 (D1; or 3V3-strapped) |
| VCC / GND | 3V3 / GND |

```cpp
rc522hce::Rc522HceReader radio(15, 5, 14, 12, 13);
```

### Raspberry Pi Pico (Arduino core)

| RC522 | Pico |
|---|---|
| SDA (SS) | 17 |
| SCK | 18 |
| MOSI | 19 |
| MISO | 16 |
| RST | 20 (or 3V3-strapped) |
| VCC / GND | 3V3 (pin 36) / GND |

```cpp
rc522hce::Rc522HceReader radio(17, 20, 18, 16, 19);
```

## RST strapping

Pass `255` as the RST pin and wire RC522 RST directly to 3V3: the driver
then uses soft reset only and drives no pin. Useful when pins are scarce
or when a board's strapping pins misbehave at boot.

## Symptoms and fixes

| Symptom | Fix |
|---|---|
| `RC522 NOT responding (version 0x00/0xFF)` | wiring, 3.3 V power, SS/RST pins |
| `SAK=0x20 ATS=0B` on every phone tap | phone too far / lifted too early — hold it 2–3 cm above the sensor, steady (see Tap distance above); driver already sets max RX gain; move the phone closer, check 3.3 V rail sag |
| `SAK=0x08` from a phone | the phone is not offering ISO-DEP: HCE app not engaged, NFC off, or no HCE support |
| Intermittent corrupt reads on 5 V boards | level-shift MOSI/SCK/SS, shorten Duponts, confirm 1 MHz SPI |
| Phone taps work, cards don't (or vice versa) | antenna detuning — keep metal away from the antenna face |
