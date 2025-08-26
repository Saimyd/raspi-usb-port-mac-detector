# Raspberry Pi USB Port MAC Detector

A comprehensive Raspberry Pi application that detects Bluetooth dongles plugged into USB ports, reads RFID cards, and communicates with a remote API for tracking and logging purposes.

## Features

- **USB Port Detection**: Monitors USB ports for Bluetooth dongle insertion/removal
- **RFID Card Reading**: Reads RFID cards using RC522 module
- **MAC Address Detection**: Automatically detects MAC addresses of Bluetooth dongles
- **API Integration**: Sends login and process requests to remote API
- **Real-time Monitoring**: Continuous monitoring with colored console output
- **Logging**: Comprehensive logging system with timestamped log files

## Hardware Requirements

- Raspberry Pi (tested on Pi 3/4)
- RC522 RFID module
- Bluetooth dongles
- RFID cards/tags

## Software Requirements

- Python 3.6+
- Raspberry Pi OS (Raspbian)
- SPI enabled on Raspberry Pi

## Installation

1. Clone this repository:
```bash
git clone https://github.com/Saimyd/raspi-usb-port-mac-detector.git
cd raspi-usb-port-mac-detector
```

2. Install required Python packages:
```bash
pip3 install -r requirements.txt
```

3. Enable SPI on your Raspberry Pi:
```bash
sudo raspi-config
# Navigate to Interfacing Options > SPI > Enable
```

4. Connect RC522 RFID module to Raspberry Pi:
- VCC → 3.3V
- RST → GPIO 22
- GND → GND
- MISO → GPIO 9 (SPI_MISO)
- MOSI → GPIO 10 (SPI_MOSI)
- SCK → GPIO 11 (SPI_CLK)
- SDA → GPIO 8 (SPI_CE0)

## Configuration

### Port Mapping
The application maps USB ports to numerical IDs. Update `PORT_NUM_TABLE` in the code if needed:

```python
PORT_NUM_TABLE = {
    "3-1.1.1": 1,      # top left
    "3-1.2": 2,        # top
    "3-1.3": 3,        # top right
    # ... add more mappings as needed
}
```

### MAC Address Mapping
Update `MAC_NUM_TABLE` with your Bluetooth dongle MAC addresses:

```python
MAC_NUM_TABLE = {
    "04:7F:0E:76:AF:41": 1,  # location 1
    "04:7F:0E:76:B5:B1": 2,  # location 2
    # ... add your MAC addresses
}
```

### API Configuration
Update the API URLs in the code:

```python
API_LOGIN_URL = "http://your-api-domain.com/api/loginrequest"
API_PROCESS_URL = "http://your-api-domain.com/api/processrequest"
```

## Usage

1. Run the application:
```bash
sudo python3 raspi.py
```

2. The application will start two main threads:
   - USB monitoring thread
   - RFID reading thread

3. Present an RFID card to log in
4. Insert/remove Bluetooth dongles to trigger detection
5. The system will automatically send data to the configured API

## API Endpoints

### Login Request
```json
{
    "userId": "card_uid",
    "deviceCode": "TLaptop",
    "loginFlag": 1  // 1 for login, 2 for logout
}
```

### Process Request
```json
{
    "userId": "card_uid",
    "deviceCode": "TLaptop",
    "componentId": 1,  // location ID from MAC mapping
    "pluggedPort": 1,  // port number from port mapping
    "processType": 1   // 1 for insert, 2 for remove
}
```

## Logging

Logs are automatically saved to `~/usb_detector_logs/` with timestamps. Each run creates a new log file.

## Troubleshooting

### Common Issues

1. **Permission denied**: Run with `sudo` as the application needs hardware access
2. **SPI not enabled**: Enable SPI using `raspi-config`
3. **RC522 not detected**: Check wiring connections
4. **Bluetooth dongles not detected**: Ensure dongles are compatible and properly inserted

### Debug Mode

Increase logging level for debugging:
```python
logging.basicConfig(level=logging.DEBUG, ...)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Developed by Pollux Labs
- Website: [en.polluxlabs.net](http://en.polluxlabs.net)

## Acknowledgments

- RC522 SPI Library for RFID functionality
- Raspberry Pi Foundation for the excellent hardware platform