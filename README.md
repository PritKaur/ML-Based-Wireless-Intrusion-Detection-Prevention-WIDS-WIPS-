# ML-Based Wireless Intrusion Detection & Prevention (WIDS/WIPS)

A small prototype that uses a K-Nearest Neighbours (KNN) classifier to detect Wi-Fi deauthentication flood attacks, raise an alert, and log the offending MAC address to a blocklist.

## What it does

1. **Generates a dataset:** 1,200 synthetic Wi-Fi samples (600 normal, 600 deauthentication attack).
2. **Preprocesses:** splits the data 80/20 into training and test sets and standardises four features with `StandardScaler`.
3. **Trains:** a `KNeighborsClassifier` with `K=5`.
4. **Evaluates:** prints accuracy and a classification report, and saves a confusion matrix image.
5. **Classifies traffic:** scales new samples and predicts normal or attack.
6. **Alerts and blocks (WIPS):** on an attack, prints an alert and appends the source MAC address to `blocklist.txt` (each MAC is only added once per run).

### Features used

| Feature | Meaning |
|---|---|
| `deauth_count` | Number of deauthentication frames |
| `mgmt_ratio` | Share of frames that are management frames |
| `frame_len` | Frame length |
| `rssi` | Received signal strength |

## Results

| | Value |
|---|---|
| Test samples | 240 |
| Accuracy | **86.25%** (207 / 240 correct) |
| Normal classified correctly | 108 of 122 |
| Attacks detected | 99 of 118 |


## Limitations

- **The data is synthetic.** The two classes are random distributions I defined, so the accuracy only shows that the model can separate those distributions. It does not prove the system detects real attacks.
- The three sample MAC addresses in the demo are made up and used as test cases.
- Detection works on pre-computed features, not live packets.

## Improvements I would make

- Live packet capture in monitor mode (Scapy or pcap) on an authorised lab network
- Test on a public dataset such as AWID3 for real-world validation
- More features (timing, sequence numbers, beacon intervals)
- Detection of other attacks (Evil Twin, jamming, probe floods)
- Real blocking and alerting rather than writing to a file
- Optimising the model for routers and IoT gateways

## How to run

Requires Python 3.8 or newer.

```bash
pip install -r requirements.txt
python wids_wips.py
```

Running the script will:

- print the accuracy, confusion matrix and classification report,
- save `confusion_matrix.png` in the same folder,
- test three sample MAC addresses and write any detected attackers to `blocklist.txt`.

The random seed is fixed (`42`), so results are the same on every run.

## Use of AI

I used Google Gemini to produce the first version of the code, including the synthetic data generation and the KNN classification logic, and to help structure the pipeline. I then reviewed and debugged the code, ran it myself in VS Code, and added the comments based on my own understanding of how each part works.

## Ethical note

This project uses only simulated data. Any real traffic capture or attack generation must be confined to your own or an approved, isolated testbed.
