# BFI 무선 센싱 실험 장비 이동 및 수행 가이드

이 문서는 독립형 5GHz 무선 센싱 환경에서 BFI(Beamforming Feedback Information) 패킷을 발생시키고, 맥북에서 스니핑한 캡처 파일을 `bfi_pcap_to_motion_png_only.py`로 분석해 움직임 지표(Motion Metrics) PNG를 생성하기 위한 실험 가이드입니다.

## 1. 현재 실험 환경 요약

### 무선 공유기 ASUS

- SSID / 대역: `ASUS_00_5GHz` / 5GHz 전용
- 보안 규격: `WPA2-Personal`
- PMF(보호된 관리 프레임): `Disable`
- 네트워크 대역: `192.168.51.X` DHCP
- 현재 AP MAC: `08:bf:b8:95:80:04`

PMF를 비활성화해야 맥북의 일반 모니터링/스니퍼 환경에서 관리 프레임과 BFI Action 프레임을 안정적으로 관측하기 쉽습니다.

### Raspberry Pi 4B

- OS: Raspberry Pi OS Legacy 64-bit Bullseye, GUI 포함
- 무선 LAN 국가 코드: `KR`
- 원격 접속: SSH 및 VNC 서버 활성화
- 현재 Wi-Fi MAC: `2c:cf:67:17:0a:3c`

현재 분석 스크립트의 기본 타깃 MAC도 이 조합으로 설정되어 있습니다.

```text
source STA = 2c:cf:67:17:0a:3c
AP         = 08:bf:b8:95:80:04
```

## 2. 장비 이동 후 부팅 순서

장비를 다른 방이나 실험실로 옮긴 뒤에는 아래 순서로 켜는 것이 가장 안정적입니다.

```text
1. 공유기 전원 ON
2. Raspberry Pi 전원 ON
3. 노트북 부팅 및 공유기 LAN 포트에 유선 연결
```

공유기를 Raspberry Pi보다 늦게 켜면, Pi가 부팅 시점에 5GHz SSID를 찾지 못해 Wi-Fi 연결이나 DHCP IP 할당이 꼬일 수 있습니다.

### 상세 순서

1. 공유기 전원을 먼저 켜고 5GHz Wi-Fi가 완전히 올라올 때까지 1-2분 기다립니다.
2. Raspberry Pi에 전원을 넣습니다. Pi는 부팅 후 `ASUS_00_5GHz`에 자동 접속합니다.
3. Windows 실험용 PC 또는 노트북을 공유기 LAN 포트에 유선으로 연결합니다.

## 3. 실험 수행 절차

### 1단계: Raspberry Pi IP 확인

공유기 관리 페이지에 접속합니다.

```text
http://192.168.51.1
```

클라이언트 목록에서 `2c:cf:67:17:0a:3c`에 해당하는 Raspberry Pi의 현재 IP를 확인합니다.

예:

```text
192.168.51.123
```

전원을 껐다 켜면 IP 끝자리가 바뀔 수 있으므로 실험마다 다시 확인하는 것이 좋습니다.

### 2단계: Raspberry Pi에서 iPerf3 서버 실행

Windows에서 명령 프롬프트를 열고 Pi에 SSH 접속합니다.

```cmd
ssh pi@[확인한_파이_IP]
```

로그인 후 iPerf3 서버를 실행합니다.

```bash
iperf3 -s
```

아래 문구가 보이면 서버 준비가 끝난 상태입니다.

```text
Server listening on 5201
```

필요하면 VNC Viewer로 같은 IP에 접속해 Pi GUI 상태를 함께 확인할 수 있습니다.

### 3단계: 맥북 무선 스니퍼 실행

1. 공유기 관리 페이지에서 현재 5GHz 채널 번호와 대역폭을 확인합니다.
2. 맥북에서 `Option` 키를 누른 채 Wi-Fi 아이콘을 클릭합니다.
3. `무선 진단 열기...`를 실행합니다.
4. 상단 메뉴에서 `윈도우` > `스니퍼`를 엽니다.
5. 공유기와 동일한 5GHz 채널 번호 및 대역폭을 선택한 뒤 스니핑을 시작합니다.

맥북 바탕화면 또는 지정된 저장 위치에 `.wcap` 캡처 파일이 생성됩니다.

### 4단계: Windows PC에서 UDP 트래픽 생성

맥북 스니퍼가 켜진 상태에서 Windows PC의 새 명령 프롬프트를 열고 `iperf3.exe`가 있는 폴더로 이동합니다.

```cmd
cd C:\iperf3
```

Raspberry Pi를 향해 UDP 트래픽을 보냅니다.

```cmd
iperf3.exe -c [라즈베리파이_IP_주소] -u -b 150M -t 30
```

이 트래픽은 유선 PC에서 AP를 거쳐 무선 Pi로 전달됩니다. Pi 무선 링크가 큰 부하를 받는 동안, Pi는 AP를 향해 VHT Compressed Beamforming Report(BFI) Action 프레임을 송신하고 맥북 스니퍼가 이를 캡처합니다.

### 5단계: 캡처 종료 및 분석

1. `iperf3` 실행이 끝나면 맥북 스니퍼를 중단합니다.
2. 생성된 `.wcap`, `.pcap`, 또는 `.pcapng` 파일을 이 프로젝트 폴더 또는 `data/` 폴더로 옮깁니다.
3. 파일 이름을 `test.pcap`으로 맞춘 뒤 `editcap` 변환 스크립트를 실행합니다. 스크립트는 `./test.pcap`을 먼저 찾고, 없으면 `data/test.pcap`을 자동으로 사용합니다.

```bash
python3 timestamp_editcap.py
```

이 명령은 아래 명령을 Python에서 실행해 `data/` 폴더 안에 타임스탬프가 찍힌 pcap을 저장합니다.

```bash
/Applications/Wireshark.app/Contents/MacOS/editcap test.pcap data/YYYYMMDD_HHMMSS.pcap
```

변환이 성공하면 원본 `test.pcap`은 자동으로 삭제됩니다. 변환이 실패하면 원본은 삭제하지 않습니다.

4. 분석 스크립트를 실행합니다.

```bash
python3 bfi_pcap_to_motion_png_only.py --clean-output
```

`pcap` 인자를 생략하면 `data/` 아래에서 타임스탬프 기준으로 가장 최근 캡처 파일을 자동 선택합니다. 결과는 같은 타임스탬프를 사용해 `data/YYYYMMDD_HHMMSS_result/` 폴더에 저장됩니다.

특정 파일을 직접 분석하고 싶으면 파일명을 명시합니다.

```bash
python3 bfi_pcap_to_motion_png_only.py data/YYYYMMDD_HHMMSS.pcap --clean-output
```

현재 스크립트에는 Raspberry Pi와 AP MAC이 기본값으로 들어가 있으므로, 보통 `--source-sta`와 `--ap` 옵션은 따로 줄 필요가 없습니다.

더 많은 진단 PNG를 보고 싶으면 `--png-set all`을 추가합니다.

```bash
python3 bfi_pcap_to_motion_png_only.py --clean-output --png-set all
```

## 4. 결과 파일

분석이 성공하면 `data/YYYYMMDD_HHMMSS_result/` 폴더에 PNG 파일이 생성됩니다.

대표 출력:

- `motion_metrics_overview.png`
- `subcarrier_139_phase.png`
- `subcarrier_139_magnitude.png`
- `subcarrier_139_quantized_angles.png`
- `antenna_row_mean_power.png`
- `antenna_row_complex_diff.png`

정상 캡처 예시에서는 다음과 같은 결과가 나왔습니다.

```text
Parsed BFI packets:  2605
Kept target packets: 1240
Selected group:      source=2c:cf:67:17:0a:3c, ap=08:bf:b8:95:80:04
V_all shape:         [1240, 234, 2, 1]
Antenna status:      PASS
```

## 5. 트러블슈팅

### BFI가 0개로 잡히는 경우

아래 항목을 순서대로 확인합니다.

- 공유기 5GHz 채널과 맥북 스니퍼 채널이 같은지 확인합니다.
- 공유기 PMF가 `Disable`인지 확인합니다.
- Raspberry Pi MAC이 `2c:cf:67:17:0a:3c`인지 확인합니다.
- AP MAC이 `08:bf:b8:95:80:04`인지 확인합니다.
- `iperf3` 트래픽 방향이 Windows PC에서 Raspberry Pi로 향하는지 확인합니다.
- 캡처 파일 안에 다른 링크의 BFI가 있는지 확인하려면 `--all-links`를 사용합니다.

```bash
python3 bfi_pcap_to_motion_png_only.py [캡처파일] --all-links --clean-output
```

이번 캡처에서는 BFI 프레임의 `addr3/BSSID`가 `00:00:00:00:00:00`으로 들어오고, 실제 AP는 `RA/DA` 필드에 있었습니다. 스크립트는 이 케이스를 처리하도록 `RA/DA`를 우선 확인하게 되어 있습니다.

### IndexError 또는 서브캐리어 인덱스 에러

공유기의 대역폭 설정에 따라 서브캐리어 수가 달라질 수 있습니다. 특정 서브캐리어 인덱스가 범위를 벗어나면 안전한 값을 직접 지정합니다.

```bash
python3 bfi_pcap_to_motion_png_only.py [캡처파일] --subcarrier-index 26 --clean-output
```

### VNC 화면이 멈추거나 느린 경우

`iperf3`로 큰 UDP 트래픽을 보내는 동안 VNC 화면 전송 패킷이 밀릴 수 있습니다. 화면만 늦게 보이는 경우가 많으며, BFI 생성과 스니핑 품질 자체에는 보통 큰 영향을 주지 않습니다.

### 인터넷이 필요할 때

실험 네트워크가 독립망이라 인터넷이 막힐 수 있습니다. Windows PC에서 검색이나 다운로드가 필요하면 잠시 유선 LAN을 빼서 인터넷망으로 전환한 뒤, 작업 후 다시 공유기 LAN에 연결하는 방식이 가장 단순합니다.

## 6. 필요 패키지

Python 패키지:

```bash
pip install pyshark numpy matplotlib
```

시스템에는 Wireshark 또는 TShark가 설치되어 있어야 합니다. `pyshark`는 내부적으로 TShark를 호출해 `.wcap`, `.pcap`, `.pcapng` 파일의 Wi-Fi 필드를 읽습니다.
