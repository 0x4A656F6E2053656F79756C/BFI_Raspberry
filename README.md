# BFI Wireless Sensing Experiment Guide

이 저장소는 Wi-Fi BFI(Beamforming Feedback Information) 패킷을 이용해 실내 사람 움직임/재실 상태를 분석하기 위한 실험 코드와 장비 세팅 절차를 정리합니다.

현재 구조는 **PCAP 파싱**과 **분석 그래프 생성**을 분리합니다. 오래 걸리는 PCAP 파싱은 한 번만 수행해 중간 결과로 저장하고, 이후 분석 방법은 중간 결과를 재사용해 빠르게 바꿔볼 수 있습니다.

## 1. 코드 역할과 실행 방법

### 파일별 역할

- `bfi_core.py`: BFI 파싱, V matrix 복원, 중간 캐시 저장/로드, 분석 metric 계산, 그래프 생성에 쓰이는 공용 함수 모듈입니다. 직접 실행하지 않습니다.
- `bfi_pcap_to_intermediate.py`: `.pcap`, `.pcapng`, `.wcap`, `.cap` 파일을 읽어 pcap당 `*_bfi_intermediate.npz` 중간 결과를 저장합니다.
- `bfi_intermediate_to_motion_png.py`: `*_bfi_intermediate.npz` 파일을 읽어 분석 PNG를 생성합니다.
- `bfi_pcap_to_motion_png_only.py`: 최신 pcap 하나만 빠르게 확인하는 smoke test용 스크립트입니다. 중간 캐시나 메타데이터를 저장하지 않습니다.
- `timestamp_editcap.py`: `test.pcap`을 `data/YYYYMMDD_HHMMSS.pcap` 형식으로 변환/정리하는 보조 스크립트입니다.
- `time_control.py`: 실험 시간 제어용 보조 스크립트입니다.

### 권장 실행 흐름

1. PCAP 폴더를 중간 결과로 변환합니다.

```bash
python bfi_pcap_to_intermediate.py data_0529
```

기본 출력은 입력 폴더 바깥의 새 캐시 폴더입니다.

```text
data_0529_bfi_cache_YYYYMMDD_HHMMSS/
```

출력 위치를 직접 지정하려면 `--out`을 사용합니다.

```bash
python bfi_pcap_to_intermediate.py data_0529 --out parsed_cache_0529
```

2. 중간 결과에서 분석 그래프를 생성합니다.

```bash
python bfi_intermediate_to_motion_png.py data_0529_bfi_cache_YYYYMMDD_HHMMSS
```

기본값은 pcap당 `BFI Motion Score` PNG 한 장입니다. 기본 출력 폴더는 다음 형태입니다.

```text
data_0529_bfi_cache_YYYYMMDD_HHMMSS_motion_png_YYYYMMDD_HHMMSS/
```

3. 추가 분석 PNG까지 생성하려면 `--analysis`를 사용합니다.

```bash
python bfi_intermediate_to_motion_png.py data_0529_bfi_cache_YYYYMMDD_HHMMSS --analysis all
```

필요한 분석만 골라 만들 수도 있습니다.

```bash
python bfi_intermediate_to_motion_png.py data_0529_bfi_cache_YYYYMMDD_HHMMSS --analysis motion doppler static
```

지원하는 분석 출력은 다음과 같습니다.

- `motion`: 발표용 `BFI Motion Score` PNG입니다. 기본값입니다.
- `doppler`: CSI-ratio phase의 PCA 1번 성분으로 만든 Doppler/STFT spectrogram PNG입니다.
- `pca`: CSI-ratio phase PCA 성분의 시간 변화와 PC1-PC2 trajectory PNG입니다.
- `static`: 초기 baseline 대비 channel-shape drift와 correlation loss PNG입니다.
- `all`: `motion`, `doppler`, `pca`, `static`을 모두 생성합니다.

STFT 시간 해상도는 옵션으로 조절할 수 있습니다.

```bash
python bfi_intermediate_to_motion_png.py data_0529_bfi_cache_YYYYMMDD_HHMMSS \
  --analysis all \
  --stft-window-seconds 4 \
  --stft-step-seconds 0.5 \
  --max-doppler-hz 5
```

4. 빠른 동작 확인만 할 때는 smoke test를 사용합니다.

```bash
python bfi_pcap_to_motion_png_only.py --data-dir data_0529
```

이 스크립트는 `--data-dir` 아래에서 타임스탬프 기준 가장 최근 capture 하나만 읽고, motion graph PNG 하나만 저장합니다.

### 중간 결과에 저장되는 데이터

`*_bfi_intermediate.npz`에는 분석 재사용을 위한 핵심 데이터와 검증용 메타데이터가 함께 들어갑니다.

- `V_all`: 복원된 BFI matrix, shape `(packet, subcarrier, Nr, Nc)`
- `angles_all`: quantized BFI angle 값
- `snrs`: BFI report의 SNR 계열 값
- `times`, `frame_numbers`: 시간축과 원본 frame 번호
- `packet_meta_json`: packet별 `feedback_type`, `codebook_info`, `bphi`, `bpsi`, BFI payload 길이, padding 정보, 원본 `bfi_payload_hex`
- `metadata`: 원본 pcap 경로/크기/수정시간, 선택된 group, 파싱 옵션, 요약 정보

## 2. 실험 구조와 라벨링 방법

### 데이터 폴더 구조

각 실험 묶음은 `data_0529`, `data_0530` 같은 폴더로 관리합니다. 폴더 안에는 pcap 파일과 `record.md`가 있습니다.

```text
data_0529/
  record.md
  20260528_233930.pcap
  20260528_235009.pcap
  ...
```

분석 코드는 해당 data 폴더 안의 pcap 파일을 타임스탬프/파일명 기준으로 정렬하고, `record.md`의 번호 목록과 순서대로 매칭합니다. 따라서 pcap 파일 순서와 `record.md` 항목 순서가 맞아야 그래프 annotation이 올바르게 붙습니다.

### `record.md` 작성 규칙

`record.md`에는 실험 조건을 번호 목록으로 적습니다.

```markdown
1. 오른쪽 두 번째 의자에 앉기 (약 1m)
2. 아무도 없음 (부재, 2분)
3. 정적 재실 (2분)
4. 방 전체를 빙글빙글 돌기 (한 주기에 20초, 2분)
```

현재 코드는 항목 텍스트에 포함된 키워드로 실험 scenario를 분류합니다.

- `앉`: 반복 seated sequence로 해석합니다.
- `정적`: static presence로 해석합니다.
- `아무도 없음`, `부재`: absent로 해석합니다.
- `방 전체`, `빙글`, `돌기`, `걷`: dynamic/walking으로 해석합니다.
- `덤벨`, `비인체`: non-human dynamic으로 해석합니다.

### 반복 seated sequence 라벨

`record.md` 항목에 `앉`이 들어간 경우, 현재 실험 프로토콜을 다음 시간 구조로 해석합니다.

```text
0-20s    Cut
20-30s   Walk in
30-50s   Seated
50-60s   Walk out
60-80s   Away
80-90s   Walk in
90-110s  Seated
110-120s Walk out
120-140s Away
140-150s Walk in
```

그래프는 데이터 길이가 120초 이상이면 발표용으로 `20-120초` 구간만 표시합니다. 데이터가 120초보다 짧으면 전체 구간을 그대로 표시합니다.

### 그래프 색상 규칙

Motion graph와 PCA time-series 배경은 실험 구간에 따라 색이 칠해집니다.

- `Walk in`: 붉은색
- `Walk out`: 주황색
- `Seated` / `Static`: 파란색
- `Away` / `Absent`: 회색
- `Non-human dynamic`: 주황색 계열

PCA 그래프의 아래쪽 PC1-PC2 trajectory 산점도도 같은 기준으로 색을 칠합니다.

- `Walk in`: 빨강
- `Walk out`: 주황
- `Seated`: 파랑
- `Away`: 회색
- 라벨이 없거나 crop 밖에서 섞인 점: 옅은 회색 `Other`

### 현재 분석 지표

발표용 `BFI Motion Score`는 여러 metric을 모두 그리지 않고, 사람의 동적/정적 재실 변화에 민감한 값들을 정규화한 뒤 평균낸 한 줄짜리 composite score입니다.

```text
complex_diff_mean_abs
ant1_ant2_stream1_relative_complex_diff_mean_abs
quantized_angle_diff_mean_abs
```

추가 분석의 의미는 다음과 같습니다.

- `doppler`: 움직임이 시간-주파수 영역에서 어떻게 나타나는지 보는 spectrogram입니다.
- `pca`: CSI-ratio phase의 주요 변화 방향을 보고, 상태별 trajectory가 분리되는지 확인합니다.
- `static`: 초기 baseline과 비교한 장기 drift/correlation loss를 봅니다. 가만히 앉아 있는 정적 재실을 motion score만으로 놓칠 때 보조 지표로 씁니다.

## 3. 실험 장비 세팅 방법

### 기본 네트워크 세팅

ASUS 공유기:

- SSID / 대역: `ASUS_00_5GHz` / 5GHz 전용
- 보안 규격: `WPA2-Personal`
- PMF(보호된 관리 프레임): `Disable`
- 네트워크 대역: `192.168.51.X` DHCP
- 현재 AP MAC: `08:bf:b8:95:80:04`

Raspberry Pi 4B:

- OS: Raspberry Pi OS Legacy 64-bit Bullseye, GUI 포함
- 무선 LAN 국가 코드: `KR`
- 원격 접속: SSH 및 VNC 서버 활성화
- 현재 Wi-Fi MAC: `2c:cf:67:17:0a:3c`

현재 분석 스크립트의 기본 target link는 다음 조합입니다.

```text
source STA = 2c:cf:67:17:0a:3c
AP         = 08:bf:b8:95:80:04
```

PMF를 비활성화해야 맥북의 일반 모니터링/스니퍼 환경에서 관리 프레임과 BFI Action 프레임을 안정적으로 관측하기 쉽습니다.

### 장비 부팅 순서

장비를 다른 방이나 실험실로 옮긴 뒤에는 아래 순서로 켜는 것이 가장 안정적입니다.

```text
1. 공유기 전원 ON
2. Raspberry Pi 전원 ON
3. Windows 실험용 PC 또는 노트북을 공유기 LAN 포트에 유선 연결
```

공유기를 Raspberry Pi보다 늦게 켜면 Pi가 부팅 시점에 5GHz SSID를 찾지 못해 Wi-Fi 연결이나 DHCP IP 할당이 꼬일 수 있습니다.

### Raspberry Pi IP 확인

공유기 관리 페이지에 접속합니다.

```text
http://192.168.51.1
```

클라이언트 목록에서 `2c:cf:67:17:0a:3c`에 해당하는 Raspberry Pi의 현재 IP를 확인합니다. 전원을 껐다 켜면 IP 끝자리가 바뀔 수 있으므로 실험마다 다시 확인하는 것이 좋습니다.

### Raspberry Pi에서 iPerf3 서버 실행

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

### 맥북 무선 스니퍼 실행

1. 공유기 관리 페이지에서 현재 5GHz 채널 번호와 대역폭을 확인합니다.
2. 맥북에서 `Option` 키를 누른 채 Wi-Fi 아이콘을 클릭합니다.
3. `무선 진단 열기...`를 실행합니다.
4. 상단 메뉴에서 `윈도우` > `스니퍼`를 엽니다.
5. 공유기와 동일한 5GHz 채널 번호 및 대역폭을 선택한 뒤 스니핑을 시작합니다.

맥북 바탕화면 또는 지정된 저장 위치에 `.wcap` 캡처 파일이 생성됩니다.

### Windows PC에서 UDP 트래픽 생성

맥북 스니퍼가 켜진 상태에서 Windows PC의 새 명령 프롬프트를 열고 `iperf3.exe`가 있는 폴더로 이동합니다.

```cmd
cd C:\iperf3
```

Raspberry Pi를 향해 UDP 트래픽을 보냅니다.

```cmd
iperf3.exe -c [라즈베리파이_IP_주소] -u -b 150M -t 30
```

이 트래픽은 유선 PC에서 AP를 거쳐 무선 Pi로 전달됩니다. Pi 무선 링크가 큰 부하를 받는 동안 Pi는 AP를 향해 VHT Compressed Beamforming Report(BFI) Action 프레임을 송신하고, 맥북 스니퍼가 이를 캡처합니다.

### 캡처 정리

1. `iperf3` 실행이 끝나면 맥북 스니퍼를 중단합니다.
2. 생성된 `.wcap`, `.pcap`, 또는 `.pcapng` 파일을 프로젝트 폴더 또는 `data_*` 폴더로 옮깁니다.
3. 필요하면 파일 이름을 `test.pcap`으로 맞춘 뒤 `timestamp_editcap.py`를 실행합니다.

```bash
python timestamp_editcap.py
```

이 스크립트는 Wireshark의 `editcap`을 호출해 `data/YYYYMMDD_HHMMSS.pcap` 형식으로 파일을 저장합니다.

### 트러블슈팅

BFI가 0개로 잡히는 경우:

- 공유기 5GHz 채널과 맥북 스니퍼 채널이 같은지 확인합니다.
- 공유기 PMF가 `Disable`인지 확인합니다.
- Raspberry Pi MAC이 `2c:cf:67:17:0a:3c`인지 확인합니다.
- AP MAC이 `08:bf:b8:95:80:04`인지 확인합니다.
- `iperf3` 트래픽 방향이 Windows PC에서 Raspberry Pi로 향하는지 확인합니다.
- 다른 링크의 BFI가 있는지 확인하려면 `--all-links`를 사용합니다.

```bash
python bfi_pcap_to_intermediate.py data_0529 --all-links
```

VNC 화면이 멈추거나 느린 경우:

- 큰 UDP 트래픽을 보내는 동안 VNC 화면 전송 패킷이 밀릴 수 있습니다.
- 화면만 늦게 보이는 경우가 많으며, BFI 생성과 스니핑 품질 자체에는 보통 큰 영향을 주지 않습니다.

### 필요 패키지

Python 패키지:

```bash
pip install pyshark numpy matplotlib
```

시스템에는 Wireshark 또는 TShark가 설치되어 있어야 합니다. `pyshark`는 내부적으로 TShark를 호출해 `.wcap`, `.pcap`, `.pcapng` 파일의 Wi-Fi 필드를 읽습니다.
