import time
import os
import sys
import threading

# --- 1. 오디오 사전 생성 (캐싱) ---
CACHE_DIR = "/tmp"

def prepare_audio_cache():
    print("TTS 오디오 파일 캐싱 중... (최초 약 1~2초 소요)")
    # 오직 숫자(1~10)만 캐싱합니다.
    for i in range(1, 11): 
        filepath = f"{CACHE_DIR}/bfi_say_{i}.aiff"
        if not os.path.exists(filepath):
            os.system(f"say -o {filepath} '{i}'")
    print("캐싱 완료!\n")

# --- 2. 비동기 실행 헬퍼 ---
def run_async(cmd):
    thread = threading.Thread(target=lambda: os.system(cmd))
    thread.daemon = True
    thread.start()

# --- 3. 알림 함수 ---
def play_cached_voice(key):
    run_async(f"afplay {CACHE_DIR}/bfi_say_{key}.aiff")

# --- 4. 대기 구간 헬퍼 (마지막 3초 카운트다운) ---
def silent_wait_with_countdown(duration, phase_name):
    quiet_time = duration - 3
    time.sleep(quiet_time)
    
    for i in range(3, 0, -1):
        sys.stdout.write(f"\r{phase_name} 대기 중... 다음 행동 준비: {i}초... ")
        sys.stdout.flush()
        play_cached_voice(str(i))
        time.sleep(1)
    print()

# --- 5. 이동 구간 헬퍼 (1~10 카운트) ---
def walking_phase(duration, phase_name):
    for i in range(1, duration + 1):
        sys.stdout.write(f"\r{phase_name} 중: {i}초... ")
        sys.stdout.flush()
        play_cached_voice(str(i))
        time.sleep(1)
    print()

# --- 메인 실행 ---
if __name__ == "__main__":
    print("=== BFI 센싱 초정밀 타이머 (대기 20초) ===\n")
    
    prepare_audio_cache()
    
    # 최초 시작 전 카운트다운 (3, 2, 1)
    for i in range(3, 0, -1):
        sys.stdout.write(f"\r시작 전 대기: {i}초... ")
        sys.stdout.flush()
        play_cached_voice(str(i))
        time.sleep(1)
        
    print("\n\n▶▶ [0:00] 실험 시작! (수집 개시)")
    
    total_time = 0
    NUM_REPEATS = 2

    # 시나리오 반복
    for lap in range(1, NUM_REPEATS + 1):
        print(f"\n--- [ 반복 {lap}/{NUM_REPEATS} ] ---")
        
        # [구간 1] 밖에서 대기 (20초로 변경됨) - 조용히 있다가 마지막 3, 2, 1
        print(f"[{total_time:02d}초] 밖에서 대기 (20초)")
        silent_wait_with_countdown(20, "밖에서 대기")
        total_time += 20
        
        # [구간 2] 안으로 걸어 들어옴 (10초) - 1~10 카운트
        print(f"[{total_time:02d}초] 안으로 걸어 들어옴 (10초)")
        walking_phase(10, "안으로 들어옴")
        total_time += 10
        
        # [구간 3] 의자에 앉기 (20초) - 조용히 있다가 마지막 3, 2, 1
        print(f"[{total_time:02d}초] 의자에 앉아 있음 (20초)")
        silent_wait_with_countdown(20, "의자 앉기")
        total_time += 20
        
        # [구간 4] 밖으로 걸어 나감 (10초) - 1~10 카운트
        print(f"[{total_time:02d}초] 밖으로 걸어 나감 (10초)")
        walking_phase(10, "밖으로 나감")
        total_time += 10

    # 종료
    print(f"\n▶▶ [{total_time:02d}초] 모든 실험 종료!")